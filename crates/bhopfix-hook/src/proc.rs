//! `/proc/self` access: where this process is mapped, and how to read its own
//! memory without ever risking a fault.
//!
//! Two readers live here and they are not interchangeable:
//!
//!   * [`read_region_safe`] copies a whole mapping page by page and zero-fills
//!     whatever vanished under us. Ranges taken from `/proc/self/maps` go
//!     stale: the engine maps and unmaps constantly while it starts up.
//!   * [`rd`] and its typed wrappers `pread` one value through a single cached
//!     descriptor. `pread` on `/proc/self/mem` reports `EIO` for an unmapped
//!     address instead of delivering SIGSEGV, which is what makes it safe to
//!     chase a pointer we are only guessing at.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicI32, Ordering};

pub(crate) struct Mapping {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) offset: usize,
    pub(crate) perms: String,
    pub(crate) path: String,
}

pub(crate) fn self_maps() -> Vec<Mapping> {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return Vec::new();
    };
    maps.lines()
        .filter_map(|line| {
            // format: "start-end perms offset dev inode pathname" (path may contain spaces)
            let mut it = line.split_whitespace();
            let range = it.next()?;
            let perms = it.next()?.to_string();
            let offset = usize::from_str_radix(it.next()?, 16).ok()?;
            it.next()?; // dev
            it.next()?; // inode
            let path = it.collect::<Vec<_>>().join(" ");
            let (s, e) = range.split_once('-')?;
            Some(Mapping {
                start: usize::from_str_radix(s, 16).ok()?,
                end: usize::from_str_radix(e, 16).ok()?,
                offset,
                perms,
                path,
            })
        })
        .collect()
}

/// A loaded module: where it sits and which file it came from (we parse the
/// file to resolve hook targets by name).
pub(crate) fn module_base(maps: &[Mapping], needle: &str) -> Option<(usize, String)> {
    maps.iter()
        .find(|m| m.path.ends_with(needle) && m.offset == 0)
        .map(|m| (m.start, m.path.clone()))
}

/// Read a process memory region page-by-page via /proc/self/mem.
/// Unmapped/unreadable pages come back zeroed instead of SIGSEGVing us
/// (mappings can vanish between reading /proc/self/maps and the scan —
/// the game maps/unmaps constantly during startup).
pub(crate) fn read_region_safe(mem: &File, start: usize, len: usize) -> Vec<u8> {
    const PAGE: usize = 4096;
    let mut buf = vec![0u8; len];
    let mut off = 0;
    while off < len {
        let end = (off + PAGE).min(len);
        let _ = mem.read_at(&mut buf[off..end], (start + off) as u64);
        off = end;
    }
    buf
}

pub(crate) fn has_insecure() -> bool {
    std::fs::read("/proc/self/cmdline")
        .map(|c| c.split(|&b| b == 0).any(|a| a == b"-insecure"))
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// fault-safe single-value reads via /proc/self/mem
//
// pread never faults on a bad address, so every one of these is safe to point
// at a pointer we recovered from a scan and are not yet sure about.
// ---------------------------------------------------------------------------

static MEM_FD: AtomicI32 = AtomicI32::new(-1);

/// Open the descriptor the readers below share. Idempotent, so any feature can
/// call it before its first read without caring who else already did.
/// Returns false only if `/proc/self/mem` cannot be opened at all, in which
/// case every read below fails closed.
pub(crate) fn open_mem() -> bool {
    if MEM_FD.load(Ordering::Relaxed) >= 0 {
        return true;
    }
    let fd = unsafe { libc::open(c"/proc/self/mem".as_ptr(), libc::O_RDONLY) };
    if fd < 0 {
        return false;
    }
    // Two threads can get here at once; the loser closes its descriptor rather
    // than leaking it. The winner's is never closed — the readers use it for
    // the remaining lifetime of the process.
    if MEM_FD
        .compare_exchange(-1, fd, Ordering::Relaxed, Ordering::Relaxed)
        .is_err()
    {
        unsafe { libc::close(fd) };
    }
    true
}

pub(crate) fn rd(buf: &mut [u8], addr: usize) -> bool {
    let fd = MEM_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return false;
    }
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), buf.len(), addr as libc::off_t) };
    n == buf.len() as isize
}

pub(crate) fn rd_i32(addr: usize) -> Option<i32> {
    let mut b = [0u8; 4];
    rd(&mut b, addr).then(|| i32::from_ne_bytes(b))
}

pub(crate) fn rd_u8(addr: usize) -> Option<u8> {
    let mut b = [0u8; 1];
    rd(&mut b, addr).then(|| b[0])
}

pub(crate) fn rd_u64(addr: usize) -> Option<usize> {
    let mut b = [0u8; 8];
    rd(&mut b, addr).then(|| usize::from_ne_bytes(b))
}

pub(crate) fn rd_cstr(addr: usize, max: usize) -> Option<String> {
    let fd = MEM_FD.load(Ordering::Relaxed);
    if fd < 0 {
        return None;
    }
    let mut buf = vec![0u8; max];
    let n = unsafe { libc::pread(fd, buf.as_mut_ptr().cast(), max, addr as libc::off_t) };
    if n <= 0 {
        return None;
    }
    buf.truncate(n as usize);
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}
