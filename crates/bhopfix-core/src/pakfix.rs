//! pakfix — Linux case-folding fix for BSP pakfiles.
//!
//! The 64-bit Source builds stopped case-folding lookups into the BSP's
//! embedded zip pakfile (ValveSoftware/Source-1-Games#6868): the engine
//! lowercases every asset lookup, so anything packed with uppercase in its
//! path never resolves on Linux — pink/black checkerboard materials, silent
//! sounds. Windows and the old 32-bit builds are unaffected, which is why so
//! many classic bhop maps ship broken paks.
//!
//! Repacking the BSP would change the file and trip the server's
//! map-consistency check ("map differs"), so instead every affected entry is
//! extracted as a LOWERCASE loose file under cstrike/download/ — the engine's
//! pak miss falls through the search path and finds it there. BSPs are never
//! modified; existing loose files are never overwritten.
//!
//! Only STORED (method 0) entries are extracted — bspzip never compresses —
//! anything else is logged and skipped rather than pulling in a decompressor.
//!
//! This code runs inside the game process (panic = abort): every read is
//! bounds-checked, nothing indexes blindly.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const LUMP_PAKFILE: usize = 40;
const BSP_HEADER_LEN: usize = 8 + 64 * 16;
/// Asset roots the engine loads from paks and that the case bug affects.
const PREFIXES: [&[u8]; 4] = [b"materials/", b"models/", b"sound/", b"particles/"];
/// BSPs come from game servers (semi-trusted). Real bspzip paks are tens of
/// MB; refuse anything absurd instead of buffering it in the game process.
const MAX_PAK_LEN: u64 = 256 * 1024 * 1024;

const EOCD_SIG: u32 = 0x0605_4b50;
const CDIR_SIG: u32 = 0x0201_4b50;
const LOCAL_SIG: u32 = 0x0403_4b50;

fn rd_u16(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}

fn rd_u32(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn invalid(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Locate the zip End Of Central Directory in the pak blob.
/// Returns (central_dir_offset, entry_count).
fn find_eocd(blob: &[u8]) -> Option<(usize, usize)> {
    // EOCD is 22 bytes + up to 65535 bytes of trailing comment.
    let lo = blob.len().saturating_sub(22 + 65535);
    let hi = blob.len().checked_sub(22)?;
    (lo..=hi).rev().find_map(|i| {
        if rd_u32(blob, i)? != EOCD_SIG {
            return None;
        }
        let count = rd_u16(blob, i + 10)? as usize;
        let cd_ofs = rd_u32(blob, i + 16)? as usize;
        Some((cd_ofs, count))
    })
}

/// A pak entry's stored name, normalized: backslashes to slashes.
/// Returns None for names that must not become filesystem paths.
fn sane_name(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.len() > 512 {
        return None;
    }
    let name: Vec<u8> = raw
        .iter()
        .map(|&b| if b == b'\\' { b'/' } else { b })
        .collect();
    if name.contains(&0) || name.first() == Some(&b'/') || name.last() == Some(&b'/') {
        return None;
    }
    // zip-slip: no "." / ".." / empty path components
    if name
        .split(|&b| b == b'/')
        .any(|c| c.is_empty() || c == b"." || c == b"..")
    {
        return None;
    }
    Some(name)
}

/// Extract case-broken pak entries of one BSP as lowercase loose files under
/// `download_dir`. Returns how many files were written. Never modifies the
/// BSP, never overwrites an existing file.
pub fn fix_bsp(bsp: &Path, download_dir: &Path) -> io::Result<usize> {
    let bspname = bsp.file_name().map(|n| n.to_string_lossy().into_owned());
    let bspname = bspname.as_deref().unwrap_or("?");

    let mut f = fs::File::open(bsp)?;
    let file_len = f.metadata()?.len();
    let mut hdr = [0u8; BSP_HEADER_LEN];
    f.read_exact(&mut hdr)?;
    if &hdr[0..4] != b"VBSP" {
        return Err(invalid("not a VBSP file"));
    }
    let lump = 8 + LUMP_PAKFILE * 16;
    let pak_ofs = rd_u32(&hdr, lump).unwrap_or(0) as u64;
    let pak_len = rd_u32(&hdr, lump + 4).unwrap_or(0) as u64;
    if pak_len == 0 {
        return Ok(0);
    }
    if pak_len > MAX_PAK_LEN {
        return Err(invalid("pak lump implausibly large, refusing"));
    }
    if pak_ofs
        .checked_add(pak_len)
        .is_none_or(|end| end > file_len)
    {
        return Err(invalid("pak lump out of bounds"));
    }

    let mut blob = vec![0u8; pak_len as usize];
    f.seek(SeekFrom::Start(pak_ofs))?;
    f.read_exact(&mut blob)?;

    let Some((cd_ofs, count)) = find_eocd(&blob) else {
        return Err(invalid("pak lump has no zip directory"));
    };

    let mut extracted = 0usize;
    // Non-overlapping stored data can never exceed the pak itself; a crafted
    // central directory with overlapping entries could otherwise amplify a
    // small pak into unbounded disk writes.
    let mut write_budget = blob.len() as u64;
    let mut p = cd_ofs;
    for _ in 0..count {
        if rd_u32(&blob, p) != Some(CDIR_SIG) {
            break;
        }
        let (Some(method), Some(comp_size), Some(uncomp_size)) = (
            rd_u16(&blob, p + 10),
            rd_u32(&blob, p + 20),
            rd_u32(&blob, p + 24),
        ) else {
            break;
        };
        let (Some(name_len), Some(extra_len), Some(comment_len), Some(local_ofs)) = (
            rd_u16(&blob, p + 28).map(usize::from),
            rd_u16(&blob, p + 30).map(usize::from),
            rd_u16(&blob, p + 32).map(usize::from),
            rd_u32(&blob, p + 42).map(|v| v as usize),
        ) else {
            break;
        };
        let Some(raw_name) = blob.get(p + 46..p + 46 + name_len) else {
            break;
        };
        let entry_end = p + 46 + name_len + extra_len + comment_len;

        if let Some(name) = sane_name(raw_name) {
            let lower = name.to_ascii_lowercase();
            let case_broken = name != lower;
            let relevant = PREFIXES.iter().any(|pre| lower.starts_with(pre));
            if case_broken && relevant {
                if u64::from(comp_size) > write_budget {
                    eprintln!("[pakfix] {bspname}: write budget exceeded (crafted pak?), stopping");
                    break;
                }
                match extract_stored(
                    &blob,
                    local_ofs,
                    method,
                    comp_size,
                    uncomp_size,
                    &lower,
                    download_dir,
                ) {
                    Ok(true) => {
                        extracted += 1;
                        write_budget -= u64::from(comp_size);
                    }
                    Ok(false) => {}
                    Err(e) => eprintln!(
                        "[pakfix] {bspname}: {}: {e}",
                        String::from_utf8_lossy(&lower)
                    ),
                }
            }
        }
        p = entry_end;
    }
    Ok(extracted)
}

/// Write one stored zip entry to `download_dir/<lower>`. Ok(false) = skipped
/// (already exists). Atomic: writes a .part file, then renames.
fn extract_stored(
    blob: &[u8],
    local_ofs: usize,
    method: u16,
    comp_size: u32,
    uncomp_size: u32,
    lower: &[u8],
    download_dir: &Path,
) -> io::Result<bool> {
    #[cfg(unix)]
    let dest: PathBuf = {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        download_dir.join(OsStr::from_bytes(lower))
    };
    #[cfg(not(unix))]
    let dest: PathBuf = download_dir.join(String::from_utf8_lossy(lower).as_ref());
    if dest.exists() {
        return Ok(false);
    }
    if method != 0 {
        return Err(invalid("compressed entry (not method 0), skipping"));
    }
    if comp_size != uncomp_size {
        return Err(invalid("stored entry with mismatched sizes, skipping"));
    }
    if rd_u32(blob, local_ofs) != Some(LOCAL_SIG) {
        return Err(invalid("bad local header"));
    }
    let (Some(nl), Some(el)) = (rd_u16(blob, local_ofs + 26), rd_u16(blob, local_ofs + 28)) else {
        return Err(invalid("truncated local header"));
    };
    let data_ofs = local_ofs + 30 + nl as usize + el as usize;
    let Some(data) = blob.get(data_ofs..data_ofs + comp_size as usize) else {
        return Err(invalid("entry data out of bounds"));
    };

    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    // unique temp name: the launcher sweep and the in-game fixer can run
    // concurrently, and two maps can pack the same asset path
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let mut part = dest.as_os_str().to_owned();
    part.push(format!(
        ".part.{}.{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let part = PathBuf::from(part);
    if let Err(e) = fs::write(&part, data) {
        let _ = fs::remove_file(&part);
        return Err(e);
    }
    match fs::rename(&part, &dest) {
        Ok(()) => Ok(true),
        Err(e) => {
            let _ = fs::remove_file(&part);
            Err(e)
        }
    }
}

/// Fix every BSP in cstrike/maps and cstrike/download/maps.
/// Returns the total number of files extracted.
#[allow(dead_code)] // used by the launcher binary; the .so uses fix_bsp directly
pub fn sweep(game_root: &Path) -> usize {
    let download_dir = game_root.join("cstrike/download");
    let mut total = 0;
    for dir in [
        game_root.join("cstrike/maps"),
        game_root.join("cstrike/download/maps"),
    ] {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "bsp") {
                continue;
            }
            let name = path
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or_default();
            match fix_bsp(&path, &download_dir) {
                Ok(0) => {} // clean map
                Ok(n) => {
                    eprintln!("[pakfix] {name}: extracted {n} case-broken file(s)");
                    total += n;
                }
                Err(e) => eprintln!("[pakfix] {name}: skipped: {e}"),
            }
        }
    }
    total
}
