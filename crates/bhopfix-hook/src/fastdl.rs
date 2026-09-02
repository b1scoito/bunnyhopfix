//! fastdl.me hijack (port of rtldg's map-download feature).

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use bhopfix_core::elf;
use bhopfix_core::pakfix;
use bhopfix_core::sig::Pattern;

use crate::proc::{self, Mapping, rd_cstr, rd_u64, self_maps};
use crate::sourcejump;
use crate::vtable::VTABLE_MAX;

/// engine.so: `CClientState::ProcessServerInfo(SVC_ServerInfo *msg)`, the
/// net-message handler the engine runs for svc_ServerInfo.
///
/// Located by walking CClientState's RTTI vtable and matching what only
/// this handler does — copy the server's 16-byte map-lump MD5 out of the
/// message — with no slot index and no address involved.
const CLIENTSTATE_CLASS: &str = "12CClientState";
/// The MD5 copy: `movdqu md5(%rbx),%xmm2` ; `movups %xmm2,disp32(%r12)`.
/// The first wildcard is the message field offset, which we read back out
/// of the match rather than hard-coding it.
const PROCSERVINFO_MD5_COPY: &str = "F3 0F 6F 53 ?? 41 0F 11 94 24 ?? ?? ?? ??";
/// Entry prologue. Required for two reasons: it tells the real function
/// apart from the this-adjusting thunks that share its code (they `jmp`
/// straight into it), and these bytes are copied verbatim into the
/// trampoline, so they must stay free of rip-relative operands and
/// relative branches — push/mov/sub only.
const PROCSERVINFO_PROLOGUE: &str = "55 48 89 E5 41 55 41 54 49 89 FC 53 48 89 F3 48 83 EC ??";
/// Must equal the pattern above; validated at resolve time.
const PROLOGUE_LEN: usize = 19;
/// How far into the body to look for the MD5 copy.
const PROCSERVINFO_WINDOW: usize = 0x200;

/// Offset of the map-lump MD5 inside the serverinfo message, recovered
/// from the matched instruction above.
static MSG_LUMP_MD5: AtomicUsize = AtomicUsize::new(0);

static ORIG: AtomicUsize = AtomicUsize::new(0);
static MAPNAME_OFFSET: AtomicUsize = AtomicUsize::new(0);

fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".cache/bunnyhopfix")
}

/// Listing of fastdl.me contents: "<sha1>,<lumpmd5hex>" per line.
fn checksum_row(line: &str) -> Option<(&str, &str)> {
    let (sha1, md5) = line.trim_end_matches('\r').split_once(',')?;
    (sha1.len() == 40
        && md5.len() == 32
        && sha1.bytes().all(|byte| byte.is_ascii_hexdigit())
        && md5.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then_some((sha1, md5))
}

fn lump_checksums_csv() -> Option<String> {
    let path = cache_dir().join("lump_checksums.csv");
    let stale = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .map(|t| t.elapsed().map(|e| e.as_secs() > 36 * 3600).unwrap_or(true))
        .unwrap_or(true);
    if stale {
        let _ = std::fs::create_dir_all(cache_dir());
        log!("downloading lump_checksums.csv from fastdl.me (~4MB)...");
        let tmp = cache_dir().join("lump_checksums.csv.part");
        let ok = std::process::Command::new("curl")
            .args([
                "-fsSL",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "30",
                "--max-filesize",
                "33554432",
                "-o",
            ])
            .arg(&tmp)
            .arg("https://venus.fastdl.me/lump_checksums.csv")
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let valid = ok
            && std::fs::read_to_string(&tmp)
                .is_ok_and(|csv| csv.lines().any(|line| checksum_row(line).is_some()));
        if valid {
            let _ = std::fs::rename(&tmp, &path);
        } else {
            let _ = std::fs::remove_file(&tmp);
            log!("fastdl.me csv download failed or returned invalid data");
        }
    }
    std::fs::read_to_string(&path)
        .ok()
        .filter(|csv| csv.lines().any(|line| checksum_row(line).is_some()))
}

fn lookup_md5<'a>(csv: &'a str, md5hex: &str) -> Option<&'a str> {
    if md5hex.len() != 32 || !md5hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    csv.lines().find_map(|line| {
        let (sha1, md5) = checksum_row(line)?;
        md5.eq_ignore_ascii_case(md5hex).then_some(sha1)
    })
}

/// Scan the message object for pointers to plausible map name strings.
/// The serverinfo carries several short strings (game dir "cstrike",
/// skybox, map name...) — the map name typically comes LAST. Game-dir
/// values are excluded explicitly. All reads go through /proc/self/mem
/// so a bad pointer can't crash the game.
fn detect_mapname(msg: *mut c_void, maps: &[Mapping]) -> Option<String> {
    const GAME_DIRS: &[&str] = &[
        "cstrike",
        "hl2",
        "valve",
        "source",
        "tf2",
        "tf",
        "czero",
        "dods",
        "csgo",
        "left4dead",
        "portal",
    ];
    // A plausible map name: bsp basenames are short and use this charset.
    let plausible = |s: &str| {
        (3..=64).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    };

    let known = MAPNAME_OFFSET.load(Ordering::Relaxed);
    if known != 0 {
        // The cached value is the offset of the POINTER slot, so
        // dereference it (read the pointer, then the string it points to)
        // exactly like discovery does. Validate the result: a wrong cached
        // offset (the original skybox bug) or a shifted struct must NOT
        // poison every subsequent map — drop the cache and re-discover.
        if let Some(ptr) = rd_u64(msg as usize + known)
            && let Some(s) = rd_cstr(ptr, 128)
            && plausible(&s)
            && !GAME_DIRS.contains(&s.as_str())
        {
            return Some(s);
        }
        MAPNAME_OFFSET.store(0, Ordering::Relaxed);
    }
    // All msg reads (pointer slots included) go through /proc/self/mem, so
    // a message shorter than the scan window can't fault the game.
    let mut candidates: Vec<(usize, String)> = Vec::new();
    for off in (0x40..0xa0).step_by(8) {
        let Some(ptr) = rd_u64(msg as usize + off) else {
            continue;
        };
        if ptr < 0x10000 {
            continue;
        }
        if maps.iter().all(|m| !(ptr >= m.start && ptr < m.end)) {
            continue;
        }
        if let Some(s) = rd_cstr(ptr, 128)
            && plausible(&s)
        {
            candidates.push((off, s));
        }
    }
    dbglog!("serverinfo string candidates: {candidates:?}");
    // serverinfo string fields are, in order: game_dir, map_name,
    // sky_name, host_name. The map name is the field IMMEDIATELY AFTER
    // the game directory — NOT the last string (that's the skybox, e.g.
    // "sky_dust", or the host name). candidates are in ascending offset
    // order, so take the one right after the game-dir entry; if the game
    // dir isn't recognized, fall back to the second field POSITIONALLY
    // (index 1), still the map name, rather than picking the game dir.
    let picked = match candidates
        .iter()
        .position(|(_, s)| GAME_DIRS.contains(&s.as_str()))
    {
        Some(i) => candidates.into_iter().nth(i + 1),
        None => candidates.into_iter().nth(1),
    };
    if let Some((off, ref s)) = picked {
        MAPNAME_OFFSET.store(off, Ordering::Relaxed);
        log!("detected map name field at msg+0x{off:x} (\"{s}\")");
    }
    picked.map(|(_, s)| s)
}

/// `bzip2 -dc <src> > <dst>`; true on success and non-empty output.
fn decompress_bz2(src: &std::path::Path, dst: &std::path::Path) -> bool {
    let Ok(out) = std::fs::File::create(dst) else {
        return false;
    };
    let ok = std::process::Command::new("bzip2")
        .arg("-dc")
        .arg(src)
        .stdout(std::process::Stdio::from(out))
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        let _ = std::fs::remove_file(dst);
    }
    ok
}

/// Returns true if this call installed+case-fixed the map (so the caller
/// can skip a redundant synchronous fix); false if nothing was written.
fn ensure_map(mapname: &str, sha1: &str) -> bool {
    let cwd = match std::fs::read_link("/proc/self/cwd") {
        Ok(p) => p,
        Err(_) => return false,
    };
    let maps_dir = cwd.join("cstrike/maps");
    let target = maps_dir.join(format!("{mapname}.bsp"));
    let sidecar = cache_dir().join(format!("{mapname}.fastdl"));

    // sidecar matches → we already installed exactly this version
    if target.exists()
        && let Ok(have) = std::fs::read_to_string(&sidecar)
        && have.trim() == sha1
    {
        return false;
    }

    log!("fetching correct map version: hashed/{sha1}.bsp.bz2 -> {mapname}.bsp");
    let _ = std::fs::create_dir_all(cache_dir());
    let part = maps_dir.join(format!("{mapname}.bsp.part"));
    // fastdl.me stopped serving plain .bsp from hashed/ (404 since 2026);
    // the direct R2 bucket serves .bsp.bz2. Old URL kept as fallback in
    // case the endpoints shuffle again.
    //
    // NB: this runs synchronously inside the ProcessServerInfo hook (it
    // MUST finish before the engine's map-consistency check, same as the
    // Windows original), so the max-times bound how long a connect can
    // stall. Worst case ~25s, matching the old single download; the bz2
    // is smaller than the old plain .bsp and the fallback fails fast on
    // fastdl.me's 404, so the realistic case is a few seconds.
    let bz2 = maps_dir.join(format!("{mapname}.bsp.bz2.part"));
    let mut ok = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            "20",
            "--max-filesize",
            "1073741824",
            "-o",
        ])
        .arg(&bz2)
        .arg(format!("https://mainr2.fastdl.me/hashed/{sha1}.bsp.bz2"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if ok {
        ok = decompress_bz2(&bz2, &part);
        if !ok {
            log!("bzip2 decompression failed (is `bzip2` installed?)");
        }
    }
    let _ = std::fs::remove_file(&bz2);
    if !ok {
        // legacy endpoint: uncompressed .bsp (currently 404s, but kept in
        // case the endpoints shuffle again). curl -f exits fast on 404.
        ok = std::process::Command::new("curl")
            .args([
                "-fsSL",
                "--proto",
                "=https",
                "--tlsv1.2",
                "--max-time",
                "8",
                "--max-filesize",
                "1073741824",
                "-o",
            ])
            .arg(&part)
            .arg(format!("https://main.fastdl.me/hashed/{sha1}.bsp"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }
    if !ok {
        let _ = std::fs::remove_file(&part);
        log!("fastdl.me download failed; stock behavior applies");
        return false;
    }
    // sanity: BSP files start with "VBSP"
    let magic_ok = std::fs::File::open(&part)
        .and_then(|mut f| {
            use std::io::Read;
            let mut m = [0u8; 4];
            f.read_exact(&mut m).map(|_| m == *b"VBSP")
        })
        .unwrap_or(false);
    if !magic_ok {
        let _ = std::fs::remove_file(&part);
        log!("downloaded file is not a BSP; refusing to install");
        return false;
    }
    if !crate::file_matches_sha1(&part, sha1) {
        let _ = std::fs::remove_file(&part);
        log!("downloaded BSP SHA-1 differs from fastdl.me; refusing to install");
        return false;
    }
    match std::fs::rename(&part, &target) {
        Ok(()) => {
            let _ = std::fs::write(&sidecar, sha1);
            log!("installed {mapname}.bsp from fastdl.me");
            // Linux case-folding fix (Source-1-Games#6868): extract any
            // uppercase-packed pak content as lowercase loose files so
            // the engine can actually find it.
            match pakfix::fix_bsp(&target, &cwd.join("cstrike/download")) {
                Ok(0) | Err(_) => {}
                Ok(n) => {
                    log!("case-fix: extracted {n} uppercase-packed file(s) from {mapname}.bsp")
                }
            }
            true
        }
        Err(e) => {
            let _ = std::fs::remove_file(&part);
            log!("installing {mapname}.bsp failed: {e}");
            false
        }
    }
}

/// Arm the Linux pakfile case fix for the map we're connecting to.
///
/// If the BSP is already on disk (pre-existing, or just installed by
/// ensure_map) it's fixed synchronously. If not, the game's OWN
/// downloader is about to fetch it (fastdl.me doesn't cover it) — a
/// background thread waits for the file to land, then fixes it. The
/// current session may still show pink until a `retry`; every later load
/// is clean.
fn watch_map_for_casefix(mapname: &str) {
    use std::sync::Mutex;
    static WATCHING: Mutex<Vec<String>> = Mutex::new(Vec::new());

    let Ok(cwd) = std::fs::read_link("/proc/self/cwd") else {
        return;
    };
    let download_dir = cwd.join("cstrike/download");
    let candidates = [
        cwd.join(format!("cstrike/maps/{mapname}.bsp")),
        cwd.join(format!("cstrike/download/maps/{mapname}.bsp")),
    ];

    if candidates.iter().any(|c| c.exists()) {
        for c in candidates.iter().filter(|c| c.exists()) {
            match pakfix::fix_bsp(c, &download_dir) {
                Ok(0) | Err(_) => {}
                Ok(n) => {
                    log!("case-fix: extracted {n} uppercase-packed file(s) from {mapname}.bsp")
                }
            }
        }
        return;
    }

    {
        let Ok(mut watching) = WATCHING.lock() else {
            return;
        };
        if watching.iter().any(|m| m == mapname) {
            return; // already have a watcher for this map
        }
        if watching.len() >= 8 {
            return; // rogue server rotating map names; don't hoard threads
        }
        watching.push(mapname.to_string());
    }
    let mapname = mapname.to_string();
    let cleanup_name = mapname.clone();
    let spawned = std::thread::Builder::new().spawn(move || {
        let mut last_size = [None::<u64>; 2];
        let mut idle = 0u32;
        // give up after ~2 min WITHOUT progress (a growing file resets
        // the countdown, so slow downloads still get fixed)
        'poll: while idle < 240 {
            std::thread::sleep(std::time::Duration::from_millis(500));
            idle += 1;
            for (c, last) in candidates.iter().zip(last_size.iter_mut()) {
                let Ok(md) = std::fs::metadata(c) else {
                    continue;
                };
                // wait until the size is stable across two polls
                // (fix_bsp additionally validates the VBSP magic and
                // zip directory, and errors just keep us polling)
                if *last == Some(md.len()) {
                    match pakfix::fix_bsp(c, &download_dir) {
                        Ok(0) => break 'poll,
                        Ok(n) => {
                            log!(
                                "case-fix: extracted {n} uppercase-packed file(s) from \
                                 {mapname}.bsp (reconnect with `retry` if textures are pink)"
                            );
                            break 'poll;
                        }
                        Err(_) => {} // partial file; keep polling
                    }
                } else {
                    idle = 0;
                }
                *last = Some(md.len());
            }
        }
        if let Ok(mut watching) = WATCHING.lock() {
            watching.retain(|m| m != &mapname);
        }
    });
    if spawned.is_err()
        && let Ok(mut watching) = WATCHING.lock()
    {
        watching.retain(|m| m != &cleanup_name);
    }
}

extern "C" fn hooked_process_server_info(this: *mut c_void, msg: *mut c_void) -> bool {
    on_serverinfo(msg);
    let orig = ORIG.load(Ordering::Relaxed);
    let f: extern "C" fn(*mut c_void, *mut c_void) -> bool = unsafe { std::mem::transmute(orig) };
    f(this, msg)
}

fn on_serverinfo(msg: *mut c_void) {
    if msg.is_null() {
        return;
    }
    // Map name first — both the fastdl lookup and the case-fix watcher
    // need it. (If detection fails we skip the csv refresh too, but that
    // only matters for keeping the 36h cache warm, and detection is
    // cached after the first success, so it's a non-issue in practice.)
    if !proc::open_mem() {
        return;
    }
    let maps = self_maps();
    let Some(mapname) = detect_mapname(msg, &maps) else {
        log!("could not locate map name in serverinfo; skipping fastdl check");
        return;
    };

    let md5_off = MSG_LUMP_MD5.load(Ordering::Relaxed);
    let server_md5: [u8; 16] = unsafe { std::ptr::read(msg.byte_add(md5_off) as *const [u8; 16]) };
    let md5hex: String = server_md5.iter().map(|b| format!("{b:02x}")).collect();

    let mut just_installed = false;
    if let Some(csv) = lump_checksums_csv() {
        if let Some(sha1) = lookup_md5(&csv, &md5hex) {
            log!("server map: {mapname} (sha1 {sha1})");
            just_installed = ensure_map(&mapname, sha1);
        } else {
            dbglog!("server map md5 {md5hex} not in fastdl.me csv");
        }
    }

    // If ensure_map just installed+fixed this exact version, we're done.
    // Otherwise — fastdl.me didn't cover it (game's own downloader will
    // fetch it) or it was already on disk — arm the case fix.
    if !just_installed {
        watch_map_for_casefix(&mapname);
    }

    // SourceJump world-record lookup for this map (off-thread; prints to
    // the tool's terminal log and, if the console interface armed, echoes
    // into the game console). Opt out with BHOPFIX_NO_SOURCEJUMP=1.
    if std::env::var_os("BHOPFIX_NO_SOURCEJUMP").is_none() {
        sourcejump::show_wr(&mapname);
    }

    // Auto-record a demo of this map (opt-in BHOPFIX_DEMOS=1); the
    // `record` fires from the first in-game CreateMove.
    crate::engine::arm_demo(&mapname);
}

/// Resolve ProcessServerInfo out of the module file by pattern.
fn resolve_target(engine: &elf::Module) -> Option<(usize, usize)> {
    let prologue = Pattern::parse(PROCSERVINFO_PROLOGUE)?;
    let md5 = Pattern::parse(PROCSERVINFO_MD5_COPY)?;
    if prologue.len() != PROLOGUE_LEN {
        log!("BUG: ProcessServerInfo prologue pattern is not {PROLOGUE_LEN} bytes");
        return None;
    }
    let disp_at = md5.wildcards().next()?;
    let t = engine.vtable(CLIENTSTATE_CLASS)?;
    let mut found = None;
    for (_, fn_va) in engine.virtuals(t, VTABLE_MAX) {
        let Some(body) = engine.read_va(fn_va, PROCSERVINFO_WINDOW) else {
            continue;
        };
        if !prologue.matches_at(&body, 0) {
            continue; // a thunk, or some other handler
        }
        let Some(at) = md5.find(&body) else {
            continue;
        };
        if found
            .replace((fn_va, body[at + disp_at] as usize))
            .is_some()
        {
            return None; // ambiguous — refuse rather than hook the wrong one
        }
    }
    found
}

/// Inline-hook engine's CClientState::ProcessServerInfo.
///
/// # Safety
/// `engine_base` must be the load address of the very `engine.so` that
/// `engine` was parsed from, and this process must own its text pages.
pub(crate) unsafe fn install(engine: &elf::Module, engine_base: usize) -> bool {
    let Some((fn_va, md5_off)) = resolve_target(engine) else {
        log!(
            "fastdl: ProcessServerInfo not found in {CLIENTSTATE_CLASS}'s vtable \
             (game updated?)"
        );
        return false;
    };
    MSG_LUMP_MD5.store(md5_off, Ordering::Relaxed);
    let target = engine_base + fn_va;
    // the loaded code must still match (another patcher may have been here)
    let cur = unsafe { std::slice::from_raw_parts(target as *const u8, PROLOGUE_LEN) };
    let matches = Pattern::parse(PROCSERVINFO_PROLOGUE).is_some_and(|p| p.matches_at(cur, 0));
    if !matches {
        log!("fastdl: ProcessServerInfo at 0x{target:x} already modified; not hooking");
        return false;
    }
    dbglog!("fastdl: ProcessServerInfo +0x{fn_va:x}, msg MD5 at +0x{md5_off:x}");
    // trampoline: original 19 bytes + movabs rax, target+19; jmp rax
    let tramp = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if tramp == libc::MAP_FAILED {
        log!("mmap for trampoline failed");
        return false;
    }
    let t = tramp as *mut u8;
    let ret_addr = (target + PROLOGUE_LEN) as u64;
    unsafe {
        std::ptr::copy_nonoverlapping(target as *const u8, t, PROLOGUE_LEN);
        *t.add(PROLOGUE_LEN) = 0x48; // movabs rax
        *t.add(PROLOGUE_LEN + 1) = 0xb8;
        std::ptr::write_unaligned(t.add(PROLOGUE_LEN + 2) as *mut u64, ret_addr);
        *t.add(PROLOGUE_LEN + 10) = 0xff; // jmp rax
        *t.add(PROLOGUE_LEN + 11) = 0xe0;
    }

    // patch: movabs rax, our_fn; jmp rax; nops to fill
    let page = target & !0xfff;
    let page_len = ((target + PROLOGUE_LEN + 0xfff) & !0xfff) - page;
    if unsafe {
        libc::mprotect(
            page as *mut c_void,
            page_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    } != 0
    {
        log!("mprotect on engine text failed");
        return false;
    }
    let ours = hooked_process_server_info as *const () as usize as u64;
    let tp = target as *mut u8;
    unsafe {
        *tp = 0x48; // movabs rax
        *tp.add(1) = 0xb8;
        std::ptr::write_unaligned(tp.add(2) as *mut u64, ours);
        *tp.add(10) = 0xff; // jmp rax
        *tp.add(11) = 0xe0;
        for i in 12..PROLOGUE_LEN {
            *tp.add(i) = 0x90; // nop
        }
        libc::mprotect(
            page as *mut c_void,
            page_len,
            libc::PROT_READ | libc::PROT_EXEC,
        );
    }

    ORIG.store(tramp as usize, Ordering::Relaxed);
    true
}

#[cfg(test)]
mod tests {
    use super::{checksum_row, lookup_md5, resolve_target};

    #[test]
    fn process_server_info_resolves_and_yields_the_md5_offset() {
        let Some(m) = crate::testutil::engine() else {
            return;
        };
        let (fn_va, md5_off) = resolve_target(&m).expect("CClientState::ProcessServerInfo");
        assert!(
            m.is_exec(fn_va),
            "ProcessServerInfo 0x{fn_va:x} is not code"
        );
        // the message field offset is read out of the matched instruction, so a
        // sane small struct displacement is the invariant, not a fixed number
        assert!(
            md5_off > 0 && md5_off < 0x400,
            "implausible msg MD5 offset 0x{md5_off:x}"
        );
    }

    #[test]
    fn checksum_rows_reject_untrusted_hashes() {
        let csv = concat!(
            "sha1,lump_md5_checksum\r\n",
            "0123456789abcdef0123456789abcdef01234567,ABCDEF0123456789ABCDEF0123456789\r\n",
            "../map,abcdef0123456789abcdef0123456789\n"
        );
        assert_eq!(
            lookup_md5(csv, "abcdef0123456789abcdef0123456789"),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert!(checksum_row("../map,abcdef0123456789abcdef0123456789").is_none());
    }
}
