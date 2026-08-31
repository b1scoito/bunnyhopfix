//! rawinput2.so — momentum-mod style `m_rawinput 2` for CS:S on Linux.
//!
//! LD_PRELOAD hook library. Port of the RawInput2 half of
//! rtldg/RawInput2BunnyhopAPE (Windows) to Linux.
//!
//! What it does: mouse input is sampled so it "lines up with the tickrate
//! properly without needing a specific framerate" — raw deltas are accumulated
//! with timestamps and split at tick boundaries instead of being lumped per
//! frame.
//!
//! Linux implementation notes (found by reversing the 64-bit CS:S build):
//!   * launcher.so's CSDLMgr accumulates SDL_MOUSEMOTION xrel/yrel into
//!     obj+0x48/+0x4C and serves them via a "GetRawMouseAccumulators" virtual
//!     — the same role as the Windows inputsystem.dll function that RawInput2
//!     hooks.
//!   * CInput::CreateMove (IInput slot 3) carries each tick's input sample
//!     interval; the live singleton is a CCSInput, which inherits it.
//!   * Raw deltas are captured by hooking launcher.so's GOT entry for
//!     SDL_PollEvent — every event the game polls passes through us, with
//!     hardware timestamps. (A GOT hook, not name interposition, so
//!     sdl2-compat's internal SDL3 calls can never recurse into us.)
//!
//! None of that is addressed by link-time vaddr: those change on every game
//! update, and a stale vtable-slot address is actively dangerous because it
//! still points at a valid pointer belonging to some other class. Targets are
//! resolved from the module files by name at startup (see `elf`), and every
//! hook validates its slot before writing.
//!
//! Hooks are installed by rewriting vtable pointers (no inline patching).
//! Requires -insecure, same policy as the patcher.

// This is an LD_PRELOAD library: it reads /proc/self/{maps,mem}, parses ELF and
// rewrites vtables in-process, none of which has a Windows analogue. The
// Windows port is the patcher only, so on Windows this crate is empty.
#![cfg(unix)]
#![allow(unused_unsafe)] // the log! macro expands in both safe and unsafe fns

// ---------------------------------------------------------------------------
// logging (init-time only; uses libc::write to stderr)
// ---------------------------------------------------------------------------

macro_rules! log {
    ($($t:tt)*) => {{
        let s = std::format!($($t)*);
        unsafe {
            libc::write(2, b"[rawinput2] ".as_ptr() as *const std::ffi::c_void, 12);
            libc::write(2, s.as_ptr() as *const std::ffi::c_void, s.len());
            libc::write(2, b"\n".as_ptr() as *const std::ffi::c_void, 1);
        }
    }};
}

macro_rules! dbglog {
    ($($t:tt)*) => {{
        if $crate::DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
            log!($($t)*);
        }
    }};
}

use std::ffi::c_void;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

// NB: log!/dbglog! (macro_rules, defined above) are in textual scope for
// these submodules because they are declared after the macro definitions.
mod elf;
mod pakfix;
#[path = "sig.rs"]
mod sig;
mod sourcejump;

// ---------------------------------------------------------------------------
// Hook targets
//
// NOTHING here is a link-time address, and nothing is a vtable slot index
// either. Every CS:S update moves addresses, and a stale vtable-slot address
// is far more dangerous than a stale code address: it still points at a valid
// function pointer, just one belonging to another class, so the hook installs
// "successfully" and corrupts an unrelated virtual. The 2026-08-24 build
// turned the old CreateMove slot constants into a `vgui::Panel` virtual and a
// `CCSGameMovement` virtual, and the old raw-mouse slot into `ConCommand`'s
// destructor slot; the game segfaulted ~13s after load inside the displaced
// Panel virtual, called with our hook's arguments.
//
// So: classes come from the RTTI Valve ships in these binaries (see `elf`),
// and each method is identified by what its code *does* (see `sig`). We walk
// the class's vtable, match the body, and require the match to be unique —
// if two slots match we are guessing, so we refuse.
// ---------------------------------------------------------------------------

/// Classes whose vtable can carry CreateMove. CS:S's input singleton is a
/// `CCSInput`, which inherits `CInput`'s CreateMove without overriding it, so
/// the *derived* vtable is the one the engine dispatches through — hooking
/// only `CInput` would intercept nothing. We hook every vtable that holds the
/// same implementation; the dormant one costs nothing.
const INPUT_CLASSES: &[&str] = &["6CInput", "8CCSInput"];
/// `CInput::CreateMove(int sequence_number, float sample_frametime, bool)`.
///
/// Identified by what only CreateMove does: index the command ring by
/// `sequence_number % MULTIPLAYER_BACKUP` — which the compiler emits as a
/// magic-number division by 90 followed by a multiply-back — *and* spill the
/// float argument. The `% 90` pair alone matches 11 CInput methods (they all
/// index the ring), and the float spill alone is common; together they are
/// unique in both input vtables.
const CREATEMOVE_BODY: &[&str] = &[
    "48 69 C0 B7 60 0B B6", // imul $0xb60b60b7,%rax,%rax  -> / 90
    "6B C0 5A",             // imul $0x5a,%eax,%eax        -> * 90
    "F3 0F 11 85",          // movss %xmm0,disp32(%rbp)    -> float arg spill
];
/// How far into a function body to look for the patterns above. Generous
/// enough for codegen churn, tight enough not to run into the next function.
const BODY_WINDOW: usize = 0x80;

/// launcher.so's ILauncherMgr implementation, which owns the raw mouse
/// accumulators (RTTI typeinfo name).
const LAUNCHER_MGR_CLASS: &str = "7CSDLMgr";
/// `GetRawMouseAccumulators(int &x, int &y)` — a tiny leaf function with an
/// unmistakable shape, matched at the entry point:
///     mov acc_x(%rdi),%eax ; mov %eax,(%rsi)
///     mov acc_y(%rdi),%eax ; mov %eax,(%rdx)
///     movq $0x0,acc_x(%rdi)   ; clears both — they are adjacent ints
///     ret
/// The field displacements are wildcarded so a struct-layout change still
/// matches. Note it sets no return value: the interface method is `void`.
const GETRAWACCUM_BODY: &str = "8B 47 ?? 89 06 8B 47 ?? 89 02 48 C7 47 ?? 00 00 00 00 C3";
/// Upper bound when walking a vtable we did not size ourselves.
const VTABLE_MAX: usize = 256;

// ---------------------------------------------------------------------------
// fastdl.me hijack (port of rtldg's map-download feature)
// ---------------------------------------------------------------------------

mod fastdl {
    use super::{self_maps, Mapping};
    use std::ffi::c_void;
    use std::fs::File;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

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
        PathBuf::from(home).join(".cache/bunnyhop-ape-linux")
    }

    /// Listing of fastdl.me contents: "<sha1>,<lumpmd5hex>" per line.
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
                .args(["-fsSL", "--max-time", "30", "-o"])
                .arg(&tmp)
                .arg("https://venus.fastdl.me/lump_checksums.csv")
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if ok {
                let _ = std::fs::rename(&tmp, &path);
            } else {
                let _ = std::fs::remove_file(&tmp);
                log!("fastdl.me csv download failed");
            }
        }
        std::fs::read_to_string(&path).ok()
    }

    fn lookup_md5<'a>(csv: &'a str, md5hex: &str) -> Option<&'a str> {
        csv.lines().find_map(|line| {
            let line = line.trim_end_matches('\r');
            let (sha1, md5) = line.split_once(',')?;
            if md5.eq_ignore_ascii_case(md5hex) {
                Some(sha1)
            } else {
                None
            }
        })
    }

    /// Scan the message object for pointers to plausible map name strings.
    /// The serverinfo carries several short strings (game dir "cstrike",
    /// skybox, map name...) — the map name typically comes LAST. Game-dir
    /// values are excluded explicitly. All reads go through /proc/self/mem
    /// so a bad pointer can't crash the game.
    fn detect_mapname(msg: *mut c_void, mem: &File, maps: &[Mapping]) -> Option<String> {
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
            if let Some(ptr) = read_ptr(mem, msg as usize + known) {
                if let Some(s) = read_cstr(mem, ptr) {
                    if plausible(&s) && !GAME_DIRS.contains(&s.as_str()) {
                        return Some(s);
                    }
                }
            }
            MAPNAME_OFFSET.store(0, Ordering::Relaxed);
        }
        // All msg reads (pointer slots included) go through /proc/self/mem, so
        // a message shorter than the scan window can't fault the game.
        let mut candidates: Vec<(usize, String)> = Vec::new();
        for off in (0x40..0xa0).step_by(8) {
            let Some(ptr) = read_ptr(mem, msg as usize + off) else {
                continue;
            };
            if ptr < 0x10000 {
                continue;
            }
            if maps.iter().all(|m| !(ptr >= m.start && ptr < m.end)) {
                continue;
            }
            if let Some(s) = read_cstr(mem, ptr) {
                if plausible(&s) {
                    candidates.push((off, s));
                }
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

    /// Read an 8-byte pointer at `addr` via /proc/self/mem (never faults).
    fn read_ptr(mem: &File, addr: usize) -> Option<usize> {
        use std::os::unix::fs::FileExt;
        let mut buf = [0u8; 8];
        mem.read_at(&mut buf, addr as u64).ok()?;
        Some(usize::from_ne_bytes(buf))
    }

    fn read_cstr(mem: &File, addr: usize) -> Option<String> {
        let mut buf = [0u8; 128];
        use std::os::unix::fs::FileExt;
        if mem.read_at(&mut buf, addr as u64).is_err() {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(128);
        if end == 0 {
            return None;
        }
        String::from_utf8(buf[..end].to_vec()).ok()
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
        if target.exists() {
            if let Ok(have) = std::fs::read_to_string(&sidecar) {
                if have.trim() == sha1 {
                    return false;
                }
            }
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
            .args(["-fsSL", "--max-time", "20", "-o"])
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
                .args(["-fsSL", "--max-time", "8", "-o"])
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
        match std::fs::rename(&part, &target) {
            Ok(()) => {
                let _ = std::fs::write(&sidecar, sha1);
                log!("installed {mapname}.bsp from fastdl.me");
                // Linux case-folding fix (Source-1-Games#6868): extract any
                // uppercase-packed pak content as lowercase loose files so
                // the engine can actually find it.
                match crate::pakfix::fix_bsp(&target, &cwd.join("cstrike/download")) {
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
                match crate::pakfix::fix_bsp(c, &download_dir) {
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
                        match crate::pakfix::fix_bsp(c, &download_dir) {
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
        if spawned.is_err() {
            if let Ok(mut watching) = WATCHING.lock() {
                watching.retain(|m| m != &cleanup_name);
            }
        }
    }

    extern "C" fn hooked_process_server_info(this: *mut c_void, msg: *mut c_void) -> bool {
        on_serverinfo(msg);
        let orig = ORIG.load(Ordering::Relaxed);
        let f: extern "C" fn(*mut c_void, *mut c_void) -> bool =
            unsafe { std::mem::transmute(orig) };
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
        let maps = self_maps();
        let Ok(mem) = File::open("/proc/self/mem") else {
            return;
        };
        let Some(mapname) = detect_mapname(msg, &mem, &maps) else {
            log!("could not locate map name in serverinfo; skipping fastdl check");
            return;
        };

        let md5_off = MSG_LUMP_MD5.load(Ordering::Relaxed);
        let server_md5: [u8; 16] =
            unsafe { std::ptr::read(msg.byte_add(md5_off) as *const [u8; 16]) };
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
        // into the game console). Opt out with RAWINPUT2_NO_SOURCEJUMP=1.
        if std::env::var_os("RAWINPUT2_NO_SOURCEJUMP").is_none() {
            crate::sourcejump::show_wr(&mapname);
        }

        // Auto-record a demo of this map (opt-in RAWINPUT2_DEMOS=1); the
        // `record` fires from the first in-game CreateMove.
        crate::engine::arm_demo(&mapname);
    }

    /// Resolve ProcessServerInfo out of the module file by pattern.
    pub fn resolve_target(engine: &crate::elf::Module) -> Option<(usize, usize)> {
        let prologue = crate::sig::Pattern::parse(PROCSERVINFO_PROLOGUE)?;
        let md5 = crate::sig::Pattern::parse(PROCSERVINFO_MD5_COPY)?;
        if prologue.len() != PROLOGUE_LEN {
            log!("BUG: ProcessServerInfo prologue pattern is not {PROLOGUE_LEN} bytes");
            return None;
        }
        let disp_at = md5.wildcards().next()?;
        let t = engine.vtable(CLIENTSTATE_CLASS)?;
        let mut found = None;
        for (_, fn_va) in engine.virtuals(t, crate::VTABLE_MAX) {
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
    pub unsafe fn install(engine: &crate::elf::Module, engine_base: usize) -> bool {
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
        let cur = std::slice::from_raw_parts(target as *const u8, PROLOGUE_LEN);
        let matches =
            crate::sig::Pattern::parse(PROCSERVINFO_PROLOGUE).is_some_and(|p| p.matches_at(cur, 0));
        if !matches {
            log!("fastdl: ProcessServerInfo at 0x{target:x} already modified; not hooking");
            return false;
        }
        dbglog!("fastdl: ProcessServerInfo +0x{fn_va:x}, msg MD5 at +0x{md5_off:x}");
        // trampoline: original 19 bytes + movabs rax, target+19; jmp rax
        let tramp = libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        );
        if tramp == libc::MAP_FAILED {
            log!("mmap for trampoline failed");
            return false;
        }
        let t = tramp as *mut u8;
        std::ptr::copy_nonoverlapping(target as *const u8, t, PROLOGUE_LEN);
        let ret_addr = (target + PROLOGUE_LEN) as u64;
        *t.add(PROLOGUE_LEN) = 0x48; // movabs rax
        *t.add(PROLOGUE_LEN + 1) = 0xb8;
        std::ptr::write_unaligned(t.add(PROLOGUE_LEN + 2) as *mut u64, ret_addr);
        *t.add(PROLOGUE_LEN + 10) = 0xff; // jmp rax
        *t.add(PROLOGUE_LEN + 11) = 0xe0;

        // patch: movabs rax, our_fn; jmp rax; nops to fill
        let page = target & !0xfff;
        let page_len = ((target + PROLOGUE_LEN + 0xfff) & !0xfff) - page;
        if libc::mprotect(
            page as *mut c_void,
            page_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            log!("mprotect on engine text failed");
            return false;
        }
        let ours = hooked_process_server_info as *const () as usize as u64;
        let tp = target as *mut u8;
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

        ORIG.store(tramp as usize, Ordering::Relaxed);
        true
    }
}

use fastdl as fastdl_impl;

// ---------------------------------------------------------------------------
// engine.so glue: run client console commands (IVEngineClient::ClientCmd),
// show map-download progress, auto-record demos, flash the window.
//
// Nothing here is addressed by link-time vaddr any more: the interface comes
// from engine.so's own CreateInterface export and the download manager from
// its RTTI. Every use is validated at init and the feature is disabled (never
// crashes) on any mismatch.
// ---------------------------------------------------------------------------
mod engine {
    use super::{self_maps, Mapping};
    use std::ffi::{c_char, c_void};
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// The concrete class behind IVEngineClient (RTTI typeinfo name). We
    /// confirm the object CreateInterface hands us really is one of these
    /// before calling through its vtable.
    const ENGINE_CLIENT_CLASS: &str = "13CEngineClient";
    /// Versioned interface names, newest first. The version pins the ABI, so
    /// the object we get back is the one whose RTTI we check below.
    const ENGINE_CLIENT_IFACES: &[&[u8]] = &[b"VEngineClient014\0", b"VEngineClient013\0"];
    /// `IVEngineClient::ClientCmd(const char *)`, found by body rather than by
    /// slot index: it stashes the string argument, checks one flag, then
    /// tail-jumps to Cbuf_AddText with the string as the first argument.
    ///     mov %rsi,%r12 ... mov %r12,%rdi ; pop %r12 ; pop %rbp ; jmp <Cbuf>
    /// Unique in CEngineClient's vtable (ServerCmd, the neighbouring slot,
    /// builds a buffer instead of tail-calling).
    const CLIENTCMD_BODY: &[&str] = &[
        "49 89 F4",             // mov %rsi,%r12   -> stash the command string
        "4C 89 E7 41 5C 5D E9", // mov %r12,%rdi ; pop ; pop ; jmp Cbuf_AddText
    ];
    const CLIENTCMD_WINDOW: usize = 0x40;

    /// CDownloadManager singleton, located by RTTI at runtime because its .bss
    /// address moves every build; its active-request pointer sits at +0x28.
    const DLMGR_CLASS: &str = "16CDownloadManager";
    const DLMGR_REQ_OFF: usize = 0x28;
    // Request layout. Unlike everything else here, these offsets could not be
    // re-verified against the 2026-08-24 build (they are only observable
    // during a live http download), so poll_downloads sanity-checks the shape
    // of what it reads and stays quiet if it looks wrong.
    const REQ_HTTP: usize = 0x03; // byte: 1 if an http(s) download
    const REQ_STATE: usize = 0x08; // int: 1=downloading, 2=done, 4=error
    const REQ_NAME: usize = 0x314; // char[256]: "maps/foo.bsp"
    const REQ_TOTAL: usize = 0x618; // int: total bytes
    const REQ_CURRENT: usize = 0x61c; // int: bytes so far

    static DLMGR: AtomicUsize = AtomicUsize::new(0); // CDownloadManager singleton
    static ENGINE_LO: AtomicUsize = AtomicUsize::new(0);
    static ENGINE_HI: AtomicUsize = AtomicUsize::new(0);
    static MEM_FD: AtomicI32 = AtomicI32::new(-1);
    static CMD_READY: AtomicBool = AtomicBool::new(false);
    static IFACE: AtomicUsize = AtomicUsize::new(0);
    static CLIENTCMD_FN: AtomicUsize = AtomicUsize::new(0);
    static FLASH_FN: AtomicUsize = AtomicUsize::new(0); // SDL_FlashWindow
    static GETWIN_FN: AtomicUsize = AtomicUsize::new(0); // SDL_GL_GetCurrentWindow
    static DEMOS_ON: AtomicBool = AtomicBool::new(false);

    static CMD_QUEUE: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static PENDING_DEMO: Mutex<Option<String>> = Mutex::new(None);
    static LAST_PCT: AtomicI32 = AtomicI32::new(-1);
    static WAS_DOWNLOADING: AtomicBool = AtomicBool::new(false);
    static POLL_N: AtomicUsize = AtomicUsize::new(0);
    static DEMO_SEQ: AtomicUsize = AtomicUsize::new(0);

    // --- fault-safe reads via /proc/self/mem (pread never faults on a bad addr)
    fn rd(buf: &mut [u8], addr: usize) -> bool {
        let fd = MEM_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return false;
        }
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                addr as libc::off_t,
            )
        };
        n == buf.len() as isize
    }
    fn rd_i32(addr: usize) -> Option<i32> {
        let mut b = [0u8; 4];
        rd(&mut b, addr).then(|| i32::from_ne_bytes(b))
    }
    fn rd_u8(addr: usize) -> Option<u8> {
        let mut b = [0u8; 1];
        rd(&mut b, addr).then(|| b[0])
    }
    fn rd_u64(addr: usize) -> Option<usize> {
        let mut b = [0u8; 8];
        rd(&mut b, addr).then(|| usize::from_ne_bytes(b))
    }
    fn rd_cstr(addr: usize, max: usize) -> Option<String> {
        let fd = MEM_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return None;
        }
        let mut buf = vec![0u8; max];
        let n = unsafe {
            libc::pread(
                fd,
                buf.as_mut_ptr() as *mut c_void,
                max,
                addr as libc::off_t,
            )
        };
        if n <= 0 {
            return None;
        }
        buf.truncate(n as usize);
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8(buf[..end].to_vec()).ok()
    }
    fn in_engine(addr: usize) -> bool {
        let (lo, hi) = (
            ENGINE_LO.load(Ordering::Relaxed),
            ENGINE_HI.load(Ordering::Relaxed),
        );
        lo != 0 && addr >= lo && addr < hi
    }

    /// Ask engine.so for IVEngineClient through its own exported
    /// CreateInterface, then validate the object structurally: its RTTI must
    /// name CEngineClient, and slot 7 must be code inside engine.so. No
    /// link-time address is involved at any step.
    unsafe fn resolve_engine_client(engine_path: &str) -> Option<(usize, usize)> {
        let path = std::ffi::CString::new(engine_path).ok()?;
        let h = libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
        if h.is_null() {
            log!("engine: engine.so is not open (dlopen NOLOAD failed)");
            return None;
        }
        let sym = libc::dlsym(h, c"CreateInterface".as_ptr());
        if sym.is_null() {
            log!("engine: engine.so exports no CreateInterface");
            return None;
        }
        let create: extern "C" fn(*const c_char, *mut i32) -> *mut c_void =
            std::mem::transmute(sym);
        for name in ENGINE_CLIENT_IFACES {
            let pretty = String::from_utf8_lossy(&name[..name.len() - 1]).to_string();
            let mut ret: i32 = 0;
            let iface = create(name.as_ptr() as *const c_char, &mut ret) as usize;
            if iface == 0 {
                continue;
            }
            // A vptr points at vtable entry 0; the typeinfo pointer sits just
            // below it and its name string at typeinfo+8 (Itanium C++ ABI).
            let Some(vt) = rd_u64(iface) else { continue };
            let cls = rd_u64(vt.wrapping_sub(8))
                .and_then(|ti| rd_u64(ti + 8))
                .and_then(|p| rd_cstr(p, 64));
            if cls.as_deref() != Some(ENGINE_CLIENT_CLASS) {
                log!("engine: {pretty} object is {cls:?}, expected {ENGINE_CLIENT_CLASS}");
                continue;
            }
            let Some(fnp) = find_clientcmd(vt) else {
                log!("engine: {pretty} vtable has no ClientCmd-shaped virtual (game updated?)");
                continue;
            };
            if !in_engine(fnp) {
                log!("engine: {pretty} ClientCmd slot 0x{fnp:x} is outside engine.so");
                continue;
            }
            log!("engine: {pretty} -> iface 0x{iface:x} ClientCmd 0x{fnp:x}");
            return Some((iface, fnp));
        }
        None
    }

    /// Find ClientCmd in a live vtable by matching its body. Every read is
    /// fault-safe, so walking past the end of the vtable is harmless, and an
    /// ambiguous match is refused rather than guessed.
    fn find_clientcmd(vt: usize) -> Option<usize> {
        let pats: Vec<crate::sig::Pattern> = CLIENTCMD_BODY
            .iter()
            .filter_map(|s| crate::sig::Pattern::parse(s))
            .collect();
        if pats.len() != CLIENTCMD_BODY.len() {
            log!("BUG: malformed ClientCmd pattern literal");
            return None;
        }
        let mut found = None;
        let mut body = vec![0u8; CLIENTCMD_WINDOW];
        for i in 0..crate::VTABLE_MAX {
            let Some(fnp) = rd_u64(vt + i * 8) else { break };
            if !in_engine(fnp) {
                break; // past the end of the vtable
            }
            if !rd(&mut body, fnp) {
                continue;
            }
            if pats.iter().all(|p| p.find(&body).is_some()) && found.replace(fnp).is_some() {
                return None;
            }
        }
        found
    }

    /// Locate the CDownloadManager singleton by scanning engine.so's writable
    /// image for an object whose vptr is that class's vtable.
    fn resolve_dlmgr(engine: &crate::elf::Module, engine_base: usize) -> Option<usize> {
        let t = engine.vtable(DLMGR_CLASS)?;
        let want = (engine_base + crate::elf::Module::vslot(t, 0)).to_ne_bytes();
        // Scan by address, not by /proc/self/maps path: this singleton lives in
        // the anonymous .bss tail, which is not attributed to engine.so.
        let (lo, hi) = engine.writable_span()?;
        let mut chunk = vec![0u8; 64 * 1024];
        let (mut addr, end) = (engine_base + lo, engine_base + hi);
        while addr < end {
            let len = chunk.len().min(end - addr);
            if rd(&mut chunk[..len], addr) {
                if let Some(i) = chunk[..len].chunks_exact(8).position(|w| w == want) {
                    return Some(addr + i * 8);
                }
            }
            addr += len;
        }
        None
    }

    /// Resolve the ClientCmd interface and the download-manager singleton, and
    /// look up the SDL flash symbols. Everything is validated; a feature whose
    /// lookup does not check out stays DISABLED instead of crashing.
    pub fn init(
        engine: &crate::elf::Module,
        engine_base: usize,
        engine_path: &str,
        sdl_handle: *mut c_void,
    ) {
        let maps = self_maps();
        let lo = maps
            .iter()
            .filter(|m: &&Mapping| m.path.ends_with("/engine.so"))
            .map(|m| m.start)
            .min();
        let hi = maps
            .iter()
            .filter(|m: &&Mapping| m.path.ends_with("/engine.so"))
            .map(|m| m.end)
            .max();
        if let (Some(lo), Some(hi)) = (lo, hi) {
            ENGINE_LO.store(lo, Ordering::Relaxed);
            ENGINE_HI.store(hi, Ordering::Relaxed);
        }
        let fd = unsafe { libc::open(c"/proc/self/mem".as_ptr(), libc::O_RDONLY) };
        if fd < 0 {
            log!("engine: cannot open /proc/self/mem; engine features disabled");
            return;
        }
        MEM_FD.store(fd, Ordering::Relaxed);

        // ClientCmd through engine.so's own CreateInterface plus an RTTI
        // identity check — the old hard-coded iface/vtable/function vaddrs are
        // exactly what the 2026-08-24 update invalidated.
        match unsafe { resolve_engine_client(engine_path) } {
            Some((iface, fnp)) => {
                IFACE.store(iface, Ordering::Relaxed);
                CLIENTCMD_FN.store(fnp, Ordering::Relaxed);
                CMD_READY.store(true, Ordering::Relaxed);
                log!("engine: ClientCmd armed");
            }
            None => log!("engine: ClientCmd unavailable (game updated?); console/demo off"),
        }

        // Download progress (cosmetic) needs the CDownloadManager singleton.
        match resolve_dlmgr(engine, engine_base) {
            Some(mgr) => {
                DLMGR.store(mgr, Ordering::Relaxed);
                dbglog!("engine: CDownloadManager @ 0x{mgr:x}");
            }
            None => dbglog!("engine: CDownloadManager not found; download progress off"),
        }

        // Auto demo recording is opt-in (it writes a .dem per connect).
        DEMOS_ON.store(
            std::env::var_os("RAWINPUT2_DEMOS").is_some(),
            Ordering::Relaxed,
        );
        if DEMOS_ON.load(Ordering::Relaxed) {
            log!("engine: auto demo recording ON (writes cstrike/<map>_<ts>.dem; prune periodically)");
        }

        // SDL flash symbols (best-effort; feature simply off if unavailable).
        if !sdl_handle.is_null() {
            unsafe {
                let flash = libc::dlsym(sdl_handle, c"SDL_FlashWindow".as_ptr());
                let getwin = libc::dlsym(sdl_handle, c"SDL_GL_GetCurrentWindow".as_ptr());
                if !flash.is_null() && !getwin.is_null() {
                    FLASH_FN.store(flash as usize, Ordering::Relaxed);
                    GETWIN_FN.store(getwin as usize, Ordering::Relaxed);
                }
            }
        }
    }

    /// Queue a client console command. Thread-safe; runs on the next SDL poll
    /// (the main/engine thread). Dropped if the interface didn't validate.
    pub fn queue_cmd(cmd: impl Into<String>) {
        if !CMD_READY.load(Ordering::Relaxed) {
            return;
        }
        let mut c = cmd.into();
        c.truncate(180); // stay under Cbuf_AddText's fixed buffer
        if let Ok(mut q) = CMD_QUEUE.lock() {
            if q.len() < 32 {
                q.push(c);
            }
        }
    }

    /// Record a demo of this map once we're actually in-game. Called at connect
    /// (ProcessServerInfo); the actual `record` is issued from the first
    /// CreateMove (see demo_tick) so the client is spawned.
    pub fn arm_demo(mapname: &str) {
        if !DEMOS_ON.load(Ordering::Relaxed) || !CMD_READY.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(mut p) = PENDING_DEMO.lock() {
            *p = Some(mapname.to_string());
        }
    }

    /// Issue the queued `record` once in-game. Call from the CreateMove hook
    /// (main thread, only runs after spawn).
    pub fn demo_tick() {
        let map = match PENDING_DEMO.lock() {
            Ok(mut p) => p.take(),
            _ => return,
        };
        let Some(map) = map else { return };
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or_else(|_| DEMO_SEQ.fetch_add(1, Ordering::Relaxed) as u64);
        // stop any prior demo, then start a per-map one
        queue_cmd("stop");
        queue_cmd(format!("record {map}_{ts}"));
        log!("demo: recording {map}_{ts}.dem");
    }

    /// Drain the command queue via ClientCmd. MUST be the main thread — call
    /// only from the SDL_PollEvent hook.
    pub fn pump() {
        if !CMD_READY.load(Ordering::Relaxed) {
            return;
        }
        let cmds: Vec<String> = match CMD_QUEUE.lock() {
            Ok(mut q) if !q.is_empty() => std::mem::take(&mut *q),
            _ => return,
        };
        let iface = IFACE.load(Ordering::Relaxed) as *mut c_void;
        let fnp = CLIENTCMD_FN.load(Ordering::Relaxed);
        if iface.is_null() || fnp == 0 {
            return;
        }
        let clientcmd: extern "C" fn(*mut c_void, *const c_char) =
            unsafe { std::mem::transmute(fnp) };
        for cmd in cmds {
            if let Ok(cs) = std::ffi::CString::new(cmd) {
                clientcmd(iface, cs.as_ptr()); // Cbuf_AddText copies it
            }
        }
    }

    /// Poll the active map download and log progress; flash the window when a
    /// download finishes. Read-only + fault-safe. Call from the SDL hook.
    pub fn poll_downloads() {
        // throttle: the SDL hook fires thousands of times a second
        if !POLL_N.fetch_add(1, Ordering::Relaxed).is_multiple_of(16) {
            return;
        }
        let mgr = DLMGR.load(Ordering::Relaxed);
        if mgr == 0 {
            return; // singleton not located; progress logging simply off
        }
        let req = match rd_u64(mgr + DLMGR_REQ_OFF) {
            Some(r) if r > 0x10000 => r,
            _ => {
                // no active request; if one just ended, flash + reset
                if WAS_DOWNLOADING.swap(false, Ordering::Relaxed) {
                    LAST_PCT.store(-1, Ordering::Relaxed);
                    log!("download complete");
                    flash_window();
                }
                return;
            }
        };
        if rd_u8(req + REQ_HTTP).unwrap_or(0) == 0 {
            return; // only http downloads carry byte counters
        }
        let state = rd_i32(req + REQ_STATE).unwrap_or(0);
        let total = rd_i32(req + REQ_TOTAL).unwrap_or(0);
        let current = rd_i32(req + REQ_CURRENT).unwrap_or(0);
        if state == 1 && total > 0 {
            WAS_DOWNLOADING.store(true, Ordering::Relaxed);
            let pct = ((current as i64 * 100) / total as i64) as i32;
            let last = LAST_PCT.load(Ordering::Relaxed);
            if last < 0 || pct >= last + 5 || pct >= 100 {
                LAST_PCT.store(pct, Ordering::Relaxed);
                // The request layout is the one thing here we could not
                // re-verify on this build, so require the name to look like a
                // real asset path before printing anything.
                let name = rd_cstr(req + REQ_NAME, 128).unwrap_or_default();
                if name.is_empty()
                    || !name.contains('/')
                    || !name.bytes().all(|b| (0x20..0x7f).contains(&b))
                {
                    return;
                }
                let name = name.rsplit('/').next().unwrap_or("map").to_string();
                log!(
                    "downloading {name}: {pct}% ({} / {} KB)",
                    current / 1024,
                    total / 1024
                );
            }
        }
    }

    fn flash_window() {
        let (flash, getwin) = (
            FLASH_FN.load(Ordering::Relaxed),
            GETWIN_FN.load(Ordering::Relaxed),
        );
        if flash == 0 || getwin == 0 {
            return;
        }
        unsafe {
            let getwin_fn: extern "C" fn() -> *mut c_void = std::mem::transmute(getwin);
            let win = getwin_fn();
            if win.is_null() {
                return;
            }
            let flash_fn: extern "C" fn(*mut c_void, i32) = std::mem::transmute(flash);
            flash_fn(win, 2); // SDL_FLASH_UNTIL_FOCUSED
        }
    }
}

// ---------------------------------------------------------------------------
// viewpunch remover (rtldg's F7 feature)
// ---------------------------------------------------------------------------

mod viewpunch {
    use std::ffi::c_void;

    // C_BasePlayer's view code ADDs m_vecPunchAngle onto the rendered eye
    // angles with three `addss <punch+0/4/8>(reg),%xmm0` in a row (pitch, yaw,
    // roll). NOPing those adds removes the visual kick regardless of the punch
    // value — which matters because m_vecPunchAngle is a PREDICTED field the
    // client restores and re-decays every frame, so zeroing the field can't win
    // the race, but never applying it does.
    //
    // The 2026-08-24 update moved all nine sites (~+0x1e80) while keeping the
    // field offset, so we no longer hard-code addresses: we decode the real
    // `addss disp32(reg),%xmm0` instructions out of .text and keep the ones
    // forming a (D, D+4, D+8) triple within a tight span. That shape is what
    // identifies a Vector add, and the punch field is the D shared by the most
    // triples — which cleanly separates it from the unrelated single adds at
    // other offsets (0x12bc, 0x1328, 0x1338, ...) in the same binary.

    /// Plausible range for m_vecPunchAngle's offset inside C_BasePlayer.
    const DISP_MIN: u32 = 0x1000;
    const DISP_MAX: u32 = 0x1400;
    /// A pitch/yaw/roll triple is emitted within a few dozen bytes.
    const TRIPLE_SPAN: usize = 0x100;

    /// A decoded `addss disp32(base),%xmm0`.
    struct Site {
        va: usize,
        disp: u32,
        len: usize,
    }

    /// Decode every `addss disp32(base),%xmm0` in client.so's .text whose
    /// displacement could be a C_BasePlayer field.
    fn find_addss(client: &crate::elf::Module) -> Vec<Site> {
        let mut out: Vec<Site> = Vec::new();
        client.scan(crate::elf::Access::Code, 15, |seg_va, buf| {
            let mut i = 0usize;
            while i + 12 <= buf.len() {
                // F3 [REX] 0F 58 modrm [sib] disp32, with reg field == xmm0
                if buf[i] != 0xf3 {
                    i += 1;
                    continue;
                }
                let mut p = i + 1;
                if buf[p] & 0xf0 == 0x40 {
                    if buf[p] & 0x04 != 0 {
                        i += 1; // REX.R set -> destination is not xmm0
                        continue;
                    }
                    p += 1;
                }
                if buf[p] != 0x0f || buf[p + 1] != 0x58 {
                    i += 1;
                    continue;
                }
                let modrm = buf[p + 2];
                if modrm >> 6 != 0b10 || (modrm >> 3) & 7 != 0 {
                    i += 1; // need mod=disp32 and reg=xmm0
                    continue;
                }
                let mut d = p + 3;
                if modrm & 7 == 4 {
                    d += 1; // SIB byte
                }
                let disp = u32::from_le_bytes([buf[d], buf[d + 1], buf[d + 2], buf[d + 3]]);
                if (DISP_MIN..DISP_MAX).contains(&disp) {
                    out.push(Site {
                        va: seg_va as usize + i,
                        disp,
                        len: d + 4 - i,
                    });
                }
                i += 1;
            }
        });
        // chunks overlap, so the same site can be decoded twice
        out.sort_unstable_by_key(|s| s.va);
        out.dedup_by_key(|s| s.va);
        out
    }

    /// Indices of the sites that form (D, D+4, D+8) triples, for the D used by
    /// the most triples.
    fn punch_sites(sites: &[Site]) -> (u32, Vec<usize>) {
        let mut triples: Vec<(u32, [usize; 3])> = Vec::new();
        for i in 0..sites.len().saturating_sub(2) {
            let (a, b, c) = (&sites[i], &sites[i + 1], &sites[i + 2]);
            if b.disp == a.disp + 4 && c.disp == a.disp + 8 && c.va - a.va < TRIPLE_SPAN {
                triples.push((a.disp, [i, i + 1, i + 2]));
            }
        }
        let Some(&(best, _)) = triples
            .iter()
            .max_by_key(|(d, _)| (triples.iter().filter(|(o, _)| o == d).count(), -(*d as i64)))
        else {
            return (0, Vec::new());
        };
        // overlapping triples would list a site twice
        let mut idx: Vec<usize> = triples
            .iter()
            .filter(|(d, _)| *d == best)
            .flat_map(|(_, t)| t.iter().copied())
            .collect();
        idx.sort_unstable();
        idx.dedup();
        (best, idx)
    }

    pub fn install(client: &crate::elf::Module, client_base: usize) {
        let sites = find_addss(client);
        let (disp, chosen) = punch_sites(&sites);
        if chosen.is_empty() {
            log!(
                "viewpunch: no punch-angle add triples found in client.so \
                 (game updated?); NOT patching"
            );
            return;
        }
        // Everything above came from the file; confirm the loaded code really
        // matches before writing to it (another patcher may have been here).
        for &i in &chosen {
            let s = &sites[i];
            let addr = client_base + s.va;
            let cur = unsafe { std::slice::from_raw_parts(addr as *const u8, s.len) };
            if client.read_va(s.va, s.len).as_deref() != Some(cur) {
                log!("viewpunch: code at 0x{addr:x} differs from client.so; NOT patching");
                return;
            }
        }
        // All sites confirmed: NOP each addss (xmm0 keeps the base eye-angle,
        // the following store writes it back unchanged — punch never applied).
        let mut done = 0usize;
        for &i in &chosen {
            let s = &sites[i];
            let addr = client_base + s.va;
            let page = addr & !0xfff;
            let page_len = ((addr + s.len + 0xfff) & !0xfff) - page;
            unsafe {
                if libc::mprotect(
                    page as *mut c_void,
                    page_len,
                    libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                ) != 0
                {
                    continue;
                }
                std::ptr::write_bytes(addr as *mut u8, 0x90, s.len);
                libc::mprotect(
                    page as *mut c_void,
                    page_len,
                    libc::PROT_READ | libc::PROT_EXEC,
                );
            }
            done += 1;
        }
        log!(
            "viewpunch remover armed: NOP'd {done}/{} punch adds \
             (m_vecPunchAngle @ +0x{disp:x}, {} view paths)",
            chosen.len(),
            chosen.len() / 3
        );
    }

    #[cfg(test)]
    mod tests {
        #[test]
        fn finds_punch_angle_triples() {
            let Some(m) = crate::testutil::client() else {
                return;
            };
            let sites = super::find_addss(&m);
            let (disp, chosen) = super::punch_sites(&sites);
            // pitch/yaw/roll per view path, so always a whole number of triples
            assert!(!chosen.is_empty(), "no punch-angle add triples found");
            assert_eq!(chosen.len() % 3, 0, "partial triple: {chosen:?}");
            // every chosen site adds one of the three Vector components
            for &i in &chosen {
                let d = sites[i].disp;
                assert!(
                    d == disp || d == disp + 4 || d == disp + 8,
                    "site 0x{:x} disp 0x{d:x} is not part of the vector at 0x{disp:x}",
                    sites[i].va
                );
            }
        }
    }
}
use viewpunch as viewpunch_impl;

/// ConVar layout (Source 2013, x86-64): m_pszName at +0x18, m_Value.m_nValue at +0x50.
const CONVAR_NAME_OFFSET: usize = 0x18;
const CONVAR_VALUE_OFFSET: usize = 0x50;

const SDL_MOUSEMOTION: u32 = 0x400;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Monotonic clock (same domain as kernel evdev timestamps, should we go
/// there later; SDL_GetTicks is also MONOTONIC-based but we don't need it).
fn mono_now() -> f64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
}

/// Ring buffer of timestamped raw deltas (single producer: the SDL hook;
/// single consumer: the GetRawMouseAccumulators hook).
const CAP: usize = 1024;
struct Ring {
    ts: [AtomicU64; CAP],
    dx: [AtomicI32; CAP],
    dy: [AtomicI32; CAP],
}
static RING: Ring = Ring {
    ts: [const { AtomicU64::new(0) }; CAP],
    dx: [const { AtomicI32::new(0) }; CAP],
    dy: [const { AtomicI32::new(0) }; CAP],
};
static W_IDX: AtomicUsize = AtomicUsize::new(0);
static R_IDX: AtomicUsize = AtomicUsize::new(0);

fn ring_push(now: f64, x: i32, y: i32) {
    let w = W_IDX.fetch_add(1, Ordering::Relaxed);
    let r = R_IDX.load(Ordering::Relaxed);
    if w - r >= CAP {
        // full: drop oldest
        R_IDX.store(w + 1 - CAP, Ordering::Relaxed);
    }
    let i = w % CAP;
    RING.dx[i].store(x, Ordering::Relaxed);
    RING.dy[i].store(y, Ordering::Relaxed);
    RING.ts[i].store(now.to_bits(), Ordering::Relaxed);
}

/// Drain all events with ts <= threshold. Returns summed deltas.
fn ring_drain(threshold: f64) -> (i32, i32) {
    let (mut x, mut y) = (0i32, 0i32);
    loop {
        let r = R_IDX.load(Ordering::Relaxed);
        let w = W_IDX.load(Ordering::Relaxed);
        if r == w {
            break;
        }
        let i = r % CAP;
        let ts = f64::from_bits(RING.ts[i].load(Ordering::Relaxed));
        if ts > threshold {
            break;
        }
        x += RING.dx[i].load(Ordering::Relaxed);
        y += RING.dy[i].load(Ordering::Relaxed);
        R_IDX.store(r + 1, Ordering::Relaxed);
    }
    (x, y)
}

/// Remaining unsampled tick time (set per tick by the CreateMove hook,
/// counts down with wall time between serve calls).
static SAMPLE_TIME_REMAINING: AtomicU64 = AtomicU64::new(0);
/// Monotonic time of the last serve call.
static LAST_SERVE_WALL: AtomicU64 = AtomicU64::new(0);

/// Pointer to m_rawinput ConVar's m_nValue int.
static CONVAR_RAWINPUT: AtomicUsize = AtomicUsize::new(0);

static ORIG_CREATEMOVE: AtomicUsize = AtomicUsize::new(0);

static DEBUG: AtomicBool = AtomicBool::new(false);

// ---------------------------------------------------------------------------
// SDL types
// ---------------------------------------------------------------------------

#[repr(C)]
struct SdlEventHeader {
    type_: u32,
    timestamp: u32,
}

#[repr(C)]
struct SdlMouseMotionEvent {
    type_: u32,     // 0
    timestamp: u32, // 4  (ms, SDL_GetTicks clock)
    window_id: u32, // 8
    which: u32,     // 12
    state: u8,      // 16
    _pad: [u8; 3],  // 17..20
    x: i32,         // 20
    y: i32,         // 24
    xrel: i32,      // 28
    yrel: i32,      // 32
}

type SdlPollEventFn = extern "C" fn(*mut c_void) -> i32;

static REAL_POLLEVENT: AtomicUsize = AtomicUsize::new(0);

// debug instrumentation (RAWINPUT2_DEBUG=1)
static POLL_CALLS: AtomicU64 = AtomicU64::new(0);
static MOTION_EVENTS: AtomicU64 = AtomicU64::new(0);
static SERVED_CALLS: AtomicU64 = AtomicU64::new(0);
static CREATEMOVE_CALLS: AtomicU64 = AtomicU64::new(0);

/// Our SDL_PollEvent hook (installed into launcher.so's GOT — NOT exported,
/// so sdl2-compat's internal SDL3 calls never recurse into us).
/// Every event the game polls passes through here: accumulate raw motion
/// with the event's own hardware timestamp, then hand it to the game.
extern "C" fn sdl_poll_event_hook(event: *mut c_void) -> i32 {
    let real = REAL_POLLEVENT.load(Ordering::Relaxed);
    if real == 0 {
        return 0;
    }
    let f: SdlPollEventFn = unsafe { std::mem::transmute(real) };
    let ret = f(event);
    if ret != 0 && !event.is_null() {
        let hdr = unsafe { &*(event as *const SdlEventHeader) };
        if hdr.type_ == SDL_MOUSEMOTION {
            let m = unsafe { &*(event as *const SdlMouseMotionEvent) };
            // NB: event timestamps are garbage under sdl2-compat, so we
            // timestamp at sight time with CLOCK_MONOTONIC.
            ring_push(mono_now(), m.xrel, m.yrel);
            MOTION_EVENTS.fetch_add(1, Ordering::Relaxed);
        }
    }
    POLL_CALLS.fetch_add(1, Ordering::Relaxed);
    // This hook runs on the game's main thread every frame — the safe place to
    // execute queued console commands and poll download progress.
    engine::pump();
    engine::poll_downloads();
    ret
}

// ---------------------------------------------------------------------------
// the rawinput2 algorithm (tick-aligned serving)
// ---------------------------------------------------------------------------

fn read_m_rawinput() -> i32 {
    let p = CONVAR_RAWINPUT.load(Ordering::Relaxed);
    if p == 0 {
        return 1; // sane default before the convar is resolved
    }
    unsafe { *(p as *const i32) }
}

/// Whether to force `m_rawinput 2` as the default (opt out RAWINPUT2_NO_FORCE=1).
static FORCE_RAWINPUT2: AtomicBool = AtomicBool::new(true);
/// One-shot guard so we only stamp the default once (the user can then freely
/// change it in-game).
static RAWINPUT_FORCED: AtomicBool = AtomicBool::new(false);

/// Stamp `m_rawinput = 2` directly into the ConVar's value once we're in-game.
/// The command-line `+m_rawinput 2` gets clobbered by the engine's one-time
/// reset path on this build, so we write the resolved ConVar's m_nValue after
/// all startup config has run (called from CreateMove, i.e. post-spawn). Done
/// exactly once; a later manual `m_rawinput 0/1` sticks.
fn force_rawinput_default() {
    if !FORCE_RAWINPUT2.load(Ordering::Relaxed) || RAWINPUT_FORCED.load(Ordering::Relaxed) {
        return;
    }
    let p = CONVAR_RAWINPUT.load(Ordering::Relaxed);
    if p == 0 {
        return; // convar not resolved yet; try again next tick
    }
    RAWINPUT_FORCED.store(true, Ordering::Relaxed);
    // Immediate functional value: what the tool AND the engine's input code
    // read (GetInt -> m_nValue). This alone makes tick-aligned sampling active.
    unsafe {
        if *(p as *const i32) != 2 {
            *(p as *mut i32) = 2;
        }
    }
    // Also run `m_rawinput 2` through the engine's own command exec so the
    // float value, the console string, and the change callback are all updated
    // properly — safer than poking the ConVar's heap-owned string ourselves.
    // No-op if the ClientCmd interface didn't validate.
    engine::queue_cmd("m_rawinput 2");
    log!("m_rawinput forced to 2 (default; change with `m_rawinput 0/1` in game, or RAWINPUT2_NO_FORCE=1)");
}

// ---------------------------------------------------------------------------
// hooks
// ---------------------------------------------------------------------------

/// Replacement for the launcher's GetRawMouseAccumulators(int&, int&).
/// The game calls this every time it wants raw mouse deltas for a sample.
///
/// mode 2: serve only the deltas timestamped up to the current tick
///         boundary (remaining tick time counts down with wall time and is
///         refreshed by the CreateMove hook every tick).
/// mode 1: serve everything (stock raw behavior).
extern "C" fn hooked_get_raw_mouse_accumulators(
    _this: *mut c_void,
    out_x: *mut i32,
    out_y: *mut i32,
) {
    let mode = read_m_rawinput();
    let now = mono_now();

    // count down the remaining tick time with elapsed wall time
    let now_bits = now.to_bits();
    let last_bits = LAST_SERVE_WALL.swap(now_bits, Ordering::Relaxed);
    let mut rem = f64::from_bits(SAMPLE_TIME_REMAINING.load(Ordering::Relaxed));
    if last_bits != 0 {
        rem = (rem - (now - f64::from_bits(last_bits))).max(0.0);
        SAMPLE_TIME_REMAINING.store(rem.to_bits(), Ordering::Relaxed);
    }

    let threshold = if mode == 2 { now - rem } else { f64::INFINITY };
    let (x, y) = ring_drain(threshold);

    unsafe {
        *out_x = x;
        *out_y = y;
    }
    let n = SERVED_CALLS.fetch_add(1, Ordering::Relaxed) + 1;
    if n % 600 == 1 {
        dbglog!(
            "served={n} poll={} motion={} mode={} out=({x},{y}) createmove={} rem={:.4} thr-now={:.4} ring={}",
            POLL_CALLS.load(Ordering::Relaxed),
            MOTION_EVENTS.load(Ordering::Relaxed),
            mode,
            CREATEMOVE_CALLS.load(Ordering::Relaxed),
            rem,
            threshold - now,
            W_IDX.load(Ordering::Relaxed) - R_IDX.load(Ordering::Relaxed),
        );
    }
}

/// CInput::CreateMove(int sequence_number, float input_sample_frametime,
/// bool active) — called once per tick; carries the tick interval.
extern "C" fn hooked_create_move(
    this: *mut c_void,
    sequence_number: i32,
    input_sample_frametime: f32,
    active: bool,
) {
    SAMPLE_TIME_REMAINING.store((input_sample_frametime as f64).to_bits(), Ordering::Relaxed);
    CREATEMOVE_CALLS.fetch_add(1, Ordering::Relaxed);
    let orig = ORIG_CREATEMOVE.load(Ordering::Relaxed);
    if orig != 0 {
        let f: extern "C" fn(*mut c_void, i32, f32, bool) = unsafe { std::mem::transmute(orig) };
        f(this, sequence_number, input_sample_frametime, active);
    }
    // Stamp the m_rawinput 2 default once we're in-game (past the engine's
    // startup reset that clobbers the command-line +m_rawinput 2).
    force_rawinput_default();
    // First in-game tick after a connect starts the per-map demo (opt-in), now
    // that the client is spawned (CreateMove only runs in-game).
    engine::demo_tick();
}

// ---------------------------------------------------------------------------
// runtime plumbing
// ---------------------------------------------------------------------------

struct Mapping {
    start: usize,
    end: usize,
    offset: usize,
    perms: String,
    path: String,
}

fn self_maps() -> Vec<Mapping> {
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
fn module_of(maps: &[Mapping], needle: &str) -> Option<(usize, String)> {
    maps.iter()
        .find(|m| m.path.ends_with(needle) && m.offset == 0)
        .map(|m| (m.start, m.path.clone()))
}

/// Point one vtable slot at `ours`, but ONLY if it currently holds `expect`.
///
/// The check is the whole point. A slot address derived against a different
/// build still holds a perfectly valid function pointer — just one belonging
/// to another class — so an unchecked write silently redirects an unrelated
/// virtual. That is exactly how the 2026-08-24 update turned these hooks into
/// a `vgui::Panel` virtual, a `CCSGameMovement` virtual and `ConCommand`'s
/// destructor slot, and the game segfaulted seconds after load. `expect` comes
/// from the module file, so a mismatch means our resolution is wrong and the
/// only safe action is to leave the slot alone.
unsafe fn vtable_hook(slot: usize, expect: usize, ours: usize) -> Result<usize, String> {
    let current = std::ptr::read(slot as *const usize);
    if current != expect {
        return Err(format!(
            "holds 0x{current:x}, expected 0x{expect:x} (game updated?)"
        ));
    }
    write_ptr(slot, ours)
}

/// Point a GOT slot at `ours`. The slot is named by the relocation that
/// created it, so there is nothing to compare against — but a live slot always
/// holds a code pointer (the stale constant used to give us the literal 0x8),
/// so require that much before writing.
unsafe fn got_hook(slot: usize, ours: usize, maps: &[Mapping]) -> Result<usize, String> {
    let current = std::ptr::read(slot as *const usize);
    if !maps
        .iter()
        .any(|m| m.perms.contains('x') && current >= m.start && current < m.end)
    {
        return Err(format!("holds 0x{current:x}, which is not code"));
    }
    write_ptr(slot, ours)
}

/// Write a pointer into a slot that may be RELRO'd, then confirm it stuck.
///
/// The page's original protection is restored exactly: forcing a .got.plt page
/// to read-only would make the next lazy symbol resolution on that page fault.
unsafe fn write_ptr(slot: usize, ours: usize) -> Result<usize, String> {
    let page = slot & !0xfff;
    let previous = std::ptr::read(slot as *const usize);
    let was_writable = self_maps()
        .iter()
        .any(|m| slot >= m.start && slot < m.end && m.perms.contains('w'));
    if libc::mprotect(
        page as *mut c_void,
        4096,
        libc::PROT_READ | libc::PROT_WRITE,
    ) != 0
    {
        return Err(format!("mprotect of 0x{page:x} failed"));
    }
    std::ptr::write(slot as *mut usize, ours);
    let restore = if was_writable {
        libc::PROT_READ | libc::PROT_WRITE
    } else {
        libc::PROT_READ
    };
    libc::mprotect(page as *mut c_void, 4096, restore);
    if std::ptr::read(slot as *const usize) != ours {
        return Err(format!("write to 0x{slot:x} did not stick"));
    }
    Ok(previous)
}

/// Find the m_rawinput ConVar and cache a pointer to its m_nValue.
unsafe fn resolve_convar() -> bool {
    // fresh snapshot — the game maps/unmaps constantly during startup
    let maps = self_maps();
    // client.so's mapped ranges (for validating ConVar vtable pointers —
    // vtables live in rodata/data.rel.ro, not in the executable text)
    let client_ranges: Vec<(usize, usize)> = maps
        .iter()
        .filter(|m| m.path.ends_with("/client.so"))
        .map(|m| (m.start, m.end))
        .collect();
    let in_client = |addr: usize| client_ranges.iter().any(|&(s, e)| addr >= s && addr < e);

    // 1) find the "m_rawinput\0" string inside client.so's mapped regions
    let mem = match File::open("/proc/self/mem") {
        Ok(f) => f,
        Err(_) => {
            log!("cannot open /proc/self/mem");
            return false;
        }
    };
    let needle = b"m_rawinput\0";
    let mut string_addr = 0usize;
    'outer: for m in maps
        .iter()
        .filter(|m| m.path.ends_with("/client.so") && m.perms.starts_with('r'))
    {
        let region = read_region_safe(&mem, m.start, m.end - m.start);
        if let Some(pos) = find_subslice(&region, needle) {
            string_addr = m.start + pos;
            break 'outer;
        }
    }
    if string_addr == 0 {
        log!("m_rawinput string not found");
        return false;
    }
    dbglog!("m_rawinput string @ 0x{string_addr:x}");

    // 2) find a qword pointing at it (ConVar::m_pszName). The ConVar object
    //    lives in client.so's .data or .bss (bss = anonymous mapping), so
    //    scan client.so-backed rw regions plus small anonymous rw ones.
    //    Every candidate is validated structurally before any dereference.
    let readable: Vec<(usize, usize)> = maps
        .iter()
        .filter(|m| m.perms.starts_with('r'))
        .map(|m| (m.start, m.end))
        .collect();
    let in_readable = |addr: usize| readable.iter().any(|&(s, e)| addr >= s && addr < e);

    for m in maps.iter().filter(|m| {
        m.perms.starts_with("rw")
            && (m.path.ends_with("/client.so")
                || (m.path.is_empty() && m.end - m.start < 32 * 1024 * 1024))
    }) {
        let region = read_region_safe(&mem, m.start, m.end - m.start);
        for off in (0..region.len().saturating_sub(8)).step_by(8) {
            let val = u64::from_ne_bytes(region[off..off + 8].try_into().unwrap()) as usize;
            if val != string_addr {
                continue;
            }
            let convar = m.start + off - CONVAR_NAME_OFFSET;
            // structural validation: a real ConVar has a vtable pointer
            // into client.so's text, and its value field must be readable
            if !in_readable(convar) {
                continue;
            }
            let vtable = *(convar as *const usize);
            if !in_client(vtable) {
                continue;
            }
            let value_ptr = convar + CONVAR_VALUE_OFFSET;
            if !in_readable(value_ptr) {
                continue;
            }
            let v = *(value_ptr as *const i32);
            if (0..=3).contains(&v) {
                CONVAR_RAWINPUT.store(value_ptr, Ordering::Relaxed);
                log!("m_rawinput ConVar @ 0x{convar:x} (current value {v})");
                return true;
            }
        }
    }
    log!("m_rawinput ConVar not found");
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Read a process memory region page-by-page via /proc/self/mem.
/// Unmapped/unreadable pages come back zeroed instead of SIGSEGVing us
/// (mappings can vanish between reading /proc/self/maps and the scan —
/// the game maps/unmaps constantly during startup).
fn read_region_safe(mem: &File, start: usize, len: usize) -> Vec<u8> {
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

fn has_insecure() -> bool {
    std::fs::read("/proc/self/cmdline")
        .map(|c| c.split(|&b| b == 0).any(|a| a == b"-insecure"))
        .unwrap_or(false)
}

/// Find the one virtual in `class`'s vtable whose body matches every pattern
/// in `specs`, searching `window` bytes from the entry point. Returns
/// (slot vaddr, fn vaddr, body bytes), or None if there is no match or more
/// than one — an ambiguous match means we would be guessing, so we refuse.
fn resolve_virtual(
    m: &elf::Module,
    class: &str,
    specs: &[&str],
    window: usize,
) -> Option<(usize, usize, Vec<u8>)> {
    let pats: Vec<sig::Pattern> = specs
        .iter()
        .filter_map(|s| sig::Pattern::parse(s))
        .collect();
    if pats.len() != specs.len() {
        log!("BUG: malformed pattern literal for {class}");
        return None;
    }
    let t = m.vtable(class)?;
    let mut hits = m
        .virtuals(t, VTABLE_MAX)
        .into_iter()
        .filter_map(|(idx, f)| {
            let body = m.read_va(f, window)?;
            pats.iter().all(|p| p.find(&body).is_some()).then_some((
                elf::Module::vslot(t, idx),
                f,
                body,
            ))
        });
    let first = hits.next()?;
    hits.next().is_none().then_some(first)
}

/// Locate `GetRawMouseAccumulators`: the launcher manager virtual whose entry
/// point *is* the accumulator-serving body. Returns (slot vaddr, fn vaddr).
fn resolve_getrawaccum(m: &elf::Module) -> Option<(usize, usize)> {
    let pat = sig::Pattern::parse(GETRAWACCUM_BODY)?;
    // matched at offset 0: it is a leaf function, and a window would bleed
    // into whatever the linker placed next
    let (slot, fn_va, body) =
        resolve_virtual(m, LAUNCHER_MGR_CLASS, &[GETRAWACCUM_BODY], pat.len())?;
    pat.matches_at(&body, 0).then_some((slot, fn_va))
}

/// Locate `CreateMove` and every input vtable slot that dispatches to it.
/// Returns (fn vaddr, slot vaddrs).
fn resolve_createmove(m: &elf::Module) -> Option<(usize, Vec<usize>)> {
    // CInput declares the implementation; CCSInput inherits it unchanged, and
    // the singleton the engine dispatches through is the derived one — so find
    // the function once, then collect every vtable that carries it.
    let (_, fn_va, _) = resolve_virtual(m, INPUT_CLASSES[0], CREATEMOVE_BODY, BODY_WINDOW)?;
    let slots: Vec<usize> = INPUT_CLASSES
        .iter()
        .filter_map(|cls| resolve_virtual(m, cls, CREATEMOVE_BODY, BODY_WINDOW))
        .filter(|&(_, f, _)| f == fn_va)
        .map(|(slot, _, _)| slot)
        .collect();
    (!slots.is_empty()).then_some((fn_va, slots))
}

fn init_thread() {
    if !has_insecure() {
        log!("game was not started with -insecure; NOT installing hooks");
        return;
    }

    // wait for client.so + launcher.so + engine.so to be mapped by the engine
    // (launcher.so pulls in libSDL2, so after this SDL is guaranteed loaded)
    let (mut client, mut launcher, mut engine_mod) = (None, None, None);
    for _ in 0..240 {
        let maps = self_maps();
        client = module_of(&maps, "/client.so");
        launcher = module_of(&maps, "/launcher.so");
        engine_mod = module_of(&maps, "/engine.so");
        if client.is_some() && launcher.is_some() && engine_mod.is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let (Some((client_base, client_path)), Some((launcher_base, launcher_path))) =
        (client, launcher)
    else {
        log!("timed out waiting for client.so/launcher.so");
        return;
    };
    log!("modules found: client 0x{client_base:x} launcher 0x{launcher_base:x}");

    // Parse the module files. Every hook target below is resolved out of these
    // by name — RTTI class, symbol relocation, instruction signature — instead
    // of by a link-time address that the next game update would invalidate.
    let (Some(client_elf), Some(launcher_elf)) = (
        elf::Module::open(&client_path),
        elf::Module::open(&launcher_path),
    ) else {
        log!("cannot parse client.so/launcher.so as ELF; NOT installing hooks");
        return;
    };

    // Resolve SDL symbols from the SDL2 handle directly (not RTLD_NEXT —
    // we must not interpose by name: sdl2-compat's internal SDL3 calls would
    // recurse into us). The GOT hook below only catches the GAME's calls.
    let sdl = unsafe {
        let h = libc::dlopen(
            c"libSDL2-2.0.so.0".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_NOLOAD,
        );
        if h.is_null() {
            libc::dlopen(c"libSDL2-2.0.so.0".as_ptr(), libc::RTLD_NOW)
        } else {
            h
        }
    };
    if sdl.is_null() {
        log!("could not get libSDL2 handle");
        return;
    }
    let pollevent = unsafe { libc::dlsym(sdl, c"SDL_PollEvent".as_ptr()) };
    if pollevent.is_null() {
        log!("SDL_PollEvent not found");
        return;
    }
    REAL_POLLEVENT.store(pollevent as usize, Ordering::Relaxed);
    log!("SDL symbols resolved");

    // convar
    unsafe { resolve_convar() };

    let maps = self_maps();

    // ---- SDL_PollEvent: hook launcher.so's GOT slot, located through the
    // relocation that names the symbol. (The old hard-coded slot address
    // landed on a plain data word in this build, so the hook was silently dead
    // and clobbered that word.)
    let sdl_hooked = match launcher_elf.jump_slot("SDL_PollEvent") {
        Some(slot) => {
            match unsafe {
                got_hook(
                    launcher_base + slot,
                    sdl_poll_event_hook as *const () as usize,
                    &maps,
                )
            } {
                Ok(prev) => {
                    dbglog!("GOT SDL_PollEvent @ +0x{slot:x} held 0x{prev:x}, now hooked");
                    log!("hooked SDL_PollEvent (GOT +0x{slot:x})");
                    true
                }
                Err(e) => {
                    log!("FAILED to hook SDL_PollEvent: {e}");
                    false
                }
            }
        }
        None => {
            log!("FAILED to hook SDL_PollEvent: launcher.so has no relocation for it");
            false
        }
    };

    // ---- GetRawMouseAccumulators. Our replacement serves deltas out of the
    // ring the SDL hook fills, so installing it without that hook would stop
    // mouse input dead — only take it over if we are actually collecting.
    if sdl_hooked {
        match resolve_getrawaccum(&launcher_elf) {
            Some((slot, fn_va)) => match unsafe {
                vtable_hook(
                    launcher_base + slot,
                    launcher_base + fn_va,
                    hooked_get_raw_mouse_accumulators as *const () as usize,
                )
            } {
                Ok(_) => log!(
                    "hooked GetRawMouseAccumulators ({LAUNCHER_MGR_CLASS} slot +0x{slot:x}, \
                     fn +0x{fn_va:x})"
                ),
                Err(e) => log!("FAILED to hook GetRawMouseAccumulators: {e}"),
            },
            None => log!(
                "FAILED to hook GetRawMouseAccumulators: not found in {LAUNCHER_MGR_CLASS}'s \
                 vtable (game updated?)"
            ),
        }
    } else {
        log!("NOT hooking GetRawMouseAccumulators without the SDL hook (mouse would stop)");
    }

    // ---- CreateMove, on every input vtable that dispatches to it.
    match resolve_createmove(&client_elf) {
        Some((fn_va, slots)) => {
            // publish the original first: a hooked slot can fire on the engine
            // thread the instant we write it
            ORIG_CREATEMOVE.store(client_base + fn_va, Ordering::Relaxed);
            let mut ok = 0usize;
            for &slot in &slots {
                match unsafe {
                    vtable_hook(
                        client_base + slot,
                        client_base + fn_va,
                        hooked_create_move as *const () as usize,
                    )
                } {
                    Ok(_) => {
                        ok += 1;
                        dbglog!("CreateMove slot +0x{slot:x} hooked");
                    }
                    Err(e) => log!("CreateMove slot +0x{slot:x} NOT hooked: {e}"),
                }
            }
            if ok == 0 {
                ORIG_CREATEMOVE.store(0, Ordering::Relaxed);
                log!("FAILED to hook CreateMove (no slot validated)");
            } else {
                log!(
                    "hooked CreateMove ({ok}/{} input vtables, fn +0x{fn_va:x})",
                    slots.len()
                );
            }
        }
        None => log!("FAILED to hook CreateMove: no CInput vtable in client.so (game updated?)"),
    }

    // viewpunch remover (skip with RAWINPUT2_KEEP_VIEWPUNCH=1)
    if std::env::var_os("RAWINPUT2_KEEP_VIEWPUNCH").is_none() {
        viewpunch_impl::install(&client_elf, client_base);
    }

    // fastdl.me map hijack + engine glue (console cmds/demos, download
    // progress, window flash). Both validate what they resolved and disable
    // themselves on a mismatch instead of writing blindly.
    if let Some((engine_base, engine_path)) = engine_mod {
        match elf::Module::open(&engine_path) {
            Some(engine_elf) => {
                if unsafe { fastdl_impl::install(&engine_elf, engine_base) } {
                    log!("hooked ProcessServerInfo (fastdl.me map hijack armed)");
                } else {
                    log!("fastdl hook NOT installed (see above)");
                }
                engine::init(&engine_elf, engine_base, &engine_path, sdl);
            }
            None => log!("cannot parse engine.so; fastdl + console features off"),
        }
    }

    log!("ready. set `m_rawinput 2` in game for tick-aligned sampling");
}

// ---------------------------------------------------------------------------
// LD_PRELOAD entry point
// ---------------------------------------------------------------------------

extern "C" fn rawinput2_init() {
    DEBUG.store(
        std::env::var_os("RAWINPUT2_DEBUG").is_some(),
        Ordering::Relaxed,
    );
    FORCE_RAWINPUT2.store(
        std::env::var_os("RAWINPUT2_NO_FORCE").is_none(),
        Ordering::Relaxed,
    );
    log!(
        "loaded into pid {}, waiting for game modules...",
        std::process::id()
    );
    std::thread::spawn(init_thread);
}

#[used]
#[link_section = ".init_array"]
static INIT: extern "C" fn() = rawinput2_init;

// ---------------------------------------------------------------------------
// Resolver regression tests
//
// The real binaries only exist in the game install, so these read it directly
// and skip when it is absent. They assert *structural* facts that hold on any
// build rather than addresses (which move on every update), so a failure means
// either the resolver regressed or a game update changed something that has to
// be re-reversed — exactly the signal that was missing when the 2026-08-24
// build silently turned these hooks into a crash.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod testutil {
    pub fn open(rel: &str) -> Option<crate::elf::Module> {
        let home = std::env::var("HOME").ok()?;
        for root in [
            format!("{home}/.local/share/Steam/steamapps/common/Counter-Strike Source"),
            format!("{home}/.steam/steam/steamapps/common/Counter-Strike Source"),
        ] {
            let p = format!("{root}/{rel}");
            if std::path::Path::new(&p).exists() {
                return crate::elf::Module::open(&p);
            }
        }
        None
    }
    pub fn client() -> Option<crate::elf::Module> {
        open("cstrike/bin/linux64/client.so")
    }
    pub fn launcher() -> Option<crate::elf::Module> {
        open("bin/linux64/launcher.so")
    }
    pub fn engine() -> Option<crate::elf::Module> {
        open("bin/linux64/engine.so")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn createmove_resolves_on_every_input_vtable() {
        let Some(m) = testutil::client() else { return };
        let (fn_va, slots) = resolve_createmove(&m).expect("CInput::CreateMove");
        assert!(m.is_exec(fn_va), "CreateMove 0x{fn_va:x} is not code");
        // CInput declares it and CCSInput inherits it unchanged; the live
        // singleton dispatches through the derived vtable, so both must resolve
        // or we would hook a vtable nothing calls.
        assert_eq!(
            slots.len(),
            INPUT_CLASSES.len(),
            "expected a slot per input class, got {slots:x?}"
        );
        for s in slots {
            assert_eq!(m.u64_va(s), Some(fn_va), "slot 0x{s:x}");
        }
    }

    #[test]
    fn raw_accumulator_virtual_is_unambiguous() {
        let Some(m) = testutil::launcher() else {
            return;
        };
        let (slot, fn_va) = resolve_getrawaccum(&m).expect("GetRawMouseAccumulators");
        assert_eq!(m.u64_va(slot), Some(fn_va));
        assert!(m.is_exec(fn_va), "accumulator fn 0x{fn_va:x} is not code");
    }

    #[test]
    fn sdl_pollevent_got_slot_comes_from_a_relocation() {
        let Some(m) = testutil::launcher() else {
            return;
        };
        let slot = m
            .jump_slot("SDL_PollEvent")
            .expect("launcher.so imports SDL_PollEvent");
        // must be a real slot in the image, not a bare address we guessed
        assert!(
            m.u64_va(slot).is_some(),
            "slot 0x{slot:x} outside the image"
        );
    }

    #[test]
    fn process_server_info_resolves_and_yields_the_md5_offset() {
        let Some(m) = testutil::engine() else { return };
        let (fn_va, md5_off) = fastdl::resolve_target(&m).expect("CClientState::ProcessServerInfo");
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
    fn engine_glue_classes_exist() {
        let Some(m) = testutil::engine() else { return };
        // ClientCmd is reached through CreateInterface at runtime, but the RTTI
        // identity check it performs needs this class to exist by name.
        assert!(
            m.vtable("13CEngineClient").is_some(),
            "CEngineClient vtable"
        );
        assert!(
            m.vtable("16CDownloadManager").is_some(),
            "CDownloadManager vtable"
        );
    }
}
