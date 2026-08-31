//! engine.so glue: run client console commands (IVEngineClient::ClientCmd),
//! show map-download progress, auto-record demos, flash the window.
//!
//! Nothing here is addressed by link-time vaddr any more: the interface comes
//! from engine.so's own CreateInterface export and the download manager from
//! its RTTI. Every use is validated at init and the feature is disabled (never
//! crashes) on any mismatch.

use std::ffi::{c_char, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use bhopfix_core::elf;
use bhopfix_core::sig::Pattern;

use crate::proc::{self, Mapping, rd, rd_cstr, rd_i32, rd_u8, rd_u64, self_maps};
use crate::vtable::VTABLE_MAX;

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
///
/// # Safety
/// `engine_path` must name the engine.so this process already has open;
/// the returned function pointer is called through a hand-written ABI.
unsafe fn resolve_engine_client(engine_path: &str) -> Option<(usize, usize)> {
    let path = std::ffi::CString::new(engine_path).ok()?;
    let h = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD) };
    if h.is_null() {
        log!("engine: engine.so is not open (dlopen NOLOAD failed)");
        return None;
    }
    let sym = unsafe { libc::dlsym(h, c"CreateInterface".as_ptr()) };
    if sym.is_null() {
        log!("engine: engine.so exports no CreateInterface");
        return None;
    }
    let create: extern "C" fn(*const c_char, *mut i32) -> *mut c_void =
        unsafe { std::mem::transmute(sym) };
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
    let pats: Vec<Pattern> = CLIENTCMD_BODY
        .iter()
        .filter_map(|s| Pattern::parse(s))
        .collect();
    if pats.len() != CLIENTCMD_BODY.len() {
        log!("BUG: malformed ClientCmd pattern literal");
        return None;
    }
    let mut found = None;
    let mut body = vec![0u8; CLIENTCMD_WINDOW];
    for i in 0..VTABLE_MAX {
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
fn resolve_dlmgr(engine: &elf::Module, engine_base: usize) -> Option<usize> {
    let t = engine.vtable(DLMGR_CLASS)?;
    let want = (engine_base + elf::Module::vslot(t, 0)).to_ne_bytes();
    // Scan by address, not by /proc/self/maps path: this singleton lives in
    // the anonymous .bss tail, which is not attributed to engine.so.
    let (lo, hi) = engine.writable_span()?;
    let mut chunk = vec![0u8; 64 * 1024];
    let (mut addr, end) = (engine_base + lo, engine_base + hi);
    while addr < end {
        let len = chunk.len().min(end - addr);
        if rd(&mut chunk[..len], addr)
            && let Some(i) = chunk[..len]
                .as_chunks::<8>()
                .0
                .iter()
                .position(|w| *w == want)
        {
            return Some(addr + i * 8);
        }
        addr += len;
    }
    None
}

/// Resolve the ClientCmd interface and the download-manager singleton, and
/// look up the SDL flash symbols. Everything is validated; a feature whose
/// lookup does not check out stays DISABLED instead of crashing.
pub(crate) fn init(
    engine: &elf::Module,
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
    if !proc::open_mem() {
        log!("engine: cannot open /proc/self/mem; engine features disabled");
        return;
    }

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
        std::env::var_os("BHOPFIX_DEMOS").is_some(),
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
pub(crate) fn queue_cmd(cmd: impl Into<String>) {
    if !CMD_READY.load(Ordering::Relaxed) {
        return;
    }
    let mut c = cmd.into();
    c.truncate(180); // stay under Cbuf_AddText's fixed buffer
    if let Ok(mut q) = CMD_QUEUE.lock()
        && q.len() < 32
    {
        q.push(c);
    }
}

/// Record a demo of this map once we're actually in-game. Called at connect
/// (ProcessServerInfo); the actual `record` is issued from the first
/// CreateMove (see demo_tick) so the client is spawned.
pub(crate) fn arm_demo(mapname: &str) {
    if !DEMOS_ON.load(Ordering::Relaxed) || !CMD_READY.load(Ordering::Relaxed) {
        return;
    }
    if let Ok(mut p) = PENDING_DEMO.lock() {
        *p = Some(mapname.to_string());
    }
}

/// Issue the queued `record` once in-game. Call from the CreateMove hook
/// (main thread, only runs after spawn).
pub(crate) fn demo_tick() {
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
pub(crate) fn pump() {
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
    let clientcmd: extern "C" fn(*mut c_void, *const c_char) = unsafe { std::mem::transmute(fnp) };
    for cmd in cmds {
        if let Ok(cs) = std::ffi::CString::new(cmd) {
            clientcmd(iface, cs.as_ptr()); // Cbuf_AddText copies it
        }
    }
}

/// Poll the active map download and log progress; flash the window when a
/// download finishes. Read-only + fault-safe. Call from the SDL hook.
pub(crate) fn poll_downloads() {
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

#[cfg(test)]
mod tests {
    #[test]
    fn engine_glue_classes_exist() {
        let Some(m) = crate::testutil::engine() else {
            return;
        };
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
