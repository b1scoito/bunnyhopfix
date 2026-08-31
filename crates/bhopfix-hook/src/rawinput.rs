//! The rawinput2 feature: tick-aligned raw mouse sampling.
//!
//! Raw deltas arrive through launcher.so's GOT entry for `SDL_PollEvent` — a
//! GOT hook, not name interposition, so sdl2-compat's internal SDL3 calls can
//! never recurse into us — and land in a timestamped ring. The game's
//! `GetRawMouseAccumulators` is replaced by one that only serves the deltas
//! belonging to the tick currently being built, and `CInput::CreateMove` (which
//! carries the tick's input sample interval) refreshes that window every tick.
//!
//! The two hooks are interlocked: the accumulator hook has nothing to serve
//! unless the SDL hook is collecting, so installing it alone would stop mouse
//! input dead (see `init_thread`).

use std::ffi::c_void;
use std::fs::File;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

use crate::engine;
use crate::proc::{read_region_safe, self_maps};

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

pub(crate) static ORIG_CREATEMOVE: AtomicUsize = AtomicUsize::new(0);

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

pub(crate) static REAL_POLLEVENT: AtomicUsize = AtomicUsize::new(0);

// debug instrumentation (BHOPFIX_DEBUG=1)
static POLL_CALLS: AtomicU64 = AtomicU64::new(0);
static MOTION_EVENTS: AtomicU64 = AtomicU64::new(0);
static SERVED_CALLS: AtomicU64 = AtomicU64::new(0);
static CREATEMOVE_CALLS: AtomicU64 = AtomicU64::new(0);

/// Our SDL_PollEvent hook (installed into launcher.so's GOT — NOT exported,
/// so sdl2-compat's internal SDL3 calls never recurse into us).
/// Every event the game polls passes through here: accumulate raw motion
/// with the event's own hardware timestamp, then hand it to the game.
pub(crate) extern "C" fn sdl_poll_event_hook(event: *mut c_void) -> i32 {
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

/// Whether to force `m_rawinput 2` as the default (opt out BHOPFIX_NO_FORCE=1).
pub(crate) static FORCE_RAWINPUT2: AtomicBool = AtomicBool::new(true);
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
    log!(
        "m_rawinput forced to 2 (default; change with `m_rawinput 0/1` in game, or BHOPFIX_NO_FORCE=1)"
    );
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
pub(crate) extern "C" fn hooked_get_raw_mouse_accumulators(
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
pub(crate) extern "C" fn hooked_create_move(
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
// m_rawinput ConVar
// ---------------------------------------------------------------------------

/// Find the m_rawinput ConVar and cache a pointer to its m_nValue.
///
/// # Safety
/// Dereferences candidate ConVar objects found by scanning client.so's
/// writable mappings; every candidate is range-checked against a fresh
/// `/proc/self/maps` snapshot first.
pub(crate) unsafe fn resolve_convar() -> bool {
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
            let vtable = unsafe { *(convar as *const usize) };
            if !in_client(vtable) {
                continue;
            }
            let value_ptr = convar + CONVAR_VALUE_OFFSET;
            if !in_readable(value_ptr) {
                continue;
            }
            let v = unsafe { *(value_ptr as *const i32) };
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

#[cfg(test)]
mod tests {
    #[test]
    fn sdl_pollevent_got_slot_comes_from_a_relocation() {
        let Some(m) = crate::testutil::launcher() else {
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
}
