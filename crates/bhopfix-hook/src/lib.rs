//! `libbhopfix.so` — the injected half of bunnyhopfix.
//!
//! LD_PRELOAD hook library. The patcher binary fixes jump prediction from the
//! outside; this library lives inside the game process and arms everything that
//! has to be in there: momentum-mod style `m_rawinput 2` (the rawinput2
//! feature, ported from the RawInput2 half of rtldg/RawInput2BunnyhopAPE on
//! Windows), the viewpunch remover, the fastdl.me map hijack and the engine
//! console glue.
//!
//! What rawinput2 does: mouse input is sampled so it "lines up with the
//! tickrate properly without needing a specific framerate" — raw deltas are
//! accumulated with timestamps and split at tick boundaries instead of being
//! lumped per frame.
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
//! resolved from the module files by name at startup (see `bhopfix_core::elf`),
//! and every hook validates its slot before writing.
//!
//! Hooks are installed by rewriting vtable pointers (no inline patching).
//! Requires -insecure, same policy as the patcher.

// This is an LD_PRELOAD library: it reads /proc/self/{maps,mem}, parses ELF and
// rewrites vtables in-process, none of which has a Windows analogue. The
// Windows port is the patcher only, so on Windows this crate is empty.
#![cfg(unix)]

use std::sync::atomic::{AtomicBool, Ordering};

use bhopfix_core::elf;

// ---------------------------------------------------------------------------
// logging (uses libc::write to stderr)
// ---------------------------------------------------------------------------

/// `BHOPFIX_DEBUG` was set: emit resolver details and the periodic sampling
/// instrumentation line. Hook threads read it, so it stays an atomic.
static DEBUG: AtomicBool = AtomicBool::new(false);

/// Write one prefixed line to stderr.
///
/// `libc::write` rather than `eprintln!`: we run on the game's own threads,
/// inside its address space, sometimes mid-frame — the one thing we must not do
/// is take a lock the game knows nothing about.
pub(crate) fn emit(msg: &str) {
    const PREFIX: &[u8] = b"[bhopfix] ";
    unsafe {
        libc::write(2, PREFIX.as_ptr().cast(), PREFIX.len());
        libc::write(2, msg.as_ptr().cast(), msg.len());
        libc::write(2, b"\n".as_ptr().cast(), 1);
    }
}

/// Whether `dbglog!` output is enabled.
pub(crate) fn debug_on() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

macro_rules! log {
    ($($t:tt)*) => { $crate::emit(&std::format!($($t)*)) };
}

macro_rules! dbglog {
    ($($t:tt)*) => {{
        if $crate::debug_on() {
            log!($($t)*);
        }
    }};
}

// NB: log!/dbglog! (macro_rules, defined above) are in textual scope for these
// submodules because they are declared after the macro definitions.
mod engine;
mod fastdl;
mod proc;
mod rawinput;
mod sourcejump;
mod viewpunch;
mod vtable;

// ---------------------------------------------------------------------------
// LD_PRELOAD entry point
// ---------------------------------------------------------------------------

extern "C" fn bhopfix_init() {
    DEBUG.store(
        std::env::var_os("BHOPFIX_DEBUG").is_some(),
        Ordering::Relaxed,
    );
    rawinput::FORCE_RAWINPUT2.store(
        std::env::var_os("BHOPFIX_NO_FORCE").is_none(),
        Ordering::Relaxed,
    );
    log!(
        "loaded into pid {}, waiting for game modules...",
        std::process::id()
    );
    std::thread::spawn(init_thread);
}

#[used]
#[unsafe(link_section = ".init_array")]
static INIT: extern "C" fn() = bhopfix_init;

/// Wait for the game's modules to appear, then resolve and arm every feature.
///
/// Runs on its own thread: the engine maps client.so/launcher.so/engine.so long
/// after the loader has run our `.init_array` entry, and nothing here may block
/// the process from starting.
fn init_thread() {
    if !proc::has_insecure() {
        log!("game was not started with -insecure; NOT installing hooks");
        return;
    }

    // wait for client.so + launcher.so + engine.so to be mapped by the engine
    // (launcher.so pulls in libSDL2, so after this SDL is guaranteed loaded)
    let (mut client, mut launcher, mut engine_mod) = (None, None, None);
    for _ in 0..240 {
        let maps = proc::self_maps();
        client = proc::module_base(&maps, "/client.so");
        launcher = proc::module_base(&maps, "/launcher.so");
        engine_mod = proc::module_base(&maps, "/engine.so");
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
    rawinput::REAL_POLLEVENT.store(pollevent as usize, Ordering::Relaxed);
    log!("SDL symbols resolved");

    // convar
    unsafe { rawinput::resolve_convar() };

    let maps = proc::self_maps();

    // ---- SDL_PollEvent: hook launcher.so's GOT slot, located through the
    // relocation that names the symbol. (The old hard-coded slot address
    // landed on a plain data word in this build, so the hook was silently dead
    // and clobbered that word.)
    let sdl_hooked = match launcher_elf.jump_slot("SDL_PollEvent") {
        Some(slot) => {
            match unsafe {
                vtable::got_hook(
                    launcher_base + slot,
                    rawinput::sdl_poll_event_hook as *const () as usize,
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
        match vtable::resolve_getrawaccum(&launcher_elf) {
            Some((slot, fn_va)) => match unsafe {
                vtable::vtable_hook(
                    launcher_base + slot,
                    launcher_base + fn_va,
                    rawinput::hooked_get_raw_mouse_accumulators as *const () as usize,
                )
            } {
                Ok(_) => log!(
                    "hooked GetRawMouseAccumulators ({} slot +0x{slot:x}, fn +0x{fn_va:x})",
                    vtable::LAUNCHER_MGR_CLASS
                ),
                Err(e) => log!("FAILED to hook GetRawMouseAccumulators: {e}"),
            },
            None => log!(
                "FAILED to hook GetRawMouseAccumulators: not found in {}'s vtable \
                 (game updated?)",
                vtable::LAUNCHER_MGR_CLASS
            ),
        }
    } else {
        log!("NOT hooking GetRawMouseAccumulators without the SDL hook (mouse would stop)");
    }

    // ---- CreateMove, on every input vtable that dispatches to it.
    match vtable::resolve_createmove(&client_elf) {
        Some((fn_va, slots)) => {
            // publish the original first: a hooked slot can fire on the engine
            // thread the instant we write it
            rawinput::ORIG_CREATEMOVE.store(client_base + fn_va, Ordering::Relaxed);
            let mut ok = 0usize;
            for &slot in &slots {
                match unsafe {
                    vtable::vtable_hook(
                        client_base + slot,
                        client_base + fn_va,
                        rawinput::hooked_create_move as *const () as usize,
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
                rawinput::ORIG_CREATEMOVE.store(0, Ordering::Relaxed);
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

    // viewpunch remover (skip with BHOPFIX_KEEP_VIEWPUNCH=1)
    if std::env::var_os("BHOPFIX_KEEP_VIEWPUNCH").is_none() {
        viewpunch::install(&client_elf, client_base);
    }

    // fastdl.me map hijack + engine glue (console cmds/demos, download
    // progress, window flash). Both validate what they resolved and disable
    // themselves on a mismatch instead of writing blindly.
    if let Some((engine_base, engine_path)) = engine_mod {
        match elf::Module::open(&engine_path) {
            Some(engine_elf) => {
                if unsafe { fastdl::install(&engine_elf, engine_base) } {
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
// Resolver regression tests
//
// The real binaries only exist in the game install, so the per-module tests
// read it directly and skip when it is absent. They assert *structural* facts
// that hold on any build rather than addresses (which move on every update), so
// a failure means either the resolver regressed or a game update changed
// something that has to be re-reversed — exactly the signal that was missing
// when the 2026-08-24 build silently turned these hooks into a crash.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod testutil {
    use bhopfix_core::elf;

    pub(crate) fn open(rel: &str) -> Option<elf::Module> {
        let home = std::env::var("HOME").ok()?;
        for root in [
            format!("{home}/.local/share/Steam/steamapps/common/Counter-Strike Source"),
            format!("{home}/.steam/steam/steamapps/common/Counter-Strike Source"),
        ] {
            let p = format!("{root}/{rel}");
            if std::path::Path::new(&p).exists() {
                return elf::Module::open(&p);
            }
        }
        None
    }
    pub(crate) fn client() -> Option<elf::Module> {
        open("cstrike/bin/linux64/client.so")
    }
    pub(crate) fn launcher() -> Option<elf::Module> {
        open("bin/linux64/launcher.so")
    }
    pub(crate) fn engine() -> Option<elf::Module> {
        open("bin/linux64/engine.so")
    }
}
