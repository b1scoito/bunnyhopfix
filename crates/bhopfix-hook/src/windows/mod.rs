//! Windows x64 injected hook lifecycle.

mod api;
mod control;
mod engine;
mod fastdl;
mod fullscreen;
mod hook;
mod module;
mod rawinput;
mod viewpunch;

use bhopfix_core::control::{
    FEATURE_CONSOLE, FEATURE_DOWNLOADS, FEATURE_FASTDL, FEATURE_FULLSCREEN, FEATURE_RAWINPUT2,
    FEATURE_SOURCEJUMP, FEATURE_VIEWPUNCH, FLAG_DEBUG, FLAG_KEEP_VIEWPUNCH, FLAG_NO_SOURCEJUMP,
    STATE_CREATED, STATE_FAILED, STATE_READY, STATE_STARTING, STATE_STOPPED, STATE_STOPPING,
};
use std::ffi::c_void;
use std::sync::atomic::Ordering;

pub(crate) fn emit(message: &str) {
    control::emit(message);
}

pub(crate) fn queue_command(command: impl Into<String>) {
    engine::queue_command(command);
}

fn command_line_is_insecure() -> bool {
    std::env::args_os().any(|argument| argument.to_string_lossy().eq_ignore_ascii_case("-insecure"))
}

fn wait_for_modules(
    session: &control::Session,
) -> Option<(
    module::LiveModule,
    module::LiveModule,
    module::LiveModule,
    module::LiveModule,
)> {
    for _ in 0..600 {
        if session.should_stop() {
            return None;
        }
        if let (Some(inputsystem), Some(client), Some(engine), Some(d3d9)) = (
            module::LiveModule::open("inputsystem.dll"),
            module::LiveModule::open("client.dll"),
            module::LiveModule::open("engine.dll"),
            module::LiveModule::open("d3d9.dll"),
        ) {
            return Some((inputsystem, client, engine, d3d9));
        }
        unsafe { api::Sleep(50) };
    }
    None
}

fn fail(session: &control::Session, code: u32, message: &str, unload_safe: bool) -> u32 {
    control::error(message);
    session.block().error.store(code, Ordering::Release);
    if unload_safe {
        session.block().features.store(0, Ordering::Release);
        session.block().unload_safe.store(1, Ordering::Release);
    }
    session.block().state.store(STATE_FAILED, Ordering::Release);
    code
}

fn run() -> u32 {
    let Some(session) = control::Session::open() else {
        return 1;
    };
    super::DEBUG.store(session.block().flags & FLAG_DEBUG != 0, Ordering::Release);
    if session
        .block()
        .state
        .compare_exchange(
            STATE_CREATED,
            STATE_STARTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return fail(
            &session,
            2,
            "hook start rejected: control block is not new",
            true,
        );
    }
    if !command_line_is_insecure() {
        return fail(
            &session,
            3,
            "hook start rejected: game was not launched with -insecure",
            true,
        );
    }
    let Some((inputsystem, client, engine_module, d3d9)) = wait_for_modules(&session) else {
        if session.should_stop() {
            session.block().unload_safe.store(1, Ordering::Release);
            session
                .block()
                .state
                .store(STATE_STOPPED, Ordering::Release);
            return 0;
        }
        return fail(
            &session,
            4,
            "hook start failed: client.dll, inputsystem.dll, engine.dll, or d3d9.dll did not load",
            true,
        );
    };
    let mut engine = match engine::Integration::install(&engine_module) {
        Ok(integration) => integration,
        Err(error) => {
            return fail(
                &session,
                5,
                &format!("engine integration failed: {error}"),
                true,
            );
        }
    };
    let mut fullscreen = match fullscreen::Hooks::install(&engine_module, &d3d9) {
        Ok(hooks) => hooks,
        Err(error) => {
            engine.shutdown();
            return fail(
                &session,
                6,
                &format!("fullscreen integration failed: {error}"),
                true,
            );
        }
    };
    let mut rawinput = match rawinput::Hooks::install(&inputsystem, &client) {
        Ok(hooks) => hooks,
        Err(error) => {
            engine.shutdown();
            let clean = rawinput::is_quiescent() && fullscreen::is_quiescent();
            return fail(
                &session,
                7,
                &format!("rawinput2 install failed: {error}"),
                clean,
            );
        }
    };
    let initial_viewpunch = session.block().flags & FLAG_KEEP_VIEWPUNCH == 0;
    let mut viewpunch = match viewpunch::Hooks::install(&client, initial_viewpunch) {
        Ok(hooks) => hooks,
        Err(error) => {
            let cleanup = rawinput.restore();
            engine.shutdown();
            let clean = cleanup.is_ok()
                && rawinput::is_quiescent()
                && viewpunch::is_quiescent()
                && fullscreen::is_quiescent();
            let error = match cleanup {
                Ok(()) => error,
                Err(cleanup) => format!("{error}; rawinput cleanup failed: {cleanup}"),
            };
            return fail(
                &session,
                8,
                &format!("viewpunch install failed: {error}"),
                clean,
            );
        }
    };
    crate::sourcejump::start();
    let mut fastdl = match fastdl::Hooks::install(&engine_module) {
        Ok(hooks) => hooks,
        Err(error) => {
            crate::sourcejump::shutdown();
            let mut cleanup_errors = Vec::new();
            if let Err(cleanup) = viewpunch.restore() {
                cleanup_errors.push(format!("viewpunch: {cleanup}"));
            }
            if let Err(cleanup) = rawinput.restore() {
                cleanup_errors.push(format!("rawinput2: {cleanup}"));
            }
            engine.shutdown();
            let clean = cleanup_errors.is_empty()
                && fastdl::is_quiescent()
                && viewpunch::is_quiescent()
                && rawinput::is_quiescent()
                && fullscreen::is_quiescent();
            let detail = if cleanup_errors.is_empty() {
                error
            } else {
                format!("{error}; cleanup failed: {}", cleanup_errors.join("; "))
            };
            return fail(
                &session,
                9,
                &format!("fastdl install failed: {detail}"),
                clean,
            );
        }
    };
    let mut features = FEATURE_RAWINPUT2
        | FEATURE_VIEWPUNCH
        | FEATURE_FASTDL
        | FEATURE_FULLSCREEN
        | FEATURE_CONSOLE
        | FEATURE_DOWNLOADS;
    if session.block().flags & FLAG_NO_SOURCEJUMP == 0 {
        features |= FEATURE_SOURCEJUMP;
    }
    session.block().features.store(features, Ordering::Release);
    session.block().state.store(STATE_READY, Ordering::Release);
    control::emit("Windows x64 hook ready");

    let mut f6_down = false;
    let mut f7_down = false;
    while !session.should_stop() {
        let f6 = unsafe { api::GetAsyncKeyState(api::VK_F6) } as u16 & 0x8000 != 0;
        if f6
            && !f6_down
            && let Err(error) = fullscreen.toggle()
        {
            control::warn(&format!("fullscreen toggle rejected: {error}"));
        }
        f6_down = f6;
        let f7 = unsafe { api::GetAsyncKeyState(api::VK_F7) } as u16 & 0x8000 != 0;
        if f7
            && !f7_down
            && let Err(error) = viewpunch.toggle()
        {
            control::warn(&format!("viewpunch toggle rejected: {error}"));
        }
        f7_down = f7;
        unsafe { api::Sleep(10) };
    }

    session
        .block()
        .state
        .store(STATE_STOPPING, Ordering::Release);
    let mut cleanup_errors = Vec::new();
    if let Err(error) = fastdl.restore() {
        cleanup_errors.push(format!("fastdl: {error}"));
    }
    crate::sourcejump::shutdown();
    if let Err(error) = fullscreen.restore() {
        cleanup_errors.push(format!("fullscreen: {error}"));
    }
    if let Err(error) = viewpunch.restore() {
        cleanup_errors.push(format!("viewpunch: {error}"));
    }
    if let Err(error) = rawinput.restore() {
        cleanup_errors.push(format!("rawinput2: {error}"));
    }
    engine.shutdown();
    let clean = cleanup_errors.is_empty()
        && fullscreen::is_quiescent()
        && fastdl::is_quiescent()
        && viewpunch::is_quiescent()
        && rawinput::is_quiescent();
    if !clean {
        return fail(
            &session,
            10,
            &format!("hook restoration failed: {}", cleanup_errors.join("; ")),
            false,
        );
    }
    session.block().features.store(0, Ordering::Release);
    session.block().unload_safe.store(1, Ordering::Release);
    session
        .block()
        .state
        .store(STATE_STOPPED, Ordering::Release);
    control::emit("Windows x64 hooks restored");
    0
}

/// Entry point called on a controller-created remote thread after LoadLibraryW.
#[unsafe(no_mangle)]
pub extern "system" fn bhopfix_start(_parameter: *mut c_void) -> u32 {
    run()
}
