//! Process-wide structured logging for the controller.

use std::io::IsTerminal as _;

#[cfg(windows)]
use tracing::Level;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

const LOG_ENV: &str = "BHOPFIX_LOG";

/// Install the controller's sole global tracing subscriber.
pub(crate) fn init() {
    let default_level = if std::env::var_os("BHOPFIX_DEBUG").is_some() {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };
    let filter = EnvFilter::builder()
        // This is a level/target filter, not a pattern-matching interface. Avoid
        // compiling user-provided field values as regular expressions.
        .with_regex(false)
        .with_env_var(LOG_ENV)
        .with_default_directive(default_level.into())
        .from_env_lossy();
    let ansi = std::io::stderr().is_terminal();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(ansi)
        .with_target(true)
        .compact()
        .init();
}

/// Whether the controller should request debug telemetry from the injected DLL.
#[cfg(windows)]
pub(crate) fn hook_debug_enabled() -> bool {
    std::env::var_os("BHOPFIX_DEBUG").is_some()
        || tracing::enabled!(target: "bhopfix_hook", Level::DEBUG)
}
