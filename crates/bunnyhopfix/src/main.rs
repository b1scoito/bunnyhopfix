//! bunnyhopfix — CS:S bhop delay (jump prediction) fixer.
//!
//! Rust rewrite of b1scoito/bunnyhopfix, with the Linux support and the code
//! organization its TODO asked for. The idea itself comes from
//! alkatrazbhop/BunnyhopAPE and the rtldg/RawInput2BunnyhopAPE fork.
//!
//! What it patches: `CGameMovement::CheckJumpButton` /
//! `CCSGameMovement::CheckJumpButton` contain
//!
//! ```cpp
//! if (mv->m_nOldButtons & IN_JUMP)
//!     return false;
//! ```
//!
//! On autobhop servers the server holds `IN_JUMP` for you, so the client's own
//! prediction of `CheckJumpButton` bails out every tick and you only *see* the
//! jump when the server snapshot arrives (feels laggy on high ping). Rewriting
//! the conditional jump after that check makes the client predict the jump
//! immediately. It does NOT let you cheat scroll times — the server still
//! decides what actually happens.
//!
//! Every address involved is found by byte pattern at runtime (see
//! [`bhopfix_core::sig`]); nothing is hard-coded to a game build. The game must
//! run with `-insecure`, because this writes into game memory.
//!
//! Platform split:
//!   * Linux x86-64 — launcher, prediction patcher, and an LD_PRELOAD hook
//!     library for rawinput2, viewpunch removal, fastdl, SourceJump, and engine
//!     integration.
//!   * Windows x86-64 — native attach-time prediction patcher plus an injected
//!     DLL implementing the same common feature set and the Windows fullscreen
//!     preservation toggle.

#[cfg(unix)]
mod linux;
mod logging;

#[cfg(windows)]
mod windows;

#[cfg(unix)]
fn main() {
    logging::init();
    linux::main();
}

#[cfg(windows)]
fn main() {
    logging::init();
    windows::main();
}
