//! bunnyhop-ape — Autobhop Prediction Enabler for Counter-Strike: Source.
//!
//! Port of the idea from alkatrazbhop/BunnyhopAPE and rtldg/RawInput2BunnyhopAPE
//! to Rust, for Linux and Windows.
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
//! Every address involved is found by byte pattern at runtime (see `sig`);
//! nothing is hard-coded to a game build. The game must run with `-insecure`,
//! because this writes into game memory.
//!
//! Platform split:
//!   * Linux — full implementation: prediction patcher plus `librawinput2.so`
//!     (LD_PRELOAD) for momentum-mod style `m_rawinput 2`, viewpunch removal,
//!     fastdl map hijack and engine console glue.
//!   * Windows — barebones: the prediction patcher only.

mod sig;

#[cfg(unix)]
mod linux;
#[cfg(unix)]
mod pakfix;

#[cfg(windows)]
mod win;

#[cfg(unix)]
fn main() {
    linux::main();
}

#[cfg(windows)]
fn main() {
    win::main();
}
