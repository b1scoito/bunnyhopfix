//! Shared foundation for the two halves of bunnyhopfix: the patcher binary
//! (`bunnyhopfix`) and the injected hook library (`libbhopfix.so`).
//!
//! Everything here answers the same question — *where is this thing in the
//! game right now?* — without ever naming an address:
//!
//! * [`sig`] finds code by what its instructions look like,
//! * [`elf`] finds classes and virtuals in Linux modules,
//! * [`pe`] finds exports and MSVC RTTI in Windows modules,
//! * [`pakfix`] repairs map pakfiles on disk rather than in memory.
//!
//! Nothing in this crate writes to another process. It reads, decodes and
//! locates; the callers decide what to do with the answer.

pub mod sig;

#[cfg(windows)]
pub mod control;
#[cfg(unix)]
pub mod elf;
pub mod pakfix;
pub mod pe;
