//! Shared foundation for the two halves of bunnyhopfix: the patcher binary
//! (`bunnyhopfix`) and the injected hook library (`libbhopfix.so`).
//!
//! Everything here answers the same question — *where is this thing in the
//! game right now?* — without ever naming an address:
//!
//! * [`sig`] finds code by what its instructions look like,
//! * [`elf`] finds classes and their virtuals through the RTTI and relocations
//!   Valve ships in the Linux binaries,
//! * [`pakfix`] is the odd one out: it repairs map pakfiles on disk rather
//!   than in memory, and both halves need it because a map can arrive before
//!   the game starts or while it is running.
//!
//! Nothing in this crate writes to another process. It reads, decodes and
//! locates; the callers decide what to do with the answer.

pub mod sig;

#[cfg(unix)]
pub mod elf;
#[cfg(unix)]
pub mod pakfix;
