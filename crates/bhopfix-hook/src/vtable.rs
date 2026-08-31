//! Pointer-slot hooking, and the specifications of what we hook.
//!
//! Two halves that only make sense together: the *resolvers*, which say where
//! a target is on the build that is actually installed, and [`vtable_hook`] /
//! [`got_hook`], which rewrite a slot only after re-checking what it holds.

use std::ffi::c_void;

use bhopfix_core::elf;
use bhopfix_core::sig::Pattern;

use crate::proc::{Mapping, self_maps};

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
// So: classes come from the RTTI Valve ships in these binaries (see
// `bhopfix_core::elf`), and each method is identified by what its code *does*
// (see `bhopfix_core::sig`). We walk the class's vtable, match the body, and
// require the match to be unique — if two slots match we are guessing, so we
// refuse.
// ---------------------------------------------------------------------------

/// Classes whose vtable can carry CreateMove. CS:S's input singleton is a
/// `CCSInput`, which inherits `CInput`'s CreateMove without overriding it, so
/// the *derived* vtable is the one the engine dispatches through — hooking
/// only `CInput` would intercept nothing. We hook every vtable that holds the
/// same implementation; the dormant one costs nothing.
pub(crate) const INPUT_CLASSES: &[&str] = &["6CInput", "8CCSInput"];
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
pub(crate) const LAUNCHER_MGR_CLASS: &str = "7CSDLMgr";
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
pub(crate) const VTABLE_MAX: usize = 256;

// ---------------------------------------------------------------------------
// resolvers
// ---------------------------------------------------------------------------

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
    let pats: Vec<Pattern> = specs.iter().filter_map(|s| Pattern::parse(s)).collect();
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
pub(crate) fn resolve_getrawaccum(m: &elf::Module) -> Option<(usize, usize)> {
    let pat = Pattern::parse(GETRAWACCUM_BODY)?;
    // matched at offset 0: it is a leaf function, and a window would bleed
    // into whatever the linker placed next
    let (slot, fn_va, body) =
        resolve_virtual(m, LAUNCHER_MGR_CLASS, &[GETRAWACCUM_BODY], pat.len())?;
    pat.matches_at(&body, 0).then_some((slot, fn_va))
}

/// Locate `CreateMove` and every input vtable slot that dispatches to it.
/// Returns (fn vaddr, slot vaddrs).
pub(crate) fn resolve_createmove(m: &elf::Module) -> Option<(usize, Vec<usize>)> {
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

// ---------------------------------------------------------------------------
// slot rewriting
// ---------------------------------------------------------------------------

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
///
/// # Safety
/// `slot` must be a readable, 8-byte-aligned address in this process.
pub(crate) unsafe fn vtable_hook(slot: usize, expect: usize, ours: usize) -> Result<usize, String> {
    let current = unsafe { std::ptr::read(slot as *const usize) };
    if current != expect {
        return Err(format!(
            "holds 0x{current:x}, expected 0x{expect:x} (game updated?)"
        ));
    }
    unsafe { write_ptr(slot, ours) }
}

/// Point a GOT slot at `ours`. The slot is named by the relocation that
/// created it, so there is nothing to compare against — but a live slot always
/// holds a code pointer (the stale constant used to give us the literal 0x8),
/// so require that much before writing.
///
/// # Safety
/// `slot` must be a readable, 8-byte-aligned address in this process.
pub(crate) unsafe fn got_hook(slot: usize, ours: usize, maps: &[Mapping]) -> Result<usize, String> {
    let current = unsafe { std::ptr::read(slot as *const usize) };
    if !maps
        .iter()
        .any(|m| m.perms.contains('x') && current >= m.start && current < m.end)
    {
        return Err(format!("holds 0x{current:x}, which is not code"));
    }
    unsafe { write_ptr(slot, ours) }
}

/// Write a pointer into a slot that may be RELRO'd, then confirm it stuck.
///
/// The page's original protection is restored exactly: forcing a .got.plt page
/// to read-only would make the next lazy symbol resolution on that page fault.
///
/// # Safety
/// `slot` must be a readable, 8-byte-aligned address in this process.
unsafe fn write_ptr(slot: usize, ours: usize) -> Result<usize, String> {
    let page = slot & !0xfff;
    let previous = unsafe { std::ptr::read(slot as *const usize) };
    let was_writable = self_maps()
        .iter()
        .any(|m| slot >= m.start && slot < m.end && m.perms.contains('w'));
    if unsafe {
        libc::mprotect(
            page as *mut c_void,
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    } != 0
    {
        return Err(format!("mprotect of 0x{page:x} failed"));
    }
    unsafe { std::ptr::write(slot as *mut usize, ours) };
    let restore = if was_writable {
        libc::PROT_READ | libc::PROT_WRITE
    } else {
        libc::PROT_READ
    };
    unsafe { libc::mprotect(page as *mut c_void, 4096, restore) };
    if unsafe { std::ptr::read(slot as *const usize) } != ours {
        return Err(format!("write to 0x{slot:x} did not stick"));
    }
    Ok(previous)
}

#[cfg(test)]
mod tests {
    use super::{INPUT_CLASSES, resolve_createmove, resolve_getrawaccum};

    #[test]
    fn createmove_resolves_on_every_input_vtable() {
        let Some(m) = crate::testutil::client() else {
            return;
        };
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
        let Some(m) = crate::testutil::launcher() else {
            return;
        };
        let (slot, fn_va) = resolve_getrawaccum(&m).expect("GetRawMouseAccumulators");
        assert_eq!(m.u64_va(slot), Some(fn_va));
        assert!(m.is_exec(fn_va), "accumulator fn 0x{fn_va:x} is not code");
    }
}
