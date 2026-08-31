//! Minimal ELF64 reader used to locate code, vtables and GOT slots inside a
//! loaded game module *by name* instead of by hard-coded link-time address.
//!
//! Why this exists: every hard-coded vaddr in this tool broke on the
//! 2026-08-24 CS:S update. Code moved ~0x1e80, client vtables ~0xa90, and
//! launcher.so's data segment gained a whole page (+0x1000). A stale *code*
//! address merely fails a byte check, but a stale *vtable slot* address still
//! points at a perfectly valid pointer — just one belonging to a different
//! class — so installing a hook there silently corrupts an unrelated virtual
//! and crashes the game (that update turned our CreateMove hooks into a
//! `vgui::Panel` virtual and a `CCSGameMovement` virtual, and our raw-mouse
//! hook into `ConCommand`'s destructor slot).
//!
//! So: nothing is addressed absolutely any more. Classes are found through the
//! Itanium C++ ABI RTTI that Valve ships in these binaries (typeinfo name
//! string -> typeinfo object -> vtable), imported functions through their
//! relocation + symbol name, and raw code through instruction signatures.
//! Callers still validate whatever they resolved before writing to it.
//!
//! Reads come from the module *file* (via pread, so nothing can fault) and
//! yield link-time vaddrs; add the module's load base for runtime addresses.
//! Relocated pointer slots (vtables, typeinfo) are readable straight from the
//! file because the linker also writes each R_X86_64_RELATIVE target into the
//! section contents, not just into the relocation's addend.

use std::fs::File;
use std::os::unix::fs::FileExt;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;

const DT_PLTRELSZ: i64 = 2;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_SYMENT: i64 = 11;
const DT_JMPREL: i64 = 23;

const R_X86_64_GLOB_DAT: u32 = 6;
const R_X86_64_JUMP_SLOT: u32 = 7;
const R_X86_64_RELATIVE: u32 = 8;

const RELA_ENT: usize = 24;
const CHUNK: usize = 1 << 20;

/// Which segments a scan should look at.
#[derive(Copy, Clone, PartialEq)]
pub enum Access {
    /// read-only, non-executable: .rodata & friends (RTTI name strings)
    Rodata,
    /// executable: .text (instruction signatures)
    Code,
}

impl Access {
    fn matches(self, flags: u32) -> bool {
        let (x, w) = (flags & PF_X != 0, flags & PF_W != 0);
        match self {
            Access::Rodata => !x && !w,
            Access::Code => x,
        }
    }
}

struct Seg {
    off: u64,
    va: u64,
    fsz: u64,
    msz: u64,
    flags: u32,
}

/// A game module (`client.so`, `engine.so`, `launcher.so`) read from disk.
///
/// Everything is resolved against the *file*, then rebased onto the module's
/// load address by the caller. That is deliberate: the file is the ground
/// truth a hook validates the live process against before writing to it.
pub struct Module {
    f: File,
    segs: Vec<Seg>,
    /// (vaddr, size) of every RELA table: DT_RELA and DT_JMPREL.
    rela: Vec<(u64, u64)>,
    symtab: u64,
    strtab: u64,
    syment: u64,
}

impl Module {
    /// Parse an ELF64 shared object: its segments, RELA tables and symbol
    /// table. Returns None for anything that is not a 64-bit ELF.
    pub fn open(path: &str) -> Option<Module> {
        let f = File::open(path).ok()?;
        let mut hdr = [0u8; 64];
        f.read_exact_at(&mut hdr, 0).ok()?;
        if &hdr[..4] != b"\x7fELF" || hdr[4] != 2 {
            return None;
        }
        let phoff = u64::from_le_bytes(hdr[32..40].try_into().ok()?);
        let phentsize = u16::from_le_bytes(hdr[54..56].try_into().ok()?) as u64;
        let phnum = u16::from_le_bytes(hdr[56..58].try_into().ok()?) as u64;
        if phentsize < 56 {
            return None;
        }

        let mut m = Module {
            f,
            segs: Vec::new(),
            rela: Vec::new(),
            symtab: 0,
            strtab: 0,
            syment: 24,
        };
        let mut dynamic = None;
        for i in 0..phnum {
            let ph = m.read_off(phoff + i * phentsize, 56)?;
            let ty = u32::from_le_bytes(ph[0..4].try_into().ok()?);
            let flags = u32::from_le_bytes(ph[4..8].try_into().ok()?);
            let off = u64::from_le_bytes(ph[8..16].try_into().ok()?);
            let va = u64::from_le_bytes(ph[16..24].try_into().ok()?);
            let fsz = u64::from_le_bytes(ph[32..40].try_into().ok()?);
            let msz = u64::from_le_bytes(ph[40..48].try_into().ok()?);
            match ty {
                PT_LOAD => m.segs.push(Seg {
                    off,
                    va,
                    fsz,
                    msz,
                    flags,
                }),
                PT_DYNAMIC => dynamic = Some((off, fsz)),
                _ => {}
            }
        }
        if m.segs.is_empty() {
            return None;
        }

        // DT_* we need: the two relocation tables plus the dynamic symbol table.
        let (doff, dsz) = dynamic?;
        let dyn_buf = m.read_off(doff, dsz as usize)?;
        let (mut rela, mut relasz) = (0u64, 0u64);
        let (mut jmprel, mut pltrelsz) = (0u64, 0u64);
        for e in dyn_buf.chunks_exact(16) {
            let tag = i64::from_le_bytes(e[0..8].try_into().ok()?);
            let val = u64::from_le_bytes(e[8..16].try_into().ok()?);
            match tag {
                0 => break,
                DT_RELA => rela = val,
                DT_RELASZ => relasz = val,
                DT_JMPREL => jmprel = val,
                DT_PLTRELSZ => pltrelsz = val,
                DT_SYMTAB => m.symtab = val,
                DT_STRTAB => m.strtab = val,
                DT_SYMENT => m.syment = val,
                _ => {}
            }
        }
        if rela != 0 && relasz != 0 {
            m.rela.push((rela, relasz));
        }
        if jmprel != 0 && pltrelsz != 0 {
            m.rela.push((jmprel, pltrelsz));
        }
        Some(m)
    }

    // --- raw reads -------------------------------------------------------

    fn read_off(&self, off: u64, len: usize) -> Option<Vec<u8>> {
        let mut b = vec![0u8; len];
        self.f.read_exact_at(&mut b, off).ok()?;
        Some(b)
    }

    fn v2o(&self, va: u64) -> Option<u64> {
        self.segs
            .iter()
            .find(|s| va >= s.va && va < s.va + s.fsz)
            .map(|s| s.off + (va - s.va))
    }

    /// Read `len` bytes at a link-time vaddr, or None if it is not backed by
    /// file contents (past end-of-file in .bss, or outside every segment).
    pub fn read_va(&self, va: usize, len: usize) -> Option<Vec<u8>> {
        self.read_off(self.v2o(va as u64)?, len)
    }

    /// Read a little-endian pointer-sized word at a link-time vaddr.
    pub fn u64_va(&self, va: usize) -> Option<usize> {
        let b = self.read_va(va, 8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?) as usize)
    }

    fn i64_va(&self, va: usize) -> Option<i64> {
        let b = self.read_va(va, 8)?;
        Some(i64::from_le_bytes(b.try_into().ok()?))
    }

    /// Vaddr span of the module's writable segments, *including* the part of
    /// .bss past end-of-file. The loader maps that tail anonymously, so it
    /// carries no module name in /proc/self/maps and a path-filtered scan
    /// misses it — which is where globals like the download manager live.
    pub fn writable_span(&self) -> Option<(usize, usize)> {
        let w = || self.segs.iter().filter(|s| s.flags & PF_W != 0);
        Some((
            w().map(|s| s.va).min()? as usize,
            w().map(|s| s.va + s.msz).max()? as usize,
        ))
    }

    /// True if this link-time vaddr lands in an executable segment. Used to
    /// reject a resolved "function" that is really data.
    pub fn is_exec(&self, va: usize) -> bool {
        let va = va as u64;
        self.segs
            .iter()
            .any(|s| s.flags & PF_X != 0 && va >= s.va && va < s.va + s.msz)
    }

    // --- scanning --------------------------------------------------------

    /// Walk the requested segments in overlapping chunks.
    pub fn scan(&self, want: Access, overlap: usize, mut f: impl FnMut(u64, &[u8])) {
        for s in self.segs.iter().filter(|s| want.matches(s.flags)) {
            let mut pos = 0u64;
            while pos < s.fsz {
                let len = ((s.fsz - pos) as usize).min(CHUNK + overlap);
                let Some(buf) = self.read_off(s.off + pos, len) else {
                    break;
                };
                f(s.va + pos, &buf);
                if len <= overlap {
                    break;
                }
                pos += (len - overlap) as u64;
            }
        }
    }

    /// Every vaddr in `want` segments where `needle` occurs.
    fn find_all(&self, needle: &[u8], want: Access) -> Vec<usize> {
        let mut out = Vec::new();
        if needle.is_empty() {
            return out;
        }
        self.scan(want, needle.len() - 1, |va, buf| {
            let mut i = 0usize;
            while i + needle.len() <= buf.len() {
                match buf[i..].iter().position(|&b| b == needle[0]) {
                    Some(p) => {
                        let s = i + p;
                        if s + needle.len() > buf.len() {
                            break;
                        }
                        if &buf[s..s + needle.len()] == needle {
                            out.push(va as usize + s);
                        }
                        i = s + 1;
                    }
                    None => break,
                }
            }
        });
        out.sort_unstable();
        out.dedup();
        out
    }

    /// One streaming pass over the relocation tables: every R_X86_64_RELATIVE
    /// slot whose target is one of `targets`. I.e. "who points at these?".
    fn relative_to(&self, targets: &[usize]) -> Vec<usize> {
        let mut out = Vec::new();
        if targets.is_empty() {
            return out;
        }
        for &(va, size) in &self.rela {
            let Some(base_off) = self.v2o(va) else {
                continue;
            };
            let mut done = 0u64;
            while done < size {
                let want = ((size - done) as usize).min(CHUNK / RELA_ENT * RELA_ENT);
                let Some(buf) = self.read_off(base_off + done, want) else {
                    break;
                };
                for e in buf.chunks_exact(RELA_ENT) {
                    let info = u64::from_le_bytes(e[8..16].try_into().unwrap());
                    if (info & 0xffff_ffff) as u32 != R_X86_64_RELATIVE {
                        continue;
                    }
                    let addend = i64::from_le_bytes(e[16..24].try_into().unwrap()) as usize;
                    if targets.contains(&addend) {
                        out.push(u64::from_le_bytes(e[0..8].try_into().unwrap()) as usize);
                    }
                }
                done += want as u64;
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    // --- named lookups ---------------------------------------------------

    fn symname(&self, idx: u32) -> Option<String> {
        if self.symtab == 0 || self.strtab == 0 {
            return None;
        }
        let sym = self.read_va((self.symtab + idx as u64 * self.syment) as usize, 4)?;
        let st_name = u32::from_le_bytes(sym.try_into().ok()?);
        let at = (self.strtab + st_name as u64) as usize;
        let buf = self.read_va(at, 96)?;
        let end = buf.iter().position(|&b| b == 0)?;
        String::from_utf8(buf[..end].to_vec()).ok()
    }

    /// GOT slot vaddr for an imported symbol (JUMP_SLOT / GLOB_DAT).
    /// This is exact: the slot is named by the relocation, never guessed.
    pub fn jump_slot(&self, sym: &str) -> Option<usize> {
        for &(va, size) in &self.rela {
            let base_off = self.v2o(va)?;
            let buf = self.read_off(base_off, size as usize)?;
            for e in buf.chunks_exact(RELA_ENT) {
                let info = u64::from_le_bytes(e[8..16].try_into().ok()?);
                let ty = (info & 0xffff_ffff) as u32;
                if ty != R_X86_64_JUMP_SLOT && ty != R_X86_64_GLOB_DAT {
                    continue;
                }
                if self.symname((info >> 32) as u32).as_deref() == Some(sym) {
                    return Some(u64::from_le_bytes(e[0..8].try_into().ok()?) as usize);
                }
            }
        }
        None
    }

    /// Vtable sub-tables of a class, found via RTTI. `mangled` is the typeinfo
    /// name (e.g. `6CInput` for `class CInput`).
    ///
    /// Returns `(t, offset_to_top)` where `t` is the vaddr of the vtable's
    /// typeinfo slot — virtual N lives at `t + 8 + 8*N`, matching the pointer
    /// an object's vptr holds (`t + 8`). `offset_to_top` is 0 for the primary
    /// sub-table and negative for the secondary ones of a multiple-inheritance
    /// class.
    pub fn vtables(&self, mangled: &str) -> Vec<(usize, i64)> {
        // The name string is NUL-terminated and preceded by the previous
        // string's NUL, which pins it to a whole entry in .rodata.
        let mut needle = Vec::with_capacity(mangled.len() + 2);
        needle.push(0u8);
        needle.extend_from_slice(mangled.as_bytes());
        needle.push(0u8);
        let names: Vec<usize> = self
            .find_all(&needle, Access::Rodata)
            .into_iter()
            .map(|v| v + 1)
            .collect();

        // A slot holding &name is typeinfo+8. We do NOT check typeinfo+0 (its
        // own vptr) here: that points at libstdc++'s __si_class_type_info
        // vtable, so it is a symbolic relocation whose file content is zero.
        // A stray pointer-to-name would survive this step, and then die on the
        // vtable-shape checks below.
        let tis: Vec<usize> = self
            .relative_to(&names)
            .into_iter()
            .filter_map(|slot| slot.checked_sub(8))
            .collect();

        // A slot holding &typeinfo is a vtable's typeinfo slot -- or a derived
        // class's base-typeinfo field, which these two checks reject: a real
        // vtable has executable code in its first virtual slot and a small
        // non-positive offset-to-top just below it.
        let mut out: Vec<(usize, i64)> = self
            .relative_to(&tis)
            .into_iter()
            .filter_map(|t| {
                if !self.is_exec(self.u64_va(t + 8)?) {
                    return None;
                }
                let otop = self.i64_va(t.checked_sub(8)?)?;
                (otop <= 0 && otop > -0x100_0000).then_some((t, otop))
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// The primary (offset-to-top 0) vtable of a class.
    pub fn vtable(&self, mangled: &str) -> Option<usize> {
        self.vtables(mangled)
            .into_iter()
            .find(|&(_, otop)| otop == 0)
            .map(|(t, _)| t)
    }

    /// Target of virtual `idx` in the vtable whose typeinfo slot is `t`.
    pub fn vfn(&self, t: usize, idx: usize) -> Option<usize> {
        let va = self.u64_va(t + 8 + 8 * idx)?;
        self.is_exec(va).then_some(va)
    }

    /// Vaddr of the slot holding virtual `idx` (what a vtable hook writes to).
    pub fn vslot(t: usize, idx: usize) -> usize {
        t + 8 + 8 * idx
    }

    /// Walk a vtable's virtuals until the entries stop being code.
    pub fn virtuals(&self, t: usize, max: usize) -> Vec<(usize, usize)> {
        let mut out = Vec::new();
        for i in 0..max {
            match self.vfn(t, i) {
                Some(f) => out.push((i, f)),
                None => break,
            }
        }
        out
    }
}
