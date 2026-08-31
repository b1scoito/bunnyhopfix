//! viewpunch remover (rtldg's F7 feature).

use std::ffi::c_void;

use bhopfix_core::elf;

// C_BasePlayer's view code ADDs m_vecPunchAngle onto the rendered eye
// angles with three `addss <punch+0/4/8>(reg),%xmm0` in a row (pitch, yaw,
// roll). NOPing those adds removes the visual kick regardless of the punch
// value — which matters because m_vecPunchAngle is a PREDICTED field the
// client restores and re-decays every frame, so zeroing the field can't win
// the race, but never applying it does.
//
// The 2026-08-24 update moved all nine sites (~+0x1e80) while keeping the
// field offset, so we no longer hard-code addresses: we decode the real
// `addss disp32(reg),%xmm0` instructions out of .text and keep the ones
// forming a (D, D+4, D+8) triple within a tight span. That shape is what
// identifies a Vector add, and the punch field is the D shared by the most
// triples — which cleanly separates it from the unrelated single adds at
// other offsets (0x12bc, 0x1328, 0x1338, ...) in the same binary.

/// Plausible range for m_vecPunchAngle's offset inside C_BasePlayer.
const DISP_MIN: u32 = 0x1000;
const DISP_MAX: u32 = 0x1400;
/// A pitch/yaw/roll triple is emitted within a few dozen bytes.
const TRIPLE_SPAN: usize = 0x100;

/// A decoded `addss disp32(base),%xmm0`.
struct Site {
    va: usize,
    disp: u32,
    len: usize,
}

/// Decode every `addss disp32(base),%xmm0` in client.so's .text whose
/// displacement could be a C_BasePlayer field.
fn find_addss(client: &elf::Module) -> Vec<Site> {
    let mut out: Vec<Site> = Vec::new();
    client.scan(elf::Access::Code, 15, |seg_va, buf| {
        let mut i = 0usize;
        while i + 12 <= buf.len() {
            // F3 [REX] 0F 58 modrm [sib] disp32, with reg field == xmm0
            if buf[i] != 0xf3 {
                i += 1;
                continue;
            }
            let mut p = i + 1;
            if buf[p] & 0xf0 == 0x40 {
                if buf[p] & 0x04 != 0 {
                    i += 1; // REX.R set -> destination is not xmm0
                    continue;
                }
                p += 1;
            }
            if buf[p] != 0x0f || buf[p + 1] != 0x58 {
                i += 1;
                continue;
            }
            let modrm = buf[p + 2];
            if modrm >> 6 != 0b10 || (modrm >> 3) & 7 != 0 {
                i += 1; // need mod=disp32 and reg=xmm0
                continue;
            }
            let mut d = p + 3;
            if modrm & 7 == 4 {
                d += 1; // SIB byte
            }
            let disp = u32::from_le_bytes([buf[d], buf[d + 1], buf[d + 2], buf[d + 3]]);
            if (DISP_MIN..DISP_MAX).contains(&disp) {
                out.push(Site {
                    va: seg_va as usize + i,
                    disp,
                    len: d + 4 - i,
                });
            }
            i += 1;
        }
    });
    // chunks overlap, so the same site can be decoded twice
    out.sort_unstable_by_key(|s| s.va);
    out.dedup_by_key(|s| s.va);
    out
}

/// Indices of the sites that form (D, D+4, D+8) triples, for the D used by
/// the most triples.
fn punch_sites(sites: &[Site]) -> (u32, Vec<usize>) {
    let mut triples: Vec<(u32, [usize; 3])> = Vec::new();
    for i in 0..sites.len().saturating_sub(2) {
        let (a, b, c) = (&sites[i], &sites[i + 1], &sites[i + 2]);
        if b.disp == a.disp + 4 && c.disp == a.disp + 8 && c.va - a.va < TRIPLE_SPAN {
            triples.push((a.disp, [i, i + 1, i + 2]));
        }
    }
    let Some(&(best, _)) = triples
        .iter()
        .max_by_key(|(d, _)| (triples.iter().filter(|(o, _)| o == d).count(), -(*d as i64)))
    else {
        return (0, Vec::new());
    };
    // overlapping triples would list a site twice
    let mut idx: Vec<usize> = triples
        .iter()
        .filter(|(d, _)| *d == best)
        .flat_map(|(_, t)| t.iter().copied())
        .collect();
    idx.sort_unstable();
    idx.dedup();
    (best, idx)
}

pub(crate) fn install(client: &elf::Module, client_base: usize) {
    let sites = find_addss(client);
    let (disp, chosen) = punch_sites(&sites);
    if chosen.is_empty() {
        log!(
            "viewpunch: no punch-angle add triples found in client.so \
             (game updated?); NOT patching"
        );
        return;
    }
    // Everything above came from the file; confirm the loaded code really
    // matches before writing to it (another patcher may have been here).
    for &i in &chosen {
        let s = &sites[i];
        let addr = client_base + s.va;
        let cur = unsafe { std::slice::from_raw_parts(addr as *const u8, s.len) };
        if client.read_va(s.va, s.len).as_deref() != Some(cur) {
            log!("viewpunch: code at 0x{addr:x} differs from client.so; NOT patching");
            return;
        }
    }
    // All sites confirmed: NOP each addss (xmm0 keeps the base eye-angle,
    // the following store writes it back unchanged — punch never applied).
    let mut done = 0usize;
    for &i in &chosen {
        let s = &sites[i];
        let addr = client_base + s.va;
        let page = addr & !0xfff;
        let page_len = ((addr + s.len + 0xfff) & !0xfff) - page;
        unsafe {
            if libc::mprotect(
                page as *mut c_void,
                page_len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            ) != 0
            {
                continue;
            }
            std::ptr::write_bytes(addr as *mut u8, 0x90, s.len);
            libc::mprotect(
                page as *mut c_void,
                page_len,
                libc::PROT_READ | libc::PROT_EXEC,
            );
        }
        done += 1;
    }
    log!(
        "viewpunch remover armed: NOP'd {done}/{} punch adds \
         (m_vecPunchAngle @ +0x{disp:x}, {} view paths)",
        chosen.len(),
        chosen.len() / 3
    );
}

#[cfg(test)]
mod tests {
    use super::{find_addss, punch_sites};

    #[test]
    fn finds_punch_angle_triples() {
        let Some(m) = crate::testutil::client() else {
            return;
        };
        let sites = find_addss(&m);
        let (disp, chosen) = punch_sites(&sites);
        // pitch/yaw/roll per view path, so always a whole number of triples
        assert!(!chosen.is_empty(), "no punch-angle add triples found");
        assert_eq!(chosen.len() % 3, 0, "partial triple: {chosen:?}");
        // every chosen site adds one of the three Vector components
        for &i in &chosen {
            let d = sites[i].disp;
            assert!(
                d == disp || d == disp + 4 || d == disp + 8,
                "site 0x{:x} disp 0x{d:x} is not part of the vector at 0x{disp:x}",
                sites[i].va
            );
        }
    }
}
