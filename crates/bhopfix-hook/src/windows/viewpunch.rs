//! Reversible Windows x64 viewpunch removal.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};

use bhopfix_core::pe::Access;

use super::control;
use super::hook::Patch;
use super::module::LiveModule;

const DISP_MIN: u32 = 0x500;
const DISP_MAX: u32 = 0x1000;
const TRIPLE_SPAN: usize = 0x100;
static DIRTY: AtomicBool = AtomicBool::new(false);

#[derive(Clone)]
struct Site {
    rva: usize,
    displacement: u32,
    bytes: Vec<u8>,
}

fn find_addss(client: &LiveModule) -> Vec<Site> {
    let mut sites = Vec::new();
    client.pe.scan(Access::Code, 15, |section_rva, bytes| {
        let mut offset = 0usize;
        while offset + 12 <= bytes.len() {
            if bytes[offset] != 0xf3 {
                offset += 1;
                continue;
            }
            let mut opcode = offset + 1;
            if bytes[opcode] & 0xf0 == 0x40 {
                if bytes[opcode] & 0x04 != 0 {
                    offset += 1;
                    continue;
                }
                opcode += 1;
            }
            if bytes[opcode] != 0x0f || bytes[opcode + 1] != 0x58 {
                offset += 1;
                continue;
            }
            let modrm = bytes[opcode + 2];
            if modrm >> 6 != 0b10 || (modrm >> 3) & 7 != 0 {
                offset += 1;
                continue;
            }
            let displacement_at = opcode + 3 + usize::from(modrm & 7 == 4);
            let Some(displacement_bytes) = bytes
                .get(displacement_at..displacement_at + 4)
                .and_then(|bytes| bytes.try_into().ok())
            else {
                offset += 1;
                continue;
            };
            let displacement = u32::from_le_bytes(displacement_bytes);
            if (DISP_MIN..DISP_MAX).contains(&displacement) {
                let length = displacement_at + 4 - offset;
                sites.push(Site {
                    rva: section_rva + offset,
                    displacement,
                    bytes: bytes[offset..offset + length].to_vec(),
                });
            }
            offset += 1;
        }
    });
    sites.sort_unstable_by_key(|site| site.rva);
    sites.dedup_by_key(|site| site.rva);
    sites
}

fn select_punch_sites(sites: &[Site]) -> Result<(u32, Vec<usize>), String> {
    let mut triples: BTreeMap<u32, Vec<[usize; 3]>> = BTreeMap::new();
    for index in 0..sites.len().saturating_sub(2) {
        let [a, b, c] = [&sites[index], &sites[index + 1], &sites[index + 2]];
        if b.displacement == a.displacement + 4
            && c.displacement == a.displacement + 8
            && c.rva - a.rva < TRIPLE_SPAN
        {
            triples
                .entry(a.displacement)
                .or_default()
                .push([index, index + 1, index + 2]);
        }
    }
    let Some(best_count) = triples.values().map(Vec::len).max() else {
        return Err("no pitch/yaw/roll addss triple found".into());
    };
    let mut best = triples
        .iter()
        .filter(|(_, matches)| matches.len() == best_count);
    let Some((&displacement, matches)) = best.next() else {
        return Err("no viewpunch candidate found".into());
    };
    if best.next().is_some() {
        return Err("multiple equally likely viewpunch fields found".into());
    }
    let mut selected: Vec<usize> = matches.iter().flatten().copied().collect();
    selected.sort_unstable();
    selected.dedup();
    if selected.len() != matches.len() * 3 {
        return Err("overlapping viewpunch triples are ambiguous".into());
    }
    Ok((displacement, selected))
}

pub(crate) struct Hooks {
    patches: Vec<Patch>,
    enabled: bool,
}

impl Hooks {
    pub(crate) fn install(client: &LiveModule, enabled: bool) -> Result<Self, String> {
        let sites = find_addss(client);
        let (displacement, selected) = select_punch_sites(&sites)?;
        let mut patches = Vec::with_capacity(selected.len());
        for index in selected {
            let site = &sites[index];
            let address = client
                .address(site.rva)
                .ok_or_else(|| "viewpunch site RVA is outside client.dll".to_string())?;
            let live = client
                .live_bytes(site.rva, site.bytes.len())
                .ok_or_else(|| "viewpunch live bytes are unavailable".to_string())?;
            if live != site.bytes {
                return Err(format!(
                    "viewpunch bytes at 0x{address:x} differ from client.dll"
                ));
            }
            patches.push(Patch::prepare(
                address,
                &site.bytes,
                vec![0x90; site.bytes.len()],
            )?);
        }
        let mut hooks = Self {
            patches,
            enabled: false,
        };
        if enabled {
            hooks.set_enabled(true)?;
        }
        control::emit(&format!(
            "viewpunch: resolved {} adds at m_vecPunchAngle +0x{displacement:x} ({})",
            hooks.patches.len(),
            if enabled { "removed" } else { "preserved" }
        ));
        Ok(hooks)
    }

    pub(crate) fn toggle(&mut self) -> Result<bool, String> {
        let enabled = !self.enabled;
        self.set_enabled(enabled)?;
        control::emit(if enabled {
            "viewpunch remover enabled"
        } else {
            "viewpunch restored"
        });
        Ok(enabled)
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        self.set_enabled(false)
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        if self.enabled == enabled {
            return Ok(());
        }
        if enabled {
            DIRTY.store(true, Ordering::Release);
            if let Err(error) = apply_all(&mut self.patches) {
                return match restore_all(&mut self.patches) {
                    Ok(()) => {
                        DIRTY.store(false, Ordering::Release);
                        Err(error)
                    }
                    Err(rollback) => Err(format!("{error}; viewpunch rollback failed: {rollback}")),
                };
            }
        } else if let Err(error) = restore_all(&mut self.patches) {
            return match apply_all(&mut self.patches) {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!(
                    "{error}; restoring the prior patch state failed: {rollback}"
                )),
            };
        } else {
            DIRTY.store(false, Ordering::Release);
        }
        self.enabled = enabled;
        Ok(())
    }
}

fn apply_all(patches: &mut [Patch]) -> Result<(), String> {
    for patch in patches {
        patch.apply()?;
    }
    Ok(())
}

fn restore_all(patches: &mut [Patch]) -> Result<(), String> {
    let mut errors = Vec::new();
    for patch in patches.iter_mut().rev() {
        if let Err(error) = patch.restore() {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

pub(crate) fn is_quiescent() -> bool {
    !DIRTY.load(Ordering::Acquire)
}
