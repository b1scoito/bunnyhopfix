//! Loaded-module access paired with the on-disk PE resolver.

use std::path::PathBuf;

use bhopfix_core::pe::{Access, Module as PeModule};
use bhopfix_core::sig::Pattern;

use super::api;

pub(crate) struct LiveModule {
    pub(crate) base: usize,
    pub(crate) path: PathBuf,
    pub(crate) pe: PeModule,
}

impl LiveModule {
    pub(crate) fn open(name: &str) -> Option<Self> {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle = unsafe { api::GetModuleHandleW(wide.as_ptr()) };
        if handle.is_null() {
            return None;
        }
        let mut path = vec![0u16; 32_768];
        let len = unsafe {
            api::GetModuleFileNameW(handle, path.as_mut_ptr(), path.len().try_into().ok()?)
        } as usize;
        if len == 0 || len >= path.len() {
            return None;
        }
        path.truncate(len);
        let path = PathBuf::from(String::from_utf16(&path).ok()?);
        let pe = PeModule::open(&path)?;
        Some(Self {
            base: handle as usize,
            path,
            pe,
        })
    }

    pub(crate) fn address(&self, rva: usize) -> Option<usize> {
        (rva < self.pe.image_size()).then(|| self.base + rva)
    }

    pub(crate) fn contains(&self, address: usize) -> bool {
        address >= self.base && address < self.base.saturating_add(self.pe.image_size())
    }

    pub(crate) fn contains_exec(&self, address: usize) -> bool {
        address
            .checked_sub(self.base)
            .is_some_and(|rva| self.pe.is_exec(rva))
    }

    pub(crate) fn live_bytes(&self, rva: usize, len: usize) -> Option<&[u8]> {
        let address = self.address(rva)?;
        rva.checked_add(len)
            .filter(|&end| end <= self.pe.image_size())?;
        Some(unsafe { std::slice::from_raw_parts(address as *const u8, len) })
    }

    pub(crate) fn find_unique(&self, specs: &[&str], access: Access) -> Option<(usize, Vec<u8>)> {
        let patterns: Vec<Pattern> = specs
            .iter()
            .map(|spec| Pattern::parse(spec))
            .collect::<Option<_>>()?;
        let overlap = patterns.iter().map(Pattern::len).max()?.saturating_sub(1);
        let mut found: Option<(usize, Vec<u8>)> = None;
        let mut ambiguous = false;
        self.pe.scan(access, overlap, |base, bytes| {
            for pattern in &patterns {
                for at in pattern.find_all(bytes) {
                    let rva = base + at;
                    if found.as_ref().is_some_and(|(prior, _)| *prior != rva) {
                        ambiguous = true;
                        return;
                    }
                    found = Some((rva, bytes[at..at + pattern.len()].to_vec()));
                }
            }
        });
        (!ambiguous).then_some(found).flatten()
    }

    pub(crate) fn resolve_virtual(
        &self,
        class: &str,
        specs: &[&str],
        window: usize,
    ) -> Option<(usize, usize)> {
        let patterns: Vec<Pattern> = specs
            .iter()
            .map(|spec| Pattern::parse(spec))
            .collect::<Option<_>>()?;
        let mut found = None;
        for vtable in self.pe.vtables(class) {
            for (index, function) in self.pe.virtuals(vtable.rva, 256) {
                let Some(body) = self.pe.read_rva(function, window) else {
                    continue;
                };
                if !patterns.iter().any(|pattern| pattern.find(body) == Some(0)) {
                    continue;
                }
                let candidate = (vtable.rva + index * 8, function);
                if found.is_some_and(|prior| prior != candidate) {
                    return None;
                }
                found = Some(candidate);
            }
        }
        found
    }
}
