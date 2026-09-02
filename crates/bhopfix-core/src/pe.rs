//! Minimal PE32+ reader for resolving code, exports and MSVC RTTI by identity.
//!
//! Windows hooks use RVAs derived from the module file, then add the live load
//! address after validating the loaded bytes. This mirrors the Linux ELF
//! resolver: game updates may move code, but no caller writes to an unverified
//! absolute address.

use std::path::Path;

const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
const CHUNK: usize = 1 << 20;

/// Which PE sections a scan should visit.
#[derive(Copy, Clone, Eq, PartialEq)]
pub enum Access {
    /// Executable image sections.
    Code,
    /// Read-only, non-executable image sections.
    Rodata,
    /// Writable image sections.
    Data,
}

impl Access {
    fn matches(self, characteristics: u32) -> bool {
        match self {
            Self::Code => characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
            Self::Rodata => {
                characteristics & IMAGE_SCN_MEM_READ != 0
                    && characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE) == 0
            }
            Self::Data => characteristics & IMAGE_SCN_MEM_WRITE != 0,
        }
    }
}

#[derive(Clone)]
struct Section {
    rva: usize,
    virtual_size: usize,
    raw: usize,
    raw_size: usize,
    characteristics: u32,
}

/// One x64 MSVC vtable found through its Complete Object Locator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Vtable {
    /// RVA of virtual slot zero, which is also the value stored in an object.
    pub rva: usize,
    /// Complete Object Locator offset for this subobject; zero is primary.
    pub object_offset: u32,
}

/// A 64-bit Windows game module read from disk.
pub struct Module {
    data: Vec<u8>,
    image_base: u64,
    image_size: usize,
    sections: Vec<Section>,
    export_rva: usize,
    export_size: usize,
}

impl Module {
    /// Parse an AMD64 PE32+ image.
    pub fn open(path: impl AsRef<Path>) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        if data.get(..2)? != b"MZ" {
            return None;
        }
        let pe = rd_u32(&data, 0x3c)? as usize;
        if data.get(pe..pe + 4)? != b"PE\0\0" {
            return None;
        }
        let coff = pe + 4;
        if rd_u16(&data, coff)? != IMAGE_FILE_MACHINE_AMD64 {
            return None;
        }
        let section_count = rd_u16(&data, coff + 2)? as usize;
        let optional_size = rd_u16(&data, coff + 16)? as usize;
        let optional = coff + 20;
        if rd_u16(&data, optional)? != PE32_PLUS_MAGIC || optional_size < 120 {
            return None;
        }
        let image_base = rd_u64(&data, optional + 24)?;
        let image_size = rd_u32(&data, optional + 56)? as usize;
        let export_rva = rd_u32(&data, optional + 112)? as usize;
        let export_size = rd_u32(&data, optional + 116)? as usize;

        let table = optional.checked_add(optional_size)?;
        let table_len = section_count.checked_mul(40)?;
        data.get(table..table.checked_add(table_len)?)?;
        let mut sections = Vec::with_capacity(section_count);
        for i in 0..section_count {
            let at = table + i * 40;
            let virtual_size = rd_u32(&data, at + 8)? as usize;
            let rva = rd_u32(&data, at + 12)? as usize;
            let raw_size = rd_u32(&data, at + 16)? as usize;
            let raw = rd_u32(&data, at + 20)? as usize;
            let characteristics = rd_u32(&data, at + 36)?;
            if raw_size != 0 {
                data.get(raw..raw.checked_add(raw_size)?)?;
            }
            sections.push(Section {
                rva,
                virtual_size,
                raw,
                raw_size,
                characteristics,
            });
        }
        if sections.is_empty() || image_size == 0 {
            return None;
        }
        Some(Self {
            data,
            image_base,
            image_size,
            sections,
            export_rva,
            export_size,
        })
    }

    /// Preferred image base recorded in the optional header.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    /// Size of the mapped image.
    pub fn image_size(&self) -> usize {
        self.image_size
    }

    fn rva_to_offset(&self, rva: usize) -> Option<usize> {
        // Header RVAs map directly before the first section.
        let first_raw = self
            .sections
            .iter()
            .map(|s| s.raw)
            .filter(|&v| v != 0)
            .min()?;
        if rva < first_raw && rva < self.data.len() {
            return Some(rva);
        }
        self.sections.iter().find_map(|s| {
            let backed = s.raw_size.min(s.virtual_size.max(s.raw_size));
            (rva >= s.rva && rva.checked_sub(s.rva)? < backed).then_some(s.raw + (rva - s.rva))
        })
    }

    /// Read file-backed bytes at an RVA.
    pub fn read_rva(&self, rva: usize, len: usize) -> Option<&[u8]> {
        let off = self.rva_to_offset(rva)?;
        self.data.get(off..off.checked_add(len)?)
    }

    /// Read a little-endian pointer at an RVA.
    pub fn pointer_rva(&self, rva: usize) -> Option<u64> {
        rd_u64(self.read_rva(rva, 8)?, 0)
    }

    /// Convert a preferred virtual address stored in the file into an RVA.
    pub fn va_to_rva(&self, va: u64) -> Option<usize> {
        let rva = va.checked_sub(self.image_base)? as usize;
        (rva < self.image_size).then_some(rva)
    }

    /// True when an RVA belongs to an executable section.
    pub fn is_exec(&self, rva: usize) -> bool {
        self.sections.iter().any(|s| {
            s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                && rva >= s.rva
                && rva < s.rva.saturating_add(s.virtual_size)
        })
    }

    /// Mapped RVA span of writable sections, including zero-filled tails.
    pub fn writable_span(&self) -> Option<(usize, usize)> {
        let writable = || {
            self.sections
                .iter()
                .filter(|s| s.characteristics & IMAGE_SCN_MEM_WRITE != 0)
        };
        Some((
            writable().map(|s| s.rva).min()?,
            writable()
                .map(|s| s.rva.saturating_add(s.virtual_size))
                .max()?,
        ))
    }

    /// Visit requested file-backed sections in overlapping chunks.
    pub fn scan(&self, want: Access, overlap: usize, mut visit: impl FnMut(usize, &[u8])) {
        for section in self
            .sections
            .iter()
            .filter(|s| want.matches(s.characteristics))
        {
            let backed = section
                .raw_size
                .min(section.virtual_size.max(section.raw_size));
            let mut pos = 0usize;
            while pos < backed {
                let len = (backed - pos).min(CHUNK + overlap);
                let Some(buf) = self.data.get(section.raw + pos..section.raw + pos + len) else {
                    break;
                };
                visit(section.rva + pos, buf);
                if len <= overlap {
                    break;
                }
                pos += len - overlap;
            }
        }
    }

    fn find_all(&self, needle: &[u8], want: Access) -> Vec<usize> {
        let mut found = Vec::new();
        if needle.is_empty() {
            return found;
        }
        self.scan(want, needle.len() - 1, |base, buf| {
            found.extend(
                buf.windows(needle.len())
                    .enumerate()
                    .filter_map(|(i, bytes)| (bytes == needle).then_some(base + i)),
            );
        });
        found.sort_unstable();
        found.dedup();
        found
    }

    fn cstr_rva(&self, rva: usize, max: usize) -> Option<&str> {
        let bytes = self.read_rva(rva, max)?;
        let end = bytes.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&bytes[..end]).ok()
    }

    /// RVA of a named PE export.
    pub fn export(&self, wanted: &str) -> Option<usize> {
        if self.export_rva == 0 || self.export_size < 40 {
            return None;
        }
        let dir = self.read_rva(self.export_rva, 40)?;
        let function_count = rd_u32(dir, 20)? as usize;
        let name_count = rd_u32(dir, 24)? as usize;
        let functions = rd_u32(dir, 28)? as usize;
        let names = rd_u32(dir, 32)? as usize;
        let ordinals = rd_u32(dir, 36)? as usize;
        for i in 0..name_count {
            let name_rva = rd_u32(self.read_rva(names + i * 4, 4)?, 0)? as usize;
            if self.cstr_rva(name_rva, 256)? != wanted {
                continue;
            }
            let ordinal = rd_u16(self.read_rva(ordinals + i * 2, 2)?, 0)? as usize;
            if ordinal >= function_count {
                return None;
            }
            let rva = rd_u32(self.read_rva(functions + ordinal * 4, 4)?, 0)? as usize;
            // Forwarded exports point back into the export directory and are
            // strings, not executable entrypoints.
            let forwarded =
                rva >= self.export_rva && rva < self.export_rva.saturating_add(self.export_size);
            return (!forwarded && rva < self.image_size).then_some(rva);
        }
        None
    }

    /// Find every x64 MSVC vtable whose TypeDescriptor has `decorated_name`.
    ///
    /// Names use MSVC RTTI spelling, for example `.?AVCInput@@`. Returned RVAs
    /// point at virtual slot zero, not at the preceding locator pointer.
    pub fn vtables(&self, decorated_name: &str) -> Vec<Vtable> {
        let mut needle = decorated_name.as_bytes().to_vec();
        needle.push(0);
        // MSVC TypeDescriptors carry a relocatable type_info vptr, so the
        // linker commonly places them in writable .data rather than .rdata.
        let mut names = self.find_all(&needle, Access::Rodata);
        names.extend(self.find_all(&needle, Access::Data));
        names.sort_unstable();
        names.dedup();
        let type_descriptors: Vec<usize> = names
            .into_iter()
            .filter_map(|name| name.checked_sub(16))
            .collect();
        if type_descriptors.is_empty() {
            return Vec::new();
        }

        // x64 CompleteObjectLocator stores image-relative references. Validate
        // pSelf as well as the TypeDescriptor RVA to reject coincidental words.
        let mut locators = Vec::new();
        self.scan(Access::Rodata, 23, |base, buf| {
            for i in (0..buf.len().saturating_sub(23)).step_by(4) {
                if rd_u32(buf, i) != Some(1) {
                    continue;
                }
                let td = rd_u32(buf, i + 12).map(|v| v as usize);
                let self_rva = rd_u32(buf, i + 20).map(|v| v as usize);
                let rva = base + i;
                if td.is_some_and(|v| type_descriptors.contains(&v)) && self_rva == Some(rva) {
                    locators.push((rva, rd_u32(buf, i + 4).unwrap_or(0)));
                }
            }
        });

        let mut out = Vec::new();
        for (locator, object_offset) in locators {
            let want = self.image_base.saturating_add(locator as u64).to_le_bytes();
            for slot in self.find_all(&want, Access::Rodata) {
                let vtable = slot.saturating_add(8);
                let Some(first) = self.pointer_rva(vtable).and_then(|va| self.va_to_rva(va)) else {
                    continue;
                };
                if self.is_exec(first) {
                    out.push(Vtable {
                        rva: vtable,
                        object_offset,
                    });
                }
            }
        }
        out.sort_unstable_by_key(|v| (v.rva, v.object_offset));
        out.dedup();
        out
    }

    /// Primary MSVC vtable for a class.
    pub fn vtable(&self, decorated_name: &str) -> Option<usize> {
        self.vtables(decorated_name)
            .into_iter()
            .find(|v| v.object_offset == 0)
            .map(|v| v.rva)
    }

    /// RVA of virtual function `index` from a vtable returned by [`Self::vtable`].
    pub fn vfn(&self, vtable: usize, index: usize) -> Option<usize> {
        let va = self.pointer_rva(vtable.checked_add(index.checked_mul(8)?)?)?;
        let rva = self.va_to_rva(va)?;
        self.is_exec(rva).then_some(rva)
    }

    /// Walk virtual functions until an entry stops pointing at module code.
    pub fn virtuals(&self, vtable: usize, max: usize) -> Vec<(usize, usize)> {
        (0..max)
            .map_while(|index| self.vfn(vtable, index).map(|rva| (index, rva)))
            .collect()
    }
}

fn rd_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn rd_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn rd_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(all(test, windows))]
mod tests {
    use super::Module;
    use std::path::PathBuf;

    fn game_module(relative: &str) -> Option<Module> {
        let program_files = std::env::var_os("ProgramFiles(x86)")
            .unwrap_or_else(|| r"C:\Program Files (x86)".into());
        let path = PathBuf::from(program_files)
            .join("Steam/steamapps/common/Counter-Strike Source")
            .join(relative);
        path.exists().then(|| Module::open(path)).flatten()
    }

    #[test]
    fn resolves_current_client_exports_and_input_vtables() {
        let Some(client) = game_module("cstrike/bin/x64/client.dll") else {
            return;
        };
        assert!(client.export("CreateInterface").is_some());
        for class in [".?AVCInput@@", ".?AVCCSInput@@"] {
            let vtable = client
                .vtable(class)
                .unwrap_or_else(|| panic!("{class} vtable"));
            assert!(client.virtuals(vtable, 256).len() > 8, "{class} virtuals");
        }
    }

    #[test]
    fn resolves_current_engine_and_inputsystem_rtti() {
        let Some(engine) = game_module("bin/x64/engine.dll") else {
            return;
        };
        assert!(engine.export("CreateInterface").is_some());
        for class in [
            ".?AVCClientState@@",
            ".?AVCDownloadManager@@",
            ".?AVCEngineClient@@",
        ] {
            assert!(engine.vtable(class).is_some(), "{class} vtable");
        }

        let Some(inputsystem) = game_module("bin/x64/inputsystem.dll") else {
            return;
        };
        assert!(inputsystem.export("CreateInterface").is_some());
        assert!(inputsystem.vtable(".?AVCInputSystem@@").is_some());
    }
}
