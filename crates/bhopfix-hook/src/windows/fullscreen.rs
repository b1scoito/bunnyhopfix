//! Optional F6 fullscreen-preservation patch from RawInput2BunnyhopAPE.
//!
//! Source's video-mode release path normally tears down exclusive fullscreen,
//! while the system D3D9 path may show the minimized game window again. The
//! paired branch changes keep those paths bypassed. Both sites are resolved and
//! validated before either can be enabled, and both are restored on shutdown.

use std::sync::atomic::{AtomicBool, Ordering};

use bhopfix_core::pe::Access;

use super::control;
use super::hook::Patch;
use super::module::LiveModule;

const VIDEO_MODE_CLASS: &str = ".?AVCVideoMode_MaterialSystem@@";
const RELEASE_VIDEO: &str = concat!(
    "40 53 48 83 EC 20 48 8B 01 48 8B D9 FF 90 ?? ?? ?? ?? ",
    "84 C0 75 ?? 48 8B 03 48 8B CB 48 83 C4 20 5B 48 FF A0 ?? ?? ?? ?? ",
    "48 83 C4 20 5B C3"
);
const RELEASE_BRANCH_OFFSET: usize = 20;
const D3D9_SHOW_WINDOW: &str = "0F 84 ?? ?? ?? ?? 48 8B 8B ?? ?? ?? ?? BA 07 00 00 00";

static DIRTY: AtomicBool = AtomicBool::new(false);

pub(crate) struct Hooks {
    release_video: Patch,
    d3d9_show_window: Patch,
    enabled: bool,
}

impl Hooks {
    pub(crate) fn install(engine: &LiveModule, d3d9: &LiveModule) -> Result<Self, String> {
        let (_, release_rva) = engine
            .resolve_virtual(VIDEO_MODE_CLASS, &[RELEASE_VIDEO], 0x40)
            .ok_or_else(|| {
                "CVideoMode_MaterialSystem::ReleaseVideo is missing or ambiguous".to_string()
            })?;
        let release_branch_rva = release_rva
            .checked_add(RELEASE_BRANCH_OFFSET)
            .ok_or_else(|| "ReleaseVideo branch RVA overflowed".to_string())?;
        let release_branch = engine
            .live_bytes(release_branch_rva, 2)
            .ok_or_else(|| "ReleaseVideo branch is unreadable".to_string())?;
        if release_branch.first() != Some(&0x75) {
            return Err("ReleaseVideo conditional branch changed".into());
        }
        let release_address = engine
            .address(release_branch_rva)
            .ok_or_else(|| "ReleaseVideo branch RVA is invalid".to_string())?;
        let release_video = Patch::prepare(release_address, &[0x75], vec![0xeb])?;

        let (d3d_rva, d3d_bytes) = d3d9
            .find_unique(&[D3D9_SHOW_WINDOW], Access::Code)
            .ok_or_else(|| {
                "D3D9 ShowWindow(SW_SHOWMINNOACTIVE) branch is missing or ambiguous".to_string()
            })?;
        if d3d_bytes.get(..2) != Some(&[0x0f, 0x84]) {
            return Err("D3D9 fullscreen branch opcode changed".into());
        }
        let d3d_address = d3d9
            .address(d3d_rva)
            .ok_or_else(|| "D3D9 fullscreen branch RVA is invalid".to_string())?;
        let d3d9_show_window = Patch::prepare(d3d_address, &[0x0f, 0x84], vec![0x90, 0xe9])?;

        control::emit(&format!(
            "fullscreen: ReleaseVideo +0x{release_branch_rva:x}; {} +0x{d3d_rva:x} (F6, off)",
            d3d9.path.display()
        ));
        Ok(Self {
            release_video,
            d3d9_show_window,
            enabled: false,
        })
    }

    pub(crate) fn toggle(&mut self) -> Result<bool, String> {
        let enabled = !self.enabled;
        self.set_enabled(enabled)?;
        control::emit(if enabled {
            "fullscreen preservation enabled"
        } else {
            "fullscreen preservation disabled"
        });
        Ok(enabled)
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        self.set_enabled(false)
    }

    fn set_enabled(&mut self, enabled: bool) -> Result<(), String> {
        if enabled == self.enabled {
            return Ok(());
        }
        if enabled {
            DIRTY.store(true, Ordering::Release);
            if let Err(error) = apply_pair(&mut self.release_video, &mut self.d3d9_show_window) {
                return match restore_pair(&mut self.release_video, &mut self.d3d9_show_window) {
                    Ok(()) => {
                        DIRTY.store(false, Ordering::Release);
                        Err(error)
                    }
                    Err(rollback) => {
                        Err(format!("{error}; fullscreen rollback failed: {rollback}"))
                    }
                };
            }
        } else if let Err(error) = restore_pair(&mut self.release_video, &mut self.d3d9_show_window)
        {
            return match apply_pair(&mut self.release_video, &mut self.d3d9_show_window) {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!(
                    "{error}; restoring the prior fullscreen patch state failed: {rollback}"
                )),
            };
        } else {
            DIRTY.store(false, Ordering::Release);
        }
        self.enabled = enabled;
        Ok(())
    }
}

fn apply_pair(release_video: &mut Patch, d3d9: &mut Patch) -> Result<(), String> {
    release_video.apply()?;
    d3d9.apply()
}

fn restore_pair(release_video: &mut Patch, d3d9: &mut Patch) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Err(error) = d3d9.restore() {
        errors.push(error);
    }
    if let Err(error) = release_video.restore() {
        errors.push(error);
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
