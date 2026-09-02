//! Mapping and lifecycle helpers for the controller-owned shared block.

use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicPtr, Ordering};

use bhopfix_core::control::{ControlBlock, LogLevel, MAGIC, VERSION};

use super::api;

static ACTIVE: AtomicPtr<ControlBlock> = AtomicPtr::new(std::ptr::null_mut());

pub(crate) struct Session {
    mapping: api::Handle,
    view: NonNull<ControlBlock>,
    controller: api::Handle,
}

impl Session {
    pub(crate) fn open() -> Option<Self> {
        let pid = unsafe { api::GetCurrentProcessId() };
        let name: Vec<u16> = format!(r"Local\bunnyhopfix-{pid}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mapping = unsafe { api::OpenFileMappingW(api::FILE_MAP_ALL_ACCESS, 0, name.as_ptr()) };
        if mapping.is_null() {
            return None;
        }
        let raw = unsafe {
            api::MapViewOfFile(
                mapping,
                api::FILE_MAP_ALL_ACCESS,
                0,
                0,
                size_of::<ControlBlock>(),
            )
        };
        let Some(view) = NonNull::new(raw.cast::<ControlBlock>()) else {
            unsafe { api::CloseHandle(mapping) };
            return None;
        };
        let block = unsafe { view.as_ref() };
        if block.magic != MAGIC || block.version != VERSION {
            unsafe {
                api::UnmapViewOfFile(raw);
                api::CloseHandle(mapping);
            }
            return None;
        }
        let controller = unsafe { api::OpenProcess(api::SYNCHRONIZE, 0, block.controller_pid) };
        if controller.is_null() {
            unsafe {
                api::UnmapViewOfFile(raw);
                api::CloseHandle(mapping);
            }
            return None;
        }
        ACTIVE.store(view.as_ptr(), Ordering::Release);
        Some(Self {
            mapping,
            view,
            controller,
        })
    }

    pub(crate) fn block(&self) -> &ControlBlock {
        unsafe { self.view.as_ref() }
    }

    pub(crate) fn should_stop(&self) -> bool {
        self.block().stop.load(Ordering::Acquire) != 0
            || unsafe { api::WaitForSingleObject(self.controller, 0) } == api::WAIT_OBJECT_0
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        ACTIVE.store(std::ptr::null_mut(), Ordering::Release);
        unsafe {
            api::CloseHandle(self.controller);
            api::UnmapViewOfFile(self.view.as_ptr().cast::<c_void>());
            api::CloseHandle(self.mapping);
        }
    }
}

fn emit_level(level: LogLevel, message: &str) {
    let block = ACTIVE.load(Ordering::Acquire);
    if let Some(block) = NonNull::new(block) {
        unsafe { block.as_ref() }.push_log(level, message);
    }
}

pub(crate) fn emit(message: &str) {
    emit_level(LogLevel::Info, message);
}

pub(crate) fn error(message: &str) {
    emit_level(LogLevel::Error, message);
}

pub(crate) fn warn(message: &str) {
    emit_level(LogLevel::Warn, message);
}

pub(crate) fn debug(message: &str) {
    emit_level(LogLevel::Debug, message);
}

pub(crate) fn flags() -> u32 {
    let block = ACTIVE.load(Ordering::Acquire);
    NonNull::new(block)
        .map(|block| unsafe { block.as_ref() }.flags)
        .unwrap_or(0)
}

pub(crate) fn record_raw_event() {
    if let Some(block) = NonNull::new(ACTIVE.load(Ordering::Acquire)) {
        unsafe { block.as_ref() }
            .raw_events
            .fetch_add(1, Ordering::Relaxed);
    }
}

pub(crate) fn record_raw_serve() {
    if let Some(block) = NonNull::new(ACTIVE.load(Ordering::Acquire)) {
        unsafe { block.as_ref() }
            .raw_serves
            .fetch_add(1, Ordering::Relaxed);
    }
}
