//! Reversible, byte-validated hooks for the current process.

use std::ffi::c_void;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::api;

const ABS_JUMP_LEN: usize = 14;
const ERROR_ACCESS_DENIED: u32 = 5;
const ERROR_NO_MORE_FILES: u32 = 18;
const ERROR_INVALID_PARAMETER: u32 = 87;
const THREAD_SUSPEND_RETRY_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThreadFailure {
    Gone,
    Retry,
    Fatal,
}

fn classify_thread_failure(error: u32, terminated: bool) -> ThreadFailure {
    if terminated || error == ERROR_INVALID_PARAMETER {
        ThreadFailure::Gone
    } else if error == ERROR_ACCESS_DENIED {
        ThreadFailure::Retry
    } else {
        ThreadFailure::Fatal
    }
}

enum SuspendAttemptError {
    Retry(String),
    Fatal(String),
}

fn thread_ids(process: u32, current: u32) -> Result<Vec<u32>, String> {
    let snapshot = unsafe { api::CreateToolhelp32Snapshot(api::TH32CS_SNAPTHREAD, 0) };
    if snapshot == api::INVALID_HANDLE_VALUE || snapshot.is_null() {
        return Err(format!("thread snapshot failed ({})", unsafe {
            api::GetLastError()
        }));
    }
    let result = (|| {
        let mut entry: api::ThreadEntry32 = unsafe { std::mem::zeroed() };
        entry.size = size_of::<api::ThreadEntry32>() as u32;
        if unsafe { api::Thread32First(snapshot, &raw mut entry) } == 0 {
            let error = unsafe { api::GetLastError() };
            return (error == ERROR_NO_MORE_FILES)
                .then(Vec::new)
                .ok_or_else(|| format!("Thread32First failed ({error})"));
        }
        let mut tids = Vec::new();
        loop {
            if entry.owner_process_id == process && entry.thread_id != current {
                tids.push(entry.thread_id);
            }
            if unsafe { api::Thread32Next(snapshot, &raw mut entry) } == 0 {
                let error = unsafe { api::GetLastError() };
                if error != ERROR_NO_MORE_FILES {
                    return Err(format!("Thread32Next failed ({error})"));
                }
                break;
            }
        }
        tids.sort_unstable();
        tids.dedup();
        Ok(tids)
    })();
    unsafe { api::CloseHandle(snapshot) };
    result
}

struct ThreadGuard {
    threads: Vec<(u32, api::Handle)>,
}

impl ThreadGuard {
    fn try_suspend_others(process: u32, current: u32) -> Result<Self, SuspendAttemptError> {
        let mut guard = Self {
            threads: Vec::new(),
        };
        for _ in 0..16 {
            for thread_id in thread_ids(process, current).map_err(SuspendAttemptError::Fatal)? {
                if guard.threads.iter().any(|(known, _)| *known == thread_id) {
                    continue;
                }
                let thread = unsafe {
                    api::OpenThread(api::THREAD_SUSPEND_RESUME | api::SYNCHRONIZE, 0, thread_id)
                };
                if thread.is_null() {
                    let error = unsafe { api::GetLastError() };
                    match classify_thread_failure(error, false) {
                        ThreadFailure::Gone => continue,
                        ThreadFailure::Retry => {
                            return Err(SuspendAttemptError::Retry(format!(
                                "OpenThread({thread_id}) failed ({error})"
                            )));
                        }
                        ThreadFailure::Fatal => {
                            return Err(SuspendAttemptError::Fatal(format!(
                                "OpenThread({thread_id}) failed ({error})"
                            )));
                        }
                    }
                }
                if unsafe { api::SuspendThread(thread) } == u32::MAX {
                    let error = unsafe { api::GetLastError() };
                    let terminated =
                        unsafe { api::WaitForSingleObject(thread, 0) } == api::WAIT_OBJECT_0;
                    unsafe { api::CloseHandle(thread) };
                    match classify_thread_failure(error, terminated) {
                        ThreadFailure::Gone => continue,
                        ThreadFailure::Retry => {
                            return Err(SuspendAttemptError::Retry(format!(
                                "SuspendThread({thread_id}) failed ({error})"
                            )));
                        }
                        ThreadFailure::Fatal => {
                            return Err(SuspendAttemptError::Fatal(format!(
                                "SuspendThread({thread_id}) failed ({error})"
                            )));
                        }
                    }
                }
                guard.threads.push((thread_id, thread));
            }
            let current_threads =
                thread_ids(process, current).map_err(SuspendAttemptError::Fatal)?;
            if current_threads
                .iter()
                .all(|tid| guard.threads.iter().any(|(known, _)| known == tid))
            {
                return Ok(guard);
            }
        }
        Err(SuspendAttemptError::Retry(
            "process kept creating threads while entering patch stop".into(),
        ))
    }

    fn suspend_others() -> Result<Self, String> {
        let process = unsafe { api::GetCurrentProcessId() };
        let current = unsafe { api::GetCurrentThreadId() };
        let started = Instant::now();
        loop {
            match Self::try_suspend_others(process, current) {
                Ok(guard) => return Ok(guard),
                Err(SuspendAttemptError::Fatal(error)) => return Err(error),
                Err(SuspendAttemptError::Retry(_))
                    if started.elapsed() < THREAD_SUSPEND_RETRY_TIMEOUT =>
                {
                    unsafe { api::Sleep(1) };
                }
                Err(SuspendAttemptError::Retry(error)) => {
                    return Err(format!(
                        "{error}; thread set did not become suspendable within {} ms",
                        THREAD_SUSPEND_RETRY_TIMEOUT.as_millis()
                    ));
                }
            }
        }
    }
}

impl Drop for ThreadGuard {
    fn drop(&mut self) {
        for &(_, thread) in self.threads.iter().rev() {
            unsafe {
                api::ResumeThread(thread);
                api::CloseHandle(thread);
            }
        }
    }
}

fn write_code(
    address: usize,
    bytes: &[u8],
    original_protection: &mut Option<u32>,
) -> Result<(), String> {
    let mut old = 0u32;
    if unsafe {
        api::VirtualProtect(
            address as *mut c_void,
            bytes.len(),
            api::PAGE_EXECUTE_READWRITE,
            &raw mut old,
        )
    } == 0
    {
        return Err(format!("VirtualProtect failed ({})", unsafe {
            api::GetLastError()
        }));
    }
    let protection = *original_protection.get_or_insert(old);

    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
    let mut errors = Vec::new();
    if unsafe {
        api::FlushInstructionCache(
            api::GetCurrentProcess(),
            address as *const c_void,
            bytes.len(),
        )
    } == 0
    {
        errors.push(format!("FlushInstructionCache failed ({})", unsafe {
            api::GetLastError()
        }));
    }
    let mut ignored = 0u32;
    if unsafe {
        api::VirtualProtect(
            address as *mut c_void,
            bytes.len(),
            protection,
            &raw mut ignored,
        )
    } == 0
    {
        errors.push(format!("VirtualProtect restore failed ({})", unsafe {
            api::GetLastError()
        }));
    }
    let current = unsafe { std::slice::from_raw_parts(address as *const u8, bytes.len()) };
    if current != bytes {
        errors.push("code write did not verify".into());
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
fn absolute_jump(target: usize) -> [u8; ABS_JUMP_LEN] {
    let mut jump = [0u8; ABS_JUMP_LEN];
    jump[..6].copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0]);
    jump[6..].copy_from_slice(&(target as u64).to_le_bytes());
    jump
}

pub(crate) struct InstallError {
    message: String,
    clean: bool,
}

impl InstallError {
    fn clean(message: String) -> Self {
        Self {
            message,
            clean: true,
        }
    }

    fn dirty(message: String) -> Self {
        Self {
            message,
            clean: false,
        }
    }

    pub(crate) fn is_clean(&self) -> bool {
        self.clean
    }
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PatchState {
    Original,
    Replacement,
    Unknown,
}

pub(crate) struct Patch {
    address: usize,
    original: Vec<u8>,
    replacement: Vec<u8>,
    original_protection: Option<u32>,
    tainted: bool,
}

impl Patch {
    pub(crate) fn prepare(
        address: usize,
        expected: &[u8],
        replacement: Vec<u8>,
    ) -> Result<Self, String> {
        if expected.len() != replacement.len() || expected.is_empty() {
            return Err("patch lengths are invalid".into());
        }
        let current = unsafe { std::slice::from_raw_parts(address as *const u8, expected.len()) };
        if current != expected {
            return Err(format!(
                "original bytes at 0x{address:x} changed; refusing blind patch"
            ));
        }
        Ok(Self {
            address,
            original: expected.to_vec(),
            replacement,
            original_protection: None,
            tainted: false,
        })
    }

    pub(crate) fn install(
        address: usize,
        expected: &[u8],
        replacement: Vec<u8>,
    ) -> Result<Self, InstallError> {
        let mut patch =
            Self::prepare(address, expected, replacement).map_err(InstallError::clean)?;
        if let Err(error) = patch.apply() {
            let cleanup = patch.restore();
            if cleanup.is_ok() && !patch.tainted && patch.state() == PatchState::Original {
                return Err(InstallError::clean(error));
            }
            let cleanup = cleanup
                .err()
                .unwrap_or_else(|| "patch state remains uncertain".to_string());
            std::mem::forget(patch);
            return Err(InstallError::dirty(format!(
                "{error}; rollback failed: {cleanup}"
            )));
        }
        Ok(patch)
    }

    fn state(&self) -> PatchState {
        let current =
            unsafe { std::slice::from_raw_parts(self.address as *const u8, self.original.len()) };
        if current == self.original {
            PatchState::Original
        } else if current == self.replacement {
            PatchState::Replacement
        } else {
            PatchState::Unknown
        }
    }

    fn force_original(&mut self) -> Result<(), String> {
        self.tainted = true;
        let result = write_code(self.address, &self.original, &mut self.original_protection);
        if result.is_ok() && self.state() == PatchState::Original {
            self.tainted = false;
            Ok(())
        } else {
            Err(result
                .err()
                .unwrap_or_else(|| "original bytes did not verify".to_string()))
        }
    }

    pub(crate) fn apply(&mut self) -> Result<(), String> {
        if self.tainted {
            self.restore()?;
        }
        match self.state() {
            PatchState::Replacement => return Ok(()),
            PatchState::Original => {}
            PatchState::Unknown => {
                return Err(format!(
                    "patch state at 0x{:x} is uncertain; refusing another write",
                    self.address
                ));
            }
        }

        let _threads = ThreadGuard::suspend_others()?;
        self.tainted = true;
        match write_code(
            self.address,
            &self.replacement,
            &mut self.original_protection,
        ) {
            Ok(()) => {
                self.tainted = false;
                Ok(())
            }
            Err(error) => match self.force_original() {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!("{error}; rollback failed: {rollback}")),
            },
        }
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        match self.state() {
            PatchState::Original if !self.tainted => return Ok(()),
            PatchState::Unknown if !self.tainted => {
                return Err(format!(
                    "bytes at 0x{:x} changed externally; refusing blind restore",
                    self.address
                ));
            }
            PatchState::Original | PatchState::Replacement | PatchState::Unknown => {}
        }
        let _threads = ThreadGuard::suspend_others()?;
        self.force_original()
    }
}

impl Drop for Patch {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(crate) struct PointerHook {
    slot: usize,
    original: usize,
    replacement: usize,
    original_protection: Option<u32>,
    tainted: bool,
}

impl PointerHook {
    pub(crate) fn install(
        slot: usize,
        expected: usize,
        replacement: usize,
    ) -> Result<Self, InstallError> {
        if !slot.is_multiple_of(size_of::<usize>()) {
            return Err(InstallError::clean("pointer slot is not aligned".into()));
        }
        let current = unsafe { std::ptr::read(slot as *const usize) };
        if current != expected {
            return Err(InstallError::clean(format!(
                "slot 0x{slot:x} holds 0x{current:x}, expected 0x{expected:x}"
            )));
        }
        let mut hook = Self {
            slot,
            original: expected,
            replacement,
            original_protection: None,
            tainted: false,
        };
        if let Err(error) = hook.apply() {
            let cleanup = hook.restore();
            if cleanup.is_ok() && !hook.tainted && hook.current() == hook.original {
                return Err(InstallError::clean(error));
            }
            let cleanup = cleanup
                .err()
                .unwrap_or_else(|| "pointer-hook state remains uncertain".to_string());
            std::mem::forget(hook);
            return Err(InstallError::dirty(format!(
                "{error}; rollback failed: {cleanup}"
            )));
        }
        Ok(hook)
    }

    fn current(&self) -> usize {
        unsafe { std::ptr::read(self.slot as *const usize) }
    }

    fn force_original(&mut self) -> Result<(), String> {
        self.tainted = true;
        let result = write_code(
            self.slot,
            &self.original.to_ne_bytes(),
            &mut self.original_protection,
        );
        if result.is_ok() && self.current() == self.original {
            self.tainted = false;
            Ok(())
        } else {
            Err(result
                .err()
                .unwrap_or_else(|| "original pointer did not verify".to_string()))
        }
    }

    fn apply(&mut self) -> Result<(), String> {
        let current = self.current();
        if current == self.replacement && !self.tainted {
            return Ok(());
        }
        if current != self.original || self.tainted {
            return Err(format!(
                "pointer-hook state at 0x{:x} is uncertain; refusing another write",
                self.slot
            ));
        }
        let _threads = ThreadGuard::suspend_others()?;
        self.tainted = true;
        match write_code(
            self.slot,
            &self.replacement.to_ne_bytes(),
            &mut self.original_protection,
        ) {
            Ok(()) => {
                self.tainted = false;
                Ok(())
            }
            Err(error) => match self.force_original() {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!("{error}; rollback failed: {rollback}")),
            },
        }
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        let current = self.current();
        if current == self.original && !self.tainted {
            return Ok(());
        }
        if current != self.replacement && !self.tainted {
            return Err(format!(
                "hooked slot 0x{:x} changed externally; refusing blind restore",
                self.slot
            ));
        }
        let _threads = ThreadGuard::suspend_others()?;
        self.force_original()
    }
}

impl Drop for PointerHook {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub(crate) struct InlineHook {
    patch: Patch,
    trampoline: *mut c_void,
}

impl InlineHook {
    pub(crate) fn install(
        address: usize,
        expected: &[u8],
        replacement: usize,
        original: &'static AtomicUsize,
    ) -> Result<Self, InstallError> {
        if expected.len() < ABS_JUMP_LEN {
            return Err(InstallError::clean(format!(
                "inline hook needs at least {ABS_JUMP_LEN} safe bytes"
            )));
        }
        let trampoline_len = expected.len() + ABS_JUMP_LEN;
        let trampoline = unsafe {
            api::VirtualAlloc(
                std::ptr::null_mut(),
                trampoline_len,
                api::MEM_COMMIT | api::MEM_RESERVE,
                api::PAGE_EXECUTE_READWRITE,
            )
        };
        if trampoline.is_null() {
            return Err(InstallError::clean(format!(
                "VirtualAlloc failed ({})",
                unsafe { api::GetLastError() }
            )));
        }
        unsafe {
            std::ptr::copy_nonoverlapping(
                expected.as_ptr(),
                trampoline.cast::<u8>(),
                expected.len(),
            );
            let back = absolute_jump(address + expected.len());
            std::ptr::copy_nonoverlapping(
                back.as_ptr(),
                trampoline.cast::<u8>().add(expected.len()),
                back.len(),
            );
        }
        let mut old = 0u32;
        let flushed = unsafe {
            api::FlushInstructionCache(api::GetCurrentProcess(), trampoline, trampoline_len)
        };
        let protected = unsafe {
            api::VirtualProtect(
                trampoline,
                trampoline_len,
                api::PAGE_EXECUTE_READ,
                &raw mut old,
            )
        };
        if flushed == 0 || protected == 0 {
            let error = unsafe { api::GetLastError() };
            unsafe { api::VirtualFree(trampoline, 0, api::MEM_RELEASE) };
            return Err(InstallError::clean(format!(
                "finalizing the trampoline failed ({error})"
            )));
        }

        original.store(trampoline as usize, Ordering::Release);
        let mut replacement_bytes = vec![0x90; expected.len()];
        replacement_bytes[..ABS_JUMP_LEN].copy_from_slice(&absolute_jump(replacement));
        let patch = match Patch::install(address, expected, replacement_bytes) {
            Ok(patch) => patch,
            Err(error) => {
                if error.is_clean() {
                    original.store(0, Ordering::Release);
                    unsafe { api::VirtualFree(trampoline, 0, api::MEM_RELEASE) };
                }
                return Err(error);
            }
        };
        Ok(Self { patch, trampoline })
    }

    pub(crate) fn release_trampoline(&mut self) -> Result<(), String> {
        if self.trampoline.is_null() {
            return Ok(());
        }
        if self.patch.tainted || self.patch.state() != PatchState::Original {
            return Err("cannot free a trampoline while its inline patch may execute".into());
        }
        if unsafe { api::VirtualFree(self.trampoline, 0, api::MEM_RELEASE) } == 0 {
            return Err(format!("VirtualFree trampoline failed ({})", unsafe {
                api::GetLastError()
            }));
        }
        self.trampoline = std::ptr::null_mut();
        Ok(())
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        self.patch.restore()
    }
}

impl Drop for InlineHook {
    fn drop(&mut self) {
        // Restoring the entry point is always safe to attempt. The trampoline
        // is only freed explicitly after the owner has observed zero active
        // callbacks; leaking it on an abnormal path avoids a use-after-free.
        let _ = self.patch.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::classify_thread_failure;
    use super::{ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ThreadFailure};

    #[test]
    fn classifies_thread_churn_without_skipping_live_failures() {
        assert_eq!(
            classify_thread_failure(ERROR_INVALID_PARAMETER, false),
            ThreadFailure::Gone
        );
        assert_eq!(
            classify_thread_failure(ERROR_ACCESS_DENIED, false),
            ThreadFailure::Retry
        );
        assert_eq!(classify_thread_failure(1234, true), ThreadFailure::Gone);
        assert_eq!(classify_thread_failure(1234, false), ThreadFailure::Fatal);
    }
}
