//! Controller-owned shared state and reversible x64 DLL injection.

use std::ffi::{c_char, c_void};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::atomic::Ordering;

use bhopfix_core::control::{
    ControlBlock, LOG_BYTES, LOG_SLOTS, LogLevel, STATE_FAILED, STATE_READY, STATE_STOPPED,
};
use bhopfix_core::pe::Module as PeModule;

use super::{Bool, Dword, Handle, Process};

const FILE_MAP_ALL_ACCESS: Dword = 0x000f_001f;
const PAGE_READWRITE: Dword = 0x04;
const MEM_COMMIT: Dword = 0x1000;
const MEM_RESERVE: Dword = 0x2000;
const MEM_RELEASE: Dword = 0x8000;
const WAIT_OBJECT_0: Dword = 0;
const WAIT_TIMEOUT: Dword = 258;
const ERROR_ALREADY_EXISTS: Dword = 183;
const GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: Dword = 0x0000_0002;
const GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS: Dword = 0x0000_0004;

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreateFileMappingW(
        file: Handle,
        attributes: *const c_void,
        protect: Dword,
        maximum_size_high: Dword,
        maximum_size_low: Dword,
        name: *const u16,
    ) -> Handle;
    fn MapViewOfFile(
        mapping: Handle,
        access: Dword,
        offset_high: Dword,
        offset_low: Dword,
        bytes: usize,
    ) -> *mut c_void;
    fn UnmapViewOfFile(address: *const c_void) -> Bool;
    fn VirtualAllocEx(
        process: Handle,
        address: *mut c_void,
        size: usize,
        allocation_type: Dword,
        protect: Dword,
    ) -> *mut c_void;
    fn VirtualFreeEx(process: Handle, address: *mut c_void, size: usize, free_type: Dword) -> Bool;
    fn CreateRemoteThread(
        process: Handle,
        attributes: *const c_void,
        stack_size: usize,
        start: Option<unsafe extern "system" fn(*mut c_void) -> Dword>,
        parameter: *mut c_void,
        flags: Dword,
        thread_id: *mut Dword,
    ) -> Handle;
    fn WaitForSingleObject(handle: Handle, milliseconds: Dword) -> Dword;
    fn GetExitCodeThread(thread: Handle, code: *mut Dword) -> Bool;
    fn GetCurrentProcessId() -> Dword;
    fn GetModuleHandleW(name: *const u16) -> Handle;
    fn GetModuleHandleExW(flags: Dword, address: *const u16, module: *mut Handle) -> Bool;
    fn GetModuleFileNameW(module: Handle, path: *mut u16, size: Dword) -> Dword;
    fn GetProcAddress(module: Handle, name: *const c_char) -> *mut c_void;
    fn WriteProcessMemory(
        process: Handle,
        address: *mut c_void,
        buffer: *const c_void,
        size: usize,
        written: *mut usize,
    ) -> Bool;
    fn CloseHandle(handle: Handle) -> Bool;
    fn GetLastError() -> Dword;
    fn Sleep(milliseconds: Dword);
}

struct Mapping {
    handle: Handle,
    view: NonNull<ControlBlock>,
}

impl Mapping {
    fn create(game_pid: u32, flags: u32) -> Result<Self, String> {
        let name: Vec<u16> = format!(r"Local\bunnyhopfix-{game_pid}")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileMappingW(
                usize::MAX as Handle,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                size_of::<ControlBlock>() as u32,
                name.as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(format!("CreateFileMappingW failed ({})", unsafe {
                GetLastError()
            }));
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err("a bunnyhopfix control mapping already exists for this game; restart the game if an earlier hook could not unload".into());
        }
        let raw =
            unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, size_of::<ControlBlock>()) };
        let Some(view) = NonNull::new(raw.cast::<ControlBlock>()) else {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(format!("MapViewOfFile failed ({error})"));
        };
        unsafe {
            std::ptr::write(
                view.as_ptr(),
                ControlBlock::new(GetCurrentProcessId(), flags),
            )
        };
        Ok(Self { handle, view })
    }

    fn block(&self) -> &ControlBlock {
        unsafe { self.view.as_ref() }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(self.view.as_ptr().cast::<c_void>());
            CloseHandle(self.handle);
        }
    }
}

struct RemoteBuffer {
    process: Handle,
    address: *mut c_void,
}

impl RemoteBuffer {
    fn write(process: Handle, bytes: &[u8]) -> Result<Self, String> {
        let address = unsafe {
            VirtualAllocEx(
                process,
                std::ptr::null_mut(),
                bytes.len(),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if address.is_null() {
            return Err(format!("VirtualAllocEx failed ({})", unsafe {
                GetLastError()
            }));
        }
        let mut written = 0usize;
        let ok = unsafe {
            WriteProcessMemory(
                process,
                address,
                bytes.as_ptr().cast::<c_void>(),
                bytes.len(),
                &raw mut written,
            )
        };
        if ok == 0 || written != bytes.len() {
            let error = unsafe { GetLastError() };
            unsafe { VirtualFreeEx(process, address, 0, MEM_RELEASE) };
            return Err(format!("WriteProcessMemory for DLL path failed ({error})"));
        }
        Ok(Self { process, address })
    }
}

impl Drop for RemoteBuffer {
    fn drop(&mut self) {
        unsafe { VirtualFreeEx(self.process, self.address, 0, MEM_RELEASE) };
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn remote_system_function(process: &Process, export: &[u8]) -> Result<usize, String> {
    let kernel32 = unsafe { GetModuleHandleW(wide("kernel32.dll").as_ptr()) };
    if kernel32.is_null() {
        return Err("local kernel32.dll is not loaded".into());
    }
    let function = unsafe { GetProcAddress(kernel32, export.as_ptr().cast::<c_char>()) };
    if function.is_null() {
        return Err(format!(
            "GetProcAddress failed for {} ({})",
            String::from_utf8_lossy(&export[..export.len().saturating_sub(1)]),
            unsafe { GetLastError() }
        ));
    }

    // GetProcAddress may resolve a forwarded kernel32 export into KernelBase.
    // Locate the module that actually owns the address, then transfer its RVA
    // to the matching module in the target process.
    let mut owner: Handle = std::ptr::null_mut();
    let ok = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            function.cast::<u16>(),
            &raw mut owner,
        )
    };
    if ok == 0 || owner.is_null() {
        return Err(format!("GetModuleHandleExW failed ({})", unsafe {
            GetLastError()
        }));
    }
    let mut path = [0u16; 32_768];
    let length =
        unsafe { GetModuleFileNameW(owner, path.as_mut_ptr(), path.len() as u32) } as usize;
    if length == 0 || length >= path.len() {
        return Err(format!("GetModuleFileNameW failed ({})", unsafe {
            GetLastError()
        }));
    }
    let owner_path = String::from_utf16(&path[..length])
        .map_err(|_| "system module path is invalid UTF-16".to_string())?;
    let name = Path::new(&owner_path)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "system module has no usable file name".to_string())?;
    let remote_owner = process
        .module(name)
        .ok_or_else(|| format!("target process does not contain {name}"))?;
    let rva = (function as usize)
        .checked_sub(owner as usize)
        .ok_or_else(|| "resolved system function precedes its module".to_string())?;
    if rva >= remote_owner.size {
        return Err(format!(
            "resolved {name} function RVA is outside the target module"
        ));
    }
    Ok(remote_owner.base + rva)
}

fn start_remote(process: Handle, start: usize, parameter: usize) -> Result<Handle, String> {
    let start: unsafe extern "system" fn(*mut c_void) -> Dword =
        unsafe { std::mem::transmute(start) };
    let thread = unsafe {
        CreateRemoteThread(
            process,
            std::ptr::null(),
            0,
            Some(start),
            parameter as *mut c_void,
            0,
            std::ptr::null_mut(),
        )
    };
    if thread.is_null() {
        return Err(format!("CreateRemoteThread failed ({})", unsafe {
            GetLastError()
        }));
    }
    Ok(thread)
}

fn wait_thread(thread: Handle, timeout_ms: u32) -> Result<u32, String> {
    match unsafe { WaitForSingleObject(thread, timeout_ms) } {
        WAIT_OBJECT_0 => {
            let mut code = 0u32;
            if unsafe { GetExitCodeThread(thread, &raw mut code) } == 0 {
                return Err(format!("GetExitCodeThread failed ({})", unsafe {
                    GetLastError()
                }));
            }
            Ok(code)
        }
        WAIT_TIMEOUT => Err("remote thread timed out".into()),
        _ => Err(format!("WaitForSingleObject failed ({})", unsafe {
            GetLastError()
        })),
    }
}

fn free_remote_library(process: &Process, module: usize, name: &str) -> Result<(), String> {
    let free_library = remote_system_function(process, b"FreeLibrary\0")?;
    let thread = start_remote(process.handle, free_library, module)?;
    let result = wait_thread(thread, 10_000);
    unsafe { CloseHandle(thread) };
    let code = result?;
    if code == 0 {
        return Err("remote FreeLibrary returned false".into());
    }
    for _ in 0..100 {
        match process.module_checked(name)? {
            None => return Ok(()),
            Some(_) => unsafe { Sleep(10) },
        }
    }
    Err(format!(
        "remote FreeLibrary returned true but {name} remains loaded"
    ))
}

pub(super) struct HookSession {
    mapping: Mapping,
    module: usize,
    worker: Handle,
    dll_name: String,
    next_log: u32,
    unloaded: bool,
}

impl HookSession {
    pub(super) fn inject(process: &Process, dll: &Path, flags: u32) -> Result<Self, String> {
        let dll = dll
            .canonicalize()
            .map_err(|error| format!("cannot resolve {}: {error}", dll.display()))?;
        let dll_name = dll
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "hook DLL has no usable file name".to_string())?;
        if process.module(dll_name).is_some() {
            return Err(format!(
                "{dll_name} is already loaded in the target; restart the game"
            ));
        }
        let image = PeModule::open(&dll)
            .ok_or_else(|| format!("{} is not a valid x64 PE DLL", dll.display()))?;
        let start_rva = image
            .export("bhopfix_start")
            .ok_or_else(|| format!("{} does not export bhopfix_start", dll.display()))?;
        let mapping = Mapping::create(process.pid, flags)?;

        let mut path: Vec<u16> = dll.as_os_str().encode_wide().collect();
        path.push(0);
        let path_bytes = unsafe {
            std::slice::from_raw_parts(path.as_ptr().cast::<u8>(), path.len() * size_of::<u16>())
        };
        let remote_path = RemoteBuffer::write(process.handle, path_bytes)?;
        let load_library = remote_system_function(process, b"LoadLibraryW\0")?;
        let loader = start_remote(process.handle, load_library, remote_path.address as usize)?;
        let load_result = wait_thread(loader, 15_000);
        unsafe { CloseHandle(loader) };
        if let Err(error) = load_result {
            // The loader thread may still be reading this buffer. Leaking it
            // into the target is safer than freeing memory beneath that thread.
            std::mem::forget(remote_path);
            return Err(format!(
                "{error} while loading the hook DLL; remote loader state is unknown, restart the game"
            ));
        }
        drop(remote_path);

        let mut remote_module = None;
        for _ in 0..100 {
            if let Some(module) = process.module(dll_name) {
                remote_module = Some(module.base);
                break;
            }
            unsafe { Sleep(10) };
        }
        let module = remote_module.ok_or_else(|| {
            format!("LoadLibraryW completed but {dll_name} is absent from the target module list")
        })?;
        let start = match module.checked_add(start_rva) {
            Some(start) => start,
            None => {
                let cleanup = free_remote_library(process, module, dll_name);
                return Err(match cleanup {
                    Ok(()) => "remote hook entry address overflowed".to_string(),
                    Err(cleanup) => format!(
                        "remote hook entry address overflowed; DLL cleanup failed: {cleanup}"
                    ),
                });
            }
        };
        let worker = match start_remote(process.handle, start, 0) {
            Ok(worker) => worker,
            Err(error) => {
                return Err(match free_remote_library(process, module, dll_name) {
                    Ok(()) => error,
                    Err(cleanup) => format!("{error}; DLL cleanup failed: {cleanup}"),
                });
            }
        };
        Ok(Self {
            mapping,
            module,
            dll_name: dll_name.to_string(),
            worker,
            next_log: 1,
            unloaded: false,
        })
    }

    pub(super) fn block(&self) -> &ControlBlock {
        self.mapping.block()
    }

    pub(super) fn flush_logs(&mut self) {
        let latest = self.block().latest_log_sequence();
        if latest.saturating_sub(self.next_log) >= LOG_SLOTS as u32 {
            let oldest = latest - LOG_SLOTS as u32 + 1;
            let dropped = oldest.saturating_sub(self.next_log);
            tracing::warn!(
                target: "bhopfix_hook",
                dropped,
                "shared hook log ring overran before the controller drained it"
            );
            self.next_log = oldest;
        }
        while self.next_log <= latest {
            let mut bytes = [0u8; LOG_BYTES];
            if let Some((level, length)) = self.block().read_log(self.next_log, &mut bytes) {
                let message = String::from_utf8_lossy(&bytes[..length]);
                match level {
                    LogLevel::Error => tracing::error!(target: "bhopfix_hook", "{message}"),
                    LogLevel::Warn => tracing::warn!(target: "bhopfix_hook", "{message}"),
                    LogLevel::Info => tracing::info!(target: "bhopfix_hook", "{message}"),
                    LogLevel::Debug => tracing::debug!(target: "bhopfix_hook", "{message}"),
                }
            }
            self.next_log += 1;
        }
    }

    fn startup_failure(&mut self, process: &Process, reason: String) -> String {
        self.block().stop.store(1, Ordering::Release);
        if let Err(error) = wait_thread(self.worker, 15_000) {
            return format!("{reason}; {error}; DLL remains loaded");
        }
        if self.block().unload_safe.load(Ordering::Acquire) == 0 {
            return format!("{reason}; hook cleanup was not proven safe; DLL remains loaded");
        }
        match free_remote_library(process, self.module, &self.dll_name) {
            Ok(()) => {
                self.unloaded = true;
                format!("{reason}; startup changes were restored and the DLL was unloaded")
            }
            Err(error) => format!("{reason}; unloading the clean DLL failed: {error}"),
        }
    }

    pub(super) fn wait_ready(&mut self, process: &Process) -> Result<(), String> {
        for _ in 0..3_000 {
            self.flush_logs();
            match self.block().state.load(Ordering::Acquire) {
                STATE_READY => return Ok(()),
                STATE_FAILED => {
                    let error = self.block().error.load(Ordering::Acquire);
                    let reason = format!("hook worker failed (code {error})");
                    return Err(self.startup_failure(process, reason));
                }
                _ => {}
            }
            if unsafe { WaitForSingleObject(self.worker, 0) } == WAIT_OBJECT_0 {
                let reason = "hook worker exited before publishing ready state".to_string();
                return Err(self.startup_failure(process, reason));
            }
            unsafe { Sleep(10) };
        }
        let reason = "hook worker did not become ready within 30 seconds".to_string();
        Err(self.startup_failure(process, reason))
    }

    pub(super) fn unloaded(&self) -> bool {
        self.unloaded
    }

    pub(super) fn shutdown(&mut self, process: &Process) -> Result<(), String> {
        if self.unloaded {
            return Ok(());
        }
        self.block().stop.store(1, Ordering::Release);
        let result = wait_thread(self.worker, 75_000);
        self.flush_logs();
        let worker_code = result?;
        let state = self.block().state.load(Ordering::Acquire);
        let unload_safe = self.block().unload_safe.load(Ordering::Acquire);
        if state != STATE_STOPPED || worker_code != 0 || unload_safe == 0 {
            return Err(format!(
                "hook did not restore cleanly (state {state}, worker code {worker_code}, \
                 unload-safe {unload_safe}); DLL remains loaded"
            ));
        }
        free_remote_library(process, self.module, &self.dll_name)?;
        self.unloaded = true;
        Ok(())
    }
}

impl Drop for HookSession {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.worker) };
    }
}
