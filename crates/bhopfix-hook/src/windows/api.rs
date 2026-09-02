//! Raw Win32 declarations used inside the injected x64 hook DLL.

use std::ffi::c_void;

pub(crate) type Handle = *mut c_void;
pub(crate) type Hmodule = *mut c_void;
pub(crate) type Hwnd = *mut c_void;
pub(crate) type Bool = i32;
pub(crate) type Dword = u32;
pub(crate) type Wparam = usize;
pub(crate) type Lparam = isize;
pub(crate) type Lresult = isize;

pub(crate) const FILE_MAP_ALL_ACCESS: Dword = 0x000f_001f;
pub(crate) const SYNCHRONIZE: Dword = 0x0010_0000;
pub(crate) const WAIT_OBJECT_0: Dword = 0;
pub(crate) const PAGE_EXECUTE_READ: Dword = 0x20;
pub(crate) const PAGE_EXECUTE_READWRITE: Dword = 0x40;
pub(crate) const MEM_COMMIT: Dword = 0x1000;
pub(crate) const MEM_RESERVE: Dword = 0x2000;
pub(crate) const MEM_RELEASE: Dword = 0x8000;
pub(crate) const TH32CS_SNAPTHREAD: Dword = 0x0000_0004;
pub(crate) const THREAD_SUSPEND_RESUME: Dword = 0x0002;
pub(crate) const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;
pub(crate) const MOVEFILE_REPLACE_EXISTING: Dword = 0x0000_0001;
pub(crate) const MOVEFILE_WRITE_THROUGH: Dword = 0x0000_0008;

pub(crate) const WM_INPUT: u32 = 0x00ff;
pub(crate) const RID_INPUT: u32 = 0x1000_0003;
pub(crate) const RIM_TYPEMOUSE: Dword = 0;
pub(crate) const VK_F6: i32 = 0x75;
pub(crate) const VK_F7: i32 = 0x76;

#[repr(C)]
pub(crate) struct ThreadEntry32 {
    pub(crate) size: Dword,
    pub(crate) usage: Dword,
    pub(crate) thread_id: Dword,
    pub(crate) owner_process_id: Dword,
    pub(crate) base_priority: i32,
    pub(crate) delta_priority: i32,
    pub(crate) flags: Dword,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawInputHeader {
    pub(crate) kind: Dword,
    pub(crate) size: Dword,
    pub(crate) device: Handle,
    pub(crate) wparam: Wparam,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawMouseButtons {
    pub(crate) flags: u16,
    pub(crate) data: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union RawMouseButtonUnion {
    pub(crate) combined: Dword,
    pub(crate) split: RawMouseButtons,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct RawMouse {
    pub(crate) flags: u16,
    pub(crate) buttons: RawMouseButtonUnion,
    pub(crate) raw_buttons: Dword,
    pub(crate) last_x: i32,
    pub(crate) last_y: i32,
    pub(crate) extra_information: Dword,
}

#[repr(C)]
pub(crate) union RawInputData {
    pub(crate) mouse: RawMouse,
    pub(crate) bytes: [u8; 48],
}

#[repr(C)]
pub(crate) struct RawInput {
    pub(crate) header: RawInputHeader,
    pub(crate) data: RawInputData,
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn CloseHandle(handle: Handle) -> Bool;
    pub(crate) fn CreateToolhelp32Snapshot(flags: Dword, process_id: Dword) -> Handle;
    pub(crate) fn FlushInstructionCache(
        process: Handle,
        address: *const c_void,
        size: usize,
    ) -> Bool;
    pub(crate) fn GetCurrentProcess() -> Handle;
    pub(crate) fn GetCurrentProcessId() -> Dword;
    pub(crate) fn GetCurrentThreadId() -> Dword;
    pub(crate) fn GetLastError() -> Dword;
    pub(crate) fn GetModuleFileNameW(module: Hmodule, path: *mut u16, size: Dword) -> Dword;
    pub(crate) fn GetModuleHandleW(name: *const u16) -> Hmodule;
    pub(crate) fn QueryPerformanceCounter(value: *mut i64) -> Bool;
    pub(crate) fn QueryPerformanceFrequency(value: *mut i64) -> Bool;
    pub(crate) fn ReadProcessMemory(
        process: Handle,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> Bool;
    pub(crate) fn MapViewOfFile(
        mapping: Handle,
        access: Dword,
        offset_high: Dword,
        offset_low: Dword,
        bytes: usize,
    ) -> *mut c_void;
    pub(crate) fn MoveFileExW(existing: *const u16, replacement: *const u16, flags: Dword) -> Bool;
    pub(crate) fn OpenFileMappingW(access: Dword, inherit: Bool, name: *const u16) -> Handle;
    pub(crate) fn OpenProcess(access: Dword, inherit: Bool, process_id: Dword) -> Handle;
    pub(crate) fn OpenThread(access: Dword, inherit: Bool, thread_id: Dword) -> Handle;
    pub(crate) fn ResumeThread(thread: Handle) -> Dword;
    pub(crate) fn Sleep(milliseconds: Dword);
    pub(crate) fn SuspendThread(thread: Handle) -> Dword;
    pub(crate) fn Thread32First(snapshot: Handle, entry: *mut ThreadEntry32) -> Bool;
    pub(crate) fn Thread32Next(snapshot: Handle, entry: *mut ThreadEntry32) -> Bool;
    pub(crate) fn UnmapViewOfFile(address: *const c_void) -> Bool;
    pub(crate) fn VirtualAlloc(
        address: *mut c_void,
        size: usize,
        allocation_type: Dword,
        protect: Dword,
    ) -> *mut c_void;
    pub(crate) fn VirtualFree(address: *mut c_void, size: usize, free_type: Dword) -> Bool;
    pub(crate) fn VirtualProtect(
        address: *mut c_void,
        size: usize,
        new_protect: Dword,
        old_protect: *mut Dword,
    ) -> Bool;
    pub(crate) fn WaitForSingleObject(handle: Handle, milliseconds: Dword) -> Dword;
}

#[link(name = "user32", kind = "raw-dylib")]
unsafe extern "system" {
    pub(crate) fn FlashWindow(window: Hwnd, invert: Bool) -> Bool;
    pub(crate) fn GetAsyncKeyState(key: i32) -> i16;
    pub(crate) fn GetRawInputData(
        raw_input: Handle,
        command: u32,
        data: *mut c_void,
        size: *mut u32,
        header_size: u32,
    ) -> u32;
}
