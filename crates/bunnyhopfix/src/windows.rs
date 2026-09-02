//! Windows x86-64 backend: prediction patcher and native hook controller.
//!
//! The controller validates the target's architecture and `-insecure` command
//! line, resolves both CheckJumpButton implementations in client.dll, applies
//! the prediction changes as one reversible transaction, and owns the injected
//! bhopfix.dll lifecycle for the remaining Windows feature set.
mod inject;

use std::ffi::c_void;
use std::path::PathBuf;

use bhopfix_core::control::{
    FEATURE_CONSOLE, FEATURE_DOWNLOADS, FEATURE_FASTDL, FEATURE_FULLSCREEN, FEATURE_RAWINPUT2,
    FEATURE_SOURCEJUMP, FEATURE_VIEWPUNCH, FLAG_DEBUG, FLAG_DEMOS, FLAG_FORCE_RAWINPUT2,
    FLAG_KEEP_VIEWPUNCH, FLAG_NO_SOURCEJUMP,
};
use std::sync::atomic::{AtomicBool, Ordering};

use bhopfix_core::sig::Sig;
use tracing::{error, info, warn};

// ---------------------------------------------------------------------------
// Signatures
//
// `if (mv->m_nOldButtons & IN_JUMP) return false;` appears in both
// CGameMovement::CheckJumpButton implementations. The current 64-bit Windows
// client uses the same `m_nOldButtons +0x28` and `IN_JUMP == 2` check as the
// Linux client:
//
//     48 8B 43 10       mov  rax,[rbx+10h]
//     F6 40 28 02       test byte ptr [rax+28h],2
//     0F 85 xx xx xx xx jne  out                 <- patch 6 bytes
//
// and:
//
//     48 8B 06          mov  rax,[rsi]
//     F6 40 28 02       test byte ptr [rax+28h],2
//     75 xx             jne  out                 <- patch 2 bytes
//
// Both x64 patterns were derived from Windows client.dll build 10897846 and
// each must match exactly once. Their surrounding instructions mirror the two
// independently derived linux64 signatures, identifying behavior rather than
// a fixed address. Patching only one of the base CGameMovement and
// CCSGameMovement copies is a silent half-fix, so ambiguity or a missing site
// rejects the whole transaction.
// ---------------------------------------------------------------------------
#[rustfmt::skip]
static SIGS: &[Sig] = &[
    Sig {
        name: "win64 CheckJumpButton #1",
        pat: "80 B9 50 14 00 00 00  0F 85 ?? ?? ?? ??  48 8B 43 10  F6 40 28 02  0F 85 ?? ?? ?? ??",
        at: 21, len: 6,
    },
    Sig {
        name: "win64 CheckJumpButton #2",
        pat: "48 8B 05 ?? ?? ?? ??  48 8D 73 10  83 78 58 00  75 ??  48 8B 06  F6 40 28 02  75 ??",
        at: 24, len: 2,
    },
];

const NOP: u8 = 0x90;

/// Current CS:S is native x86-64.
const GAME_EXES: &[&str] = &["cstrike_win64.exe"];
const GAME_EXE_DISPLAY: &str = "cstrike_win64.exe";
const CLIENT_DLL: &str = "client.dll";

// ---------------------------------------------------------------------------
// Win32
// ---------------------------------------------------------------------------

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;
type NtStatus = i32;

const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;
const PROCESS_CREATE_THREAD: Dword = 0x0002;
const PROCESS_VM_READ: Dword = 0x0010;
const PROCESS_VM_WRITE: Dword = 0x0020;
const PROCESS_VM_OPERATION: Dword = 0x0008;
const PROCESS_QUERY_INFORMATION: Dword = 0x0400;
const TH32CS_SNAPPROCESS: Dword = 0x0000_0002;
const TH32CS_SNAPTHREAD: Dword = 0x0000_0004;
const TH32CS_SNAPMODULE: Dword = 0x0000_0008;
const THREAD_SUSPEND_RESUME: Dword = 0x0002;
const ERROR_NO_MORE_FILES: Dword = 18;
const ERROR_INVALID_PARAMETER: Dword = 87;
const VK_F5: i32 = 0x74;
const VK_SCROLL: i32 = 0x91;
const CTRL_C_EVENT: Dword = 0;
const CTRL_BREAK_EVENT: Dword = 1;
/// `GetExitCodeProcess` reports this while the process is still running.
const STILL_ACTIVE: Dword = 259;

/// `PROCESSINFOCLASS::ProcessBasicInformation` — includes the native PEB.
const PROCESS_BASIC_INFORMATION_CLASS: Dword = 0;
const PEB64_PROCESS_PARAMETERS: usize = 0x20;
const PARAMS64_COMMAND_LINE: usize = 0x70;
const IMAGE_FILE_MACHINE_UNKNOWN: u16 = 0;
const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;
const PAGE_EXECUTE: Dword = 0x10;
const PAGE_EXECUTE_READ: Dword = 0x20;
const PAGE_EXECUTE_READWRITE: Dword = 0x40;
const PAGE_EXECUTE_WRITECOPY: Dword = 0x80;

/// Layout exported by `NtQueryInformationProcess(ProcessBasicInformation)`.
///
/// `winternl.h` intentionally exposes the fields around the PEB as reserved
/// pointers. This six-pointer form has the correct x64 alignment and keeps us
/// independent of the private names of the remaining fields.
#[repr(C)]
struct ProcessBasicInformation {
    _reserved1: *mut c_void,
    peb_base_address: *mut c_void,
    _reserved2: [*mut c_void; 2],
    _unique_process_id: usize,
    _reserved3: *mut c_void,
}

#[repr(C)]
struct ProcessEntry32W {
    dw_size: Dword,
    cnt_usage: Dword,
    th32_process_id: Dword,
    th32_default_heap_id: usize,
    th32_module_id: Dword,
    cnt_threads: Dword,
    th32_parent_process_id: Dword,
    pc_pri_class_base: i32,
    dw_flags: Dword,
    sz_exe_file: [u16; 260],
}

#[repr(C)]
struct ThreadEntry32 {
    size: Dword,
    usage: Dword,
    thread_id: Dword,
    owner_process_id: Dword,
    base_priority: i32,
    delta_priority: i32,
    flags: Dword,
}

#[repr(C)]
struct ModuleEntry32W {
    dw_size: Dword,
    th32_module_id: Dword,
    th32_process_id: Dword,
    glbl_cnt_usage: Dword,
    proc_cnt_usage: Dword,
    mod_base_addr: *mut u8,
    mod_base_size: Dword,
    h_module: Handle,
    sz_module: [u16; 256],
    sz_exe_path: [u16; 260],
}

#[repr(C)]
struct MemoryBasicInformation {
    _base_address: *mut c_void,
    _allocation_base: *mut c_void,
    _allocation_protect: Dword,
    _partition_id: u16,
    _region_size: usize,
    _state: Dword,
    protect: Dword,
    _kind: Dword,
}

// Everything below is declared with `kind = "raw-dylib"`, which makes rustc
// synthesise the import stubs from the DLL name alone. That matters for the
// two non-kernel32 libraries: std only guarantees kernel32 is linked, ntdll
// and user32 are not, and their import libraries live in different places on
// the MSVC and mingw targets. raw-dylib needs neither, so the same source
// links from a Windows runner and from `cargo zigbuild` on Linux.
#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(flags: Dword, pid: Dword) -> Handle;
    fn Process32FirstW(snap: Handle, e: *mut ProcessEntry32W) -> Bool;
    fn Process32NextW(snap: Handle, e: *mut ProcessEntry32W) -> Bool;
    fn Module32FirstW(snap: Handle, e: *mut ModuleEntry32W) -> Bool;
    fn Module32NextW(snap: Handle, e: *mut ModuleEntry32W) -> Bool;
    fn Thread32First(snap: Handle, e: *mut ThreadEntry32) -> Bool;
    fn Thread32Next(snap: Handle, e: *mut ThreadEntry32) -> Bool;
    fn OpenThread(access: Dword, inherit: Bool, thread_id: Dword) -> Handle;
    fn SuspendThread(thread: Handle) -> Dword;
    fn ResumeThread(thread: Handle) -> Dword;
    fn CloseHandle(h: Handle) -> Bool;
    fn OpenProcess(access: Dword, inherit: Bool, pid: Dword) -> Handle;
    fn ReadProcessMemory(
        h: Handle,
        addr: *const c_void,
        buf: *mut c_void,
        n: usize,
        got: *mut usize,
    ) -> Bool;
    fn WriteProcessMemory(
        h: Handle,
        addr: *mut c_void,
        buf: *const c_void,
        n: usize,
        put: *mut usize,
    ) -> Bool;
    fn FlushInstructionCache(h: Handle, addr: *const c_void, n: usize) -> Bool;
    fn VirtualProtectEx(
        h: Handle,
        addr: *mut c_void,
        n: usize,
        prot: Dword,
        old: *mut Dword,
    ) -> Bool;
    fn VirtualQueryEx(
        h: Handle,
        addr: *const c_void,
        info: *mut MemoryBasicInformation,
        len: usize,
    ) -> usize;
    fn IsWow64Process2(h: Handle, process_machine: *mut u16, native_machine: *mut u16) -> Bool;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn GetLastError() -> Dword;
    fn GetExitCodeProcess(h: Handle, code: *mut Dword) -> Bool;
    fn Sleep(ms: Dword);
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(Dword) -> Bool>,
        add: Bool,
    ) -> Bool;
}

#[link(name = "user32", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetAsyncKeyState(vk: i32) -> i16;
}

#[link(name = "shell32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CommandLineToArgvW(command_line: *const u16, argc: *mut i32) -> *mut *mut u16;
}

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn NtQueryInformationProcess(
        h: Handle,
        class: Dword,
        info: *mut c_void,
        len: Dword,
        ret_len: *mut Dword,
    ) -> NtStatus;
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

fn command_line_has_exact_arg(command_line: &str, wanted: &str) -> Result<bool, String> {
    if command_line.contains('\0') {
        return Err("target command line contains an embedded NUL".into());
    }
    let wide: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut argc = 0i32;
    let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &raw mut argc) };
    if argv.is_null() || argc < 0 {
        return Err(format!("CommandLineToArgvW failed ({})", unsafe {
            GetLastError()
        }));
    }
    let arguments = unsafe { std::slice::from_raw_parts(argv, argc as usize) };
    let found = arguments.iter().copied().any(|argument| {
        if argument.is_null() {
            return false;
        }
        let mut length = 0usize;
        while length < 32_768 && unsafe { *argument.add(length) } != 0 {
            length += 1;
        }
        length < 32_768
            && String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(argument, length) })
                .eq_ignore_ascii_case(wanted)
    });
    unsafe { LocalFree(argv.cast::<c_void>()) };
    Ok(found)
}

/// RAII snapshot handle — Toolhelp snapshots must be closed.
struct Snapshot(Handle);

impl Snapshot {
    fn new(flags: Dword, pid: Dword) -> Option<Snapshot> {
        let h = unsafe { CreateToolhelp32Snapshot(flags, pid) };
        (h != INVALID_HANDLE_VALUE && !h.is_null()).then_some(Snapshot(h))
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

// ---------------------------------------------------------------------------
// Target process
// ---------------------------------------------------------------------------

pub struct Module {
    pub base: usize,
    pub size: usize,
}

pub struct Process {
    handle: Handle,
    pub pid: u32,
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl Process {
    /// First running process whose image name is a supported CS:S executable.
    pub fn find_game() -> Option<u32> {
        let snap = Snapshot::new(TH32CS_SNAPPROCESS, 0)?;
        let mut e: ProcessEntry32W = unsafe { std::mem::zeroed() };
        e.dw_size = size_of::<ProcessEntry32W>() as Dword;
        let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
        while ok != 0 {
            let image = wide_to_string(&e.sz_exe_file);
            if GAME_EXES
                .iter()
                .any(|want| want.eq_ignore_ascii_case(&image))
            {
                return Some(e.th32_process_id);
            }
            ok = unsafe { Process32NextW(snap.0, &mut e) };
        }
        None
    }

    pub fn open(pid: u32) -> Option<Process> {
        let access = PROCESS_CREATE_THREAD
            | PROCESS_VM_READ
            | PROCESS_VM_WRITE
            | PROCESS_VM_OPERATION
            | PROCESS_QUERY_INFORMATION;
        let handle = unsafe { OpenProcess(access, 0, pid) };
        (!handle.is_null()).then_some(Process { handle, pid })
    }

    pub fn is_native_x64(&self) -> Result<bool, String> {
        let mut process_machine = 0u16;
        let mut native_machine = 0u16;
        if unsafe {
            IsWow64Process2(
                self.handle,
                &raw mut process_machine,
                &raw mut native_machine,
            )
        } == 0
        {
            return Err(format!("IsWow64Process2 failed ({})", unsafe {
                GetLastError()
            }));
        }
        Ok(process_machine == IMAGE_FILE_MACHINE_UNKNOWN
            && native_machine == IMAGE_FILE_MACHINE_AMD64)
    }

    /// Locate a module in the native x86-64 target.
    pub fn module(&self, want: &str) -> Option<Module> {
        self.module_checked(want).ok().flatten()
    }

    pub fn module_checked(&self, want: &str) -> Result<Option<Module>, String> {
        let snap = Snapshot::new(TH32CS_SNAPMODULE, self.pid)
            .ok_or_else(|| format!("module snapshot failed ({})", unsafe { GetLastError() }))?;
        let mut entry: ModuleEntry32W = unsafe { std::mem::zeroed() };
        entry.dw_size = size_of::<ModuleEntry32W>() as Dword;
        if unsafe { Module32FirstW(snap.0, &raw mut entry) } == 0 {
            let error = unsafe { GetLastError() };
            return (error == ERROR_NO_MORE_FILES)
                .then_some(None)
                .ok_or_else(|| format!("Module32FirstW failed ({error})"));
        }
        loop {
            if want.eq_ignore_ascii_case(&wide_to_string(&entry.sz_module)) {
                return Ok(Some(Module {
                    base: entry.mod_base_addr as usize,
                    size: entry.mod_base_size as usize,
                }));
            }
            if unsafe { Module32NextW(snap.0, &raw mut entry) } == 0 {
                let error = unsafe { GetLastError() };
                return (error == ERROR_NO_MORE_FILES)
                    .then_some(None)
                    .ok_or_else(|| format!("Module32NextW failed ({error})"));
            }
        }
    }

    pub fn read(&self, addr: usize, len: usize) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut got = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                self.handle,
                addr as *const c_void,
                buf.as_mut_ptr().cast::<c_void>(),
                len,
                &raw mut got,
            )
        };
        (ok != 0 && got == len).then_some(buf)
    }

    /// True while the target is still running. Used instead of re-scanning for
    /// the game by name, so `--attach <pid>` on any process behaves sanely.
    fn is_alive(&self) -> bool {
        let mut code: Dword = 0;
        let ok = unsafe { GetExitCodeProcess(self.handle, &raw mut code) };
        ok != 0 && code == STILL_ACTIVE
    }

    /// Read a whole span, tolerating unreadable pages (they come back zeroed).
    /// A module's image can contain guard/uncommitted pages that would fail an
    /// all-or-nothing read, and a zeroed hole simply cannot match a signature.
    pub fn read_span(&self, addr: usize, len: usize) -> Vec<u8> {
        const CHUNK: usize = 64 * 1024;
        let mut out = vec![0u8; len];
        let mut off = 0;
        while off < len {
            let n = CHUNK.min(len - off);
            if let Some(part) = self.read(addr + off, n) {
                out[off..off + n].copy_from_slice(&part);
            }
            off += n;
        }
        out
    }

    /// Decode UTF-16 bytes read from the target.
    fn read_utf16(&self, buffer: usize, len: usize) -> Option<String> {
        if buffer == 0 || len == 0 || !len.is_multiple_of(2) {
            return None;
        }
        let raw = self.read(buffer, len)?;
        let utf16: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&utf16))
    }

    fn command_line64(&self, peb: usize) -> Option<String> {
        let params = u64::from_le_bytes(
            self.read(peb + PEB64_PROCESS_PARAMETERS, 8)?
                .try_into()
                .ok()?,
        ) as usize;
        let us = self.read(params + PARAMS64_COMMAND_LINE, 16)?;
        let len = u16::from_le_bytes([us[0], us[1]]) as usize;
        let buffer = u64::from_le_bytes(us[8..16].try_into().ok()?) as usize;
        self.read_utf16(buffer, len)
    }

    /// Read the target's own command line from its native x86-64 PEB.
    ///
    /// Returns None for every failure along the way; the caller treats that as
    /// unknown, never as evidence that `-insecure` was absent.
    pub fn command_line(&self) -> Option<String> {
        let mut ret_len: Dword = 0;
        let mut basic: ProcessBasicInformation = unsafe { std::mem::zeroed() };
        let status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                PROCESS_BASIC_INFORMATION_CLASS,
                (&raw mut basic).cast::<c_void>(),
                size_of::<ProcessBasicInformation>() as Dword,
                &raw mut ret_len,
            )
        };
        if status < 0 || basic.peb_base_address.is_null() {
            return None;
        }
        self.command_line64(basic.peb_base_address as usize)
    }

    fn protection(&self, addr: usize) -> Result<Dword, String> {
        let mut info: MemoryBasicInformation = unsafe { std::mem::zeroed() };
        let read = unsafe {
            VirtualQueryEx(
                self.handle,
                addr as *const c_void,
                &raw mut info,
                size_of::<MemoryBasicInformation>(),
            )
        };
        if read != size_of::<MemoryBasicInformation>() {
            return Err(format!(
                "VirtualQueryEx failed at 0x{addr:x} ({})",
                unsafe { GetLastError() }
            ));
        }
        if !matches!(
            info.protect & 0xff,
            PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
        ) {
            return Err(format!(
                "0x{addr:x} is not in executable memory (protection 0x{:x})",
                info.protect
            ));
        }
        Ok(info.protect)
    }

    /// Write and verify executable bytes, always restoring the discovered
    /// protection. `repair_protection` is only for rollback after this
    /// transaction's own failed write.
    fn write(
        &self,
        addr: usize,
        data: &[u8],
        protection: Dword,
        repair_protection: bool,
    ) -> Result<(), String> {
        if data.is_empty() {
            return Err("refusing an empty executable-memory write".into());
        }

        let mut old: Dword = 0;
        if unsafe {
            VirtualProtectEx(
                self.handle,
                addr as *mut c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &raw mut old,
            )
        } == 0
        {
            return Err(format!("VirtualProtectEx failed ({})", unsafe {
                GetLastError()
            }));
        }
        if old != protection && !repair_protection {
            let mut ignored = 0u32;
            let restored = unsafe {
                VirtualProtectEx(
                    self.handle,
                    addr as *mut c_void,
                    data.len(),
                    old,
                    &raw mut ignored,
                )
            };
            return Err(if restored == 0 {
                format!(
                    "page protection changed from 0x{protection:x} to 0x{old:x}; \
                     restoring it also failed ({})",
                    unsafe { GetLastError() }
                )
            } else {
                format!("page protection changed from 0x{protection:x} to 0x{old:x}")
            });
        }

        let mut errors = Vec::new();
        let mut put = 0usize;
        let wrote = unsafe {
            WriteProcessMemory(
                self.handle,
                addr as *mut c_void,
                data.as_ptr().cast::<c_void>(),
                data.len(),
                &raw mut put,
            )
        };
        if wrote == 0 || put != data.len() {
            errors.push(format!(
                "WriteProcessMemory wrote {put}/{} bytes ({})",
                data.len(),
                unsafe { GetLastError() }
            ));
        }
        if unsafe { FlushInstructionCache(self.handle, addr as *const c_void, data.len()) } == 0 {
            errors.push(format!("FlushInstructionCache failed ({})", unsafe {
                GetLastError()
            }));
        }
        let mut ignored = 0u32;
        if unsafe {
            VirtualProtectEx(
                self.handle,
                addr as *mut c_void,
                data.len(),
                protection,
                &raw mut ignored,
            )
        } == 0
        {
            errors.push(format!("VirtualProtectEx restore failed ({})", unsafe {
                GetLastError()
            }));
        }
        if self.read(addr, data.len()).as_deref() != Some(data) {
            errors.push("executable-memory write did not verify".into());
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
}

fn target_thread_ids(pid: u32) -> Result<Vec<u32>, String> {
    let snapshot = Snapshot::new(TH32CS_SNAPTHREAD, 0)
        .ok_or_else(|| format!("thread snapshot failed ({})", unsafe { GetLastError() }))?;
    let mut entry: ThreadEntry32 = unsafe { std::mem::zeroed() };
    entry.size = size_of::<ThreadEntry32>() as u32;
    if unsafe { Thread32First(snapshot.0, &raw mut entry) } == 0 {
        let error = unsafe { GetLastError() };
        return (error == ERROR_NO_MORE_FILES)
            .then(Vec::new)
            .ok_or_else(|| format!("Thread32First failed ({error})"));
    }
    let mut tids = Vec::new();
    loop {
        if entry.owner_process_id == pid {
            tids.push(entry.thread_id);
        }
        if unsafe { Thread32Next(snapshot.0, &raw mut entry) } == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_NO_MORE_FILES {
                return Err(format!("Thread32Next failed ({error})"));
            }
            break;
        }
    }
    tids.sort_unstable();
    tids.dedup();
    Ok(tids)
}

struct RemoteThreadGuard {
    threads: Vec<(u32, Handle)>,
}

impl RemoteThreadGuard {
    fn suspend(pid: u32) -> Result<Self, String> {
        let mut guard = Self {
            threads: Vec::new(),
        };
        for _ in 0..16 {
            for thread_id in target_thread_ids(pid)? {
                if guard.threads.iter().any(|(known, _)| *known == thread_id) {
                    continue;
                }
                let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, thread_id) };
                if thread.is_null() {
                    let error = unsafe { GetLastError() };
                    if error == ERROR_INVALID_PARAMETER {
                        continue;
                    }
                    return Err(format!("OpenThread({thread_id}) failed ({error})"));
                }
                if unsafe { SuspendThread(thread) } == u32::MAX {
                    let error = unsafe { GetLastError() };
                    unsafe { CloseHandle(thread) };
                    if error == ERROR_INVALID_PARAMETER {
                        continue;
                    }
                    return Err(format!("SuspendThread({thread_id}) failed ({error})"));
                }
                guard.threads.push((thread_id, thread));
            }
            let current = target_thread_ids(pid)?;
            if current
                .iter()
                .all(|tid| guard.threads.iter().any(|(known, _)| known == tid))
            {
                return Ok(guard);
            }
        }
        Err("target kept creating threads while entering patch stop".into())
    }
}

impl Drop for RemoteThreadGuard {
    fn drop(&mut self) {
        for &(_, thread) in self.threads.iter().rev() {
            unsafe {
                ResumeThread(thread);
                CloseHandle(thread);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Patch state
// ---------------------------------------------------------------------------
struct PatchSite {
    name: &'static str,
    addr: usize,
    original: Vec<u8>,
    replacement: Vec<u8>,
    protection: Dword,
}

/// Set by the console control handler so the main loop can restore and exit.
static QUIT: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_ctrl(event: Dword) -> Bool {
    if event == CTRL_C_EVENT || event == CTRL_BREAK_EVENT {
        QUIT.store(true, Ordering::SeqCst);
        return 1; // handled: let the loop unwind and restore the bytes
    }
    0
}

fn quitting() -> bool {
    QUIT.load(Ordering::SeqCst)
}
fn find_sites(process: &Process, module: &Module) -> Result<Vec<PatchSite>, String> {
    let code = process.read_span(module.base, module.size);
    let mut sites = Vec::with_capacity(SIGS.len());
    for signature in SIGS {
        let pattern = signature
            .pattern()
            .ok_or_else(|| format!("signature {:?} is malformed", signature.name))?;
        let matches = pattern.find_all(&code);
        if matches.len() != 1 {
            return Err(format!(
                "{} matched {} times; expected exactly one",
                signature.name,
                matches.len()
            ));
        }
        let at = matches[0]
            .checked_add(signature.at)
            .ok_or_else(|| format!("{} patch offset overflowed", signature.name))?;
        let end = at
            .checked_add(signature.len)
            .ok_or_else(|| format!("{} patch length overflowed", signature.name))?;
        let original = code
            .get(at..end)
            .ok_or_else(|| format!("{} patch bytes are outside client.dll", signature.name))?
            .to_vec();
        let valid_branch = matches!(original.as_slice(), [0x0f, 0x85, ..] | [0x75, _]);
        if !valid_branch {
            return Err(format!("{} branch opcode changed", signature.name));
        }
        let addr = module
            .base
            .checked_add(at)
            .ok_or_else(|| format!("{} address overflowed", signature.name))?;
        if process.read(addr, original.len()).as_deref() != Some(original.as_slice()) {
            return Err(format!(
                "{} live bytes changed during discovery",
                signature.name
            ));
        }
        sites.push(PatchSite {
            name: signature.name,
            addr,
            replacement: vec![NOP; original.len()],
            protection: process.protection(addr)?,
            original,
        });
    }
    let [first, second] = sites.as_slice() else {
        return Err(format!(
            "resolved {} CheckJumpButton sites; expected exactly two",
            sites.len()
        ));
    };
    if first.addr == second.addr {
        return Err("CheckJumpButton signatures resolved to the same branch".into());
    }
    Ok(sites)
}

fn apply(process: &Process, sites: &[PatchSite], enabled: bool) -> Result<(), String> {
    let _threads = RemoteThreadGuard::suspend(process.pid)?;
    for site in sites {
        let expected = if enabled {
            &site.original
        } else {
            &site.replacement
        };
        if process.read(site.addr, expected.len()).as_deref() != Some(expected.as_slice()) {
            return Err(format!(
                "{} @ 0x{:x} is not in the expected prior state",
                site.name, site.addr
            ));
        }
        let protection = process.protection(site.addr)?;
        if protection != site.protection {
            return Err(format!(
                "{} @ 0x{:x} protection changed from 0x{:x} to 0x{protection:x}",
                site.name, site.addr, site.protection
            ));
        }
    }

    for (index, site) in sites.iter().enumerate() {
        let desired = if enabled {
            &site.replacement
        } else {
            &site.original
        };
        if let Err(error) = process.write(site.addr, desired, site.protection, false) {
            let mut rollback_errors = Vec::new();
            for rollback in sites[..=index].iter().rev() {
                let prior = if enabled {
                    &rollback.original
                } else {
                    &rollback.replacement
                };
                if let Err(rollback_error) =
                    process.write(rollback.addr, prior, rollback.protection, true)
                {
                    rollback_errors.push(format!("{}: {rollback_error}", rollback.name));
                }
            }
            let rollback = if rollback_errors.is_empty() {
                "transaction rolled back".to_string()
            } else {
                format!("rollback failed: {}", rollback_errors.join("; "))
            };
            return Err(format!(
                "writing {} @ 0x{:x}: {error}; {rollback}",
                site.name, site.addr
            ));
        }
    }

    println!(
        "\n=== Autobhop prediction: {} ===",
        if enabled { "ON" } else { "OFF" }
    );
    for site in sites {
        println!("    {:<28} @ {:#x}", site.name, site.addr);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Waiting for the game
// ---------------------------------------------------------------------------

/// Poll until CS:S is running. Unlike upstream we do not exit when the game is
/// not up yet — you can start this first and then launch the game.
fn wait_for_game() -> Option<u32> {
    if let Some(pid) = Process::find_game() {
        return Some(pid);
    }
    info!(game = GAME_EXE_DISPLAY, "waiting for CS:S");
    while !quitting() {
        unsafe { Sleep(250) };
        if let Some(pid) = Process::find_game() {
            return Some(pid);
        }
    }
    None
}

/// Poll until `client.dll` is mapped. It only appears once the game has loaded
/// the client, so this covers "run the tool at the main menu".
fn wait_for_client_dll(p: &Process) -> Option<Module> {
    if let Some(m) = p.module(CLIENT_DLL) {
        return Some(m);
    }
    info!(module = CLIENT_DLL, "waiting for game module");
    while !quitting() {
        unsafe { Sleep(250) };
        if let Some(m) = p.module(CLIENT_DLL) {
            return Some(m);
        }
        // the game exiting while we wait would otherwise spin forever
        if !p.is_alive() {
            warn!(module = CLIENT_DLL, "game exited while waiting for module");
            return None;
        }
    }
    None
}

/// One line naming the build, so a bug report identifies exactly what ran.
fn version_line() -> String {
    format!(
        "bunnyhopfix {} ({})",
        env!("CARGO_PKG_VERSION"),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    )
}

fn hook_dll_path() -> Result<PathBuf, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate bunnyhopfix.exe: {error}"))?;
    let directory = executable
        .parent()
        .ok_or_else(|| "bunnyhopfix.exe has no parent directory".to_string())?;
    let dll = directory.join("bhopfix.dll");
    if !dll.is_file() {
        return Err(format!("hook DLL is missing: {}", dll.display()));
    }
    Ok(dll)
}

fn hook_flags() -> u32 {
    let mut flags = 0u32;
    if crate::logging::hook_debug_enabled() {
        flags |= FLAG_DEBUG;
    }
    if std::env::var_os("BHOPFIX_NO_FORCE").is_none() {
        flags |= FLAG_FORCE_RAWINPUT2;
    }
    if std::env::var_os("BHOPFIX_DEMOS").is_some() {
        flags |= FLAG_DEMOS;
    }
    if std::env::var_os("BHOPFIX_KEEP_VIEWPUNCH").is_some() {
        flags |= FLAG_KEEP_VIEWPUNCH;
    }
    if std::env::var_os("BHOPFIX_NO_SOURCEJUMP").is_some() {
        flags |= FLAG_NO_SOURCEJUMP;
    }
    flags
}

fn print_feature_matrix(features: u64) {
    for (name, bit) in [
        ("rawinput2", FEATURE_RAWINPUT2),
        ("viewpunch remover", FEATURE_VIEWPUNCH),
        ("fastdl map interception", FEATURE_FASTDL),
        ("engine console", FEATURE_CONSOLE),
        ("download progress/flash", FEATURE_DOWNLOADS),
        ("fullscreen preservation", FEATURE_FULLSCREEN),
        ("SourceJump records", FEATURE_SOURCEJUMP),
    ] {
        println!(
            "    {:<27} {}",
            name,
            if features & bit != 0 {
                "ready"
            } else {
                "disabled"
            }
        );
    }
}

fn usage() {
    eprintln!(
        "{} (Windows x86-64) — CS:S prediction and feature hook\n\
         \n\
         USAGE:\n\
         \x20 bunnyhopfix [--attach <pid>] [--scroll-lock]\n\
         \n\
         Keep bunnyhopfix.exe and bhopfix.dll in the same directory. Start the\n\
         native x86-64 CS:S with -insecure first, then run this controller. It\n\
         patches both CheckJumpButton implementations and injects rawinput2,\n\
         viewpunch, fastdl, SourceJump, download, console, and fullscreen hooks.\n\
         \n\
         \x20 --attach <pid>   patch this pid instead of auto-detecting CS:S\n\
         \x20 --scroll-lock    let Scroll Lock also toggle prediction\n\
         \x20 --version, -V    print the version and exit\n\
         \n\
         LOGGING:\n\
         \x20 BHOPFIX_LOG=<filter>  tracing filter (for example: debug)\n\
         \x20 BHOPFIX_DEBUG=1       shorthand enabling hook/input debug telemetry\n\
         \n\
         F5 toggles prediction, F6 toggles fullscreen preservation, and F7\n\
         toggles viewpunch removal. Ctrl+C restores every patch and unloads the\n\
         hook DLL.\n\
         \n\
         Only use this on servers that actually do autobhop, and only with\n\
         -insecure. On a vanilla server, holding jump will mispredict.",
        version_line()
    );
}

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return;
    }
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{}", version_line());
        return;
    }
    let scroll_lock = args.iter().any(|a| a == "--scroll-lock");
    unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };

    // --- find the process ---------------------------------------------------
    let pid = match args.iter().position(|a| a == "--attach") {
        Some(i) => match args.get(i + 1).and_then(|s| s.parse::<u32>().ok()) {
            Some(pid) => {
                info!(pid, "attaching to game");
                pid
            }
            None => {
                usage();
                std::process::exit(2);
            }
        },
        None => match wait_for_game() {
            Some(pid) => {
                info!(pid, "found CS:S");
                pid
            }
            None => return, // Ctrl+C while waiting
        },
    };
    // Keep session context on error-only filters; span levels are filtered too.
    let _session_span = tracing::error_span!("game_session", pid).entered();

    let Some(proc) = Process::open(pid) else {
        error!(
            win32_error = unsafe { GetLastError() },
            "cannot open game process; try running as administrator"
        );
        std::process::exit(1);
    };

    match proc.is_native_x64() {
        Ok(true) => {}
        Ok(false) => {
            error!("target is not a native x86-64 process; refusing to patch");
            std::process::exit(1);
        }
        Err(error) => {
            error!(%error, "could not validate target architecture");
            std::process::exit(1);
        }
    }

    // --- -insecure enforcement ----------------------------------------------
    // Fail closed. This process is about to inject executable code; an
    // unreadable target command line is not evidence that VAC is disabled.
    match proc.command_line() {
        Some(command_line) => match command_line_has_exact_arg(&command_line, "-insecure") {
            Ok(true) => info!("confirmed exact -insecure command-line argument"),
            Ok(false) => {
                error!(
                    "game was not started with -insecure; refusing to patch or inject; \
                     add -insecure to the CS:S launch options and restart it"
                );
                std::process::exit(1);
            }
            Err(error) => {
                error!(%error, "could not parse the game's command line");
                std::process::exit(1);
            }
        },
        None => {
            error!(
                "could not read the game's command line; refusing to patch or inject; \
                 verify the target is native x86-64"
            );
            std::process::exit(1);
        }
    }

    // --- find client.dll ----------------------------------------------------
    let Some(module) = wait_for_client_dll(&proc) else {
        return; // Ctrl+C, or the game went away
    };
    info!(
        module = CLIENT_DLL,
        base = format_args!("{:#x}", module.base),
        size_kib = module.size / 1024,
        "game module ready"
    );

    // --- scan ---------------------------------------------------------------
    let sites = match find_sites(&proc, &module) {
        Ok(sites) => sites,
        Err(error) => {
            error!(
                %error,
                "CheckJumpButton discovery failed; no prediction bytes were written"
            );
            std::process::exit(1);
        }
    };
    info!(sites = sites.len(), "resolved prediction patch sites");

    // --- inject feature hook ------------------------------------------------
    let dll = match hook_dll_path() {
        Ok(path) => path,
        Err(error) => {
            error!(%error, "cannot locate hook DLL");
            std::process::exit(1);
        }
    };
    info!(dll = %dll.display(), "injecting feature hook");
    let mut hook = match inject::HookSession::inject(&proc, &dll, hook_flags()) {
        Ok(hook) => hook,
        Err(error) => {
            error!(%error, "hook injection failed");
            std::process::exit(1);
        }
    };
    if let Err(error) = hook.wait_ready(&proc) {
        hook.flush_logs();
        error!(%error, "hook startup failed");
        if !hook.unloaded() {
            error!("restart the game before retrying");
        }
        std::process::exit(1);
    }
    let features = hook.block().features.load(Ordering::Acquire);
    info!("Windows x64 hook feature matrix");
    print_feature_matrix(features);

    // --- patch --------------------------------------------------------------
    let mut on = true;
    if let Err(error) = apply(&proc, &sites, on) {
        error!(%error, "prediction patch transaction failed");
        match hook.shutdown(&proc) {
            Ok(()) => info!("hook DLL restored and unloaded"),
            Err(shutdown) => {
                error!(%shutdown, "hook cleanup after prediction failure failed");
                error!("restart the game before retrying");
            }
        }
        std::process::exit(1);
    }
    if scroll_lock {
        println!("(F5 or Scroll Lock toggles prediction; Ctrl+C restores and exits)");
    } else {
        println!("(F5 toggles prediction; Ctrl+C restores and exits)");
    }

    // Edge-detect the physical key rather than reading a toggle state: a
    // console app has no message pump, so GetKeyState's toggle bit is stale,
    // while GetAsyncKeyState's 0x8000 "down right now" bit is always live.
    let mut f5_down = unsafe { GetAsyncKeyState(VK_F5) } as u16 & 0x8000 != 0;
    let mut scroll_down = unsafe { GetAsyncKeyState(VK_SCROLL) } as u16 & 0x8000 != 0;
    while !quitting() {
        unsafe { Sleep(10) };
        hook.flush_logs();
        // the game exiting invalidates the module: stop touching it
        if proc.read(module.base, 2).is_none() {
            info!("game exited");
            return; // its memory is gone; nothing to restore
        }
        let f5 = unsafe { GetAsyncKeyState(VK_F5) } as u16 & 0x8000 != 0;
        let scroll = scroll_lock && unsafe { GetAsyncKeyState(VK_SCROLL) } as u16 & 0x8000 != 0;
        if f5 && !f5_down || scroll_lock && scroll && !scroll_down {
            let requested = !on;
            match apply(&proc, &sites, requested) {
                Ok(()) => on = requested,
                Err(error) => warn!(%error, "prediction toggle rejected"),
            }
        }
        f5_down = f5;
        scroll_down = scroll;
    }
    let restore_error = if on {
        apply(&proc, &sites, false).err()
    } else {
        None
    };
    if let Some(error) = &restore_error {
        error!(%error, "prediction restoration failed");
    } else {
        info!("original prediction bytes restored");
    }
    let hook_error = hook.shutdown(&proc).err();
    if let Some(error) = &hook_error {
        error!(%error, "hook shutdown failed");
    } else {
        info!("hook DLL restored and unloaded");
    }
    if restore_error.is_some() || hook_error.is_some() {
        error!("restart the game before running bunnyhopfix again");
        std::process::exit(1);
    }
}
