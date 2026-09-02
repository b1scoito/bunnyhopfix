//! Validated Windows engine console, demo, download, and flash integration.

use std::ffi::{CString, c_char, c_void};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};

use bhopfix_core::control::FLAG_DEMOS;

use super::api;
use super::control;
use super::module::LiveModule;

const ENGINE_CLIENT_CLASS: &str = ".?AVCEngineClient@@";
const ENGINE_CLIENT_INTERFACE: &[u8] = b"VEngineClient014\0";
const CLIENT_CMD_PATTERN: &str = "40 53 48 83 EC 20 80 3D ?? ?? ?? ?? 00 48 8B DA";
const DOWNLOAD_MANAGER_CLASS: &str = ".?AVCDownloadManager@@";
const DOWNLOAD_UPDATE_PATTERN: &str = "40 53 48 81 EC 40 02 00 00 4C 8B 41 28 48 8B D9";

const MANAGER_REQUEST: usize = 0x28;
const REQUEST_HTTP: usize = 0x03;
const REQUEST_STATE: usize = 0x08;
const REQUEST_NAME: usize = 0x314;
const REQUEST_TOTAL: usize = 0x618;
const REQUEST_CURRENT: usize = 0x61c;

static INTERFACE: AtomicUsize = AtomicUsize::new(0);
static CLIENT_CMD: AtomicUsize = AtomicUsize::new(0);
static DOWNLOAD_MANAGER: AtomicUsize = AtomicUsize::new(0);
static GAME_WINDOW: AtomicUsize = AtomicUsize::new(0);
static READY: AtomicBool = AtomicBool::new(false);
static DEMOS_ENABLED: AtomicBool = AtomicBool::new(false);
static WAS_DOWNLOADING: AtomicBool = AtomicBool::new(false);
static LAST_PERCENT: AtomicI32 = AtomicI32::new(-1);
static POLLS: AtomicUsize = AtomicUsize::new(0);
static DEMO_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

static COMMANDS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static PENDING_DEMO: Mutex<Option<String>> = Mutex::new(None);

type CreateInterface = unsafe extern "system" fn(*const c_char, *mut i32) -> *mut c_void;
type ClientCmd = unsafe extern "system" fn(*mut c_void, *const c_char);

fn read_value<T: Copy>(address: usize) -> Option<T> {
    let mut value = std::mem::MaybeUninit::<T>::uninit();
    let mut read = 0usize;
    let ok = unsafe {
        api::ReadProcessMemory(
            api::GetCurrentProcess(),
            address as *const c_void,
            value.as_mut_ptr().cast::<c_void>(),
            size_of::<T>(),
            &raw mut read,
        )
    };
    (ok != 0 && read == size_of::<T>()).then(|| unsafe { value.assume_init() })
}

fn resolve_client_cmd(engine: &LiveModule) -> Result<(usize, usize), String> {
    let create_rva = engine
        .pe
        .export("CreateInterface")
        .ok_or_else(|| "engine.dll does not export CreateInterface".to_string())?;
    let create_address = engine
        .address(create_rva)
        .filter(|&address| engine.contains_exec(address))
        .ok_or_else(|| "engine CreateInterface export is not executable".to_string())?;
    let create: CreateInterface = unsafe { std::mem::transmute(create_address) };
    let mut status = 0i32;
    let interface = unsafe {
        create(
            ENGINE_CLIENT_INTERFACE.as_ptr().cast::<c_char>(),
            &raw mut status,
        )
    } as usize;
    if interface == 0 {
        return Err(format!(
            "CreateInterface(VEngineClient014) failed ({status})"
        ));
    }
    let vtable = read_value::<usize>(interface)
        .ok_or_else(|| "VEngineClient014 object is unreadable".to_string())?;

    let (slot_rva, function_rva) = engine
        .resolve_virtual(ENGINE_CLIENT_CLASS, &[CLIENT_CMD_PATTERN], 0x70)
        .ok_or_else(|| "CEngineClient ClientCmd virtual is missing or ambiguous".to_string())?;
    let owner = engine
        .pe
        .vtables(ENGINE_CLIENT_CLASS)
        .into_iter()
        .find(|candidate| {
            slot_rva >= candidate.rva
                && slot_rva < candidate.rva + 256 * size_of::<usize>()
                && (slot_rva - candidate.rva).is_multiple_of(size_of::<usize>())
        })
        .ok_or_else(|| "ClientCmd slot has no CEngineClient vtable owner".to_string())?;
    let expected_vtable = engine
        .address(owner.rva)
        .ok_or_else(|| "CEngineClient vtable RVA is invalid".to_string())?;
    if vtable != expected_vtable {
        return Err(format!(
            "VEngineClient014 vptr 0x{vtable:x} is not CEngineClient 0x{expected_vtable:x}"
        ));
    }
    let function = engine
        .address(function_rva)
        .filter(|&address| engine.contains_exec(address))
        .ok_or_else(|| "ClientCmd function is not executable engine code".to_string())?;
    let live_slot = read_value::<usize>(engine.base + slot_rva)
        .ok_or_else(|| "ClientCmd vtable slot is unreadable".to_string())?;
    if live_slot != function {
        return Err("ClientCmd live vtable slot differs from engine.dll".into());
    }
    Ok((interface, function))
}

fn resolve_download_manager(engine: &LiveModule) -> Result<usize, String> {
    let vtables = engine.pe.vtables(DOWNLOAD_MANAGER_CLASS);
    let [vtable] = vtables.as_slice() else {
        return Err("CDownloadManager primary vtable is missing or ambiguous".into());
    };
    if vtable.object_offset != 0 {
        return Err("CDownloadManager primary vtable has a nonzero object offset".into());
    }
    engine
        .resolve_virtual(DOWNLOAD_MANAGER_CLASS, &[DOWNLOAD_UPDATE_PATTERN], 0x30)
        .ok_or_else(|| "CDownloadManager request layout validation failed".to_string())?;
    let wanted = engine
        .address(vtable.rva)
        .ok_or_else(|| "CDownloadManager vtable RVA is invalid".to_string())?;
    let (start, end) = engine
        .pe
        .writable_span()
        .ok_or_else(|| "engine.dll has no writable image span".to_string())?;
    let data = engine
        .live_bytes(start, end - start)
        .ok_or_else(|| "engine writable image is unreadable".to_string())?;
    let mut found = None;
    for (index, word) in data.as_chunks::<8>().0.iter().enumerate() {
        if usize::from_ne_bytes(*word) != wanted {
            continue;
        }
        let candidate = engine.base + start + index * 8;
        if found.replace(candidate).is_some() {
            return Err("multiple live CDownloadManager objects found".into());
        }
    }
    found.ok_or_else(|| "live CDownloadManager singleton was not found".to_string())
}

pub(crate) struct Integration;

impl Integration {
    pub(crate) fn install(engine: &LiveModule) -> Result<Self, String> {
        let (interface, client_cmd) = resolve_client_cmd(engine)?;
        let download_manager = resolve_download_manager(engine)?;
        INTERFACE.store(interface, Ordering::Release);
        CLIENT_CMD.store(client_cmd, Ordering::Release);
        DOWNLOAD_MANAGER.store(download_manager, Ordering::Release);
        DEMOS_ENABLED.store(control::flags() & FLAG_DEMOS != 0, Ordering::Release);
        READY.store(true, Ordering::Release);
        control::emit(&format!(
            "engine: VEngineClient014 ClientCmd 0x{client_cmd:x}; CDownloadManager 0x{download_manager:x}"
        ));
        if DEMOS_ENABLED.load(Ordering::Relaxed) {
            control::emit("engine: automatic per-map POV demos enabled");
        }
        Ok(Self)
    }

    pub(crate) fn shutdown(&mut self) {
        READY.store(false, Ordering::Release);
        INTERFACE.store(0, Ordering::Release);
        CLIENT_CMD.store(0, Ordering::Release);
        DOWNLOAD_MANAGER.store(0, Ordering::Release);
        GAME_WINDOW.store(0, Ordering::Release);
        if let Ok(mut commands) = COMMANDS.lock() {
            commands.clear();
        }
        if let Ok(mut demo) = PENDING_DEMO.lock() {
            *demo = None;
        }
    }
}

pub(crate) fn set_window(window: api::Hwnd) {
    if !window.is_null() {
        GAME_WINDOW.store(window as usize, Ordering::Release);
    }
}

pub(crate) fn queue_command(command: impl Into<String>) {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let mut command = command.into();
    if command.len() > 180 {
        let mut boundary = 180;
        while !command.is_char_boundary(boundary) {
            boundary -= 1;
        }
        command.truncate(boundary);
    }
    if let Ok(mut commands) = COMMANDS.lock()
        && commands.len() < 32
    {
        commands.push(command);
    }
}

impl Drop for Integration {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) fn arm_demo(map: &str) {
    if !DEMOS_ENABLED.load(Ordering::Acquire) || !READY.load(Ordering::Acquire) {
        return;
    }
    if let Ok(mut pending) = PENDING_DEMO.lock() {
        *pending = Some(map.to_string());
    }
}

fn start_demo() {
    let map = match PENDING_DEMO.lock() {
        Ok(mut pending) => pending.take(),
        Err(_) => None,
    };
    let Some(map) = map else {
        return;
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_else(|_| DEMO_SEQUENCE.fetch_add(1, Ordering::Relaxed) as u64);
    queue_command("stop");
    queue_command(format!("record {map}_{timestamp}"));
    control::emit(&format!("demo: recording {map}_{timestamp}.dem"));
}

fn pump_commands() {
    if !READY.load(Ordering::Acquire) {
        return;
    }
    let commands = match COMMANDS.lock() {
        Ok(mut commands) if !commands.is_empty() => std::mem::take(&mut *commands),
        _ => return,
    };
    let interface = INTERFACE.load(Ordering::Acquire) as *mut c_void;
    let function = CLIENT_CMD.load(Ordering::Acquire);
    if interface.is_null() || function == 0 {
        return;
    }
    let client_cmd: ClientCmd = unsafe { std::mem::transmute(function) };
    for command in commands {
        if let Ok(command) = CString::new(command) {
            unsafe { client_cmd(interface, command.as_ptr()) };
        }
    }
}

fn poll_downloads() {
    if !POLLS.fetch_add(1, Ordering::Relaxed).is_multiple_of(16) {
        return;
    }
    let manager = DOWNLOAD_MANAGER.load(Ordering::Acquire);
    if manager == 0 {
        return;
    }
    let Some(request) = read_value::<usize>(manager + MANAGER_REQUEST) else {
        return;
    };
    if request == 0 {
        if WAS_DOWNLOADING.swap(false, Ordering::AcqRel) {
            LAST_PERCENT.store(-1, Ordering::Release);
            control::emit("download complete");
            let window = GAME_WINDOW.load(Ordering::Acquire) as api::Hwnd;
            if !window.is_null() {
                unsafe { api::FlashWindow(window, 1) };
            }
        }
        return;
    }
    let Some(http) = read_value::<u8>(request + REQUEST_HTTP) else {
        return;
    };
    let Some(state) = read_value::<i32>(request + REQUEST_STATE) else {
        return;
    };
    let Some(total) = read_value::<i32>(request + REQUEST_TOTAL) else {
        return;
    };
    let Some(current) = read_value::<i32>(request + REQUEST_CURRENT) else {
        return;
    };
    if http == 0 || state != 1 || total <= 0 || current < 0 || current > total {
        return;
    }
    let percent = ((i64::from(current) * 100) / i64::from(total)) as i32;
    let last = LAST_PERCENT.load(Ordering::Acquire);
    if last >= 0 && percent < last + 5 && percent < 100 {
        return;
    }
    let Some(name) = read_value::<[u8; 128]>(request + REQUEST_NAME) else {
        return;
    };
    let end = name
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(name.len());
    let name = &name[..end];
    if name.is_empty()
        || !name.iter().all(|byte| (0x20..0x7f).contains(byte))
        || !name.contains(&b'/') && !name.contains(&b'\\')
    {
        return;
    }
    LAST_PERCENT.store(percent, Ordering::Release);
    WAS_DOWNLOADING.store(true, Ordering::Release);
    let file = name
        .rsplit(|byte| *byte == b'/' || *byte == b'\\')
        .next()
        .unwrap_or(b"map");
    control::emit(&format!(
        "downloading {}: {percent}% ({} / {} KB)",
        String::from_utf8_lossy(file),
        current / 1024,
        total / 1024
    ));
}

pub(crate) fn tick() {
    start_demo();
    pump_commands();
    poll_downloads();
}
