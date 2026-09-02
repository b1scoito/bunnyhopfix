//! Tick-aligned Raw Input 2 implementation for the Windows x64 client.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

use bhopfix_core::control::{FLAG_DEBUG, FLAG_FORCE_RAWINPUT2};
use bhopfix_core::pe::Access;

use super::api;
use super::control;
use super::hook::{InlineHook, PointerHook};
use super::module::LiveModule;

const CAPACITY: usize = 1024;
const WINDOW_PROC_PATTERN: &str = "44 89 44 24 ?? 48 89 54 24 ?? 55 56 57 41 56 41 57";
const GET_RAW_PATTERN: &str = "8B 81 DC 48 00 00 89 02 8B 81 E0 48 00 00 41 89 00";
const SET_SAMPLE_PATTERN: &str = "F3 0F 11 49 20 C3";
const ACCUMULATE_PATTERN: &str = concat!(
    "48 89 5C 24 18 48 89 74 24 20 57 48 83 EC 20 ",
    "8B 41 0C 49 8B F8 89 02 48 8B F2 8B 41 10 48 8B D9 41 89 00 ",
    "48 8B 05 ?? ?? ?? ?? 83 78 58 00"
);

static ORIGINAL_WINDOW_PROC: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_GET_RAW: AtomicUsize = AtomicUsize::new(0);
static ORIGINAL_SET_SAMPLE: AtomicUsize = AtomicUsize::new(0);
static M_RAWINPUT: AtomicUsize = AtomicUsize::new(0);
static FORCED: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);
static ACTIVE_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static SAMPLE_REMAINING: AtomicU64 = AtomicU64::new(0);
static LAST_SERVE: AtomicU64 = AtomicU64::new(0);
static FREQUENCY: AtomicU64 = AtomicU64::new(0);
static SERVES: AtomicU64 = AtomicU64::new(0);

struct Ring {
    timestamps: [AtomicU64; CAPACITY],
    x: [AtomicI32; CAPACITY],
    y: [AtomicI32; CAPACITY],
}

static RING: Ring = Ring {
    timestamps: [const { AtomicU64::new(0) }; CAPACITY],
    x: [const { AtomicI32::new(0) }; CAPACITY],
    y: [const { AtomicI32::new(0) }; CAPACITY],
};
static WRITE_INDEX: AtomicUsize = AtomicUsize::new(0);
static READ_INDEX: AtomicUsize = AtomicUsize::new(0);

fn qpc_now() -> f64 {
    let mut frequency = FREQUENCY.load(Ordering::Relaxed);
    if frequency == 0 {
        let mut resolved = 0i64;
        if unsafe { api::QueryPerformanceFrequency(&raw mut resolved) } == 0 || resolved <= 0 {
            return 0.0;
        }
        frequency = resolved as u64;
        FREQUENCY.store(frequency, Ordering::Relaxed);
    }
    let mut counter = 0i64;
    if unsafe { api::QueryPerformanceCounter(&raw mut counter) } == 0 {
        return 0.0;
    }
    counter as f64 / frequency as f64
}

fn ring_push(timestamp: f64, x: i32, y: i32) {
    // WindowProc is the sole producer. Do not publish WRITE_INDEX until every
    // field is initialized; if the consumer falls a full ring behind, dropping
    // the newest event is safer than overwriting a slot it may be reading.
    let write = WRITE_INDEX.load(Ordering::Relaxed);
    let read = READ_INDEX.load(Ordering::Acquire);
    if write.wrapping_sub(read) >= CAPACITY {
        return;
    }
    let slot = write % CAPACITY;
    RING.x[slot].store(x, Ordering::Relaxed);
    RING.y[slot].store(y, Ordering::Relaxed);
    RING.timestamps[slot].store(timestamp.to_bits(), Ordering::Relaxed);
    WRITE_INDEX.store(write.wrapping_add(1), Ordering::Release);
}

fn ring_drain(threshold: f64) -> (i32, i32) {
    let (mut x, mut y) = (0i32, 0i32);
    loop {
        let read = READ_INDEX.load(Ordering::Relaxed);
        let write = WRITE_INDEX.load(Ordering::Acquire);
        if read == write {
            break;
        }
        let slot = read % CAPACITY;
        let timestamp = f64::from_bits(RING.timestamps[slot].load(Ordering::Acquire));
        if timestamp > threshold {
            break;
        }
        x = x.saturating_add(RING.x[slot].load(Ordering::Relaxed));
        y = y.saturating_add(RING.y[slot].load(Ordering::Relaxed));
        READ_INDEX.store(read + 1, Ordering::Release);
    }
    (x, y)
}

fn rawinput_mode() -> i32 {
    let address = M_RAWINPUT.load(Ordering::Acquire);
    if address == 0 {
        return 1;
    }
    unsafe { std::ptr::read_volatile(address as *const i32) }
}

fn force_rawinput2() {
    if control::flags() & FLAG_FORCE_RAWINPUT2 == 0 || FORCED.swap(true, Ordering::AcqRel) {
        return;
    }
    let address = M_RAWINPUT.load(Ordering::Acquire);
    if address == 0 {
        FORCED.store(false, Ordering::Release);
        return;
    }
    unsafe { std::ptr::write_volatile(address as *mut i32, 2) };
    super::engine::queue_command("m_rawinput 2");
    control::emit("m_rawinput defaulted to mode 2; modes 0 and 1 remain selectable");
}

type WindowProc = unsafe extern "system" fn(
    *mut c_void,
    api::Hwnd,
    u32,
    api::Wparam,
    api::Lparam,
) -> api::Lresult;
type GetRaw = unsafe extern "system" fn(*mut c_void, *mut i32, *mut i32) -> bool;
type SetSample = unsafe extern "system" fn(*mut c_void, f32);
struct CallbackGuard;

impl CallbackGuard {
    fn enter() -> Self {
        ACTIVE_CALLBACKS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for CallbackGuard {
    fn drop(&mut self) {
        ACTIVE_CALLBACKS.fetch_sub(1, Ordering::AcqRel);
    }
}

unsafe extern "system" fn hooked_window_proc(
    this: *mut c_void,
    window: api::Hwnd,
    message: u32,
    wparam: api::Wparam,
    lparam: api::Lparam,
) -> api::Lresult {
    let _guard = CallbackGuard::enter();
    super::engine::set_window(window);
    if message == api::WM_INPUT {
        let mut input: api::RawInput = unsafe { std::mem::zeroed() };
        let mut size = size_of::<api::RawInput>() as u32;
        let copied = unsafe {
            api::GetRawInputData(
                lparam as api::Handle,
                api::RID_INPUT,
                (&raw mut input).cast::<c_void>(),
                &raw mut size,
                size_of::<api::RawInputHeader>() as u32,
            )
        };
        if copied != u32::MAX
            && copied >= (size_of::<api::RawInputHeader>() + size_of::<api::RawMouse>()) as u32
            && input.header.kind == api::RIM_TYPEMOUSE
        {
            let mouse = unsafe { input.data.mouse };
            // Absolute pointing devices report coordinates, not deltas.
            if mouse.flags & 1 == 0 && (mouse.last_x != 0 || mouse.last_y != 0) {
                ring_push(qpc_now(), mouse.last_x, mouse.last_y);
                control::record_raw_event();
            }
        }
    }

    let original = ORIGINAL_WINDOW_PROC.load(Ordering::Acquire);
    if original == 0 {
        return 0;
    }
    let original: WindowProc = unsafe { std::mem::transmute(original) };
    unsafe { original(this, window, message, wparam, lparam) }
}

unsafe extern "system" fn hooked_get_raw(
    this: *mut c_void,
    out_x: *mut i32,
    out_y: *mut i32,
) -> bool {
    let _guard = CallbackGuard::enter();
    let original = ORIGINAL_GET_RAW.load(Ordering::Acquire);
    if original == 0 || out_x.is_null() || out_y.is_null() {
        return false;
    }
    let original: GetRaw = unsafe { std::mem::transmute(original) };
    let (mut stock_x, mut stock_y) = (0i32, 0i32);
    let supported = unsafe { original(this, &raw mut stock_x, &raw mut stock_y) };
    let mode = rawinput_mode();

    let now = qpc_now();
    let last = LAST_SERVE.swap(now.to_bits(), Ordering::AcqRel);
    let mut remaining = f64::from_bits(SAMPLE_REMAINING.load(Ordering::Acquire));
    if last != 0 {
        remaining = (remaining - (now - f64::from_bits(last))).max(0.0);
        SAMPLE_REMAINING.store(remaining.to_bits(), Ordering::Release);
    }

    let (x, y) = if mode == 2 {
        ring_drain(now - remaining)
    } else {
        let _ = ring_drain(f64::INFINITY);
        (stock_x, stock_y)
    };
    unsafe {
        *out_x = x;
        *out_y = y;
    }
    control::record_raw_serve();

    let serves = SERVES.fetch_add(1, Ordering::Relaxed) + 1;
    if serves % 600 == 1 && control::flags() & FLAG_DEBUG != 0 {
        control::debug(&format!(
            "rawinput: serves={serves} mode={mode} out=({x},{y}) queued={}",
            WRITE_INDEX
                .load(Ordering::Relaxed)
                .wrapping_sub(READ_INDEX.load(Ordering::Relaxed))
        ));
    }
    supported
}

unsafe extern "system" fn hooked_set_sample(this: *mut c_void, sample_time: f32) {
    let _guard = CallbackGuard::enter();
    SAMPLE_REMAINING.store((sample_time.max(0.0) as f64).to_bits(), Ordering::Release);
    LAST_SERVE.store(qpc_now().to_bits(), Ordering::Release);
    let original = ORIGINAL_SET_SAMPLE.load(Ordering::Acquire);
    if original != 0 {
        let original: SetSample = unsafe { std::mem::transmute(original) };
        unsafe { original(this, sample_time) };
    }
    force_rawinput2();
    super::engine::tick();
}

fn resolve_m_rawinput(client: &LiveModule) -> Result<usize, String> {
    let (function_rva, bytes) = client
        .find_unique(&[ACCUMULATE_PATTERN], Access::Code)
        .ok_or_else(|| {
            "client raw-input accumulator signature is missing or ambiguous".to_string()
        })?;
    const LOAD_OFFSET: usize = 35;
    if bytes.get(LOAD_OFFSET..LOAD_OFFSET + 3) != Some(&[0x48, 0x8b, 0x05]) {
        return Err("client raw-input ConVar instruction changed".into());
    }
    let displacement = i32::from_le_bytes(
        bytes
            .get(LOAD_OFFSET + 3..LOAD_OFFSET + 7)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "client raw-input displacement is truncated".to_string())?,
    );
    let pointer_cell_rva = (function_rva + LOAD_OFFSET + 7)
        .checked_add_signed(displacement as isize)
        .ok_or_else(|| "client raw-input ConVar displacement overflowed".to_string())?;
    let pointer_cell = client
        .address(pointer_cell_rva)
        .ok_or_else(|| "client raw-input ConVar pointer is outside client.dll".to_string())?;
    let object = unsafe { std::ptr::read_unaligned(pointer_cell as *const usize) };
    if !client.contains(object) {
        return Err("m_rawinput object is outside client.dll".into());
    }
    let object_rva = object - client.base;
    let value_rva = object_rva
        .checked_add(0x58)
        .ok_or_else(|| "m_rawinput value address overflowed".to_string())?;
    let (data_start, data_end) = client
        .pe
        .writable_span()
        .ok_or_else(|| "client.dll has no writable PE span".to_string())?;
    if object_rva < data_start || value_rva + size_of::<i32>() > data_end {
        return Err("m_rawinput object is not in writable client data".into());
    }
    let name_pointer = unsafe { std::ptr::read_unaligned((object + 0x18) as *const usize) };
    if !client.contains(name_pointer) {
        return Err("m_rawinput name pointer is outside client.dll".into());
    }
    let name = unsafe { std::slice::from_raw_parts(name_pointer as *const u8, 11) };
    if name != b"m_rawinput\0" {
        return Err("resolved ConVar is not m_rawinput".into());
    }
    let value = unsafe { std::ptr::read_volatile((object + 0x58) as *const i32) };
    if !(0..=2).contains(&value) {
        return Err(format!("m_rawinput has invalid live value {value}"));
    }
    Ok(object + 0x58)
}

pub(crate) struct Hooks {
    sample: Vec<PointerHook>,
    get_raw: PointerHook,
    window_proc: InlineHook,
}

impl Hooks {
    pub(crate) fn install(inputsystem: &LiveModule, client: &LiveModule) -> Result<Self, String> {
        let (window_rva, window_bytes) = inputsystem
            .find_unique(&[WINDOW_PROC_PATTERN], Access::Code)
            .ok_or_else(|| {
                "CInputSystem::WindowProc signature is missing or ambiguous".to_string()
            })?;
        let (get_slot_rva, get_function_rva) = inputsystem
            .resolve_virtual(".?AVCInputSystem@@", &[GET_RAW_PATTERN], 32)
            .ok_or_else(|| {
                "CInputSystem::GetRawMouseAccumulators vtable slot is missing".to_string()
            })?;

        let mut sample_targets = Vec::with_capacity(2);
        for class in [".?AVCInput@@", ".?AVCCSInput@@"] {
            let target = client
                .resolve_virtual(class, &[SET_SAMPLE_PATTERN], 16)
                .ok_or_else(|| format!("{class}::IN_SetSampleTime vtable slot is missing"))?;
            if !sample_targets.contains(&target) {
                sample_targets.push(target);
            }
        }
        let [first_sample, second_sample] = sample_targets.as_slice() else {
            return Err("CInput sample-time vtables did not resolve exactly twice".into());
        };
        if first_sample.1 != second_sample.1 {
            return Err(
                "CInput sample-time vtables do not share one validated implementation".into(),
            );
        }

        let rawinput = resolve_m_rawinput(client)?;
        let get_original = inputsystem
            .address(get_function_rva)
            .ok_or_else(|| "raw-input function RVA is invalid".to_string())?;
        let sample_original = client
            .address(first_sample.1)
            .ok_or_else(|| "sample-time function RVA is invalid".to_string())?;
        let window_address = inputsystem
            .address(window_rva)
            .ok_or_else(|| "window-proc function RVA is invalid".to_string())?;
        let get_slot = inputsystem
            .address(get_slot_rva)
            .ok_or_else(|| "raw-input vtable slot RVA is invalid".to_string())?;
        let sample_slots = sample_targets
            .iter()
            .map(|(slot_rva, _)| {
                client
                    .address(*slot_rva)
                    .ok_or_else(|| "sample-time vtable slot RVA is invalid".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;

        M_RAWINPUT.store(rawinput, Ordering::Release);
        ORIGINAL_GET_RAW.store(get_original, Ordering::Release);
        ORIGINAL_SET_SAMPLE.store(sample_original, Ordering::Release);
        FORCED.store(false, Ordering::Release);

        DIRTY.store(true, Ordering::Release);
        let mut window_proc = match InlineHook::install(
            window_address,
            &window_bytes,
            hooked_window_proc as *const () as usize,
            &ORIGINAL_WINDOW_PROC,
        ) {
            Ok(hook) => hook,
            Err(error) => {
                if error.is_clean() {
                    clear_globals();
                    DIRTY.store(false, Ordering::Release);
                }
                return Err(error.to_string());
            }
        };
        let mut get_raw = match PointerHook::install(
            get_slot,
            get_original,
            hooked_get_raw as *const () as usize,
        ) {
            Ok(hook) => hook,
            Err(error) => {
                if !error.is_clean() {
                    return Err(error.to_string());
                }
                let cleanup = cleanup_hooks(&mut [], None, &mut window_proc);
                return Err(with_cleanup(error.to_string(), cleanup));
            }
        };
        let mut sample = Vec::with_capacity(sample_slots.len());
        for slot in sample_slots {
            match PointerHook::install(
                slot,
                sample_original,
                hooked_set_sample as *const () as usize,
            ) {
                Ok(hook) => sample.push(hook),
                Err(error) => {
                    if !error.is_clean() {
                        return Err(error.to_string());
                    }
                    let cleanup = cleanup_hooks(&mut sample, Some(&mut get_raw), &mut window_proc);
                    return Err(with_cleanup(error.to_string(), cleanup));
                }
            }
        }

        control::emit("rawinput2: WindowProc, accumulator, and tick hooks installed");
        Ok(Self {
            sample,
            get_raw,
            window_proc,
        })
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        cleanup_hooks(
            &mut self.sample,
            Some(&mut self.get_raw),
            &mut self.window_proc,
        )
    }
}

fn with_cleanup(error: String, cleanup: Result<(), String>) -> String {
    match cleanup {
        Ok(()) => error,
        Err(cleanup) => format!("{error}; partial-hook cleanup failed: {cleanup}"),
    }
}

fn cleanup_hooks(
    sample: &mut [PointerHook],
    mut get_raw: Option<&mut PointerHook>,
    window_proc: &mut InlineHook,
) -> Result<(), String> {
    let mut first_error = None;
    for hook in sample.iter_mut().rev() {
        if let Err(error) = hook.restore()
            && first_error.is_none()
        {
            first_error = Some(error);
        }
    }
    if let Some(hook) = get_raw.as_mut()
        && let Err(error) = hook.restore()
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    if let Err(error) = window_proc.restore()
        && first_error.is_none()
    {
        first_error = Some(error);
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    for _ in 0..10_000 {
        if ACTIVE_CALLBACKS.load(Ordering::Acquire) == 0 {
            window_proc.release_trampoline()?;
            clear_globals();
            DIRTY.store(false, Ordering::Release);
            return Ok(());
        }
        unsafe { api::Sleep(1) };
    }
    Err("rawinput callbacks did not quiesce within 10 seconds".into())
}

pub(crate) fn is_quiescent() -> bool {
    !DIRTY.load(Ordering::Acquire) && ACTIVE_CALLBACKS.load(Ordering::Acquire) == 0
}

fn clear_globals() {
    ORIGINAL_WINDOW_PROC.store(0, Ordering::Release);
    ORIGINAL_GET_RAW.store(0, Ordering::Release);
    ORIGINAL_SET_SAMPLE.store(0, Ordering::Release);
    M_RAWINPUT.store(0, Ordering::Release);
    FORCED.store(false, Ordering::Release);
    SAMPLE_REMAINING.store(0, Ordering::Release);
    LAST_SERVE.store(0, Ordering::Release);
    READ_INDEX.store(WRITE_INDEX.load(Ordering::Acquire), Ordering::Release);
}
