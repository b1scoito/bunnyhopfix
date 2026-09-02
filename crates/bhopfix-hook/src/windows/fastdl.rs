//! Reversible fastdl.me map-version interception for the Windows x64 engine.

use std::ffi::c_void;
use std::fmt::Write as _;
use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bhopfix_core::control::FLAG_NO_SOURCEJUMP;
use bhopfix_core::sig::Pattern;
use bzip2::read::BzDecoder;

use super::api;
use super::control;
use super::hook::PointerHook;
use super::module::LiveModule;

const CLIENT_STATE_CLASS: &str = ".?AVCClientState@@";
const PROCESS_SERVER_INFO: &str = concat!(
    "48 89 5C 24 08 57 48 83 EC 20 48 8B FA 48 8B D9 ",
    "E8 ?? ?? ?? ?? 48 8B D7 48 8B CB E8 ?? ?? ?? ?? 84 C0"
);
const MD5_COPY: &str = "0F 10 47 ?? 0F 11 83 ?? ?? ?? ??";
const MAP_COPY: &str = "48 8B 56 ?? 48 8D 8F ?? ?? ?? ?? 48 89 5C 24 ?? 41 B8 04 01 00 00";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_CSV_BYTES: u64 = 32 * 1024 * 1024;

static ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static MSG_MD5_OFFSET: AtomicUsize = AtomicUsize::new(0);
static MSG_MAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_CALLBACKS: AtomicUsize = AtomicUsize::new(0);
static DIRTY: AtomicBool = AtomicBool::new(false);
static GAME_ROOT: OnceLock<PathBuf> = OnceLock::new();
static CACHE_ROOT: OnceLock<PathBuf> = OnceLock::new();

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

fn read_cstring(address: usize, maximum: usize) -> Option<String> {
    if address < 0x1_0000 {
        return None;
    }
    let mut bytes = Vec::with_capacity(maximum.min(96));
    for offset in 0..maximum {
        let byte = read_value::<u8>(address.checked_add(offset)?)?;
        if byte == 0 {
            return String::from_utf8(bytes).ok();
        }
        bytes.push(byte);
    }
    None
}

fn plausible_map_name(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn unique_match(pattern: &Pattern, bytes: &[u8]) -> Option<usize> {
    let matches = pattern.find_all(bytes);
    if matches.len() == 1 {
        matches.first().copied()
    } else {
        None
    }
}

fn relative_call_target(function_rva: usize, body: &[u8], opcode_at: usize) -> Option<usize> {
    if body.get(opcode_at) != Some(&0xe8) {
        return None;
    }
    let displacement = i32::from_le_bytes(body.get(opcode_at + 1..opcode_at + 5)?.try_into().ok()?);
    function_rva
        .checked_add(opcode_at + 5)?
        .checked_add_signed(displacement as isize)
}

fn resolve(engine: &LiveModule) -> Result<(usize, usize, usize, usize), String> {
    let (slot_rva, function_rva) = engine
        .resolve_virtual(CLIENT_STATE_CLASS, &[PROCESS_SERVER_INFO], 0x200)
        .ok_or_else(|| "CClientState::ProcessServerInfo is missing or ambiguous".to_string())?;

    let mut owner = None;
    for vtable in engine.pe.vtables(CLIENT_STATE_CLASS) {
        for (index, function) in engine.pe.virtuals(vtable.rva, 256) {
            if vtable.rva + index * size_of::<usize>() == slot_rva
                && function == function_rva
                && owner.replace((vtable.object_offset, index)).is_some()
            {
                return Err("ProcessServerInfo vtable owner is ambiguous".into());
            }
        }
    }
    let Some((object_offset, slot_index)) = owner else {
        return Err("ProcessServerInfo has no CClientState vtable owner".into());
    };
    if object_offset != 16 {
        return Err(format!(
            "ProcessServerInfo resolved on unexpected CClientState subobject +0x{object_offset:x}"
        ));
    }

    let body = engine
        .pe
        .read_rva(function_rva, 0x200)
        .ok_or_else(|| "ProcessServerInfo body is truncated".to_string())?;
    let md5_pattern =
        Pattern::parse(MD5_COPY).ok_or_else(|| "invalid MD5 resolver pattern".to_string())?;
    let md5_at = unique_match(&md5_pattern, body)
        .ok_or_else(|| "ProcessServerInfo MD5 copy is missing or ambiguous".to_string())?;
    let md5_offset = usize::from(
        body.get(md5_at + 3)
            .copied()
            .ok_or_else(|| "ProcessServerInfo MD5 displacement is truncated".to_string())?,
    );

    // The matched entry has two direct calls: host-state reset, then the base
    // ProcessServerInfo implementation. The latter copies msg->map_name into
    // CBaseClientState; recover that message displacement from its instruction.
    let base_rva = relative_call_target(function_rva, body, 27)
        .filter(|&rva| engine.pe.is_exec(rva))
        .ok_or_else(|| "ProcessServerInfo base call changed".to_string())?;
    let base = engine
        .pe
        .read_rva(base_rva, 0x440)
        .ok_or_else(|| "base ProcessServerInfo body is truncated".to_string())?;
    let map_pattern =
        Pattern::parse(MAP_COPY).ok_or_else(|| "invalid map resolver pattern".to_string())?;
    let map_at = unique_match(&map_pattern, base)
        .ok_or_else(|| "base ProcessServerInfo map copy is missing or ambiguous".to_string())?;
    let map_offset = usize::from(
        base.get(map_at + 3)
            .copied()
            .ok_or_else(|| "ProcessServerInfo map displacement is truncated".to_string())?,
    );

    if !(0x20..=0x100).contains(&md5_offset)
        || !(0x40..=0x100).contains(&map_offset)
        || !map_offset.is_multiple_of(size_of::<usize>())
    {
        return Err(format!(
            "implausible server-info layout: MD5 +0x{md5_offset:x}, map +0x{map_offset:x}"
        ));
    }

    let slot = engine
        .address(slot_rva)
        .ok_or_else(|| "ProcessServerInfo slot RVA is invalid".to_string())?;
    let function = engine
        .address(function_rva)
        .filter(|&address| engine.contains_exec(address))
        .ok_or_else(|| "ProcessServerInfo function is not executable engine code".to_string())?;
    control::emit(&format!(
        "fastdl: CClientState+0x{object_offset:x} slot {slot_index}, MD5 msg+0x{md5_offset:x}, map msg+0x{map_offset:x}"
    ));
    Ok((slot, function, md5_offset, map_offset))
}

fn game_root(engine: &LiveModule) -> Result<PathBuf, String> {
    let root = engine
        .path
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .ok_or_else(|| format!("cannot derive game root from {}", engine.path.display()))?
        .to_path_buf();
    if !root.join("cstrike").is_dir() {
        return Err(format!(
            "derived game root has no cstrike directory: {}",
            root.display()
        ));
    }
    Ok(root)
}

fn cache_root() -> Option<&'static Path> {
    CACHE_ROOT.get().map(PathBuf::as_path)
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn replace_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    let source = wide(source);
    let destination = wide(destination);
    let ok = unsafe {
        api::MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            api::MOVEFILE_REPLACE_EXISTING | api::MOVEFILE_WRITE_THROUGH,
        )
    };
    if ok == 0 {
        Err(std::io::Error::from_raw_os_error(
            unsafe { api::GetLastError() } as i32,
        ))
    } else {
        Ok(())
    }
}

fn curl_to(url: &str, output: &Path, seconds: u32, maximum_bytes: u64) -> bool {
    let _ = std::fs::remove_file(output);
    Command::new(crate::curl_program())
        .creation_flags(CREATE_NO_WINDOW)
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-time",
            &seconds.to_string(),
            "--max-filesize",
            &maximum_bytes.to_string(),
            "--output",
        ])
        .arg(output)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn load_csv(path: &Path) -> Option<String> {
    let length = std::fs::metadata(path).ok()?.len();
    if !(1_024..=MAX_CSV_BYTES).contains(&length) {
        return None;
    }
    let csv = std::fs::read_to_string(path).ok()?;
    csv.lines()
        .any(|line| {
            line.split_once(',').is_some_and(|(sha1, md5)| {
                sha1.len() == 40
                    && md5.trim_end_matches('\r').len() == 32
                    && sha1.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        })
        .then_some(csv)
}

fn lump_checksums_csv() -> Option<String> {
    let cache = cache_root()?;
    let path = cache.join("lump_checksums.csv");
    let stale = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .map(|elapsed| elapsed > Duration::from_secs(36 * 60 * 60))
        .unwrap_or(true);
    if stale {
        let _ = std::fs::create_dir_all(cache);
        let temporary = cache.join("lump_checksums.csv.part");
        control::emit("fastdl: refreshing lump_checksums.csv (~4 MB)");
        if curl_to(
            "https://venus.fastdl.me/lump_checksums.csv",
            &temporary,
            30,
            MAX_CSV_BYTES,
        ) && load_csv(&temporary).is_some()
        {
            if let Err(error) = replace_file(&temporary, &path) {
                control::warn(&format!(
                    "fastdl: installing checksum cache failed: {error}"
                ));
                let _ = std::fs::remove_file(&temporary);
            }
        } else {
            control::warn("fastdl: checksum refresh failed; using any valid cached copy");
            let _ = std::fs::remove_file(&temporary);
        }
    }
    load_csv(&path)
}

fn lookup_md5<'a>(csv: &'a str, md5: &str) -> Option<&'a str> {
    csv.lines().find_map(|line| {
        let (sha1, candidate) = line.trim_end_matches('\r').split_once(',')?;
        (candidate.eq_ignore_ascii_case(md5)
            && sha1.len() == 40
            && sha1.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then_some(sha1)
    })
}

fn decompress_bz2(source: &Path, destination: &Path) -> std::io::Result<()> {
    let input = File::open(source)?;
    let mut decoder = BzDecoder::new(input);
    let mut output = File::create(destination)?;
    std::io::copy(&mut decoder, &mut output)?;
    output.flush()?;
    output.sync_all()
}

fn valid_bsp(path: &Path) -> bool {
    File::open(path)
        .and_then(|mut file| {
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)?;
            Ok(magic == *b"VBSP")
        })
        .unwrap_or(false)
}

fn ensure_map(map_name: &str, sha1: &str) -> bool {
    let Some(root) = GAME_ROOT.get() else {
        return false;
    };
    let Some(cache) = cache_root() else {
        return false;
    };
    let maps = root.join("cstrike/maps");
    if std::fs::create_dir_all(&maps).is_err() || std::fs::create_dir_all(cache).is_err() {
        return false;
    }
    let target = maps.join(format!("{map_name}.bsp"));
    let sidecar = cache.join(format!("{map_name}.fastdl"));
    if target.is_file()
        && std::fs::read_to_string(&sidecar)
            .is_ok_and(|contents| contents.trim().eq_ignore_ascii_case(sha1))
    {
        return false;
    }

    control::emit(&format!(
        "fastdl: fetching hashed/{sha1}.bsp.bz2 as {map_name}.bsp"
    ));
    let compressed = maps.join(format!("{map_name}.bsp.bz2.part"));
    let part = maps.join(format!("{map_name}.bsp.part"));
    let mut ready = curl_to(
        &format!("https://mainr2.fastdl.me/hashed/{sha1}.bsp.bz2"),
        &compressed,
        20,
        1024 * 1024 * 1024,
    );
    if ready {
        ready = decompress_bz2(&compressed, &part).is_ok();
        if !ready {
            control::warn("fastdl: bzip2 decompression failed; trying legacy endpoint");
            let _ = std::fs::remove_file(&part);
        }
    }
    let _ = std::fs::remove_file(&compressed);
    if !ready {
        ready = curl_to(
            &format!("https://main.fastdl.me/hashed/{sha1}.bsp"),
            &part,
            8,
            1024 * 1024 * 1024,
        );
    }
    if !ready || !valid_bsp(&part) {
        let _ = std::fs::remove_file(&part);
        control::warn("fastdl: map download failed validation; stock behavior applies");
        return false;
    }
    if !crate::file_matches_sha1(&part, sha1) {
        let _ = std::fs::remove_file(&part);
        control::warn("fastdl: map SHA-1 differs from fastdl.me; stock behavior applies");
        return false;
    }
    if let Err(error) = replace_file(&part, &target) {
        let _ = std::fs::remove_file(&part);
        control::warn(&format!(
            "fastdl: installing {} failed: {error}",
            target.display()
        ));
        return false;
    }

    let sidecar_part = cache.join(format!("{map_name}.fastdl.part"));
    if std::fs::write(&sidecar_part, sha1).is_ok() {
        let _ = replace_file(&sidecar_part, &sidecar);
    }
    control::emit(&format!("fastdl: installed {map_name}.bsp"));
    true
}

fn map_name(message: usize, map_offset: usize) -> Option<String> {
    let map_pointer = read_value::<usize>(message.checked_add(map_offset)?)?;
    let map = read_cstring(map_pointer, 65)?;
    if !plausible_map_name(&map) {
        return None;
    }

    // In SVC_ServerInfo the immediately preceding pointer is the game-dir
    // string. This guards against accepting a structurally valid but unrelated
    // string if an update changes the message layout.
    let game_offset = map_offset.checked_sub(size_of::<usize>())?;
    let game_pointer = read_value::<usize>(message.checked_add(game_offset)?)?;
    let game = read_cstring(game_pointer, 32)?;
    (game == "cstrike").then_some(map)
}

fn on_server_info(message: *mut c_void) {
    let message = message as usize;
    if message == 0 {
        return;
    }
    let md5_offset = MSG_MD5_OFFSET.load(Ordering::Acquire);
    let map_offset = MSG_MAP_OFFSET.load(Ordering::Acquire);
    let Some(map_name) = map_name(message, map_offset) else {
        control::warn("fastdl: server-info map field failed live validation");
        return;
    };
    let Some(md5) = read_value::<[u8; 16]>(message.saturating_add(md5_offset)) else {
        return;
    };
    let mut md5_hex = String::with_capacity(32);
    for byte in md5 {
        let _ = write!(&mut md5_hex, "{byte:02x}");
    }

    if control::flags() & FLAG_NO_SOURCEJUMP == 0 {
        crate::sourcejump::show_wr(&map_name);
    }
    super::engine::arm_demo(&map_name);

    let Some(csv) = lump_checksums_csv() else {
        return;
    };
    if let Some(sha1) = lookup_md5(&csv, &md5_hex) {
        control::emit(&format!("fastdl: server map {map_name} -> sha1 {sha1}"));
        let _ = ensure_map(&map_name, sha1);
    } else if crate::debug_on() {
        control::debug(&format!("fastdl: server map MD5 {md5_hex} is not indexed"));
    }
}

unsafe extern "system" fn hooked_process_server_info(
    this: *mut c_void,
    message: *mut c_void,
) -> bool {
    let _guard = CallbackGuard::enter();
    on_server_info(message);
    let original = ORIGINAL.load(Ordering::Acquire);
    if original == 0 {
        return false;
    }
    let original: unsafe extern "system" fn(*mut c_void, *mut c_void) -> bool =
        unsafe { std::mem::transmute(original) };
    unsafe { original(this, message) }
}

pub(crate) struct Hooks {
    process_server_info: PointerHook,
}

impl Hooks {
    pub(crate) fn install(engine: &LiveModule) -> Result<Self, String> {
        let curl = crate::curl_program();
        if !curl.is_file() {
            return Err(format!("system curl is unavailable at {}", curl.display()));
        }
        let root = game_root(engine)?;
        let cache = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("TEMP").map(PathBuf::from))
            .ok_or_else(|| "LOCALAPPDATA and TEMP are unavailable".to_string())?
            .join("bunnyhopfix");
        GAME_ROOT
            .set(root)
            .map_err(|_| "fastdl game root was already initialized".to_string())?;
        CACHE_ROOT
            .set(cache)
            .map_err(|_| "fastdl cache root was already initialized".to_string())?;

        let (slot, original, md5_offset, map_offset) = resolve(engine)?;
        ORIGINAL.store(original, Ordering::Release);
        MSG_MD5_OFFSET.store(md5_offset, Ordering::Release);
        MSG_MAP_OFFSET.store(map_offset, Ordering::Release);
        DIRTY.store(true, Ordering::Release);
        let process_server_info = match PointerHook::install(
            slot,
            original,
            hooked_process_server_info as *const () as usize,
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
        control::emit("fastdl: map-version interceptor installed");
        Ok(Self {
            process_server_info,
        })
    }

    pub(crate) fn restore(&mut self) -> Result<(), String> {
        self.process_server_info.restore()?;
        for _ in 0..45_000 {
            if ACTIVE_CALLBACKS.load(Ordering::Acquire) == 0 {
                clear_globals();
                DIRTY.store(false, Ordering::Release);
                return Ok(());
            }
            unsafe { api::Sleep(1) };
        }
        Err("fastdl callback did not quiesce within 45 seconds".into())
    }
}

pub(crate) fn is_quiescent() -> bool {
    !DIRTY.load(Ordering::Acquire) && ACTIVE_CALLBACKS.load(Ordering::Acquire) == 0
}

fn clear_globals() {
    ORIGINAL.store(0, Ordering::Release);
    MSG_MD5_OFFSET.store(0, Ordering::Release);
    MSG_MAP_OFFSET.store(0, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use bzip2::Compression;
    use bzip2::write::BzEncoder;

    use super::*;

    #[test]
    fn checksum_lookup_accepts_crlf_and_matches_case_insensitively() {
        let csv = concat!(
            "sha1,lump_md5_checksum\r\n",
            "0123456789abcdef0123456789abcdef01234567,ABCDEF0123456789ABCDEF0123456789\r\n"
        );
        assert_eq!(
            lookup_md5(csv, "abcdef0123456789abcdef0123456789"),
            Some("0123456789abcdef0123456789abcdef01234567")
        );
        assert_eq!(lookup_md5(csv, "00000000000000000000000000000000"), None);
    }

    #[test]
    fn pure_rust_bzip2_path_produces_a_valid_bsp() {
        let directory = std::env::temp_dir().join(format!(
            "bhopfix-fastdl-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let source = directory.join("map.bsp.bz2");
        let destination = directory.join("map.bsp");
        let mut encoder = BzEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(b"VBSPtest payload").unwrap();
        std::fs::write(&source, encoder.finish().unwrap()).unwrap();

        decompress_bz2(&source, &destination).unwrap();
        assert!(valid_bsp(&destination));
        assert_eq!(std::fs::read(&destination).unwrap(), b"VBSPtest payload");
        assert!(crate::file_matches_sha1(
            &destination,
            "b97b83cb9447e881cb70994d2cc9d6052082c849"
        ));
        assert!(!crate::file_matches_sha1(
            &destination,
            "0000000000000000000000000000000000000000"
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
