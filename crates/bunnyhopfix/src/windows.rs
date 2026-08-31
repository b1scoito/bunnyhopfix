//! Windows backend — the bunnyhopfix jump-prediction patcher.
//!
//! What this does and does not do:
//!   * DOES patch every `CheckJumpButton` early-out in a running 32-bit
//!     `client.dll`, exactly like the Linux patcher, with a Scroll Lock toggle
//!     and a byte restore on exit.
//!   * Does NOT inject anything. The Linux build also preloads `libbhopfix.so`
//!     for `m_rawinput 2`, viewpunch removal, the fastdl map hijack and the
//!     engine console glue; all of that is LD_PRELOAD/ELF/procfs machinery with
//!     no Windows analogue, so it is Linux-only.
//!   * Does NOT launch the game. Start CS:S yourself (with `-insecure`), then
//!     run this — it waits for `hl2.exe`, and then for `client.dll` to load.
//!
//! Like the C++ bunnyhopfix this replaces, it refuses to patch a game that was
//! not started with `-insecure`, and it reads that flag out of the *target's*
//! own command line rather than trusting our argv.
//!
//! The patcher is built x86_64 and drives the 32-bit (WOW64) game through
//! ReadProcessMemory/WriteProcessMemory, which is supported in both directions.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};

use bhopfix_core::sig::Sig;

// ---------------------------------------------------------------------------
// Signatures
//
// `if (mv->m_nOldButtons & IN_JUMP) return false;` — the same client-side
// anti-pogo guard the Linux patcher removes, in MSVC's 32-bit encoding:
//
//     85 C0              test eax,eax
//     8B 46 08           mov  eax,[esi+8]
//     0F 84 ?? FF FF FF  jz   out
//     F6 40 28 02        test byte [eax+0x28],2   ; m_nOldButtons & IN_JUMP
//     0F 85 ?? FF FF FF  jnz  out                 <- the 6 bytes we NOP
//
// `+0x28` (m_nOldButtons) and `IN_JUMP == 2` match the Linux signatures
// exactly, which is the cross-check that this is the same code; the Windows
// pattern simply carries 11 bytes more leading context.
//
// Provenance: this is the production signature of the C++ bunnyhopfix this
// crate replaces (release 1.0, `bunnyhopfix.exe`), which scans
// `\x85\xC0\x8B\x46\x08\x0F\x84\x00\xFF\xFF\xFF\xF6\x40\x28\x02\x0F\x85\x00\xFF\xFF\xFF`
// with mask `xxxxxxx?xxxxxxxxx?xxx` and NOPs 6 bytes at +15 — the same bytes
// alkatrazbhop/BunnyhopAPE and the rtldg/RawInput2BunnyhopAPE fork use. `??`
// here is exactly upstream's `?`: the two rel32 displacements, which move
// whenever the surrounding function is relaid out.
//
// One deliberate difference from upstream: it stops at the FIRST match, we
// patch every match. The Linux client has two copies of this check (the base
// CGameMovement and the CCSGameMovement override), and patching one of two is
// a silent half-fix — so we report the count and rewrite all of them.
// ---------------------------------------------------------------------------
#[rustfmt::skip]
static SIGS: &[Sig] = &[
    Sig {
        name: "win32 CheckJumpButton",
        pat: "85 C0  8B 46 08  0F 84 ?? FF FF FF  F6 40 28 02  0F 85 ?? FF FF FF",
        at: 15, len: 6,
    },
];

const NOP: u8 = 0x90;

/// CS:S on Windows is `hl2.exe -game cstrike`; there is no `cstrike.exe`.
/// Same process name upstream looks for.
const GAME_EXE: &str = "hl2.exe";
const CLIENT_DLL: &str = "client.dll";

// ---------------------------------------------------------------------------
// Win32
// ---------------------------------------------------------------------------

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;
type NtStatus = i32;

const INVALID_HANDLE_VALUE: Handle = usize::MAX as Handle;
const PROCESS_VM_READ: Dword = 0x0010;
const PROCESS_VM_WRITE: Dword = 0x0020;
const PROCESS_VM_OPERATION: Dword = 0x0008;
const PROCESS_QUERY_INFORMATION: Dword = 0x0400;
const TH32CS_SNAPPROCESS: Dword = 0x0000_0002;
const TH32CS_SNAPMODULE: Dword = 0x0000_0008;
const TH32CS_SNAPMODULE32: Dword = 0x0000_0010;
const PAGE_EXECUTE_READWRITE: Dword = 0x40;
const VK_SCROLL: i32 = 0x91;
const CTRL_C_EVENT: Dword = 0;
const CTRL_BREAK_EVENT: Dword = 1;
/// `GetExitCodeProcess` reports this while the process is still running.
const STILL_ACTIVE: Dword = 259;

/// `PROCESSINFOCLASS::ProcessWow64Information` — writes the address of the
/// target's 32-bit PEB, or 0 when the target is not a WOW64 process.
const PROCESS_WOW64_INFORMATION: Dword = 26;

/// Field offsets inside the *target's* 32-bit structures. These are the WOW64
/// (i.e. 32-bit) layouts, which is why they differ from the familiar 64-bit
/// numbers (`ProcessParameters` +0x20, `CommandLine` +0x70).
///
/// ```text
/// PEB32                      RTL_USER_PROCESS_PARAMETERS32
///   +0x00 BitField etc.        +0x00 MaximumLength / Length / Flags / DebugFlags
///   +0x04 Mutant               +0x10 ConsoleHandle / ConsoleFlags
///   +0x08 ImageBaseAddress     +0x18 StandardInput / Output / Error
///   +0x0c Ldr                  +0x24 CurrentDirectory (UNICODE_STRING32 + HANDLE)
///   +0x10 ProcessParameters    +0x30 DllPath        (UNICODE_STRING32)
///                              +0x38 ImagePathName  (UNICODE_STRING32)
///                              +0x40 CommandLine    (UNICODE_STRING32)
/// ```
const PEB32_PROCESS_PARAMETERS: usize = 0x10;
const PARAMS32_COMMAND_LINE: usize = 0x40;

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
    fn VirtualProtectEx(
        h: Handle,
        addr: *mut c_void,
        n: usize,
        prot: Dword,
        old: *mut Dword,
    ) -> Bool;
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
    /// First running process whose image name is [`GAME_EXE`].
    pub fn find_game() -> Option<u32> {
        let snap = Snapshot::new(TH32CS_SNAPPROCESS, 0)?;
        let mut e: ProcessEntry32W = unsafe { std::mem::zeroed() };
        e.dw_size = size_of::<ProcessEntry32W>() as Dword;
        let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
        while ok != 0 {
            if GAME_EXE.eq_ignore_ascii_case(&wide_to_string(&e.sz_exe_file)) {
                return Some(e.th32_process_id);
            }
            ok = unsafe { Process32NextW(snap.0, &mut e) };
        }
        None
    }

    pub fn open(pid: u32) -> Option<Process> {
        let access =
            PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION;
        let handle = unsafe { OpenProcess(access, 0, pid) };
        (!handle.is_null()).then_some(Process { handle, pid })
    }

    /// Locate a module by name. SNAPMODULE32 is what makes this work against a
    /// 32-bit (WOW64) game from this 64-bit process.
    pub fn module(&self, want: &str) -> Option<Module> {
        let snap = Snapshot::new(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)?;
        let mut e: ModuleEntry32W = unsafe { std::mem::zeroed() };
        e.dw_size = size_of::<ModuleEntry32W>() as Dword;
        let mut ok = unsafe { Module32FirstW(snap.0, &mut e) };
        while ok != 0 {
            if want.eq_ignore_ascii_case(&wide_to_string(&e.sz_module)) {
                return Some(Module {
                    base: e.mod_base_addr as usize,
                    size: e.mod_base_size as usize,
                });
            }
            ok = unsafe { Module32NextW(snap.0, &mut e) };
        }
        None
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

    /// Little-endian u32 out of the target.
    fn u32_at(&self, addr: usize) -> Option<u32> {
        let b = self.read(addr, 4)?;
        Some(u32::from_le_bytes(b.try_into().ok()?))
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

    /// The target's own command line, walked out of its 32-bit PEB.
    ///
    /// `NtQueryInformationProcess(ProcessWow64Information)` hands us the PEB32
    /// address of a WOW64 target (0 means "not WOW64", i.e. not the 32-bit game
    /// we know how to patch). From there it is PEB32 -> `ProcessParameters` ->
    /// `CommandLine`, a 32-bit `UNICODE_STRING` (u16 `Length` in *bytes*, u16
    /// `MaximumLength`, u32 `Buffer`).
    ///
    /// Returns None for every failure along the way; the caller treats that as
    /// "unknown", never as "no `-insecure`".
    pub fn command_line(&self) -> Option<String> {
        let mut peb32: u64 = 0;
        let mut ret_len: Dword = 0;
        let status = unsafe {
            NtQueryInformationProcess(
                self.handle,
                PROCESS_WOW64_INFORMATION,
                (&raw mut peb32).cast::<c_void>(),
                size_of::<u64>() as Dword,
                &raw mut ret_len,
            )
        };
        if status < 0 || peb32 == 0 {
            return None;
        }
        let params = self.u32_at(peb32 as usize + PEB32_PROCESS_PARAMETERS)? as usize;
        let us = self.read(params + PARAMS32_COMMAND_LINE, 8)?;
        let len = u16::from_le_bytes([us[0], us[1]]) as usize;
        let buffer = u32::from_le_bytes([us[4], us[5], us[6], us[7]]) as usize;
        if len == 0 || buffer == 0 {
            return None;
        }
        let raw = self.read(buffer, len)?;
        let utf16: Vec<u16> = raw
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        Some(String::from_utf16_lossy(&utf16))
    }

    /// Write bytes, flipping page protection for the duration.
    pub fn write(&self, addr: usize, data: &[u8]) -> Result<(), String> {
        let mut old: Dword = 0;
        let ok = unsafe {
            VirtualProtectEx(
                self.handle,
                addr as *mut c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &raw mut old,
            )
        };
        if ok == 0 {
            return Err(format!("VirtualProtectEx failed (err {})", unsafe {
                GetLastError()
            }));
        }
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
        let mut ignored: Dword = 0;
        unsafe {
            VirtualProtectEx(
                self.handle,
                addr as *mut c_void,
                data.len(),
                old,
                &raw mut ignored,
            )
        };
        if wrote == 0 || put != data.len() {
            return Err(format!("WriteProcessMemory failed (err {})", unsafe {
                GetLastError()
            }));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Patch state
// ---------------------------------------------------------------------------

struct PatchSite {
    name: &'static str,
    addr: usize,
    original: Vec<u8>,
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

/// True once Ctrl+C / Ctrl+Break asked us to stop.
fn quitting() -> bool {
    QUIT.load(Ordering::SeqCst)
}

fn find_sites(p: &Process, m: &Module) -> Vec<PatchSite> {
    let code = p.read_span(m.base, m.size);
    let mut sites = Vec::new();
    for s in SIGS {
        let Some(pat) = s.pattern() else {
            eprintln!("[!] signature {:?} is malformed; skipping", s.name);
            continue;
        };
        for off in pat.find_all(&code) {
            let at = off + s.at;
            sites.push(PatchSite {
                name: s.name,
                addr: m.base + at,
                original: code[at..at + s.len].to_vec(),
            });
        }
    }
    sites
}

fn apply(p: &Process, sites: &[PatchSite], on: bool) {
    for s in sites {
        let bytes = if on {
            vec![NOP; s.original.len()]
        } else {
            s.original.clone()
        };
        if let Err(e) = p.write(s.addr, &bytes) {
            eprintln!("[!] {} @ {:#x}: {e}", s.name, s.addr);
        }
    }
    println!(
        "\n=== Autobhop prediction: {} ===",
        if on { "ON" } else { "OFF" }
    );
    for s in sites {
        println!("    {:<28} @ {:#x}", s.name, s.addr);
    }
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
    println!("[*] waiting for {GAME_EXE} (start CS:S with -insecure)...");
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
    println!("[*] waiting for {CLIENT_DLL} to load...");
    while !quitting() {
        unsafe { Sleep(250) };
        if let Some(m) = p.module(CLIENT_DLL) {
            return Some(m);
        }
        // the game exiting while we wait would otherwise spin forever
        if !p.is_alive() {
            eprintln!("[!] the game exited while waiting for {CLIENT_DLL}");
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

fn usage() {
    eprintln!(
        "{} (Windows) — CS:S bhop delay (jump prediction) fixer\n\
         \n\
         USAGE:\n\
         \x20 bunnyhopfix [--attach <pid>] [--scroll-lock]\n\
         \n\
         Start CS:S with -insecure first, then run this. It patches the\n\
         client-side `m_nOldButtons & IN_JUMP` early-out in CheckJumpButton so\n\
         the client predicts autobhop jumps immediately.\n\
         \n\
         \x20 --attach <pid>   patch this pid instead of searching for hl2.exe\n\
         \x20 --scroll-lock    Scroll Lock toggles prediction on and off\n\
         \x20 --version, -V    print the version and exit\n\
         \n\
         Ctrl+C restores the original bytes and exits.\n\
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
                println!("[*] attaching to pid {pid}");
                pid
            }
            None => {
                usage();
                std::process::exit(2);
            }
        },
        None => match wait_for_game() {
            Some(pid) => {
                println!("[*] found {GAME_EXE} (pid {pid})");
                pid
            }
            None => return, // Ctrl+C while waiting
        },
    };

    let Some(proc) = Process::open(pid) else {
        eprintln!(
            "[!] cannot open pid {pid} (err {}). Try running as administrator.",
            unsafe { GetLastError() }
        );
        std::process::exit(1);
    };

    // --- -insecure enforcement ----------------------------------------------
    // Same policy as upstream and as the Linux backend: the game must have been
    // started with -insecure. A command line we can READ and that lacks the
    // flag is a hard refusal; a command line we cannot read at all (unexpected
    // Windows build, 64-bit game, hardened process) only downgrades the check —
    // an unreadable PEB must never brick the tool.
    match proc.command_line() {
        Some(cmdline) if cmdline.to_ascii_lowercase().contains("-insecure") => {
            println!("[*] -insecure confirmed on the game's own command line");
        }
        Some(_) => {
            eprintln!(
                "[!] the game was NOT started with -insecure.\n\
                 [!] refusing to patch (same policy as the original bunnyhopfix).\n\
                 [!] add -insecure to the CS:S launch options and restart it."
            );
            std::process::exit(1);
        }
        None => {
            eprintln!(
                "[!] warning: could not read the game's command line (PEB32 not\n\
                 [!] readable — not a WOW64 process?); the -insecure check was\n\
                 [!] SKIPPED. Only continue if you did start it with -insecure."
            );
        }
    }

    // --- find client.dll ----------------------------------------------------
    let Some(module) = wait_for_client_dll(&proc) else {
        return; // Ctrl+C, or the game went away
    };
    println!(
        "[*] {CLIENT_DLL} at {:#x} ({} KB)",
        module.base,
        module.size / 1024
    );

    // --- scan ---------------------------------------------------------------
    let sites = find_sites(&proc, &module);
    if sites.is_empty() {
        eprintln!(
            "[!] no signature matched in {CLIENT_DLL}; nothing was patched.\n\
             \x20   Either the game already has this patch applied, or the build\n\
             \x20   changed the CheckJumpButton encoding and the pattern needs\n\
             \x20   re-deriving. Nothing is guessed at: no match, no write."
        );
        std::process::exit(1);
    }
    println!("[*] found {} patch site(s)", sites.len());

    // --- patch --------------------------------------------------------------
    let mut on = true;
    apply(&proc, &sites, on);
    if scroll_lock {
        println!("(Scroll Lock toggles prediction; Ctrl+C to restore and exit)");
    } else {
        println!("(Ctrl+C to restore and exit)");
    }

    // Edge-detect the physical key rather than reading a toggle state: a
    // console app has no message pump, so GetKeyState's toggle bit is stale,
    // while GetAsyncKeyState's 0x8000 "down right now" bit is always live.
    let mut scroll_down = false;
    while !quitting() {
        unsafe { Sleep(100) };
        // the game exiting invalidates the module: stop touching it
        if proc.read(module.base, 2).is_none() {
            println!("[*] game exited");
            return; // its memory is gone; nothing to restore
        }
        if scroll_lock {
            let down = unsafe { GetAsyncKeyState(VK_SCROLL) } as u16 & 0x8000 != 0;
            if down && !scroll_down {
                on = !on;
                apply(&proc, &sites, on);
            }
            scroll_down = down;
        }
    }
    if on {
        apply(&proc, &sites, false);
    }
    println!("[*] original bytes restored");
}
