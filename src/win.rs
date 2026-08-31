//! Windows backend — barebones autobhop prediction patcher.
//!
//! What this does and does not do:
//!   * DOES patch `CheckJumpButton` in a running `client.dll`, exactly like the
//!     Linux patcher, with a Scroll Lock toggle and byte restore on exit.
//!   * Does NOT inject anything. The Linux build also preloads
//!     `librawinput2.so` for `m_rawinput 2`, viewpunch removal, the fastdl map
//!     hijack and the engine console glue; all of that is LD_PRELOAD/ELF/procfs
//!     machinery with no Windows analogue, so it is Linux-only.
//!   * Does NOT launch the game. Start CS:S yourself (with `-insecure`), then
//!     run this.
//!
//! Honesty about the signature: the pattern below comes from upstream's public
//! source, which targets the 32-bit `client.dll`, and this tool has NOT been
//! run against a real Windows CS:S install. If it does not match, it patches
//! nothing and says so — it will never write to a location it did not verify.
//! The patcher itself is built x86_64 and drives a 32-bit (WOW64) game through
//! ReadProcessMemory/WriteProcessMemory, which is supported in both directions.

use std::ffi::c_void;

use crate::sig::Sig;

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
// exactly, which is the cross-check that this is the same code.
//
// Provenance: alkatrazbhop/BunnyhopAPE (BunnyhopAPE/ape.cpp) and the
// rtldg/RawInput2BunnyhopAPE fork, both of which scan
// `\x85\xC0\x8B\x46\x08\x0F\x84\x00\xFF\xFF\xFF\xF6\x40\x28\x02\x0F\x85\x00\xFF\xFF\xFF`
// with mask `xxxxxxx?xxxxxxxxx?xxx` and NOP 6 bytes at +15. Upstream patches
// ONE site on Windows (Linux has two: base + the CS override).
//
// UNVERIFIED against a current build: upstream's signature dates from 2016 and
// nobody has re-confirmed it against the 64-bit Windows client, for which we
// have no pattern at all. A no-match is reported, never guessed around.
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
/// Process names CS:S runs under.
const GAME_EXES: &[&str] = &["hl2.exe", "cstrike.exe"];
const CLIENT_DLL: &str = "client.dll";

// ---------------------------------------------------------------------------
// Win32
// ---------------------------------------------------------------------------

type Handle = *mut c_void;
type Dword = u32;
type Bool = i32;

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

extern "system" {
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
    fn GetAsyncKeyState(vk: i32) -> i16;
    fn Sleep(ms: Dword);
    fn SetConsoleCtrlHandler(
        handler: Option<unsafe extern "system" fn(Dword) -> Bool>,
        add: Bool,
    ) -> Bool;
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
    /// First running process whose image name is one of `GAME_EXES`.
    pub fn find_game() -> Option<(u32, String)> {
        let snap = Snapshot::new(TH32CS_SNAPPROCESS, 0)?;
        let mut e: ProcessEntry32W = unsafe { std::mem::zeroed() };
        e.dw_size = std::mem::size_of::<ProcessEntry32W>() as Dword;
        let mut ok = unsafe { Process32FirstW(snap.0, &mut e) };
        while ok != 0 {
            let name = wide_to_string(&e.sz_exe_file);
            if GAME_EXES.iter().any(|g| g.eq_ignore_ascii_case(&name)) {
                return Some((e.th32_process_id, name));
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
        e.dw_size = std::mem::size_of::<ModuleEntry32W>() as Dword;
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
                buf.as_mut_ptr() as *mut c_void,
                len,
                &mut got,
            )
        };
        (ok != 0 && got == len).then_some(buf)
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

    /// Write bytes, flipping page protection for the duration.
    pub fn write(&self, addr: usize, data: &[u8]) -> Result<(), String> {
        let mut old: Dword = 0;
        let ok = unsafe {
            VirtualProtectEx(
                self.handle,
                addr as *mut c_void,
                data.len(),
                PAGE_EXECUTE_READWRITE,
                &mut old,
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
                data.as_ptr() as *const c_void,
                data.len(),
                &mut put,
            )
        };
        let mut ignored: Dword = 0;
        unsafe {
            VirtualProtectEx(
                self.handle,
                addr as *mut c_void,
                data.len(),
                old,
                &mut ignored,
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
static QUIT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

unsafe extern "system" fn on_ctrl(event: Dword) -> Bool {
    if event == CTRL_C_EVENT {
        QUIT.store(true, std::sync::atomic::Ordering::SeqCst);
        return 1; // handled: let the loop unwind and restore the bytes
    }
    0
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
        match p.write(s.addr, &bytes) {
            Ok(()) => {}
            Err(e) => eprintln!("[!] {} @ {:#x}: {e}", s.name, s.addr),
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

fn usage() {
    eprintln!(
        "bunnyhop-ape (Windows) — Autobhop Prediction Enabler for CS:S\n\
         \n\
         USAGE:\n\
         \x20 bunnyhop-ape [--attach <pid>] [--scroll-lock]\n\
         \n\
         Start CS:S with -insecure first, then run this. It patches the\n\
         client-side `m_nOldButtons & IN_JUMP` early-out in CheckJumpButton so\n\
         the client predicts autobhop jumps immediately.\n\
         \n\
         \x20 --attach <pid>   patch this pid instead of searching for the game\n\
         \x20 --scroll-lock    tie prediction to the Scroll Lock LED\n\
         \n\
         Ctrl+C restores the original bytes and exits.\n\
         \n\
         Only use this on servers that actually do autobhop, and only with\n\
         -insecure. On a vanilla server, holding jump will mispredict."
    );
}

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return;
    }
    let scroll_lock = args.iter().any(|a| a == "--scroll-lock");
    let pid = match args.iter().position(|a| a == "--attach") {
        Some(i) => match args.get(i + 1).and_then(|s| s.parse::<u32>().ok()) {
            Some(pid) => pid,
            None => {
                usage();
                std::process::exit(2);
            }
        },
        None => match Process::find_game() {
            Some((pid, name)) => {
                println!("[*] found {name} (pid {pid})");
                pid
            }
            None => {
                eprintln!(
                    "[!] CS:S is not running (looked for {}). Start it with -insecure first.",
                    GAME_EXES.join(" / ")
                );
                std::process::exit(1);
            }
        },
    };

    let Some(proc) = Process::open(pid) else {
        eprintln!(
            "[!] cannot open pid {pid} (err {}). Try running as administrator.",
            unsafe { GetLastError() }
        );
        std::process::exit(1);
    };
    let Some(module) = proc.module(CLIENT_DLL) else {
        eprintln!("[!] {CLIENT_DLL} is not loaded in pid {pid} yet — join a server first.");
        std::process::exit(1);
    };
    println!(
        "[*] {CLIENT_DLL} at {:#x} ({} KB)",
        module.base,
        module.size / 1024
    );

    let sites = find_sites(&proc, &module);
    if sites.is_empty() {
        eprintln!(
            "[!] no signature matched in {CLIENT_DLL}; nothing was patched.\n\
             \x20   The Windows pattern comes from upstream's 32-bit client.dll and is\n\
             \x20   unverified against current builds — if your game works otherwise,\n\
             \x20   this signature needs re-deriving for your client.dll."
        );
        std::process::exit(1);
    }
    println!("[*] found {} patch site(s)", sites.len());

    unsafe { SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    let mut on = if scroll_lock {
        unsafe { GetAsyncKeyState(VK_SCROLL) & 1 != 0 }
    } else {
        true
    };
    apply(&proc, &sites, on);
    if scroll_lock {
        println!("(prediction follows Scroll Lock; Ctrl+C to restore and exit)");
    } else {
        println!("(Ctrl+C to restore and exit)");
    }

    while !QUIT.load(std::sync::atomic::Ordering::SeqCst) {
        unsafe { Sleep(100) };
        // the game exiting invalidates the module: stop touching it
        if proc.read(module.base, 2).is_none() {
            println!("[*] game exited");
            return; // its memory is gone; nothing to restore
        }
        if scroll_lock {
            let want = unsafe { GetAsyncKeyState(VK_SCROLL) & 1 != 0 };
            if want != on {
                on = want;
                apply(&proc, &sites, on);
            }
        }
    }
    if on {
        apply(&proc, &sites, false);
    }
    println!("[*] original bytes restored");
}
