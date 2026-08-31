//! Linux backend — Autobhop Prediction Enabler for Counter-Strike: Source.
//!
//! Port of the idea from alkatrazbhop/BunnyhopAPE and rtldg/RawInput2BunnyhopAPE
//! to Linux, in Rust.
//!
//! What it patches (found by reversing the current CS:S Linux client.so):
//!   CGameMovement::CheckJumpButton / CCSGameMovement::CheckJumpButton contain:
//!       if (mv->m_nOldButtons & IN_JUMP) return false;
//!   On autobhop servers the server holds IN_JUMP for you, so the client-side
//!   prediction of CheckJumpButton bails out every tick and you only see the
//!   jump when the server snapshot arrives (feels laggy on high ping).
//!   NOPing the 6-byte `jne` after that check makes the client predict the
//!   jump immediately. It does NOT let you cheat scroll times — the server
//!   still decides what actually happens.
//!
//! The game must run with -insecure (like the original tool), because this
//! writes into game memory. On VAC-secured servers you should not use it.

use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Signatures
//
// `CheckJumpButton` exists twice in client.so — the base CGameMovement and the
// CCSGameMovement override — and both contain:
//
//     if (mv->m_nOldButtons & IN_JUMP)     // IN_JUMP == 2, m_nOldButtons +0x28
//         return false;
//
// We locate that `jne` by pattern and NOP it. Patterns rather than addresses:
// the 2026-08-24 update moved both functions ~0x1e80 while leaving these exact
// instructions intact, so the scan kept working where an address did not. On
// that build each pattern matches exactly once, inside CGameMovement[30] and
// CCSGameMovement[30] respectively.
// ---------------------------------------------------------------------------

use crate::sig::Sig;

#[rustfmt::skip]
static SIGS: &[Sig] = &[
    Sig {
        name: "linux64 CheckJumpButton #1",
        // cmpb $0x0,0x1448(%rax) ; jne out ; mov 0x10(%rbx),%rdx
        // testb $0x2,0x28(%rdx)  ; jne out   <- patched
        pat: "80 B8 48 14 00 00 00  0F 85 ?? FF FF FF  48 8B 53 10  F6 42 28 02  0F 85 ?? FF FF FF",
        at: 21, len: 6,
    },
    Sig {
        name: "linux64 CheckJumpButton #2",
        // mov 0x58(%rax),%edx ; test %edx,%edx ; jne short
        // mov 0x10(%r12),%rax ; testb $0x2,0x28(%rax) ; jne out   <- patched
        pat: "8B 50 58  85 D2  75 ??  49 8B 44 24 10  F6 40 28 02  0F 85 ?? FF FF FF",
        at: 16, len: 6,
    },
    Sig {
        name: "linux32 CheckJumpButton #1",
        // same logic, 32-bit encoding (m_vecPunchAngle-era layout: +0xfa4)
        pat: "80 B8 A4 0F 00 00 00  0F 85 ?? FF FF FF  8B 53 08  F6 42 28 02  0F 85 ?? FF FF FF",
        at: 20, len: 6,
    },
    Sig {
        name: "linux32 CheckJumpButton #2",
        pat: "8B 50 30  85 D2  75 ??  8B 43 08  F6 40 28 02  0F 85 ?? FF FF FF",
        at: 14, len: 6,
    },
];

const NOP: u8 = 0x90;

/// Scan `buf` for every signature. Returns (sig index, offset in buf) hits.
fn scan(buf: &[u8]) -> Vec<(usize, usize)> {
    let mut hits = Vec::new();
    for (si, s) in SIGS.iter().enumerate() {
        match s.pattern() {
            Some(p) => hits.extend(p.find_all(buf).into_iter().map(|off| (si, off))),
            // a malformed literal is a bug in this table, not a game update
            None => eprintln!("[!] signature {:?} is malformed; skipping", s.name),
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// /proc helpers
// ---------------------------------------------------------------------------

const GAME_COMMS: [&str; 3] = ["cstrike_linux64", "cstrike_linux", "hl2_linux"];

/// True if `pid` currently names a CS:S game process (guards PID reuse).
fn pid_is_game(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|c| GAME_COMMS.contains(&c.trim()))
        .unwrap_or(false)
}

fn find_game_pid() -> Option<u32> {
    // NB: use flatten()/continue, not `?`, so one unreadable /proc entry
    // (a process that exited mid-scan) doesn't abort the whole search.
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
            if GAME_COMMS.contains(&comm.trim()) {
                return name.parse().ok();
            }
        }
    }
    None
}

/// Parent pid from /proc/<pid>/stat, robust to a comm containing spaces or
/// parentheses (the ppid is the 2nd field after the final ')').
fn parent_pid(pid: u32) -> Option<u32> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1; // " R <ppid> ..."
    let mut it = after.split_whitespace();
    it.next()?; // process state
    it.next()?.parse().ok()
}

/// True if `pid` is `ancestor` or descends from it (bounded walk).
fn is_descendant_of(mut pid: u32, ancestor: u32) -> bool {
    for _ in 0..24 {
        if pid == ancestor {
            return true;
        }
        match parent_pid(pid) {
            Some(p) if p > 1 => pid = p,
            _ => return false,
        }
    }
    false
}

/// Find the running CS:S game process that descends from `ancestor`.
///
/// We launch `cstrike.sh`, which FORKS the game as a child (it does not
/// `exec`), so the real game is a grandchild in a DIFFERENT pid than our
/// spawned child. Restricting to descendants of our launcher child avoids
/// grabbing an unrelated/previous game instance.
fn find_game_pid_under(ancestor: u32) -> Option<u32> {
    for entry in fs::read_dir("/proc").ok()?.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        if let Ok(comm) = fs::read_to_string(entry.path().join("comm")) {
            if GAME_COMMS.contains(&comm.trim()) && is_descendant_of(pid, ancestor) {
                return Some(pid);
            }
        }
    }
    None
}

/// Executable span of client.so: (start, size). Returns the UNION of all
/// r-xp client.so mappings, not just the first — inline patching elsewhere
/// (e.g. librawinput2.so's viewpunch NOPs) mprotects sub-ranges, which splits
/// the single r-xp VMA into several contiguous fragments. Taking only the
/// first fragment would miss CheckJumpButton if it lands past the first split.
fn client_so_region(pid: u32) -> Option<(u64, u64)> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut lo: Option<u64> = None;
    let mut hi: Option<u64> = None;
    for line in maps.lines() {
        if line.contains("/client.so") && line.contains("r-xp") {
            let range = line.split_whitespace().next()?;
            let (start, end) = range.split_once('-')?;
            let start = u64::from_str_radix(start, 16).ok()?;
            let end = u64::from_str_radix(end, 16).ok()?;
            lo = Some(lo.map_or(start, |l| l.min(start)));
            hi = Some(hi.map_or(end, |h| h.max(end)));
        }
    }
    let (lo, hi) = (lo?, hi?);
    Some((lo, hi - lo))
}

fn cmdline_has_insecure(pid: u32) -> bool {
    fs::read(format!("/proc/{pid}/cmdline"))
        .map(|c| c.split(|&b| b == 0).any(|arg| arg == b"-insecure"))
        .unwrap_or(false)
}

fn read_mem(pid: u32, addr: u64, len: usize) -> std::io::Result<Vec<u8>> {
    let mem = File::open(format!("/proc/{pid}/mem"))?;
    let mut buf = vec![0u8; len];
    mem.read_at(&mut buf, addr)?;
    Ok(buf)
}

fn write_mem(pid: u32, addr: u64, data: &[u8]) -> std::io::Result<()> {
    let mem = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{pid}/mem"))?;
    mem.write_at(data, addr)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ptrace wrapper (stop the main thread while patching, then resume)
// ---------------------------------------------------------------------------

struct PtraceGuard {
    pid: u32,
    attached: bool,
}

impl PtraceGuard {
    fn attach(pid: u32) -> Option<Self> {
        unsafe {
            if libc::ptrace(
                libc::PTRACE_ATTACH,
                pid as libc::pid_t,
                std::ptr::null_mut::<c_void>(),
                std::ptr::null_mut::<c_void>(),
            ) < 0
            {
                return None;
            }
            let mut status: libc::c_int = 0;
            libc::waitpid(pid as libc::pid_t, &mut status, 0);
        }
        Some(Self {
            pid,
            attached: true,
        })
    }
}

impl Drop for PtraceGuard {
    fn drop(&mut self) {
        if self.attached {
            unsafe {
                libc::ptrace(
                    libc::PTRACE_DETACH,
                    self.pid as libc::pid_t,
                    std::ptr::null_mut::<c_void>(),
                    std::ptr::null_mut::<c_void>(),
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Patch state
// ---------------------------------------------------------------------------

struct PatchSite {
    name: &'static str,
    addr: u64,
    len: usize,
    original: Vec<u8>,
}

struct Patcher {
    pid: u32,
    sites: Vec<PatchSite>,
    enabled: bool,
}

impl Patcher {
    /// Scan the game's client.so and build the site list.
    fn discover(pid: u32) -> Result<Self, String> {
        let (base, size) = client_so_region(pid)
            .ok_or_else(|| "client.so not found in process maps yet".to_string())?;
        let buf = read_mem(pid, base, size as usize)
            .map_err(|e| format!("reading client.so memory: {e}"))?;
        let hits = scan(&buf);
        if hits.is_empty() {
            return Err("no signatures matched (game updated? already patched?)".into());
        }
        let mut sites = Vec::new();
        for (si, off) in hits {
            let s = &SIGS[si];
            let addr = base + off as u64 + s.at as u64;
            let original =
                read_mem(pid, addr, s.len).map_err(|e| format!("reading original bytes: {e}"))?;
            sites.push(PatchSite {
                name: s.name,
                addr,
                len: s.len,
                original,
            });
        }
        Ok(Self {
            pid,
            sites,
            enabled: false,
        })
    }

    fn apply(&self, nops: bool) -> std::io::Result<()> {
        // Guard against PID reuse: never write to /proc/<pid>/mem unless the
        // pid still names the game (it could have exited and the number been
        // recycled to an unrelated process between our checks).
        if !pid_is_game(self.pid) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "target pid is no longer a CS:S process",
            ));
        }
        let _guard = PtraceGuard::attach(self.pid); // best effort; write works without it if permitted
        for site in &self.sites {
            if nops {
                write_mem(self.pid, site.addr, &vec![NOP; site.len])?;
            } else {
                write_mem(self.pid, site.addr, &site.original)?;
            }
        }
        Ok(())
    }

    fn enable(&mut self) {
        match self.apply(true) {
            Ok(()) => {
                self.enabled = true;
                print_status(true, &self.sites);
            }
            Err(e) => eprintln!("[!] failed to patch: {e}"),
        }
    }

    fn disable(&mut self) {
        match self.apply(false) {
            Ok(()) => {
                self.enabled = false;
                print_status(false, &self.sites);
            }
            Err(e) => eprintln!("[!] failed to restore: {e}"),
        }
    }
}

impl Drop for Patcher {
    fn drop(&mut self) {
        if self.enabled {
            let _ = self.apply(false);
        }
    }
}

fn print_status(enabled: bool, sites: &[PatchSite]) {
    println!(
        "\n=== Autobhop prediction: {} ===",
        if enabled { "ON" } else { "OFF" }
    );
    for s in sites {
        println!("    {:<28} @ 0x{:x}", s.name, s.addr);
    }
    println!(
        "(toggle: kill -USR1 {}, or --scroll-lock for Scroll Lock)\n",
        std::process::id(),
    );
}

// ---------------------------------------------------------------------------
// Scroll Lock detection via sysfs LEDs (no X11 dependency)
// ---------------------------------------------------------------------------

fn scroll_lock_on() -> bool {
    let Ok(entries) = fs::read_dir("/sys/class/leds") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        if name.to_string_lossy().ends_with("::scrolllock") {
            if let Ok(v) = fs::read_to_string(entry.path().join("brightness")) {
                return v.trim() != "0";
            }
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

static GOT_SIGUSR1: AtomicBool = AtomicBool::new(false);
static GOT_TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigusr1(_: libc::c_int) {
    GOT_SIGUSR1.store(true, Ordering::SeqCst);
}
extern "C" fn on_sigterm(_: libc::c_int) {
    GOT_TERM.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    unsafe {
        libc::signal(libc::SIGUSR1, on_sigusr1 as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_sigterm as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_sigterm as *const () as libc::sighandler_t);
    }
}

// ---------------------------------------------------------------------------
// CS:S locating & launching
// ---------------------------------------------------------------------------

fn find_css_dir() -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let candidates = [
        format!("{home}/.local/share/Steam/steamapps/common/Counter-Strike Source"),
        format!("{home}/.steam/steam/steamapps/common/Counter-Strike Source"),
        format!("{home}/.steam/root/steamapps/common/Counter-Strike Source"),
    ];
    // Also parse libraryfolders.vdf for extra libraries.
    let mut extra = Vec::new();
    for base in [
        format!("{home}/.local/share/Steam/steamapps/libraryfolders.vdf"),
        format!("{home}/.steam/steam/steamapps/libraryfolders.vdf"),
    ] {
        if let Ok(vdf) = fs::read_to_string(base) {
            for line in vdf.lines() {
                if let Some(idx) = line.find("\"path\"") {
                    // crude VDF parse: "path"  "VALUE"
                    let val: String = line[idx + 6..]
                        .chars()
                        .skip_while(|c| *c != '"')
                        .skip(1)
                        .take_while(|c| *c != '"')
                        .collect();
                    if !val.is_empty() {
                        extra.push(format!(
                            "{}/steamapps/common/Counter-Strike Source",
                            val.replace("\\\\", "/")
                        ));
                    }
                }
            }
        }
    }
    candidates
        .iter()
        .chain(extra.iter())
        .map(PathBuf::from)
        .find(|p| p.join("cstrike.sh").exists())
}

/// Snapshot the current mode+rate of every connected output via xrandr,
/// so we can restore them after the game exits (fullscreen games leave the
/// display at whatever mode they picked, e.g. 60Hz).
fn save_display_modes() -> Vec<(String, String, String)> {
    let mut out = Vec::new();
    let Ok(stdout) = Command::new("xrandr")
        .arg("--query")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    else {
        return out;
    };
    let mut current_output: Option<String> = None;
    for line in stdout.lines() {
        if line.contains(" connected") {
            current_output = line.split_whitespace().next().map(str::to_string);
        } else if let (Some(output), true) = (&current_output, line.starts_with(' ')) {
            let mut parts = line.split_whitespace();
            if let Some(mode) = parts.next() {
                // the current rate is the token carrying '*', wherever it is
                if let Some(rate) = parts.find(|r| r.contains('*')) {
                    let rate = rate.trim_end_matches(['*', '+']).to_string();
                    out.push((output.clone(), mode.to_string(), rate));
                }
            }
        }
    }
    out
}

fn restore_display_modes(modes: &[(String, String, String)]) {
    if modes.is_empty() {
        return;
    }
    println!("[*] restoring desktop display modes...");
    for (output, mode, rate) in modes {
        let _ = Command::new("xrandr")
            .args(["--output", output, "--mode", mode, "--rate", rate])
            .status();
    }
}

fn running_i3() -> bool {
    ["XDG_CURRENT_DESKTOP", "DESKTOP_SESSION"].iter().any(|k| {
        std::env::var(k)
            .map(|v| v.split(':').any(|p| p.eq_ignore_ascii_case("i3")))
            .unwrap_or(false)
    })
}

/// On i3, fullscreen the (already-mapped) CS:S window so it covers the whole
/// output — otherwise a borderless window is tiled below full-screen and a
/// compositor won't unredirect it (adding a frame of latency). The runtime
/// `[criteria] fullscreen enable` command acts on the existing window, so this
/// runs AFTER the window has mapped. Best-effort (i3-msg reports success even
/// when it matches zero windows, so we also point at the reliable config
/// rule). Source's window title is "Counter-Strike: Source" — i3 matches the
/// substring.
fn i3_fullscreen_game_window() {
    let _ = Command::new("i3-msg")
        .arg(r#"[title="Counter-Strike"] fullscreen enable"#)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    println!(
        "[*] i3: fullscreened the game window so borderless covers the whole output\n\
         [*]   (picom then presents it directly — no extra latency). If it stays\n\
         [*]   tiled, add this to your i3 config for a permanent fix:\n\
         [*]     for_window [title=\"Counter-Strike\"] fullscreen enable"
    );
}

/// Primary connected output's current resolution (width, height) via xrandr.
fn primary_resolution() -> Option<(u32, u32)> {
    let out = Command::new("xrandr").arg("--query").output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    for line in s.lines() {
        // e.g. "DP-4 connected primary 1920x1080+0+500 (normal ...) ..."
        if line.contains(" connected") && line.contains(" primary ") {
            if let Some(geo) = line
                .split_whitespace()
                .find(|t| t.contains('x') && t.contains('+'))
            {
                let dims = geo.split('+').next()?;
                if let Some((w, h)) = dims.split_once('x') {
                    if let (Ok(w), Ok(h)) = (w.parse(), h.parse()) {
                        return Some((w, h));
                    }
                }
            }
        }
    }
    None
}

fn launch_css(css_dir: &Path, extra_args: &[String]) -> std::io::Result<Child> {
    let mut default_args: Vec<String> = vec![
        "-game".into(),
        "cstrike".into(),
        "-insecure".into(),
        "-novid".into(),
    ];
    // Display mode. Default is BORDERLESS windowed at the primary output's
    // resolution: it avoids the exclusive-fullscreen mode-switch (which was
    // timing out and stuttering — repeated "mode switch ... reverting"), and
    // under a compositor with unredirect-if-possible (or a bare WM) the
    // full-screen borderless window is presented directly, so input latency
    // matches exclusive fullscreen. Force exclusive fullscreen with
    // BHOP_FULLSCREEN=1 (then -freq keeps the display off 60Hz; CSS_FREQ
    // overrides the rate, CSS_FREQ=off drops -freq).
    if std::env::var_os("BHOP_FULLSCREEN").is_some() {
        match std::env::var("CSS_FREQ").as_deref() {
            Ok("off") => {}
            Ok(rate) => {
                default_args.push("-freq".into());
                default_args.push(rate.into());
            }
            Err(_) => {
                default_args.push("-freq".into());
                default_args.push("144".into());
            }
        }
    } else {
        default_args.push("-windowed".into());
        default_args.push("-noborder".into());
        match primary_resolution() {
            Some((w, h)) => {
                default_args.push("-w".into());
                default_args.push(w.to_string());
                default_args.push("-h".into());
                default_args.push(h.to_string());
                println!("[*] display: borderless windowed {w}x{h} (BHOP_FULLSCREEN=1 for exclusive fullscreen)");
            }
            None => {
                println!("[*] display: borderless windowed (resolution auto-detect failed; BHOP_FULLSCREEN=1 for exclusive)");
            }
        }
    }

    // Force m_rawinput 2 at launch. The whole point of librawinput2.so is the
    // tick-aligned mode-2 sampler, but config.cfg ships "m_rawinput 1" (plus
    // m_rawinput_onetime_reset) which overrides autoexec.cfg depending on load
    // order — so setting it in autoexec is unreliable. A command-line
    // "+m_rawinput 2" is applied AFTER all configs load and reliably wins; the
    // user can still change it in-game or override it via `-- +m_rawinput N`.
    // Opt out with RAWINPUT2_NO_FORCE=1.
    if std::env::var_os("RAWINPUT2_NO_FORCE").is_none() {
        default_args.push("+m_rawinput".into());
        default_args.push("2".into());
    }

    let mut cmd = Command::new(css_dir.join("cstrike.sh"));
    cmd.current_dir(css_dir)
        .args(&default_args)
        .args(extra_args);

    // Inject rawinput2.so (m_rawinput 2 hooks) if it sits next to this binary,
    // filtering the Steam overlay out of any inherited LD_PRELOAD (see below).
    let mut preload_parts: Vec<String> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let lib = dir.join("librawinput2.so");
            if lib.exists() {
                preload_parts.push(lib.to_string_lossy().into_owned());
                println!("[*] injecting librawinput2.so (m_rawinput 2 hooks)");
            } else {
                println!(
                    "[*] librawinput2.so not found next to binary; skipping m_rawinput 2 hooks"
                );
            }
        }
    }
    harden_launch_env(&mut cmd, &mut preload_parts);
    if !preload_parts.is_empty() {
        cmd.env("LD_PRELOAD", preload_parts.join(":"));
    }

    cmd.spawn()
}

/// Component 6: pre-launch environment hardening for known Source-on-Linux
/// bhop issues. Each tweak is individually opt-out via env so power users
/// keep control; we only ever ADD/keep, never silently override a value the
/// user set. `preload_parts` is the LD_PRELOAD list being assembled (our hook
/// lib, if any, is already first).
fn harden_launch_env(cmd: &mut Command, preload_parts: &mut Vec<String>) {
    // 1) Keep the Steam overlay (gameoverlayrenderer.so) OUT of the preload
    //    chain: it causes an input-triggered frametime-sawtooth "timebomb"
    //    after ~25-40 min even when the overlay is disabled in the UI
    //    (steam-for-linux#11446). We inherit LD_PRELOAD but drop that one lib.
    //    Opt out with BHOP_KEEP_OVERLAY=1.
    if std::env::var_os("BHOP_KEEP_OVERLAY").is_none() {
        if let Ok(existing) = std::env::var("LD_PRELOAD") {
            let mut dropped = false;
            // glibc treats space/tab AND colon as LD_PRELOAD separators.
            for part in existing.split([':', ' ', '\t']).filter(|p| !p.is_empty()) {
                // Match the basename exactly, not a substring of the whole
                // path (so a user lib in a "...gameoverlayrenderer..." dir is
                // never dropped by mistake).
                if Path::new(part)
                    .file_name()
                    .map(|f| f == "gameoverlayrenderer.so")
                    == Some(true)
                {
                    dropped = true;
                } else {
                    preload_parts.push(part.to_string());
                }
            }
            if dropped {
                println!("[*] hardening: excluded gameoverlayrenderer.so from LD_PRELOAD (#11446 stutter guard)");
            }
        }
    } else if let Ok(existing) = std::env::var("LD_PRELOAD") {
        preload_parts.extend(
            existing
                .split([':', ' ', '\t'])
                .filter(|p| !p.is_empty())
                .map(String::from),
        );
    }

    // LD_PRELOAD has no quoting: a path with a space/tab is split by the
    // loader and every fragment fails to load. Warn if our own hook path (or
    // any assembled entry) contains whitespace — the hook would silently not
    // inject.
    if let Some(bad) = preload_parts.iter().find(|p| p.contains([' ', '\t'])) {
        println!(
            "[!] warning: LD_PRELOAD entry contains whitespace and will NOT load\n\
             [!]   ({bad})\n\
             [!]   glibc can't quote preload paths — install to a space-free path."
        );
    }

    // 2) DXVK: cap the frame queue to 1 for tighter input latency (the one
    //    DXVK knob that helps here; the in-game fps_max stays the limiter).
    //    CS:S 64-bit renders via vendored dxvk-native (confirmed: the game's
    //    d3d9 log reports "Found config env: d3d9.maxFrameLatency = 1"), which
    //    reads DXVK_CONFIG. Merged into any DXVK_CONFIG the user set. Opt out
    //    with BHOP_NO_DXVK_TWEAKS=1.
    if std::env::var_os("BHOP_NO_DXVK_TWEAKS").is_none()
        && std::env::var_os("DXVK_CONFIG_FILE").is_none()
    {
        let base = std::env::var("DXVK_CONFIG").unwrap_or_default();
        // dedupe on the specific key so an unrelated *.maxFrameLatency the
        // user set (e.g. dxgi.maxFrameLatency) doesn't suppress ours.
        if !base.contains("d3d9.maxFrameLatency") {
            let mut v = base;
            if !v.is_empty() && !v.trim_end().ends_with(';') {
                v.push_str("; ");
            }
            v.push_str("d3d9.maxFrameLatency = 1");
            cmd.env("DXVK_CONFIG", v);
            println!("[*] hardening: DXVK_CONFIG d3d9.maxFrameLatency = 1");
        }
    }

    // 3) SDL audio: pin the PulseAudio backend, but ONLY if a Pulse endpoint
    //    is actually reachable. SDL initializes just the named driver and does
    //    NOT fall back, so pinning it on a pure-ALSA / bare-PipeWire (no
    //    pipewire-pulse) box would mean total silence. The pipewire-pulse
    //    shim exposes the same socket, which is what we probe for. This dodges
    //    the SDL PipeWire-backend stutter/echo regression (#8013). Opt out
    //    with BHOP_NO_SDL_AUDIO=1.
    if std::env::var_os("BHOP_NO_SDL_AUDIO").is_none()
        && std::env::var_os("SDL_AUDIODRIVER").is_none()
        && std::env::var_os("SDL_AUDIO_DRIVER").is_none()
    {
        if pulse_socket_present() {
            cmd.env("SDL_AUDIODRIVER", "pulseaudio"); // classic SDL2 name
            cmd.env("SDL_AUDIO_DRIVER", "pulseaudio"); // SDL3/sdl2-compat name
            println!("[*] hardening: SDL audio backend pinned to pulseaudio (#8013 guard)");
        } else {
            println!("[*] hardening: no PulseAudio socket found; leaving SDL audio on auto-detect");
        }
    }
}

/// True if a PulseAudio-compatible socket (native pulse, or the
/// pipewire-pulse shim exposing the same path) is reachable for this user.
fn pulse_socket_present() -> bool {
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", unsafe { libc::getuid() })));
    runtime.join("pulse/native").exists()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

fn print_usage() {
    eprintln!(
        "bunnyhop-ape — Autobhop Prediction Enabler for CS:S (Linux)\n\
         \n\
         USAGE:\n\
         \x20 bunnyhop-ape [-- extra game args]   launch CS:S with -insecure and patch it\n\
         \x20 bunnyhop-ape --attach [pid]         patch a running game (auto-finds pid; needs sudo)\n\
         \x20 bunnyhop-ape --scan-file <path>     offline: verify signatures against client.so\n\
         \x20 bunnyhop-ape --fix-maps [game-root] extract uppercase-packed pak content of all maps\n\
         \x20                                             as lowercase loose files (Linux pink-texture fix)\n\
         \n\
         Toggle prediction at runtime with Scroll Lock or: kill -USR1 <pid of this tool>\n\
         \n\
         WARNING: only use with -insecure. Patching memory on VAC-secured\n\
         servers is your own risk."
    );
}

pub fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // --- help ---------------------------------------------------------------
    // (explicit, so an unknown flag doesn't silently fall through to "launch
    // the game with these extra args".)
    if matches!(args.first().map(String::as_str), Some("--help" | "-h")) {
        print_usage();
        return;
    }

    // --- offline signature verification -------------------------------------
    if args.first().map(String::as_str) == Some("--scan-file") {
        let Some(path) = args.get(1) else {
            print_usage();
            std::process::exit(2);
        };
        let mut buf = Vec::new();
        File::open(path)
            .and_then(|mut f| f.read_to_end(&mut buf))
            .unwrap_or_else(|e| {
                eprintln!("cannot read {path}: {e}");
                std::process::exit(1);
            });
        let hits = scan(&buf);
        if hits.is_empty() {
            println!("no signatures matched in {path}");
            std::process::exit(1);
        }
        for (si, off) in hits {
            let s = &SIGS[si];
            println!(
                "MATCH {:<28} file offset 0x{:x} (patch at 0x{:x}, {} bytes)",
                s.name,
                off,
                off + s.at,
                s.len
            );
        }
        return;
    }

    // --- standalone pakfile case-fix sweep ------------------------------------
    if args.first().map(String::as_str) == Some("--fix-maps") {
        let css_dir = match args.get(1) {
            Some(path) if !path.starts_with('-') && args.len() == 2 => PathBuf::from(path),
            None => find_css_dir().unwrap_or_else(|| {
                eprintln!("[!] could not locate Counter-Strike Source install");
                std::process::exit(1);
            }),
            _ => {
                print_usage();
                std::process::exit(2);
            }
        };
        if !css_dir.join("cstrike").is_dir() {
            eprintln!("[!] {} has no cstrike/ directory", css_dir.display());
            std::process::exit(1);
        }
        println!("[*] CS:S found at {}", css_dir.display());
        let n = crate::pakfix::sweep(&css_dir);
        println!(
            "[*] case-fix sweep done: {n} file(s) extracted to cstrike/download\n\
             [*] (a running game picks them up on the next map load — `retry` in console)"
        );
        return;
    }

    install_signal_handlers();

    // --- attach or launch ----------------------------------------------------
    let mut child: Option<Child> = None;
    // The process we patch. In --attach this is the game directly. When we
    // launch, our child is cstrike.sh (which forks the game as a grandchild),
    // so `pid` stays 0 until we resolve the real game process below.
    let mut pid: u32 = 0;
    let mut wrapper_pid: Option<u32> = None;
    let mut saved_modes: Vec<(String, String, String)> = Vec::new();

    if args.first().map(String::as_str) == Some("--attach") {
        pid = match args.get(1) {
            Some(pid_str) => pid_str.parse().unwrap_or_else(|_| {
                eprintln!("invalid pid: {pid_str}");
                std::process::exit(2);
            }),
            None => find_game_pid().unwrap_or_else(|| {
                eprintln!("[!] no running CS:S process found");
                std::process::exit(1);
            }),
        };
        if !cmdline_has_insecure(pid) {
            eprintln!(
                "[!] the game was NOT started with -insecure.\n\
                 [!] refusing to patch (same policy as the original BunnyhopAPE).\n\
                 [!] restart the game through this tool instead."
            );
            std::process::exit(1);
        }
        println!("[*] attaching to running game (pid {pid})");
    } else {
        let extra: Vec<String> = if let Some(pos) = args.iter().position(|a| a == "--") {
            args[pos + 1..].to_vec()
        } else {
            Vec::new()
        };
        let Some(css_dir) = find_css_dir() else {
            eprintln!("[!] could not locate Counter-Strike Source install");
            std::process::exit(1);
        };
        println!("[*] CS:S found at {}", css_dir.display());
        // Linux case-folding fix (Source-1-Games#6868) for maps already on
        // disk, before the game boots; newly downloaded maps are handled at
        // runtime by librawinput2.so.
        let fixed = crate::pakfix::sweep(&css_dir);
        if fixed > 0 {
            println!("[*] case-fix: extracted {fixed} uppercase-packed file(s) from map pakfiles");
        }
        println!("[*] launching CS:S with -insecure -novid ...");
        println!("[*] tip: run this tool via `gamemoderun bunnyhop-ape` to keep gamemode");
        saved_modes = save_display_modes();
        match launch_css(&css_dir, &extra) {
            Ok(c) => {
                wrapper_pid = Some(c.id()); // cstrike.sh; the game forks off it
                child = Some(c);
            }
            Err(e) => {
                eprintln!("[!] failed to launch CS:S: {e}");
                std::process::exit(1);
            }
        }
    }

    // --- wait for client.so --------------------------------------------------
    println!("[*] waiting for the game process + client.so to load...");
    let patcher = loop {
        if GOT_TERM.load(Ordering::SeqCst) {
            return;
        }
        if let Some(c) = child.as_mut() {
            if let Ok(Some(status)) = c.try_wait() {
                println!("[*] launcher exited before the game loaded ({status})");
                return;
            }
        }
        // Launch mode: resolve the real game process (a cstrike_linux64
        // descendant of our cstrike.sh child), since child.id() is the shell.
        if pid == 0 {
            if let Some(wp) = wrapper_pid {
                match find_game_pid_under(wp) {
                    Some(gp) => {
                        pid = gp;
                        println!("[*] game process is pid {pid}");
                    }
                    None => {
                        thread::sleep(Duration::from_millis(250));
                        continue;
                    }
                }
            }
        }
        if pid != 0 && client_so_region(pid).is_some() {
            // give the loader a moment to finish relocations
            thread::sleep(Duration::from_millis(500));
            match Patcher::discover(pid) {
                Ok(p) => break p,
                Err(e) => {
                    eprintln!("[!] {e}; retrying...");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        } else {
            thread::sleep(Duration::from_millis(250));
        }
    };
    let mut patcher = patcher;

    println!("[*] found {} patch site(s)", patcher.sites.len());
    patcher.enable();

    // Drop any SIGUSR1 that arrived during the (possibly long) wait for the
    // game to load, so it doesn't immediately toggle the patch back off.
    GOT_SIGUSR1.store(false, Ordering::SeqCst);

    // Borderless on i3: fullscreen the (now-mapped) game window so it covers
    // the whole output and the compositor presents it directly (no added
    // latency). Launch + borderless mode only; attach leaves the user's setup
    // alone.
    if child.is_some() && std::env::var_os("BHOP_FULLSCREEN").is_none() && running_i3() {
        i3_fullscreen_game_window();
    }

    // --- main loop: toggle & watch -------------------------------------------
    // Scroll Lock toggling is opt-in: X11/game keyboard grabs can flip the LED
    // and cause phantom toggles. Default toggle is SIGUSR1 only.
    let scroll_toggle = args.iter().any(|a| a == "--scroll-lock");
    let mut last_scroll = scroll_lock_on();
    loop {
        thread::sleep(Duration::from_millis(100));

        if GOT_TERM.load(Ordering::SeqCst) {
            println!("\n[*] restoring original bytes and exiting");
            if patcher.enabled {
                patcher.disable();
            }
            restore_display_modes(&saved_modes);
            return;
        }

        if GOT_SIGUSR1.swap(false, Ordering::SeqCst) {
            if patcher.enabled {
                patcher.disable();
            } else {
                patcher.enable();
            }
        }

        if scroll_toggle {
            let sl = scroll_lock_on();
            if sl != last_scroll {
                last_scroll = sl;
                if patcher.enabled {
                    patcher.disable();
                } else {
                    patcher.enable();
                }
            }
        }

        // The resolved game process disappearing is authoritative in BOTH
        // attach and launch mode (in launch mode `child` is cstrike.sh, which
        // can linger or exit independently of the game). The launcher child
        // exiting is an additional early signal.
        let child_gone = child
            .as_mut()
            .map(|c| matches!(c.try_wait(), Ok(Some(_))))
            .unwrap_or(false);
        if client_so_region(pid).is_none() || child_gone {
            println!("[*] game exited");
            restore_display_modes(&saved_modes);
            return; // Patcher::drop restores bytes if still enabled
        }
    }
}
