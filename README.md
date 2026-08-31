# bunnyhop-ape

**Autobhop Prediction Enabler + RawInput2 for Counter-Strike: Source**, written
in Rust. Full-featured on Linux; barebones prediction patcher on Windows.

A port of [alkatrazbhop/BunnyhopAPE](https://github.com/alkatrazbhop/BunnyhopAPE)
and [rtldg/RawInput2BunnyhopAPE](https://github.com/rtldg/RawInput2BunnyhopAPE)
(both Windows-only) to Linux, plus a Windows patcher of our own.

| artifact | what it is |
|---|---|
| `bunnyhop-ape` | launcher/patcher: autobhop jump-prediction patch (BunnyhopAPE half) |
| `librawinput2.so` | LD_PRELOAD hook library, Linux only: momentum-style `m_rawinput 2` (RawInput2 half) **+ fastdl.me map hijack** |

## Platform support

| | Linux | Windows |
|---|---|---|
| autobhop prediction patch | ✅ verified on build 10897846 | ⚠️ builds, signature unverified |
| `m_rawinput 2`, viewpunch, fastdl, console glue | ✅ | ❌ (LD_PRELOAD/ELF/procfs only) |
| launches the game for you | ✅ | ❌ start CS:S yourself, then attach |

The Windows port is deliberately barebones: it finds `client.dll` in a running
game, patches `CheckJumpButton`, offers the same Scroll Lock toggle, and
restores the bytes on exit. Its signature comes from upstream's public source,
which targets the 32-bit `client.dll`, and **has not been run against a real
Windows install** — it is validated only by compiling, linking and CI. If it
does not match your `client.dll` it patches nothing and tells you so; it will
never write to a location it did not verify. Patches welcome from anyone who
can test it.

Development builds the Windows binary from Linux with
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):

```sh
rustup target add x86_64-pc-windows-gnu
cargo zigbuild --release --bin bunnyhop-ape --target x86_64-pc-windows-gnu
```

## Nothing is addressed by offset

Every location this tool touches — in both backends — is found at runtime by
what the code *is*: an instruction signature (see `src/sig.rs`), an RTTI class
name, or a relocation that names a symbol. No link-time addresses, and no
vtable slot indices either.

That is not stylistic. The 2026-08-24 CS:S update moved code ~0x1e80, moved
client vtables ~0xa90, and gave `launcher.so`'s data segment an extra page. A
stale *code* address just fails a byte check, but a stale *vtable slot* address
still points at a valid function pointer — one belonging to a different class —
so the hook installs "successfully" and corrupts an unrelated virtual. That
update turned this tool's two CreateMove slot constants into a `vgui::Panel`
virtual and a `CCSGameMovement` virtual, and its raw-mouse slot into
`ConCommand`'s destructor, and the game segfaulted ~13 s after load. Meanwhile
the stale `SDL_PollEvent` GOT constant was not a relocation at all (it held the
literal `0x8`), so raw-input sampling had been silently dead while clobbering a
data word.

Where a value can be read out of a matched instruction, it is: the view-punch
field offset and the serverinfo MD5 offset are both recovered from the
displacement bytes of the instruction that uses them. Every lookup requires a
*unique* match and disables its own feature rather than guessing.

| RawInput2BunnyhopAPE feature | In our port? |
|---|---|
| BunnyhopAPE (jump prediction) | ✅ done |
| RawInput2 (`m_rawinput 2`) | ✅ done |
| fastdl.me map hijack | ✅ done (safer variant: no message mutation) |
| Viewpunch remover (F7) | ✅ done (NOP the CalcView punch-adds; `RAWINPUT2_KEEP_VIEWPUNCH=1` to keep) |
| Download progress display | ✅ done (read-only poll of CDownloadManager) |
| fastdl 404-fallback | ❌ (planned; largely redundant with our ProcessServerInfo hijack) |
| *(ours)* in-game console (`ClientCmd`) | ✅ enables the three below |
| *(ours)* auto POV demo recording | ✅ opt-in `RAWINPUT2_DEMOS=1` (for SourceJump submissions) |
| *(ours)* SourceJump WRs in the game console | ✅ echoes WRs in-console, not just the terminal |
| *(ours)* window flash on download-finish | ✅ SDL_FlashWindow when a long download completes |
| Fullscreen hook (F6) | ➖ N/A on Linux (DXVK + your WM handle this) |
| *(ours)* pakfile case fix (pink textures) | ✅ Linux-only problem, not in the originals |
| *(ours)* launch-env hardening | ✅ Linux-only; guards known Source-on-Linux bugs |
| *(ours)* SourceJump WR display | ✅ prints map world records on connect |

## Component 5: pakfile case fix (pink-texture fix)

The 64-bit Source builds stopped case-folding lookups into the BSP's embedded
zip pakfile ([Source-1-Games#6868](https://github.com/ValveSoftware/Source-1-Games/issues/6868)):
the engine lowercases every asset lookup, so anything packed with uppercase in
its path (`materials/MIRRORSEDGE/RED.vmt`) never resolves on Linux — pink/black
checkerboards, silent sounds. Windows and the old 32-bit builds are unaffected,
which is why so many classic bhop maps ship broken paks.

Repacking the BSP would trip the server's map-consistency check, so instead the
affected entries are extracted as **lowercase loose files** under
`cstrike/download/` — the engine's pak miss falls through the search path and
finds them there. BSPs are never modified, existing files never overwritten.
It runs everywhere a map can appear:

* launcher startup: sweep of `cstrike/maps` + `cstrike/download/maps`,
* after every fastdl.me install (component 3),
* a watcher thread arms on connect for maps the *game's own* downloader
  fetches — fixed as soon as the download lands (gives up after ~2 min without
  download progress; that first session may need a `retry` in console, every
  later load is clean),
* manually: `./bunnyhop-ape --fix-maps [game-root]`.

Caveat: `sv_pure 1` servers make the client ignore loose files (still no fix
possible there without repacking); bhop servers virtually all run `sv_pure 0`.

**Still required as of build 10897846.** The 2026-08-24 update's notes include
*"Fixed a bug where certain custom maps would not load assets correctly on
Linux"*, which sounds like this, but that is a different bug — #6868 is still
live. Re-tested directly: holding back the extracted
`download/materials/skyppy4/new/metal_ceiling01a.vmt` and loading
`bhop_infernoserz` makes the engine log

```
material "materials/skyppy4/new/metal_ceiling01a" not found.
Missing map material: MATERIALS/SKYPPY4/NEW/METAL_CEILING01A
```

— the lowercased lookup missing against the uppercase-packed name. Of 54
installed maps, 22 pack uppercase asset paths. Re-run that check after a future
update before deleting this component.

## Component 6: launch-environment hardening

The launcher sets a few environment defaults that dodge known
Source-on-Linux bugs. Each is only applied if you haven't set it yourself,
and each has an opt-out:

* **Steam overlay excluded from `LD_PRELOAD`** — `gameoverlayrenderer.so`
  causes an input-triggered frametime-sawtooth *timebomb* after ~25–40 min,
  even with the overlay disabled in the UI
  ([steam-for-linux#11446](https://github.com/ValveSoftware/steam-for-linux/issues/11446)).
  We inherit `LD_PRELOAD` but drop that one entry. (Launching via this tool
  instead of Steam usually avoids it already; this is belt-and-suspenders.)
  Opt out: `BHOP_KEEP_OVERLAY=1`.
* **`DXVK_CONFIG=d3d9.maxFrameLatency = 1`** — caps DXVK's frame queue for
  tighter input latency (the in-game `fps_max` stays the frame limiter).
  Merged into any `DXVK_CONFIG` you set; skipped if `DXVK_CONFIG_FILE` is set.
  Opt out: `BHOP_NO_DXVK_TWEAKS=1`.
* **`SDL_AUDIODRIVER=pulseaudio`** (+ the SDL3 `SDL_AUDIO_DRIVER` spelling) —
  the SDL PipeWire backend regressed into heavy stutter/echo in 2026
  ([Source-1-Games#8013](https://github.com/ValveSoftware/Source-1-Games/issues/8013));
  pipewire-pulse serves the PulseAudio path cleanly. Opt out:
  `BHOP_NO_SDL_AUDIO=1`.

## Component 7: SourceJump world-record display

On connect (reusing the ProcessServerInfo hook, which already has the map
name) the tool asks [sourcejump.net](https://sourcejump.net) for the map's
records and prints the WR plus a couple of chasers to its terminal log:

```
[rawinput2] sourcejump WRs for bhop_badges:
[rawinput2]   WR 5:58.330  Jehoshaphat  (sync 93.8%, 614 strafes)
[rawinput2]      6:00.040  shinoum      (sync 92.1%, 821 strafes)
```

Read-only, off the engine thread (a slow API never stalls a connect), using
the community-shared public API key. Opt out: `RAWINPUT2_NO_SOURCEJUMP=1`.
WRs also echo into the **in-game console** via component 8.

## Component 8: engine glue (console, demos, progress, flash)

Resolves `IVEngineClient` by asking engine.so's own exported `CreateInterface`
for `VEngineClient014`, then confirms the object's RTTI really names
`CEngineClient` before calling vtable slot 7 = `ClientCmd` (verified in
disassembly to tail-call `Cbuf_AddText`). No addresses, and any mismatch
disables the console features rather than risking a fault. No code patching;
a plain validated indirect call. Built on it:

* **Console commands** — a thread-safe queue drained from the SDL_PollEvent
  hook (the main/engine thread), so background threads (e.g. SourceJump) can
  safely run commands.
* **Auto POV demo recording** *(opt-in `RAWINPUT2_DEMOS=1`)* — on connect,
  `record <map>_<unixts>` is issued from the first in-game tick (CS:S has no
  autorecord, and SourceJump only accepts demos). Writes `cstrike/*.dem`;
  prune periodically.
* **SourceJump WRs in-console** — component 7's WRs are `echo`'d into the game
  console, sanitized to a safe charset.

Download progress + window flash need no ClientCmd — they poll the
`CDownloadManager` singleton, located at runtime by scanning engine.so's
writable image (including the anonymous `.bss` tail) for an object whose vptr
is that class's RTTI vtable. Its active request is at `+0x28`; fields at
`+0x03` http, `+0x08` state, `+0x314` name, `+0x618/+0x61c` total/current.
All reads are read-only and fault-safe from the SDL hook, and the request is
shape-checked before anything is printed (the field offsets are the one thing
here that can only be re-verified during a live download):

```
[rawinput2] downloading bhop_infernoserz.bsp: 45% (31728 / 70446 KB)
[rawinput2] download complete
```

On completion the game window flashes (`SDL_FlashWindow`, resolved by name)
so an alt-tabbed long download grabs your attention.

## Component 4: viewpunch remover

No screen kick on landings/damage. `C_BasePlayer::CalcView` and a secondary
view path add `m_vecPunchAngle` onto the rendered eye angles with three
`addss <punch+0/4/8>(reg),%xmm0` each (pitch/yaw/roll). We **NOP all 9 of
those adds** so the punch is simply never applied to the view. Skip with
`RAWINPUT2_KEEP_VIEWPUNCH=1`.

The sites are not hard-coded: we decode every `addss disp32(reg),%xmm0` in
client.so's `.text` and keep those forming a `(D, D+4, D+8)` triple within a
tight span — the shape of a Vector add — taking the `D` shared by the most
triples as the punch field. That cleanly ignores the unrelated single adds at
other offsets in the same binary.

**Why not just zero the field?** `m_vecPunchAngle` is a *predicted* field: the
client restores it from its prediction backup and re-decays it every frame, so
zeroing it in the entity (or the descriptor) loses the race — the punch
reappears (decaying) before most frames render. Never *applying* it wins
regardless. (An earlier attempt wrote to what looked like a `RecvProp` proxy
slot; that structure is actually a prediction `typedescription_t` and the write
crashed the client — this approach touches neither the descriptor nor the
predicted field.)

**Safety:** every site is checked against the exact instruction bytes decoded
from client.so before anything is written; if the loaded code differs, the
remover bails without patching rather than corrupting code. On the 2026-08-24
build this finds 9 sites in 3 view paths with `m_vecPunchAngle` at `+0x1274`.

## Component 3: fastdl.me map hijack

Port of rtldg's map-download feature. Never get kicked for
`Missing map` / `Map differs` on covered servers again.

* Inline-hooks the engine's `CClientState::ProcessServerInfo` — found through
  the class's RTTI vtable (slot 17), prologue-verified before patching;
  original runs via trampoline. (A prologue *scan* would be ambiguous: those
  19 bytes occur at 12 places in engine.so.)
* On connect, reads the server's **map lump MD5** from the serverinfo message
  (`msg+0x38` — verified in disassembly) and looks it up in
  [fastdl.me](https://fastdl.me)'s `lump_checksums.csv` (cached in
  `~/.cache/bunnyhop-ape-linux/`, refreshed every 36h).
* The map **name** field is auto-detected at runtime by scanning the message
  for a plausible pointer (all reads via `/proc/self/mem`, so a bad guess
  can't crash the game — it self-logs the detected offset).
* If fastdl.me has the server's exact map version, it's downloaded from
  `https://mainr2.fastdl.me/hashed/<sha1>.bsp.bz2` (decompressed with the
  system `bzip2`; the legacy plain-`.bsp` endpoint is the fallback) and
  installed to
  `cstrike/maps/<mapname>.bsp` (BSP magic verified, atomic rename) **before**
  the game's own map validation runs — so the check passes and the connect
  proceeds. A sidecar cache makes repeat connects instant.
* If fastdl.me doesn't have it, the stock behavior applies unchanged.

Unlike the Windows original, this **doesn't rewrite the serverinfo message**
(no heap-overflow risk); it simply makes sure the right file is on disk first

## Component 1: autobhop prediction (BunnyhopAPE)

> Makes autobhop feel a lot less laggy on high ping servers — **without**
> allowing you to cheat scroll times like clientside autobhop does.

Both `CGameMovement::CheckJumpButton` and `CCSGameMovement::CheckJumpButton`
in `client.so` contain:

```cpp
if (mv->m_nOldButtons & IN_JUMP)
    return false;
```

On autobhop servers the server holds `IN_JUMP` for you, so client-side
prediction bails out of `CheckJumpButton` every tick and you only *see* the
jump one round-trip later. The patcher NOPs the 6-byte `jne` after that check
(in both movement classes), so the client predicts the jump immediately.

**Use it only on servers that actually do autobhop.** The check being removed
is the client's own "you are still holding jump, don't re-jump" guard, so on a
vanilla server (or a plain local `map` listen server) holding jump makes the
client predict a jump every grounded tick that the server then refuses — the
correction shows up as the jump animation visibly bugging out. Tapping jump
still behaves normally, because client and server agree on the first tick.
That is the patch working as designed, not a fault; toggle prediction off with
Scroll Lock (`--scroll-lock`) or `kill -USR1 <tool pid>` when you are not on a
bhop server.

## Component 2: rawinput2 (`m_rawinput 2`)

> Mouse input sampled so it "lines up with the tickrate properly without
> needing a specific framerate" (momentum mod behavior).

`librawinput2.so` is injected via `LD_PRELOAD` by the launcher and:

* hooks `launcher.so`'s **GOT entry for SDL_PollEvent** to accumulate raw
  mouse deltas with hardware timestamps (a GOT hook rather than name
  interposition, so sdl2-compat's internal SDL3 calls can't recurse into us);
  the slot is found via the relocation that names the symbol,
* hooks **`CSDLMgr::GetRawMouseAccumulators`** to serve the accumulated input
  — identified by its function body inside the class's RTTI vtable, and only
  installed if the SDL hook is live (our replacement is the sole source of
  deltas, so hooking it alone would stop mouse input dead),
* hooks **`CInput::CreateMove`** (IInput slot 3) for the per-tick input sample
  interval, on both the `CInput` and `CCSInput` vtables — the live singleton
  is a `CCSInput`, which inherits the same implementation,
* implements the exact tick-boundary splitting algorithm from the original
  `main.cpp` (see `core_split` in `src/lib.rs`),
* resolves the `m_rawinput` ConVar at runtime (no hardcoded offsets).

Hooks are vtable-pointer rewrites — no inline code patching. Set
`m_rawinput 2` in game to enable tick-aligned sampling (`0`/`1` behave like
stock). `RAWINPUT2_DEBUG=1` for verbose logs.

## Usage

### Linux

```sh
# launch the game through the tool (adds -insecure, injects librawinput2.so,
# and being the game's parent lets it patch without sudo):
./bunnyhop-ape

# with extra game args:
./bunnyhop-ape -- -console +exec autoexec

# keep gamemode active:
gamemoderun ./bunnyhop-ape

# attach to an already-running game, patcher only (needs sudo):
sudo ./bunnyhop-ape --attach

# offline: verify the CheckJumpButton signatures against a client.so on disk
./bunnyhop-ape --scan-file ".../cstrike/bin/linux64/client.so"

# fix pink textures in all installed maps right now (see component 5):
./bunnyhop-ape --fix-maps

# check that the patch + hooks are actually live in the running game:
sudo ./verify-live.sh
```

### Windows

Start CS:S yourself with `-insecure`, join a server, then:

```bat
bunnyhop-ape.exe                    :: find the game and patch it
bunnyhop-ape.exe --attach 1234      :: patch a specific pid
bunnyhop-ape.exe --scroll-lock      :: tie prediction to the Scroll Lock LED
```

Ctrl+C restores the original bytes. Run it elevated if opening the process
fails.

Toggle jump prediction at runtime with **Scroll Lock**, or on Linux
`kill -USR1 <tool pid>`. Original bytes are restored on
toggle-off/exit/Ctrl-C.

## Warning

Same policy as the originals: **only use with `-insecure`**. Every component
refuses to work without it. Modifying game memory/hooks on VAC-secured servers
is entirely your own risk.

And only on servers that actually do autobhop — see the caveat in component 1:
on a vanilla server, *holding* jump will mispredict and the jump animation will
visibly break. That is the patch working as designed.

## Building

```sh
cargo build --release
# -> target/release/bunnyhop-ape
# -> target/release/librawinput2.so

cargo test          # pattern engine + resolver regression tests
```

The resolver tests read the installed game if it is present and skip when it is
not, so they are a genuine "did a game update break the lookups?" check.

Only dependency is `libc`. Everything else is plain
`/proc/<pid>/{maps,mem,cmdline}`, sysfs (`/sys/class/leds/*::scrolllock`),
and `dlopen`/`dlsym` for SDL2.

## License

GPL-3.0 (same as the original BunnyhopAPE).
