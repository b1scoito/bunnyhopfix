# bunnyhopfix

**Bhop delay fixer for Counter-Strike: Source** — enables client-side jump
prediction on autobhop servers, so the jump happens when you press it instead
of one server round-trip later.

**2.0.0 is a full Rust rewrite of the C++ `bunnyhopfix`.** The 1.0 TODO list
was exactly two items — *Linux support* and *code organization* — and this
release is both. The maintained targets are native **Linux x86-64** and
**Windows x86-64**; 32-bit game builds are not supported.

Lineage: the prediction patch is the technique from
[alkatrazbhop/BunnyhopAPE](https://github.com/alkatrazbhop/BunnyhopAPE), which
b1scoito's C++ [bunnyhopfix](https://github.com/b1scoito/bunnyhopfix) packaged
as a standalone Windows patcher. The common hook feature set comes from
[rtldg/RawInput2BunnyhopAPE](https://github.com/rtldg/RawInput2BunnyhopAPE).
The Windows x64 implementation uses the signatures and calling-convention
work from its [x64 pull request](https://github.com/rtldg/RawInput2BunnyhopAPE/pull/2),
then fills the fastdl gap that pull request intentionally left disabled.

| artifact | what it is |
|---|---|
| `bunnyhopfix` | Linux launcher/controller and autobhop prediction patcher |
| `libbhopfix.so` | Linux LD_PRELOAD hook: rawinput2, fastdl, viewpunch, SourceJump, and engine integration |
| `bunnyhopfix.exe` | Windows controller and autobhop prediction patcher |
| `bhopfix.dll` | Windows injected hook implementing the common feature set plus fullscreen preservation; keep it beside `bunnyhopfix.exe` |

## Platform support

| feature | Linux x86-64 | Windows x86-64 |
|---|---|---|
| autobhop prediction patch | ✅ | ✅ |
| tick-aligned `m_rawinput 2` | ✅ | ✅ |
| viewpunch remover | ✅ | ✅ |
| fastdl.me exact-map interception | ✅ | ✅ |
| engine console, demos, download progress/flash | ✅ | ✅ |
| SourceJump world records | ✅ | ✅ |
| fullscreen control | launcher environment | F6 preservation toggle |
| BSP pakfile case fix | ✅ Linux filesystem workaround | N/A: Windows lookups are already case-insensitive |
| launch-environment hardening | ✅ Linux-specific | N/A |
| starts CS:S | ✅ | attach to a game you started with `-insecure` |

The Windows controller accepts only `cstrike_win64.exe` (or an explicit native
x86-64 PID), confirms an exact `-insecure` command-line argument, finds both
`CheckJumpButton` implementations in `client.dll`, and injects `bhopfix.dll`.
The DLL resolves every hook from live PE exports, RTTI, vtables, and unique
instruction signatures. Missing or ambiguous targets abort installation rather
than enabling a partial feature set.

The two Windows signatures describe the same `m_nOldButtons + 0x28` /
`IN_JUMP == 2` checks as the independently derived Linux signatures:

```
80 B9 50 14 00 00 00 0F 85 ?? ?? ?? ?? 48 8B 43 10 F6 40 28 02 0F 85 ?? ?? ?? ??
48 8B 05 ?? ?? ?? ?? 48 8D 73 10 83 78 58 00 75 ?? 48 8B 06 F6 40 28 02 75 ??
```

The 6-byte near `jne` in the first match and 2-byte short `jne` in the second
are NOPed as one transaction. Windows suspends the target threads, preflights
every original byte and page protection, verifies each write, and rolls the
whole set back on failure. Hook installation/restoration follows the same
fail-closed rule. The DLL is unloaded only after hooks point away from it and
active callbacks have drained; an uncertain cleanup requires a game restart
instead of risking execution through freed code.

The native Windows x64 path was exercised on 2026-09-01 against CS:S build
10897846. The game-side prediction behavior was confirmed in play. Automated
live checks then re-derived both prediction sites and every DLL resolver,
observed 100/100 synthetic raw mouse events through the `WM_INPUT` hook,
toggled and byte-verified both fullscreen patches, toggled viewpunch, restored
the exact original prediction/fullscreen bytes, and confirmed that
`bhopfix.dll` disappeared after Ctrl+C. The fastdl checksum feed and a hashed
map were also fetched from the production endpoints; its compressed payload
expanded to a valid `VBSP` whose SHA-1 matched its URL.

## Workspace layout

Three crates, because the controller and injected library share parsers but
have different process-lifecycle responsibilities:

| crate | artifact | what lives there |
|---|---|---|
| `bhopfix-core` | rlib | portable signature and PE readers, Linux ELF/RTTI/GOT reading, BSP pakfile repair, and the Windows control-block protocol |
| `bhopfix-hook` | `libbhopfix.so` / `bhopfix.dll` | everything injected into the game: rawinput2, viewpunch, fastdl, engine glue, SourceJump, and Windows fullscreen preservation |
| `bunnyhopfix` | `bunnyhopfix` / `bunnyhopfix.exe` | Linux launcher plus the platform prediction patchers and Windows DLL lifecycle controller |

Edition 2024, MSRV 1.88, `unsafe_op_in_unsafe_fn` denied workspace-wide: in a
tool that writes into a live process, every hazardous operation has to state
that permission at the operation rather than inherit it from an `unsafe fn`.

## Nothing is addressed by offset

Every location this tool touches — in both backends — is found at runtime by
what the code *is*: an instruction signature (see
`crates/bhopfix-core/src/sig.rs`), an RTTI class name, or a relocation that
names a symbol. No link-time addresses, and no vtable slot indices either.

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

| feature | Linux x86-64 | Windows x86-64 |
|---|---|---|
| BunnyhopAPE prediction | ✅ | ✅ |
| rawinput2 (`m_rawinput 2`) | ✅ | ✅ |
| fastdl.me map hijack + compressed/plain fallback | ✅ | ✅ |
| viewpunch remover (F7 on Windows) | ✅ | ✅ |
| download progress + completion flash | ✅ | ✅ |
| validated in-game console (`ClientCmd`) | ✅ | ✅ |
| automatic POV demos (`BHOPFIX_DEMOS=1`) | ✅ | ✅ |
| SourceJump records in the terminal and game console | ✅ | ✅ |
| fullscreen preservation (F6) | N/A | ✅ |
| BSP pakfile case fix | ✅ | N/A |
| launch-environment hardening | ✅ | N/A |

## Component 1: autobhop prediction (the bhop delay fix)

> Makes autobhop feel a lot less laggy on high ping servers — **without**
> allowing you to cheat scroll times like clientside autobhop does.

Both `CGameMovement::CheckJumpButton` and
`CCSGameMovement::CheckJumpButton` in the platform client module contain:

```cpp
if (mv->m_nOldButtons & IN_JUMP)
    return false;
```

On autobhop servers the server holds `IN_JUMP` for you, so client-side
prediction bails out of `CheckJumpButton` every tick and you only *see* the
jump one round-trip later. The patcher removes the validated conditional branch
after that check in both movement classes, so the client predicts the jump
immediately. Linux and Windows each require exactly two platform-specific
x86-64 matches before either site is changed.

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

Both hooks implement the original timestamped ring/split algorithm, but use
the native input path for each platform:

* **Linux:** hook `launcher.so`'s relocation-backed `SDL_PollEvent` GOT slot to
  timestamp mouse events, the RTTI-resolved
  `CSDLMgr::GetRawMouseAccumulators` vtable slot to serve them, and the
  `CInput`/`CCSInput` tick callback to establish the sample boundary.
* **Windows:** inline-hook the uniquely matched `CInputSystem::WindowProc` to
  read `WM_INPUT` through `GetRawInputData`, then hook the RTTI-resolved
  `CInputSystem::GetRawMouseAccumulators` and both
  `CInput`/`CCSInput::IN_SetSampleTime` vtable slots.
* **Both:** resolve and validate the live `m_rawinput` ConVar and drain only
  events belonging to the current input tick. Mode `2` uses the tick-aligned
  stream; modes `0` and `1` continue through the stock behavior.

The launcher defaults `m_rawinput` to `2` once the client is ticking because
`config.cfg` can reset it. Use `BHOPFIX_NO_FORCE=1` to leave the initial value
alone and `BHOPFIX_DEBUG=1` for sampling telemetry.

## Component 3: fastdl.me map hijack

Port of rtldg's map-download feature. Never get kicked for
`Missing map` / `Map differs` on covered servers again.

* Hooks the engine's RTTI-resolved
  `CClientState::ProcessServerInfo` virtual. Linux installs a validated inline
  trampoline; Windows replaces the validated vtable pointer and drains active
  callbacks before unload.
* Recovers both the server's **map lump MD5** and map-name message
  displacements from the instructions that copy them; no fixed message layout
  is trusted.
* Looks the MD5 up in [fastdl.me](https://fastdl.me)'s
  `lump_checksums.csv`, cached for 36 hours.
* Downloads the exact version from
  `https://mainr2.fastdl.me/hashed/<sha1>.bsp.bz2`, with the legacy plain
  `.bsp` endpoint as fallback. Linux uses the system `bzip2`; Windows uses the
  linked Rust decoder.
* Verifies `VBSP` magic and the expected SHA-1, then atomically installs
  `cstrike/maps/<mapname>.bsp` **before** stock map validation. A sidecar makes
  repeat connects instant. A miss or failed validation leaves stock behavior
  unchanged.

Unlike the original implementation, this never rewrites the serverinfo message
(and therefore cannot overflow its map-name buffer); it puts the validated map
on disk before calling the original handler.

## Component 4: viewpunch remover

No screen kick on landings/damage. `C_BasePlayer::CalcView` and a secondary
view path add `m_vecPunchAngle` onto the rendered eye angles with three
`addss <punch+0/4/8>(reg),%xmm0` each (pitch/yaw/roll). We **NOP all 9 of
those adds** so the punch is simply never applied to the view. Skip with
`BHOPFIX_KEEP_VIEWPUNCH=1`.

The sites are not hard-coded: each backend decodes every
`addss disp32(reg),%xmm0` in the client module's executable image and keeps
those forming a `(D, D+4, D+8)` triple within a tight span — the shape of a
Vector add — taking the `D` shared by the most triples as the punch field. That
cleanly ignores unrelated scalar adds in the same binary.

**Why not just zero the field?** `m_vecPunchAngle` is a *predicted* field: the
client restores it from its prediction backup and re-decays it every frame, so
zeroing it in the entity (or the descriptor) loses the race — the punch
reappears (decaying) before most frames render. Never *applying* it wins
regardless. (An earlier attempt wrote to what looked like a `RecvProp` proxy
slot; that structure is actually a prediction `typedescription_t` and the write
crashed the client — this approach touches neither the descriptor nor the
predicted field.)

**Safety:** every site is checked against the exact decoded instruction before
anything is written; a mismatch rejects the whole patch set. On build 10897846,
Linux resolves 9 adds in 3 paths at field `+0x1274`; Windows resolves the active
pitch/yaw/roll triple at field `+0x7a8`.

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
* manually: `./bunnyhopfix --fix-maps [game-root]`.

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
  Opt out: `BHOPFIX_KEEP_OVERLAY=1`.
* **`DXVK_CONFIG=d3d9.maxFrameLatency = 1`** — caps DXVK's frame queue for
  tighter input latency (the in-game `fps_max` stays the frame limiter).
  Merged into any `DXVK_CONFIG` you set; skipped if `DXVK_CONFIG_FILE` is set.
  Opt out: `BHOPFIX_NO_DXVK_TWEAKS=1`.
* **`SDL_AUDIODRIVER=pulseaudio`** (+ the SDL3 `SDL_AUDIO_DRIVER` spelling) —
  the SDL PipeWire backend regressed into heavy stutter/echo in 2026
  ([Source-1-Games#8013](https://github.com/ValveSoftware/Source-1-Games/issues/8013));
  pipewire-pulse serves the PulseAudio path cleanly. Opt out:
  `BHOPFIX_NO_SDL_AUDIO=1`.

## Component 7: SourceJump world-record display

On connect (reusing the ProcessServerInfo hook, which already has the map
name) the tool asks [sourcejump.net](https://sourcejump.net) for the map's
records and prints the WR plus a couple of chasers to its terminal log:

```
[bhopfix] sourcejump WRs for bhop_badges:
[bhopfix]   WR 5:58.330  Jehoshaphat  (sync 93.8%, 614 strafes)
[bhopfix]      6:00.040  shinoum      (sync 92.1%, 821 strafes)
```

Read-only, off the engine thread (a slow API never stalls a connect), using
the community-shared public API key. Opt out: `BHOPFIX_NO_SOURCEJUMP=1`.
WRs also echo into the **in-game console** via component 8.

## Component 8: engine glue (console, demos, progress, flash)

Each backend calls the engine module's exported `CreateInterface` for
`VEngineClient014`, verifies that the returned object's RTTI and vtable belong
to `CEngineClient`, and locates the `ClientCmd` virtual by its implementation.
No fixed vtable index is trusted. Built on it:

* **Console commands** — a bounded thread-safe queue drained from a game-thread
  input callback, so background workers such as SourceJump never call engine
  code directly.
* **Auto POV demo recording** *(opt-in `BHOPFIX_DEMOS=1`)* — on connect,
  `record <map>_<unixts>` is issued from the first in-game tick. Demos land in
  `cstrike/`; prune them periodically.
* **SourceJump records in-console** — component 7's rows are sanitized and
  passed through `echo`.

Download progress is a read-only poll of the uniquely identified
`CDownloadManager` singleton. Its vtable, update implementation, active request,
state, name, and byte counts are validated before output:

```
[bhopfix] downloading bhop_infernoserz.bsp: 45% (31728 / 70446 KB)
[bhopfix] download complete
```

After a long download completes, Linux calls the resolved `SDL_FlashWindow`;
Windows calls `FlashWindow` on the HWND observed by its input hook.

## Component 9: fullscreen behavior

On Windows, F6 atomically toggles the two changes used by the upstream x64
pull request: the validated branch in
`CVideoMode_MaterialSystem::ReleaseVideo`, and the matching system `d3d9.dll`
fullscreen-loss branch. It is off by default. Both sites are preflighted,
written, and restored as one transaction; Ctrl+C always restores the original
bytes before the DLL unloads.

Linux needs no Direct3D patch. `BHOPFIX_FULLSCREEN=1` asks the launcher for
exclusive fullscreen instead of its default borderless mode; `CSS_FREQ=<hz>`
sets the requested refresh rate and `CSS_FREQ=off` removes `-freq`.

## Usage

### Linux

```sh
# launch the game through the tool (adds -insecure, injects libbhopfix.so,
# and being the game's parent lets it patch without sudo):
./bunnyhopfix

# with extra game args:
./bunnyhopfix -- -console +exec autoexec

# keep gamemode active:
gamemoderun ./bunnyhopfix

# attach to an already-running game, patcher only (needs sudo):
sudo ./bunnyhopfix --attach

# offline: verify the CheckJumpButton signatures against a client.so on disk
./bunnyhopfix --scan-file ".../cstrike/bin/linux64/client.so"

# fix pink textures in all installed maps right now (see component 5):
./bunnyhopfix --fix-maps

# check that the patch + hooks are actually live in the running game:
sudo ./verify-live.sh
```

### Windows

Download the `bunnyhopfix-<tag>-x86_64-windows.zip` release and extract it.
`bunnyhopfix.exe` and `bhopfix.dll` must remain in the same directory. Set
`-insecure` in CS:S launch options, start the native x64 game, then run:

```bat
bunnyhopfix.exe                    :: auto-detect cstrike_win64.exe
bunnyhopfix.exe --attach 1234      :: attach to one native x64 pid
bunnyhopfix.exe --scroll-lock      :: let Scroll Lock also toggle prediction
```

Runtime keys: **F5** prediction, **F6** fullscreen preservation, **F7**
viewpunch removal. Prediction and viewpunch removal start enabled; fullscreen
preservation starts disabled. Ctrl+C restores every prediction/hook patch,
waits for active callbacks, and unloads `bhopfix.dll`. If cleanup cannot be
proven, the controller says to restart the game instead of unloading unsafe
code. Run elevated only if Windows denies opening the game process.

On Linux, `kill -USR1 <tool pid>` toggles prediction.

### Environment variables

| variable | platform | effect |
|---|---|---|
| `BHOPFIX_DEBUG=1` | both | verbose hook/resolver and input telemetry |
| `BHOPFIX_LOG=<filter>` | both | controller tracing filter, for example `debug` or `bhopfix_hook=debug` |
| `BHOPFIX_NO_FORCE=1` | both | leave the initial `m_rawinput` value alone |
| `BHOPFIX_DEMOS=1` | both | auto-record one POV demo per connect (component 8) |
| `BHOPFIX_KEEP_VIEWPUNCH=1` | both | start without viewpunch removal |
| `BHOPFIX_NO_SOURCEJUMP=1` | both | do not query sourcejump.net |
| `BHOPFIX_FULLSCREEN=1` | Linux | request exclusive fullscreen instead of borderless |
| `CSS_FREQ=<hz>` / `CSS_FREQ=off` | Linux | set or remove the fullscreen refresh-rate argument |
| `BHOPFIX_KEEP_OVERLAY=1` | Linux | retain `gameoverlayrenderer.so` in `LD_PRELOAD` |
| `BHOPFIX_NO_DXVK_TWEAKS=1` | Linux | leave `DXVK_CONFIG` unchanged |
| `BHOPFIX_NO_SDL_AUDIO=1` | Linux | leave the SDL audio driver unchanged |

Controller diagnostics are structured `tracing` events written to stderr.
`BHOPFIX_LOG` accepts
[`EnvFilter`](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html)
directives. `BHOPFIX_DEBUG=1` remains the simple shorthand for debug-level
controller output and hook instrumentation. On Windows, the unloadable DLL
publishes typed log records through shared memory and the controller emits them
under the `bhopfix_hook` tracing target.

Fastdl cache data lives in `~/.cache/bunnyhopfix/` on Linux and
`%LOCALAPPDATA%\bunnyhopfix\` on Windows.

## Warning

Same policy as the originals: **only use with `-insecure`**. Every component
refuses to work without it. Modifying game memory/hooks on VAC-secured servers
is entirely your own risk.

And only on servers that actually do autobhop — see the caveat in component 1:
on a vanilla server, *holding* jump will mispredict and the jump animation will
visibly break. That is the patch working as designed.

## Building

```sh
cargo build --workspace --release
# Linux:  target/release/bunnyhopfix + libbhopfix.so
# Windows: target/release/bunnyhopfix.exe + bhopfix.dll

cargo test --workspace
```

Resolver tests read the installed game when present and self-skip on bare CI
runners. On a machine with CS:S, they are the regression check for a game
update moving signatures or RTTI.

Windows is also cross-built from Linux with
[cargo-zigbuild](https://github.com/rust-cross/cargo-zigbuild):

```sh
rustup target add x86_64-pc-windows-gnu
cargo zigbuild --workspace --release --target x86_64-pc-windows-gnu
```

Cargo dependencies are `libc` for Linux, `bzip2` for the self-contained
Windows map decoder, and `sha1` for content-address verification on both
platforms. Runtime fastdl/SourceJump requests use `curl` (the bundled
`curl.exe` on current Windows); Linux compressed-map installs also require the
system `bzip2` command.

## Releases and CI

Development happens on `dev`; `main` is the release branch. `main` only ever
moves by merging `dev` into it, and a merge that carries a new version number
publishes a release. Nobody commits to `main` directly. The version lives in
exactly one place, `[workspace.package] version` in the root `Cargo.toml`, and
the three crates inherit it. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
commit convention and the full contributor loop.

| workflow | when | what it does |
|---|---|---|
| `ci.yml` | every push to `dev` and `main`, every PR | commit convention, fmt/clippy, tests, native Linux and Windows workspace builds, Windows zig cross-build, MSRV, and changelog preview |
| `release.yml` | every push to `main` | resolves the workspace version, builds and packages both x86-64 platforms, generates checksums/notes, tags, and publishes |
| `schedule.yml` | Mondays 05:00 UTC (`0 5 * * 1`), or manual | stable/beta/nightly canary plus rolling Linux and Windows builds from `dev` |

**The changelog is derived from the commits.** `CHANGELOG.md` is generated by
[git-cliff](https://git-cliff.org) from the history since the previous tag,
configured by `cliff.toml`: `feat` → Added, `fix` → Fixed, `perf` →
Performance, `refactor` → Changed, `docs` → Documentation, `revert` → Reverted,
while `test`, `ci`, `build` and `chore` stay out of it. It is written at release
time, not on every push, so `dev` never collects bot commits; the pending notes
are rendered into the `changelog-preview` job summary on every push to `dev` and
every PR. A hand-written `## [<version>]` section wins — if one exists for the
version being released it is used verbatim and nothing is generated, which is
how the curated `2.0.0` entry survives.

**Releasing is a version bump and a merge:**

```sh
# on dev: bump [workspace.package] version in Cargo.toml
git commit -am 'chore(release): 2.0.1'
# then open a PR dev -> main and merge it
```

`release.yml` does the rest: it creates and pushes the tag `v2.0.1`, commits the
regenerated `CHANGELOG.md` back to `main`, and publishes the assets. There is no
`git tag` step for a normal release — the tag is an output, not the trigger —
and because the workflow stops when the tag already exists, a `dev` → `main`
merge without a version bump is a no-op rather than a duplicate release.

**Tagged releases are still cut by a human**, deliberately: this tool is
verified against a *running* game, which no runner can do, so the decision to
bump the version and merge into `main` means a human played on it. CI automates
the packaging, not the judgement.

Release assets:

| asset | contents |
|---|---|
| `bunnyhopfix-<tag>-x86_64-linux.tar.gz` | `bunnyhopfix`, `libbhopfix.so`, `README.md`, `LICENSE`, `verify-live.sh` |
| `bunnyhopfix-<tag>-x86_64-windows.zip` | `bunnyhopfix.exe`, `bhopfix.dll`, `README.md`, `LICENSE` |
| `SHA256SUMS.txt` | checksums of both archives |

Windows release builds link the CRT statically
(`-C target-feature=+crt-static`), so neither the controller nor hook requires a
separate Visual C++ redistributable. The two files are still a required pair:
the controller refuses to patch if the adjacent hook DLL is missing.

**`nightly` refreshes weekly.** Every Monday, if `dev` has moved since the
`nightly` tag, the tag is force-moved and the prerelease is rebuilt with stable
asset names. If nothing changed, the job skips instead of republishing an
identical build. A nightly is CI-clean, not live-game verified; use the newest
tagged release for the human-verified build.

**The canary reports toolchain rot even in a quiet week.** The same Monday run
builds and tests the workspace on `stable`, `beta` and `nightly` rustc. A
`stable`/`beta` failure means the toolchain moved under us — a new lint, a
behaviour change — and files (or comments on) a single `Weekly canary failed`
issue, so a long breakage is one thread and not one issue per week. `nightly`
rustc is `continue-on-error`: it is a weather report, not a gate.

## License

GPL-3.0 (same as the original BunnyhopAPE).
