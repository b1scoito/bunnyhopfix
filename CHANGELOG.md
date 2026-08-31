# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries below are generated from the commit history by
[git-cliff](https://git-cliff.org); a release may instead carry hand-written
prose when the change deserves more than a list of commit subjects.

There is no "Unreleased" section: work that has not shipped yet is rendered by
CI into the *pending release notes* job summary of every push to `dev` and
every pull request.

## [2.0.0] - 2026-08-31

**bunnyhopfix 2.0.0 is a full Rust rewrite of the C++ `bunnyhopfix`, and
supersedes it.** The 1.0 TODO list was exactly *"Linux support"* and *"Code
organization"*; this release is both. 1.0 remains available as history, but it
is no longer the implementation this project maintains.

### Changed

- **BREAKING — everything is named `bunnyhopfix` now.** The Rust prototype that
  became this release shipped under the working names `bunnyhop-ape-linux` /
  `bunnyhop-ape` with a `rawinput2`-prefixed environment; every one of those
  names is gone, with no compatibility aliases:

  | was | is |
  |---|---|
  | binary `bunnyhop-ape` | `bunnyhopfix` (`bunnyhopfix.exe` on Windows) |
  | `librawinput2.so` | `libbhopfix.so` |
  | log prefix `[rawinput2] ` | `[bhopfix] ` |
  | `RAWINPUT2_DEBUG` | `BHOPFIX_DEBUG` |
  | `RAWINPUT2_NO_FORCE` | `BHOPFIX_NO_FORCE` |
  | `RAWINPUT2_DEMOS` | `BHOPFIX_DEMOS` |
  | `RAWINPUT2_KEEP_VIEWPUNCH` | `BHOPFIX_KEEP_VIEWPUNCH` |
  | `RAWINPUT2_NO_SOURCEJUMP` | `BHOPFIX_NO_SOURCEJUMP` |
  | `BHOP_FULLSCREEN` | `BHOPFIX_FULLSCREEN` |
  | `BHOP_KEEP_OVERLAY` | `BHOPFIX_KEEP_OVERLAY` |
  | `BHOP_NO_DXVK_TWEAKS` | `BHOPFIX_NO_DXVK_TWEAKS` |
  | `BHOP_NO_SDL_AUDIO` | `BHOPFIX_NO_SDL_AUDIO` |
  | `~/.cache/bunnyhop-ape-linux/` | `~/.cache/bunnyhopfix/` |

  Scripts, `.desktop` entries and shell aliases that set the old variables will
  silently stop having any effect — the old names are not read at all. The
  game's own `m_rawinput` ConVar is untouched, and "rawinput2" still names the
  *feature* ported from RawInput2BunnyhopAPE.
- **Code organization: one crate became a three-crate workspace.** This is the
  second half of the C++ TODO. `bhopfix-core` holds the pattern engine, the
  ELF/RTTI/GOT reader and the BSP pakfile repair, and contains no writes into
  another process — it only finds and validates. `bhopfix-hook` builds the
  injected `libbhopfix.so` and is `#![cfg(unix)]`. `bunnyhopfix` builds the
  launcher/patcher binary for both platforms. The patcher and the hook stopped
  being two halves of one 2000-line file that happened to share a `mod`.
- **Edition 2024, MSRV 1.88, `unsafe_op_in_unsafe_fn` denied workspace-wide.**
  An `unsafe fn` no longer hands its whole body a blanket permission: each
  hazardous operation is wrapped where it happens, which in a tool that writes
  into a live game's address space is the difference between an audit that
  means something and one that does not. `clippy::all` is denied and
  `missing_docs` warns; the blanket `#![allow(unused_unsafe)]` the old crate
  root carried is deleted, because the edition change removed its reason to
  exist.
- **The Windows backend now uses upstream bunnyhopfix's production
  signature** — `85 C0 8B 46 08 0F 84 ?? FF FF FF F6 40 28 02 0F 85 ?? FF FF FF`,
  NOPing the 6-byte `jne` at `+15` — the exact pattern shipped in the C++ 1.0
  release, replacing the derived-from-source guess the prototype carried. What
  this repository's automation still cannot prove is that a live Windows CS:S
  matches it: CI compiles, links and cross-links the binary, but a GitHub
  runner cannot run the game. On a no-match it patches nothing and says so.
- The Windows backend **enforces `-insecure`** like every other component,
  reading the target's command line out of its WOW64 PEB (`client.dll` is
  32-bit, so the game is a WOW64 process) and refusing to patch a VAC-secured
  client.

### Added

- **CI on every push and pull request** (`ci.yml`): `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, a native Linux release build that asserts both
  `target/release/bunnyhopfix` and `target/release/libbhopfix.so` exist, a
  native Windows build of the bin, the `cargo-zigbuild` cross-compile that
  maintainers use locally, and a `cargo check` pinned to 1.88 so the declared
  MSRV stays true.
- **A `dev` → `main` branch model with a commit-derived changelog.** `dev` is
  where work lands; `main` only moves when a release is cut. Commit subjects
  are Conventional Commits, enforced by a `commits` job on every push and pull
  request, and [git-cliff](https://git-cliff.org) (`cliff.toml`) turns them
  into this file — one commit, one bullet, grouped by type. A hand-written
  `## [x.y.z]` section still wins when a release deserves real prose, which is
  why the entry you are reading is not a list of subjects. See
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Releases publish themselves** (`release.yml`). Merging `dev` into `main`
  with a new `[workspace.package] version` builds Linux and Windows, resolves
  the notes, creates the `v<version>` tag and publishes: a Linux tarball, a
  Windows zip, the bare `bunnyhopfix.exe` under the same asset name the C++
  1.0 release used, and a `SHA256SUMS.txt` over all of them. A merge that does
  not bump the version is a no-op rather than a duplicate release. Every
  Windows build — CI, release and nightly — links the CRT statically
  (`-C target-feature=+crt-static`), so `bunnyhopfix.exe` runs without a VC++
  redistributable, exactly like the single-file 1.0 asset.
- **A weekly schedule** (`schedule.yml`, Mondays 05:00 UTC): a toolchain canary
  across `stable`/`beta`/`nightly` rustc that files or updates one
  `Weekly canary failed` issue instead of spamming, and a `nightly` rolling
  prerelease that rebuilds from `dev` only when `dev` has actually moved.
- Dependabot for `cargo` and `github-actions`, grouped so the tree's single
  dependency cannot generate weekly noise.
- `--version` / `-V` on both backends, printing the crate version and whether
  the build is a debug or release one, so a bug report identifies exactly what
  ran. The release workflow refuses to publish a tag that disagrees with the
  workspace version, so that string is always the version people downloaded.

## [0.2.0] - 2026-08-31

Pre-release development history of this rewrite: the Rust tool as it existed
before it took the `bunnyhopfix` name, when it was still `bunnyhop-ape` /
`bunnyhop-ape-linux`. Never published as a release; kept here because it is
where every hard-coded game address was removed, which is the reason 2.0.0
survives game updates at all. **The names below are historical** — see the
rename table in 2.0.0 for what they are called today.

### Added

- **Barebones Windows support** — the autobhop jump-prediction patcher only.
  It finds `client.dll` in a running game, patches `CheckJumpButton` by
  signature, offers the same Scroll Lock toggle, and restores the bytes on
  exit. The signature is upstream's (alkatrazbhop/BunnyhopAPE, targeting the
  32-bit `client.dll`, one site — Linux has two) and is **unverified against a
  real Windows install**: this port is validated only by compiling, linking
  (via `cargo-zigbuild` to `x86_64-pc-windows-gnu`) and CI. On a no-match it
  patches nothing and says so. RawInput2, the fastdl map hijack, the pakfile
  case fix and the launch-environment hardening remain Linux-only:
  `librawinput2.so` is an `LD_PRELOAD` library and the others work around
  Source-on-Linux bugs.
- **Shared IDA-style pattern engine** (`src/sig.rs`) used by both platforms:
  patterns such as `F3 0F 58 ?? 74` with `??` wildcards, plus a `Sig`
  descriptor that pairs a pattern with the offset and length of the bytes to
  rewrite, so a signature and its patch window are declared in one place and
  a patch window outside its own match is rejected as a typo.
- Uniqueness checking for signature matches: an ambiguous pattern (more or
  fewer matches than expected) is reported rather than patched.

### Changed

- **Every hook target is now resolved by name or pattern at runtime.** Nothing
  is addressed absolutely any more:
  - classes and their virtuals are found through the Itanium C++ ABI RTTI
    Valve ships in these binaries (typeinfo name → typeinfo → vtable),
  - the `SDL_PollEvent` GOT slot is found through the relocation that names
    the symbol, not through an offset,
  - code sites (`CheckJumpButton`, the `CalcView` viewpunch adds) are found by
    instruction signature,
  - `IVEngineClient` comes from `engine.so`'s own exported `CreateInterface`,
    and the object's RTTI is confirmed to name `CEngineClient` before its
    vtable is called.
- **Every hook validates its target before writing, and disables its feature
  instead of writing blind on a mismatch.** A vtable slot is only rewritten if
  it currently holds the function pointer the module file says it should; a GOT
  slot is only rewritten if it currently holds a pointer into mapped code; code
  is only patched if the loaded bytes match the bytes decoded from the module
  on disk. Any mismatch logs `FAILED`/`NOT` and turns that one feature off, so
  a future game update degrades the tool instead of corrupting the game.
- `verify-live.sh` is likewise address-free: it re-derives everything it checks
  the same way the tool does, so it can no longer print expectations from a
  stale build.
- **Vtable slot indices are gone too**, not just addresses. `CreateMove`,
  `ProcessServerInfo` and `ClientCmd` used to be addressed as "slot N of this
  class"; each is now identified by what its body does, and the match must be
  unique or the feature disables itself:
  - `CreateMove` — indexes the command ring by `sequence % MULTIPLAYER_BACKUP`
    (a magic-number division by 90 and a multiply back) *and* spills its float
    argument. The `% 90` pair alone matches 11 `CInput` methods.
  - `ProcessServerInfo` — copies the server's 16-byte map-lump MD5 out of the
    message, and has the relocatable prologue the trampoline needs, which is
    what tells it apart from the this-adjusting thunks that share its code.
  - `ClientCmd` — stashes its string argument and tail-jumps to
    `Cbuf_AddText`.
- Offsets that appear as instruction displacements are now *read out of the
  matched instruction*: the `m_vecPunchAngle` field offset and the serverinfo
  MD5 offset are no longer written down anywhere.
- Verified that the **pakfile case fix is still required** on build 10897846.
  The update's notes mention fixing custom-map assets on Linux, but that is a
  different bug: with an extracted lowercase asset held back, the engine still
  logs `Missing map material: MATERIALS/SKYPPY4/NEW/METAL_CEILING01A` for an
  uppercase-packed material (Source-1-Games#6868 is live). 22 of 54 installed
  maps pack uppercase paths.

### Fixed

- **The game no longer segfaults about 13 seconds after load on builds newer
  than the tool.** The 2026-08-24 CS:S update relocated code and vtables (code
  moved ~`0x1e80`, client vtables ~`0xa90`, and `launcher.so`'s data segment
  gained a whole page), which made the tool's hard-coded link-time addresses
  stale. A stale *code* address is harmless — it fails a byte check — but a
  stale *vtable slot* address still points at a perfectly valid function
  pointer, just one belonging to a different class. Three of the tool's slot
  constants landed exactly there:
  - the old `CInput::CreateMove` slot constants became a `vgui::Panel`
    virtual (slot 169) and a `CCSGameMovement` virtual (slot 20), and
  - the old `CSDLMgr::GetRawMouseAccumulators` slot became `ConCommand`'s
    destructor slot.

  So all three hooks installed "successfully", silently redirected unrelated
  virtuals, and the game died inside the displaced `vgui::Panel` virtual —
  called with our hook's arguments — roughly 13 s after load.
- **Raw-input sampling was silently dead on that build, and was clobbering a
  data word.** The stale `SDL_PollEvent` GOT constant was not pointing at a
  relocation at all: the slot it named held the literal value `0x8`. The hook
  therefore never intercepted a single event, while the write itself overwrote
  an unrelated data word. The GOT slot is now located through the relocation
  that names `SDL_PollEvent`, and is only written if it currently holds a
  pointer into mapped code.
- Viewpunch removal survives relocation: the nine `addss` punch-angle adds are
  decoded out of `client.so`'s `.text` by shape (a `(D, D+4, D+8)` triple in a
  tight span) instead of being hard-coded, and all nine are byte-verified
  against the module before any of them is NOPed.
