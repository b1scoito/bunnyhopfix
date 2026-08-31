# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-08-31

First release of the project under its cross-platform name `bunnyhop-ape`
(previously `bunnyhop-ape-linux`), and the release that removes every
hard-coded game address from the tool.

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
