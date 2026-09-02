# bunnyhopfix

`bunnyhopfix` removes the client-side jump prediction delay in Counter-Strike:
Source on autobhop servers.

Supported game builds:

- Linux x86-64
- Windows x86-64 (`cstrike_win64.exe`)

32-bit builds are not supported.

[Download the latest release](https://github.com/b1scoito/bunnyhopfix/releases/latest)

## Features

| Feature | Linux | Windows |
|---|---|---|
| Autobhop prediction | Yes | Yes |
| Tick-aligned `m_rawinput 2` | Yes | Yes |
| Viewpunch removal | Yes | Yes |
| Correct-map download through fastdl.me | Yes | Yes |
| SourceJump records | Yes | Yes |
| Engine console, demos, download progress, and completion flash | Yes | Yes |
| Fullscreen handling | Launch configuration | F6 toggle |
| BSP pakfile case fix | Yes | Not required |
| Launch-environment fixes | Yes | Not required |

The prediction patch changes local prediction only. The server remains
authoritative.

## Safety

Run the game with `-insecure`. The controller refuses to patch or inject
otherwise.

Use the prediction patch only on autobhop servers. Holding jump on a normal
server can produce incorrect local prediction.

Game code is located at runtime through instruction patterns, PE or ELF
metadata, exports, RTTI, vtables, and decoded operands. Required matches must be
unique. Original bytes are checked before every write.

Patch transactions roll back on failure. On Windows, `bhopfix.dll` is unloaded
only after hooks are restored and active callbacks have finished. If cleanup
cannot be proven safe, restart the game before running the tool again.

## Windows

Extract the Windows release archive. Keep `bunnyhopfix.exe` and `bhopfix.dll`
in the same directory.

Add `-insecure` to the CS:S launch options, start the game, then run:

```powershell
.\bunnyhopfix.exe
```

Attach to a specific native x86-64 process:

```powershell
.\bunnyhopfix.exe --attach 1234
```

Controls:

| Input | Action |
|---|---|
| F5 | Toggle prediction |
| F6 | Toggle fullscreen preservation |
| F7 | Toggle viewpunch removal |
| Ctrl+C | Restore patches and unload the DLL |

## Linux

Extract the Linux release archive, then run:

```sh
./bunnyhopfix
```

The launcher starts CS:S with `-insecure`, injects `libbhopfix.so`, and applies
the prediction patch.

Common commands:

```sh
# pass extra game arguments
./bunnyhopfix -- -console +exec autoexec

# launch through GameMode
gamemoderun ./bunnyhopfix

# attach to a running game
sudo ./bunnyhopfix --attach

# verify signatures against a client.so
./bunnyhopfix --scan-file /path/to/client.so

# extract case-broken assets from installed BSP files
./bunnyhopfix --fix-maps

# verify the running patch and hooks
sudo ./verify-live.sh
```

Send `SIGUSR1` to toggle prediction:

```sh
kill -USR1 <bunnyhopfix-pid>
```

Linux runtime downloads require `curl`. Compressed map downloads require
`bzip2`.

## Configuration

| Variable | Platform | Effect |
|---|---|---|
| `BHOPFIX_LOG=<filter>` | Both | Set the controller tracing filter |
| `BHOPFIX_DEBUG=1` | Both | Enable hook and input diagnostics |
| `BHOPFIX_NO_FORCE=1` | Both | Do not set `m_rawinput 2` at startup |
| `BHOPFIX_DEMOS=1` | Both | Record one POV demo per map |
| `BHOPFIX_KEEP_VIEWPUNCH=1` | Both | Start with viewpunch enabled |
| `BHOPFIX_NO_SOURCEJUMP=1` | Both | Disable SourceJump lookups |
| `BHOPFIX_FULLSCREEN=1` | Linux | Use exclusive fullscreen |
| `CSS_FREQ=<hz>` | Linux | Set the exclusive-fullscreen refresh rate |
| `CSS_FREQ=off` | Linux | Do not pass a refresh rate |
| `BHOPFIX_KEEP_OVERLAY=1` | Linux | Keep `gameoverlayrenderer.so` in `LD_PRELOAD` |
| `BHOPFIX_NO_DXVK_TWEAKS=1` | Linux | Leave `DXVK_CONFIG` unchanged |
| `BHOPFIX_NO_SDL_AUDIO=1` | Linux | Leave the SDL audio driver unchanged |

`BHOPFIX_LOG` uses
[`tracing-subscriber` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html).
Common values are `debug` and `info,bhopfix_hook=debug`.

`m_rawinput 2` is the default. Modes `0` and `1` remain selectable.

Fastdl cache data is stored in `~/.cache/bunnyhopfix/` on Linux and
`%LOCALAPPDATA%\bunnyhopfix\` on Windows. Maps are checked as BSP files and
verified against the published SHA-1 before installation.

## Build

Requires Rust 1.88 or newer.

```sh
cargo build --workspace --release
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

The release build produces `bunnyhopfix` and `libbhopfix.so` on Linux, or
`bunnyhopfix.exe` and `bhopfix.dll` on Windows.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for repository and release procedures.

## Credits

The implementation builds on
[BunnyhopAPE](https://github.com/alkatrazbhop/BunnyhopAPE),
[bunnyhopfix](https://github.com/b1scoito/bunnyhopfix), and
[RawInput2BunnyhopAPE](https://github.com/rtldg/RawInput2BunnyhopAPE).

## License

GPL-3.0-only. See [`LICENSE`](LICENSE).
