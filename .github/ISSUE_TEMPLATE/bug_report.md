---
name: Bug report
about: The patch or a hook does not work, or the game misbehaves with the tool
title: "[bug] "
labels: bug
---

> **Read this first.** This tool patches a *live* Counter-Strike: Source
> client, and Valve ships CS:S updates without warning. **The single most
> useful line in your report is any hook line that says `FAILED` or `NOT`** —
> for example:
>
> ```
> [bhopfix] FAILED to hook GetRawMouseAccumulators: not found in ...'s vtable (game updated?)
> [bhopfix] CreateMove slot +0x... NOT hooked: holds 0x..., expected 0x... (game updated?)
> [bhopfix] viewpunch: code at 0x... differs from client.so; NOT patching
> ```
>
> A game update shows up *exactly* there: the tool resolves and validates every
> target before writing, so when something moves it refuses to patch and says
> so. Please paste those lines verbatim, including the `0x...` values.

## What happened

<!-- What you expected, and what actually happened instead. -->

## Environment

- **OS / distro + version:**
- **Game build:** <!-- Steam Linux native 64-bit build, or Windows -->
- **CS:S build number:** <!--
    AppID 240. The game log prints a line like `Version: 9530147` early in
    startup (also visible in the console with `version`). Please give the
    number, not "latest". -->
- **Tool version / commit:** <!-- release tag, `nightly` build date, or
    `git rev-parse --short HEAD` -->
- **Launched how:** <!-- through the tool (`./bunnyhopfix`), or `--attach` to a
    running game -->
- **Was `-insecure` used?** <!-- yes / no. Every component refuses to work
    without it; the tool adds it itself when it launches the game. -->

## Full tool output

Run with debug logging on and paste **everything**, from the first line:

```sh
BHOPFIX_DEBUG=1 ./bunnyhopfix 2>&1 | tee /tmp/bhopfix.log
```

<details>
<summary>output</summary>

```
paste here
```

</details>

## verify-live.sh output

If the game was running, this says whether the patch and the hooks are actually
live in the process (it re-derives everything by signature, so it stays valid
across game updates):

```sh
sudo ./verify-live.sh
```

<details>
<summary>output</summary>

```
paste here
```

</details>

## Crash dumps

Did the game itself crash? Check for a fresh minidump:

```sh
ls -lt /tmp/dumps | head
```

- **Dump appeared in `/tmp/dumps`:** <!-- yes (timestamp) / no / directory absent -->

## Offline signature check (optional, very helpful)

If the report is "the jump prediction did nothing", this verifies the
`CheckJumpButton` signatures against the `client.so` on your disk without
running the game:

```sh
./bunnyhopfix --scan-file "<steam>/steamapps/common/Counter-Strike Source/cstrike/bin/linux64/client.so"
```

<details>
<summary>output</summary>

```
paste here
```

</details>

## Anything else

<!-- Server you were on (autobhop or vanilla?), map, whether it reproduces on
     a local listen server, gamemode/DXVK/Proton or wine details, other
     LD_PRELOAD libraries in play. -->
