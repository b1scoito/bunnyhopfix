#!/bin/bash
# verify-live.sh — check that the patch + hooks are actually live in the game.
#
# Deliberately address-free: it finds things the same way the tool does, by
# instruction signature and by looking for pointers into librawinput2, so a
# game update can never make this script report nonsense. (The previous version
# hard-coded vaddrs from an old build and happily printed wrong expectations.)
#
# Usage: sudo ./verify-live.sh
#   (reading another process's memory needs ptrace rights: with the usual
#    kernel.yama.ptrace_scope=1 only root or the game's own parent may do it)
set -u
PID=$(pgrep -f cstrike_linux64 | head -1)
if [ -z "${PID}" ]; then echo "game not running"; exit 1; fi
echo "game pid: ${PID}"

exec python3 - "$PID" <<'PY'
import re, sys

pid = sys.argv[1]
maps = []
for line in open(f"/proc/{pid}/maps"):
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s+(.*)", line.rstrip())
    if m:
        maps.append((int(m[1], 16), int(m[2], 16), m[3], m[4]))

def ranges(needle, perms=None):
    return [r for r in maps if needle in r[3] and (perms is None or r[2].startswith(perms))]

try:
    mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
except PermissionError:
    print(f"cannot read /proc/{pid}/mem - re-run with sudo "
          f"(kernel.yama.ptrace_scope="
          f"{open('/proc/sys/kernel/yama/ptrace_scope').read().strip()})")
    sys.exit(1)
def read(addr, n):
    try:
        mem.seek(addr)
        return mem.read(n)
    except OSError:
        return b""

hook = ranges("librawinput2.so")
if not hook:
    print("librawinput2.so NOT loaded -> no hooks (LD_PRELOAD failed?)")
    sys.exit(1)
lo, hi = min(r[0] for r in hook), max(r[1] for r in hook)
print(f"librawinput2.so: 0x{lo:x}-0x{hi:x}\n")

# --- 1. installed hooks: pointers into librawinput2 sitting in game data -----
print("installed hooks (game data slots pointing into librawinput2):")
found = 0
for name in ("/client.so", "/launcher.so", "/engine.so"):
    for s, e, _p, path in ranges(name, "rw"):
        buf = read(s, e - s)
        for i in range(0, max(0, len(buf) - 8), 8):
            v = int.from_bytes(buf[i:i + 8], "little")
            if lo <= v < hi:
                print(f"  {path.rsplit('/', 1)[-1]:12s} slot 0x{s + i:x} -> 0x{v:x}")
                found += 1
print(f"  total: {found}" if found else "  NONE - nothing was hooked")

# --- 2. autobhop patch state, located by signature, not by address ----------
# Each entry: (name, prefix pattern with None wildcards) -- the 6 bytes that
# follow the prefix are the `jne` the patcher NOPs.
SIGS = [
    ("CheckJumpButton #1", [0x80, 0xB8, 0x48, 0x14, 0x00, 0x00, 0x00,
                            0x0F, 0x85, None, 0xFF, 0xFF, 0xFF,
                            0x48, 0x8B, 0x53, 0x10,
                            0xF6, 0x42, 0x28, 0x02]),
    ("CheckJumpButton #2", [0x8B, 0x50, 0x58,
                            0x85, 0xD2,
                            0x75, None,
                            0x49, 0x8B, 0x44, 0x24, 0x10,
                            0xF6, 0x40, 0x28, 0x02]),
]

def anchor(pat):
    out = bytearray()
    for b in pat:
        if b is None:
            break
        out.append(b)
    return bytes(out)

print("\nautobhop prediction patch:")
text = ranges("/client.so", "r-x")
for name, pat in SIGS:
    a, hits = anchor(pat), []
    for s, e, _p, _path in text:
        buf = read(s, e - s)
        i = buf.find(a)
        while i >= 0:
            if i + len(pat) + 6 <= len(buf) and all(
                p is None or buf[i + j] == p for j, p in enumerate(pat)
            ):
                hits.append((s + i + len(pat), buf[i + len(pat):i + len(pat) + 6]))
            i = buf.find(a, i + 1)
    if not hits:
        print(f"  {name}: signature not found (game updated?)")
    for addr, six in hits:
        if six == b"\x90" * 6:
            state = "ON  (NOP'd -> client predicts the jump)"
        elif six[:2] == b"\x0f\x85":
            state = "OFF (stock jne -> prediction bails on m_nOldButtons)"
        else:
            state = f"UNKNOWN ({six.hex()})"
        print(f"  {name} @ 0x{addr:x}: {state}")
PY
