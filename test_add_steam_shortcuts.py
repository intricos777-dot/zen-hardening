#!/usr/bin/env python3
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
"""Tests for the binary shortcuts.vdf reader/writer.

The reader and writer are hand-rolled against an undocumented binary format,
so they are checked against each other at the byte level. A shortcuts.vdf that
round-trips through this pair but that Steam cannot parse still loses the whole
non-Steam library, so these tests exist to catch format drift early.
"""
import importlib.util
import struct
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "ass", Path(__file__).parent / "add_steam_shortcuts.py")
ass = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ass)

FAILED = []


def check(cond, msg):
    if cond:
        print("  pass  " + msg)
    else:
        print("  FAIL  " + msg)
        FAILED.append(msg)


def entry(appid, name, exe, tags=("Tools",), start="/home/livings"):
    return {
        "appid": appid, "AppName": name, "Exe": exe, "StartDir": start,
        "icon": "", "ShortcutPath": "", "LaunchOptions": "",
        "IsHidden": 0, "AllowDesktopConfig": 1, "AllowOverlay": 1,
        "OpenVR": 0, "LastPlayTime": 0, "Devkit": "", "DevkitGameID": "",
        "tags": list(tags),
    }


print("round-trip: empty list")
blob = ass.serialise([])
check(blob == b"\0shortcuts\0\x02\0", "empty file is header + terminator")
check(ass.parse(blob) == [], "empty file parses to no entries")

print("\nround-trip: single entry")
e = entry(2147483648, "Hermes Agent", "/usr/bin/hermes")
rt = ass.parse(ass.serialise([e]))
check(len(rt) == 1, "one entry in, one entry out (got {})".format(len(rt)))
if rt:
    got = rt[0]
    check(got.get("appid") == 2147483648, "appid survives")
    check(got.get("AppName") == "Hermes Agent", "AppName survives")
    check(got.get("Exe") == "/usr/bin/hermes", "Exe survives")
    check(got.get("StartDir") == "/home/livings", "StartDir survives")
    check(got.get("tags") == ["Tools"], "tags survive (got {})".format(
        got.get("tags")))
    check(got.get("AllowOverlay") == 1, "uint32 flag survives")

print("\nround-trip: the two real shortcuts")
real = [
    entry(2147483648, "Hermes Agent", "/usr/bin/hermes", ("Tools", "AI")),
    entry(2147483649, "opencode", "/usr/bin/opencode", ("Tools", "AI"),
          start="/home/livings/Projects"),
]
rt = ass.parse(ass.serialise(real))
check(len(rt) == 2, "exactly 2 entries, no phantom (got {})".format(len(rt)))
check([r.get("appid") for r in rt] == [2147483648, 2147483649],
      "appids in order and distinct")
check(all(r.get("tags") == ["Tools", "AI"] for r in rt), "both tag lists")

print("\nno phantom entry past the last one")
# The bug this guards: the writer omitted the per-entry 0x02 object close, so
# the reader ran off the end of entry N into the N+1 header and produced an
# extra bogus entry.
for n in (1, 2, 3, 5):
    many = [entry(2147483648 + i, "App{}".format(i), "/bin/x{}".format(i))
            for i in range(n)]
    rt = ass.parse(ass.serialise(many))
    check(len(rt) == n,
          "{} entries in -> {} out".format(n, len(rt)))

print("\nempty and multi-byte values")
tricky = entry(2147483650, "", "", tags=())
rt = ass.parse(ass.serialise([tricky]))
check(len(rt) == 1 and rt[0].get("AppName") == "", "empty AppName survives")
check(rt and rt[0].get("tags") == [], "empty tag list survives")

uni = entry(2147483651, "Ünïcodé ✓", "/usr/bin/héllo", tags=("Ünïcodé",))
rt = ass.parse(ass.serialise([uni]))
check(rt and rt[0].get("AppName") == "Ünïcodé ✓", "unicode AppName survives")
check(rt and rt[0].get("tags") == ["Ünïcodé"], "unicode tag survives")

print("\nbyte-level structure")
b = ass.serialise([e])
check(b[:10] == b"\x00shortcuts", "starts with NUL + 'shortcuts'")
check(b.endswith(b"\x02\x00"), "ends with outer 0x02 0x00")
check(b.count(b"\x02") == 2, "one inner + one outer 0x02 (got {})".format(
    b.count(b"\x02")))
check(b"\x00appid\x00" in b, "'appid' key present")
check(struct.pack("<I", 2147483648) + b"\x00" in b,
      "appid is uint32 LE followed by NUL")
check(b"\x00LastPlayTime\x00" in b, "LastPlayTime present")

print("\nrejects garbage")
for bad, label in [(b"", "empty"),
                   (b"not a vdf at all", "wrong magic"),
                   (b"\x00somethingelse\x00", "wrong root key")]:
    try:
        ass.parse(bad)
        check(False, "rejects " + label)
    except ValueError:
        check(True, "rejects " + label)

print("\nnext_appid")
check(ass.next_appid([]) == 2147483648, "first free id is 2^31")
check(ass.next_appid([entry(2147483648, "a", "/a")]) == 2147483649,
      "skips a taken id")
check(ass.next_appid([entry(2147483648, "a", "/a"),
                      entry(2147483649, "b", "/b")]) == 2147483650,
      "skips consecutive taken ids")
check(all(ass.next_appid([entry(2147483648 + i, "x", "/x")
                          for i in range(3)]) > 2 ** 31 - 1
          for _ in [0]), "stays in the reserved non-Steam range")

print()
if FAILED:
    print("{} FAILED:".format(len(FAILED)))
    for f in FAILED:
        print("  - " + f)
    sys.exit(1)
print("all tests passed")
