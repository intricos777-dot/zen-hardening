#!/usr/bin/env python3
"""Add non-Steam game shortcuts to Steam's shortcuts.vdf.

Steam keeps non-Steam shortcuts in a BINARY vdf at
~/.local/share/Steam/userdata/<steamid>/config/shortcuts.vdf. The client
holds the whole file in memory and rewrites it on exit, so this must only
be run while Steam is CLOSED -- otherwise the edit is silently discarded.

Usage:
    python3 add_steam_shortcuts.py            # write (refuses if steam runs)
    python3 add_steam_shortcuts.py --dry-run  # parse + show, write nothing

Binary vdf layout, all strings NUL-terminated, all keys NUL-prefixed:
    \\x00 'shortcuts' \\x00
      \\x00 <index-as-string> \\x00
        \\x00 'appid' \\x00 <uint32 LE> \\x00
        \\x00 'AppName' \\x00 <str> \\x00
        ...
      \\x02 \\x00
"""
import os
import struct
import sys
from pathlib import Path

STEAM_ROOT = Path(os.environ.get(
    "STEAM_ROOT", Path.home() / ".local/share/Steam"))
USERDATA = STEAM_ROOT / "userdata"

# Steam derives the grid artwork for a non-Steam entry from the Exe's basename.
# A bare name gives a generic blank tile, so point icon at a real file when we
# have one.
SHORTCUTS = [
    {
        "AppName": "Hermes Agent",
        "Exe": "/usr/bin/hermes",
        "StartDir": str(Path.home()),
        "icon": "",
        "LaunchOptions": "",
        "tags": ["Tools", "AI"],
    },
    {
        "AppName": "opencode",
        "Exe": "/usr/bin/opencode",
        "StartDir": str(Path.home() / "Projects"),
        "icon": "",
        "LaunchOptions": "",
        "tags": ["Tools", "AI"],
    },
]


def die(msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def steam_running():
    """True if a steam client process is alive.

    Checked because shortcuts.vdf is rewritten wholesale from the client's
    in-memory copy when it exits. Writing underneath a running client looks
    like it worked and is then lost.
    """
    proc = Path("/proc")
    for pid in proc.iterdir():
        if not pid.name.isdigit():
            continue
        try:
            exe = (pid / "cmdline").read_bytes().split(b"\0")[0].decode(
                "utf-8", "replace")
        except (OSError, IndexError):
            continue
        # Match the client, not our own grep.
        if exe.endswith("/ubuntu12_32/steam") or exe.endswith("/steam.sh"):
            return int(pid.name)
    return None


def find_shortcuts_file():
    if not USERDATA.is_dir():
        die("no Steam userdata at {} -- is Steam installed?".format(USERDATA))
    # Prefer the 32-bit config dir; that is the one the client reads on Linux.
    cands = sorted(USERDATA.glob("*/config"))
    for cfg in cands:
        if (cfg / "shortcuts.vdf").exists():
            return cfg / "shortcuts.vdf"
    if cands:
        return cands[0] / "shortcuts.vdf"
    die("no userdata/*/config dir under {}".format(USERDATA))


# ---------------------------------------------------------------- read side

def _rd_bytes(buf, i):
    end = buf.index(b"\0", i)
    return buf[i:end], end + 1


def parse(buf):
    """Return a list of dicts. Tolerant: stops cleanly at a malformed tail
    rather than raising, so a hand-edited or truncated file is still usable."""
    if not buf or buf[0:1] != b"\0" or b"shortcuts" not in buf[:12]:
        raise ValueError("not a shortcuts.vdf (bad header)")
    i = buf.index(b"shortcuts") + len("shortcuts") + 1
    out = []
    n = len(buf)
    while i < n and buf[i] == 0x00 and buf[i:i + 1] != b"\x02":
        # index key
        i += 1
        _, i = _rd_bytes(buf, i)
        entry = {}
        while i < n and buf[i] == 0x00 and buf[i + 1:i + 2] != b"\x02":
            i += 1
            key, i = _rd_bytes(buf, i)
            key = key.decode("utf-8", "replace")
            if key == "appid":
                entry["appid"] = struct.unpack_from("<I", buf, i)[0]
                i += 4
                i += 1  # NUL-terminated like every other value
            elif key == "tags":
                cnt = struct.unpack_from("<I", buf, i)[0]
                i += 4
                i += 1  # the count is NUL-terminated as well
                tags = []
                for _ in range(cnt):
                    if buf[i] != 0x00:
                        break
                    i += 1
                    t, i = _rd_bytes(buf, i)
                    tags.append(t.decode("utf-8", "replace"))
                entry["tags"] = tags
            elif key in ("IsHidden", "AllowDesktopConfig", "AllowOverlay",
                         "OpenVR", "LastPlayTime"):
                entry[key] = struct.unpack_from("<I", buf, i)[0]
                i += 4
                i += 1  # uint32 values are NUL-terminated too
            else:
                # A string value is prefixed by its own NUL. Skip it first, or
                # _rd_bytes finds the terminator immediately and yields "".
                if buf[i] != 0x00:
                    break
                i += 1
                v, i = _rd_bytes(buf, i)
                entry[key] = v.decode("utf-8", "replace")
        if buf[i:i + 1] == b"\x02":
            i += 1
        if entry:
            out.append(entry)
    return out


# ---------------------------------------------------------------- write side

def _w_str(parts, s):
    """Append a NUL-terminated, NUL-prefixed string to the output.

    `parts` is a list of byte chunks, NOT a bytes object. `buf += x` on a bytes
    local only rebinds that local, so a write helper taking bytes silently
    discards every chunk it was given.
    """
    parts.append(b"\0")
    parts.append(s.encode("utf-8") if isinstance(s, str) else s)
    parts.append(b"\0")


def _w_uint32(parts, v):
    parts.append(struct.pack("<I", v))
    parts.append(b"\0")


def serialise(entries):
    parts = [b"\0shortcuts\0"]
    for idx, e in enumerate(entries):
        _w_str(parts, str(idx))
        _w_str(parts, "appid")
        _w_uint32(parts, e.get("appid", 0))
        _w_str(parts, "AppName")
        _w_str(parts, e.get("AppName", ""))
        _w_str(parts, "Exe")
        _w_str(parts, e.get("Exe", ""))
        _w_str(parts, "StartDir")
        _w_str(parts, e.get("StartDir", ""))
        _w_str(parts, "icon")
        _w_str(parts, e.get("icon", ""))
        _w_str(parts, "ShortcutPath")
        _w_str(parts, "")
        _w_str(parts, "LaunchOptions")
        _w_str(parts, e.get("LaunchOptions", ""))
        for k in ("IsHidden", "AllowDesktopConfig", "AllowOverlay", "OpenVR"):
            _w_str(parts, k)
            _w_uint32(parts, e.get(k, 0))
        _w_str(parts, "Devkit")
        _w_str(parts, "")
        _w_str(parts, "DevkitGameID")
        _w_str(parts, "")
        _w_str(parts, "LastPlayTime")
        _w_uint32(parts, e.get("LastPlayTime", 0))
        _w_str(parts, "tags")
        tags = e.get("tags", [])
        _w_uint32(parts, len(tags))
        for t in tags:
            _w_str(parts, t)
        # Each entry is its own object and MUST be closed, or the reader runs
        # past the last field into the next entry and invents a phantom one.
        parts.append(b"\x02")
    # Close the outer 'shortcuts' object.
    parts.append(b"\x02\0")
    return b"".join(parts)


def next_appid(entries):
    """Non-Steam appids must not collide with real Steam app ids.

    Steam reserves anything at or above 2^31 for non-Steam entries, so pick
    the next free slot in that range.
    """
    used = {e.get("appid") for e in entries}
    a = 2147483648
    while a in used:
        a += 1
    return a


def main():
    dry = "--dry-run" in sys.argv
    path = find_shortcuts_file()

    pid = steam_running()
    if pid and not dry:
        die("Steam is running (pid {}). Quit it fully first -- it rewrites "
            "shortcuts.vdf from memory on exit and will discard this "
            "edit.".format(pid))

    existing = []
    if path.exists():
        raw = path.read_bytes()
        if raw:
            try:
                existing = parse(raw)
            except ValueError as exc:
                die("{} is not parseable ({}). Move it aside first so it is "
                    "not lost.".format(path, exc))
    print("{}: {} existing shortcut(s)".format(path, len(existing)))
    for e in existing:
        print("  [{}] {}  ->  {}".format(
            e.get("appid"), e.get("AppName"), e.get("Exe")))

    added = 0
    for sc in SHORTCUTS:
        exe = Path(sc["Exe"])
        if not exe.exists():
            print("skip {}: {} does not exist".format(sc["AppName"], exe))
            continue
        if any(e.get("Exe") == sc["Exe"] for e in existing):
            print("skip {}: already present".format(sc["AppName"]))
            continue
        if not os.access(exe, os.X_OK):
            print("skip {}: not executable".format(sc["AppName"]))
            continue
        e = dict(sc)
        e["appid"] = next_appid(existing)
        for k in ("IsHidden", "AllowDesktopConfig", "AllowOverlay", "OpenVR",
                  "LastPlayTime"):
            e.setdefault(k, 0)
        existing.append(e)
        added += 1
        print("  + [{}] {}  ->  {}".format(
            e["appid"], e["AppName"], e["Exe"]))

    if not added:
        print("nothing to add")
        return

    blob = serialise(existing)
    # Read-back check: a shortcuts.vdf Steam cannot parse means the library
    # silently loses every non-Steam entry, with no error shown anywhere.
    try:
        rt = parse(blob)
    except Exception as exc:
        die("internal: generated file does not re-parse: {}".format(exc))
    if len(rt) != len(existing):
        die("internal: round-trip lost entries ({} != {})".format(
            len(rt), len(existing)))
    for e in existing:
        match = [x for x in rt
                 if x.get("appid") == e["appid"]
                 and x.get("Exe") == e["Exe"]]
        if not match:
            die("internal: {} did not survive the round-trip".format(
                e["AppName"]))

    if dry:
        print("\n--dry-run: {} would be written ({} bytes)".format(
            path, len(blob)))
        return
    path.write_bytes(blob)
    print("\nwrote {} ({} bytes, {} shortcuts)".format(
        path, len(blob), len(existing)))


if __name__ == "__main__":
    main()
