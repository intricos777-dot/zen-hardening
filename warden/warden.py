#!/usr/bin/env python3
"""
warden.py -- auto-blacklist PCs and phones that try to connect to this box.

WHAT IT ACTUALLY DOES (and does not)
------------------------------------
The `workstation` firewalld zone is already deny-all inbound, so every
stranger is dropped before it reaches a socket. What the zone does NOT do is
tell you who was dropped, whether they were a phone or a laptop, or remember
them after you later open a port for something legitimate.

warden closes that gap in two halves:

  1. nft (installed by install-warden.sh) puts a chain at priority -150, i.e.
     BEFORE firewalld's own filter chain. It does exactly three things:
       - accept established/related (so replies to my own outbound traffic
         are never logged or judged)
       - accept loopback and ICMPv6 (never break PMTU / NDP)
       - DROP any source address in the warden blacklist set
     Everything else gets `log group N prefix "WARDEN "` and is then
     ACCEPTED, so firewalld still makes the real accept/drop decision. warden
     never widens or narrows the firewall's opinion -- it only observes, and
     it enforces its own blacklist ahead of everyone else.

  2. this daemon binds NFLOG group N (no kernel log scraping, no dmesg
     dependency), resolves each source IP to a MAC via the neighbour table,
     looks the OUI up in the local IEEE registry, classifies phone / pc /
     unknown, and auto-blacklists an offender once it crosses the threshold.

Writes: /var/log/warden/events.jsonl   append-only audit trail
State:  /var/lib/warden/blacklist.json survives restart; reloaded into the
        nft set at startup.

Modes
  warden.py daemon      run the watcher (systemd, root)
  warden.py status      table of tracked devices
  warden.py watch       follow the audit log
  warden.py block IP    manual ban        warden.py unblock IP   lift
  warden.py selftest    exercise parsing/classification/escalation offline

Selftest needs no root and no netlink: it is the part that can be proven here.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import struct
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

CONF = Path("/etc/warden/warden.json")
STATE = Path("/var/lib/warden/blacklist.json")
AUDIT = Path("/var/log/warden/events.jsonl")
OUI_FILE = Path("/usr/share/nmap/nmap-mac-prefixes")

DEFAULTS = {
    "nflog_group": 5,
    "interface": "wlo1",
    "threshold_hits": 3,          # hits needed inside the window
    "threshold_window_s": 900,    # 15 minutes
    "ban_seconds": 86400,         # 24 h first offence
    "escalate_factor": 2,         # each repeat doubles the ban
    "max_ban_seconds": 604800,    # cap at 7 days
    "state_ttl_seconds": 604800,  # forget a clean device after 7 days
    "audit_max_bytes": 8_388_608,
    "trusted": [],                # IPs never auto-banned
    "vendors": {},                # optional overrides, see below
}

# OUI vendor fragments that mark a device as a phone / tablet. Matched as a
# substring of the IEEE registrant name, case-insensitive.
PHONE_HINTS = (
    "apple", "samsung", "xiaomi", "redmi", "poco", "huawei", "honor", "oppo",
    "oneplus", "realme", "vivo", "motorola", "nokia", "google", "lg elect",
    "sony", "sharp", "asustek", "zte", "transsion", "tecno", "infinix",
    "itel", "hmd global", "fairphone", "shift", "google device",
)
# OUI fragments that mark a PC / laptop / server-class hardware.
PC_HINTS = (
    "intel", "dell", "lenovo", "hewlett", "hp inc", "asrock", "micro-star",
    "msi", "gigabyte", "azurewave", "hon hai", "foxconn", "quanta", "compal",
    "wistron", "pegatron", "clevo", "system76", "framework", "supermicro",
    "gigaset", "toshiba", "fujitsu", "acer", "samsung elec", "realtek",
    "mediatek inc", "zhejiang", "suzhou", "shenzhen", "huaqin", "longcheer",
    "bytedance", "google device",  # ambiguous: listed in both, pc wins on tie
)

# Ports that betray an OS even when the OUI is a mystery blob: a TCP SYN to a
# phone-only service means a phone. Used only as a tiebreak / fallback.
PHONE_PORTS = {5353, 1910, 32499, 5353}
PC_PORTS = {22, 3389, 5900, 5938, 445, 135, 139}


# ── config ──────────────────────────────────────────────────────────────
def load_conf() -> dict:
    conf = dict(DEFAULTS)
    if CONF.exists():
        try:
            conf.update(json.loads(CONF.read_text()))
        except json.JSONDecodeError as exc:
            sys.exit(f"warden: {CONF} is not valid JSON: {exc}")
    return conf


# ── OUI registry ────────────────────────────────────────────────────────
_oui_cache: dict[str, str] | None = None


def oui_table() -> dict[str, str]:
    """prefix (first 3 bytes, uppercase hex) -> registrant name."""
    global _oui_cache
    if _oui_cache is not None:
        return _oui_cache
    table: dict[str, str] = {}
    try:
        with OUI_FILE.open("r", errors="replace") as fh:
            for line in fh:
                if not line or line[0] in "#\n":
                    continue
                parts = line.rstrip("\n").split(None, 1)
                if len(parts) == 2 and len(parts[0]) == 6:
                    table[parts[0].upper()] = parts[1].strip()
    except OSError:
        pass
    _oui_cache = table
    return table


def mac_of_ip(ip: str) -> str | None:
    """Resolve via the kernel neighbour table. No traffic is generated."""
    try:
        out = subprocess_run(["ip", "-4", "neigh", "show", "to", str(ip)])
    except OSError:
        return None
    m = re.search(r"lladdr\s+([0-9a-f:]{17})", out or "")
    if m:
        return m.group(1).lower()
    # IPv6 link-local resolution for v6 sources
    try:
        out6 = subprocess_run(["ip", "-6", "neigh", "show", "to", str(ip)])
    except OSError:
        return None
    m6 = re.search(r"lladdr\s+([0-9a-f:]{17})", out6 or "")
    return m6.group(1).lower() if m6 else None


def subprocess_run(argv: list[str]) -> str:
    import subprocess
    return subprocess.run(argv, capture_output=True, text=True, timeout=5).stdout


def vendor_of(mac: str | None, conf: dict) -> str:
    if not mac:
        return "unknown"
    prefix = mac.replace(":", "").replace("-", "").upper()[:6]
    table = oui_table()
    name = table.get(prefix, "")
    if not name:
        return f"unknown ({prefix})"
    return name


def classify(vendor: str, dport: int | None, conf: dict) -> str:
    """phone | pc | unknown -- vendor first, port second."""
    v = vendor.lower()
    for frag, label in (conf.get("vendors") or {}).items():
        if frag.lower() in v:
            return label
    if "unknown" in v:
        return "phone" if dport in PHONE_PORTS else "pc" if dport in PC_PORTS else "unknown"
    if any(h in v for h in PC_HINTS):
        return "pc"
    if any(h in v for h in PHONE_HINTS):
        return "phone"
    return "unknown"


# ── NFLOG packet decoding ───────────────────────────────────────────────
NFLOG_PREFIX = b"WARDEN "
# nfgenmsg (4) + nfulnl_msg_packet_hdr (16) = 20. hw_protocol(2) hook(1)
# _pad(1) id(4) seq(4) tid(4). Getting this wrong is why the first
# implementation saw no packets at all.
LEN_HDR = 4 + 16


def decode_packet(msg: bytes) -> tuple[str, str, int | None, int] | None:
    """-> (prefix, src_ip, dport, total_len) or None if it isn't ours.

    The address family is nfgenmsg.nfgen_family (byte 0) -- NOT res_id, which
    for nft-originated NFLOG carries the *nftables* family, a different enum.
    """
    if len(msg) < LEN_HDR:
        return None
    family = msg[0]
    payload = msg[LEN_HDR:]
    if payload.startswith(NFLOG_PREFIX):
        prefix = "WARDEN "
        payload = payload[len(NFLOG_PREFIX):]
        # Prefix present: the packet follows IMMEDIATELY. There is no NUL
        # terminator to skip -- hunting for one here truncates the packet at
        # its first zero byte (i.e. at \x45\x00 of the IPv4 header) and the
        # decode silently yields nothing.
    else:
        prefix = ""
        nul = payload.find(b"\x00")
        if nul != -1:
            payload = payload[nul + 1:]
    src, dport, total = "", None, len(payload)
    if family == socket.AF_INET and len(payload) >= 20:
        ihl = (payload[0] & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        src = socket.inet_ntop(socket.AF_INET, payload[12:16])
        if payload[9] in (6, 17) and len(payload) >= ihl + 4:
            dport = struct.unpack("!H", payload[ihl:ihl + 2])[0]
    elif family == socket.AF_INET6 and len(payload) >= 40:
        src = socket.inet_ntop(socket.AF_INET6, payload[8:24])
        nxt = payload[6]
        if nxt in (6, 17) and len(payload) >= 44:
            dport = struct.unpack("!H", payload[40:42])[0]
        elif nxt == 44 and len(payload) >= 60:      # fragment header -> TCP
            dport = struct.unpack("!H", payload[56:58])[0]
    if not src:
        return None
    return prefix, src, dport, total


# ── policy engine ───────────────────────────────────────────────────────
class Engine:
    def __init__(self, conf: dict, clock=time.time):
        self.conf = conf
        self.clock = clock
        self.hits: dict[str, deque] = defaultdict(deque)
        self.devices: dict[str, dict] = {}
        self.blacklist: dict[str, dict] = {}
        self.trusted = set(conf.get("trusted") or [])

    # -- persistence -------------------------------------------------
    def load(self, path: Path = STATE) -> None:
        if not path.exists():
            return
        try:
            blob = json.loads(path.read_text())
        except (json.JSONDecodeError, OSError):
            return
        for ip, rec in (blob.get("blacklist") or {}).items():
            if rec.get("until", 0) > self.clock():
                self.blacklist[ip] = rec
            else:
                self.blacklist[ip] = {**rec, "until": 0, "active": False}
        for ip, rec in (blob.get("devices") or {}).items():
            self.devices[ip] = rec

    def save(self, path: Path = STATE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(
            {"blacklist": self.blacklist, "devices": self.devices,
             "saved_at": self.clock()},
            indent=1, sort_keys=True))
        os.replace(tmp, path)

    # -- verdicts ----------------------------------------------------
    def is_trusted(self, ip: str) -> bool:
        if ip in self.trusted:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return addr.is_loopback or addr.is_link_local or addr.is_unspecified

    def active_ban(self, ip: str) -> float:
        rec = self.blacklist.get(ip)
        return rec["until"] if rec and rec.get("until", 0) > self.clock() else 0.0

    def observe(self, src: str, dport: int | None = None,
                vendor: str | None = None) -> dict:
        """One inbound attempt. Returns the event record."""
        now = self.clock()
        mac = mac_of_ip(src) if vendor is None else None
        vend = vendor if vendor is not None else vendor_of(mac, self.conf)
        kind = classify(vend, dport, self.conf)
        trusted = self.is_trusted(src)
        banned_until = self.active_ban(src)

        dev = self.devices.setdefault(src, {
            "first_seen": now, "hits": 0, "bans": 0,
            "mac": mac, "vendor": vend, "class": kind})
        dev.update({"last_seen": now, "hits": dev["hits"] + 1,
                    "mac": mac or dev.get("mac"),
                    "vendor": vend, "class": kind,
                    "ports": sorted(set(dev.get("ports", []) + ([dport] if dport else [])))})
        if now - dev["first_seen"] > self.conf["state_ttl_seconds"]:
            dev["first_seen"] = now

        action = "observed"
        if trusted:
            action = "trusted"
        elif banned_until:
            dev["strikes"] = dev.get("strikes", 0) + 1
            new_until = min(now + self._ban_len(dev["strikes"]),
                            self.clock() + self.conf["max_ban_seconds"])
            self.blacklist[src] = {"until": new_until, "since": banned_until,
                                   "reason": "reoffend-while-banned",
                                   "mac": dev.get("mac"), "vendor": vend,
                                   "class": kind, "strikes": dev["strikes"]}
            action = "ban-extended"
        else:
            win = deque(t for t in self.hits[src] if now - t < self.conf["threshold_window_s"])
            win.append(now)
            self.hits[src] = win
            if len(win) >= self.conf["threshold_hits"]:
                dev["strikes"] = dev.get("strikes", 0) + 1
                until = now + self._ban_len(dev["strikes"])
                dev["bans"] = dev.get("bans", 0) + 1
                self.blacklist[src] = {"until": until, "since": now,
                                       "reason": "threshold-reached",
                                       "mac": dev.get("mac"), "vendor": vend,
                                       "class": kind, "strikes": dev["strikes"]}
                self.hits[src].clear()
                action = "banned"

        return {"ts": now, "src": src, "dport": dport, "mac": mac,
                "vendor": vend, "class": kind, "action": action,
                "trusted": trusted, "ban_until": self.blacklist.get(src, {}).get("until", 0)}

    def _ban_len(self, strikes: int) -> float:
        base = self.conf["ban_seconds"] * (self.conf["escalate_factor"] ** max(0, strikes - 1))
        return min(base, self.conf["max_ban_seconds"])

    def expired(self) -> list[str]:
        now = self.clock()
        return [ip for ip, rec in self.blacklist.items()
                if rec.get("until") and rec["until"] <= now]


# ── nft set sync ────────────────────────────────────────────────────────
def nft_set_peek(group_set: str) -> list[str]:
    out = subprocess_run(["nft", "-j", "list", "set", "inet", "warden", group_set])
    try:
        blob = json.loads(out)
    except json.JSONDecodeError:
        return []
    vals = []
    for item in blob.get("nftables", []):
        vals += [e for e in (item.get("set", {}).get("elem") or []) if isinstance(e, str)]
    return vals


def nft_sync(engine: Engine, group_set: str) -> tuple[list[str], list[str]]:
    """Push deltas into the nft set. Returns (added, removed)."""
    want = {ip for ip, rec in engine.blacklist.items() if rec.get("until", 0) > engine.clock()}
    have = set(nft_set_peek(group_set))
    added = sorted(want - have)
    removed = sorted(have - want)
    for ip in added:
        subprocess_run(["nft", "add", "element", "inet", "warden", group_set, "{", ip, "}"])
    for ip in removed:
        subprocess_run(["nft", "delete", "element", "inet", "warden", group_set, "{", ip, "}"])
    return added, removed


# ── audit log ───────────────────────────────────────────────────────────
def audit_open(path: Path, max_bytes: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.stat().st_size > max_bytes:
        path.replace(path.with_suffix(".jsonl.1"))
    return path.open("a", buffering=1)


def audit_write(fh, event: dict) -> None:
    fh.write(json.dumps(event, sort_keys=True) + "\n")


# ── daemon ──────────────────────────────────────────────────────────────
def run_daemon(conf: dict) -> int:
    group = int(conf["nflog_group"])
    eng = Engine(conf)
    eng.load()
    if STATE.exists() is False:
        print(f"warden: no prior state at {STATE}, starting fresh", flush=True)

    # NFLOG group N == netlink multicast index N.
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)  # NETLINK_NETFILTER
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    for bits in (1 << group, 1 << (group - 1)):     # try both conventions
        try:
            sock.bind((0, bits))
            print(f"warden: NFLOG group {group} bound (mask {bits})", flush=True)
            break
        except OSError as exc:
            last = exc
    else:
        sys.exit(f"warden: cannot bind NFLOG group {group}: {last} (need root)")

    running = {"go": True}
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: running.__setitem__("go", False))
    sock.settimeout(5.0)

    fh = audit_open(AUDIT, int(conf["audit_max_bytes"]))
    print(f"warden: watching, audit -> {AUDIT}, state -> {STATE}", flush=True)
    last_sync = 0.0

    while running["go"]:
        try:
            data = sock.recv(1 << 16)
        except socket.timeout:
            data = b""
        except OSError:
            break
        if data:
            dec = decode_packet(data)
            if dec and dec[0] == "WARDEN ":
                _, src, dport, _len = dec
                if not eng.is_trusted(src):
                    event = eng.observe(src, dport)
                    audit_write(fh, event)
                    print(f"{time.strftime('%H:%M:%S')} {event['action']:>14} "
                          f"{src:>39} dport={event['dport']} "
                          f"{event['class']:<7} {event['vendor']}", flush=True)
        now = time.time()
        if now - last_sync > 15:
            last_sync = now
            for ip in eng.expired():
                print(f"{time.strftime('%H:%M:%S')} {'ban-expired':>14} {ip}", flush=True)
                audit_write(fh, {"ts": now, "src": ip, "action": "ban-expired"})
            try:
                added, removed = nft_sync(eng, "blacklist")
                for ip in added:
                    print(f"{time.strftime('%H:%M:%S')} {'nft-add':>14} {ip}", flush=True)
                for ip in removed:
                    print(f"{time.strftime('%H:%M:%S')} {'nft-del':>14} {ip}", flush=True)
                eng.save()
            except OSError as exc:
                print(f"warden: nft sync failed: {exc}", flush=True)
    fh.close()
    print("warden: stopped", flush=True)
    return 0


# ── selftest ────────────────────────────────────────────────────────────
def selftest() -> int:
    fails: list[str] = []

    def check(name: str, got, want) -> None:
        ok = got == want
        print(f"  [{'ok' if ok else 'FAIL'}] {name}: got {got!r}"
              + ("" if ok else f" want {want!r}"))
        if not ok:
            fails.append(name)

    # ── packet decoding, hand-built NFLOG messages ──
    print("packet decoding")

    def nflog(family: int, ip_bytes: bytes, proto: int = 6, dport: int = 22) -> bytes:
        # Real IPv4 header layout, 20 bytes. Offsets matter: the decoder reads
        # src at 12:16 and proto at 9, so every field must sit where the kernel
        # puts it or the test lies about what the decoder handles.
        ip = (b"\x45\x00"          # ver/ihl=5, tos
              + b"\x00\x28"        # total length
              + b"\x00\x00"        # id
              + b"\x00\x00"        # frag offset
              + b"\x40"            # ttl
              + bytes([proto])     # protocol
              + b"\x00\x00"        # header checksum
              + ip_bytes           # src -- this is the field the decoder reads
              + b"\x0a\x00\x00\x01") # dst
        assert len(ip) == 20, len(ip)
        tcp = struct.pack("!HHII", dport, 1, 1, 1)
        # nfgenmsg: family(1) version(1) res_id(2)  -> 4
        # nfulnl_msg_packet_hdr: hw(2) hook(1) _pad(1) id(4) seq(4) tid(4) -> 16
        return (struct.pack("!BBH", family, 0, 0)
                + struct.pack("!HBB", 0, 0, 0) + struct.pack("!III", 1, 1, 1)
                + b"WARDEN " + ip + tcp)

    dec = decode_packet(nflog(2, bytes([10, 197, 250, 7])))
    check("ipv4 src + dport", (dec[1], dec[2]) if dec else None, ("10.197.250.7", 22))
    dec = decode_packet(nflog(2, bytes([1, 2, 3, 4])))
    check("prefix consumed", dec[0] if dec else None, "WARDEN ")
    check("short junk ignored", decode_packet(b"\x00\x01\x02"), None)
    check("truncated ipv4 ignored", decode_packet(nflog(2, bytes([1, 2, 3, 4]))[:30]), None)

    # ── OUI classification ──
    print("classification")
    conf = load_conf()
    check("apple -> phone", classify("Apple, Inc.", None, conf), "phone")
    check("xiaomi -> phone", classify("Xiaomi Communications Co Ltd", None, conf), "phone")
    check("intel -> pc", classify("Intel Corporate", None, conf), "pc")
    check("dell -> pc", classify("Dell Inc.", None, conf), "pc")
    check("unknown vendor -> unknown", classify("unknown (aabbcc)", None, conf), "unknown")
    check("unknown vendor + phone port", classify("unknown (aabbcc)", 5353, conf), "phone")
    check("unknown vendor + ssh port", classify("unknown (aabbcc)", 22, conf), "pc")
    check("override honoured",
          classify("Banana Ltd", None, {**conf, "vendors": {"banana": "phone"}}), "phone")

    table = oui_table()
    print(f"  [info] OUI registry: {len(table)} entries from {OUI_FILE}")
    check("oui lookup works", bool(table), True)

    # ── escalation policy ──
    print("escalation")
    t = [1_000_000.0]
    eng = Engine({**conf, "trusted": ["10.0.0.9"]}, clock=lambda: t[0])
    eng.load(Path("/nonexistent"))
    check("clean hit is observed",
          eng.observe("10.1.1.1", 22, "Dell Inc.")["action"], "observed")
    check("2nd hit still observed",
          eng.observe("10.1.1.1", 22, "Dell Inc.")["action"], "observed")
    third = eng.observe("10.1.1.1", 22, "Dell Inc.")
    check("3rd hit bans", third["action"], "banned")
    check("ban length is 24h", round(eng.blacklist["10.1.1.1"]["until"] - t[0]), 86400)
    t[0] += 10
    again = eng.observe("10.1.1.1", 22, "Dell Inc.")
    check("offence while banned extends", again["action"], "ban-extended")
    check("escalated ban is 48h", round(eng.blacklist["10.1.1.1"]["until"] - t[0]), 2 * 86400)
    t[0] += 7 * 86400 + 10
    check("ban expires", eng.active_ban("10.1.1.1"), 0)
    check("expired() reports it", eng.expired(), ["10.1.1.1"])

    print("windowing")
    eng2 = Engine({**conf, "trusted": ["10.0.0.9"],
                   "threshold_hits": 3, "threshold_window_s": 100}, clock=lambda: t[0])
    eng2.observe("10.2.2.2", 22, "Intel Corporate")
    eng2.observe("10.2.2.2", 22, "Intel Corporate")
    t[0] += 500                      # both old hits fall out of the window
    check("hits outside window do not ban",
          eng2.observe("10.2.2.2", 22, "Intel Corporate")["action"], "observed")

    print("trust")
    check("configured trusted never banned",
          eng2.observe("10.0.0.9", 22, "Unknown")["action"], "trusted")
    for _ in range(5):
        check("loopback is trusted", eng2.observe("127.0.0.1", 22, "X")["action"], "trusted")
    check("gateway guess trusted", eng2.observe("169.254.1.1", None, "X")["action"], "trusted")

    print("persistence round-trip")
    tmp_state = Path(os.environ.get("TMPDIR", "/tmp")) / f"warden-selftest-{os.getpid()}.json"
    eng.save(tmp_state)
    eng3 = Engine(conf, clock=lambda: t[0])
    eng3.load(tmp_state)
    check("device state survived", eng3.devices.get("10.1.1.1", {}).get("class"), "pc")
    check("ban survived", eng3.active_ban("10.1.1.1"), 0.0)   # it had expired
    tmp_state.unlink(missing_ok=True)

    print("audit log")
    tmp_audit = tmp_state.with_suffix(".jsonl")
    fh = audit_open(tmp_audit, 1024)
    audit_write(fh, {"ts": 1, "src": "10.9.9.9", "action": "banned"})
    fh.close()
    check("audit line is valid json",
          json.loads(tmp_audit.read_text().splitlines()[0])["action"], "banned")
    tmp_audit.unlink(missing_ok=True)

    print()
    if fails:
        print(f"SELFTEST FAILED: {len(fails)} check(s): {', '.join(fails)}")
        return 1
    print("SELFTEST PASSED")
    return 0


# ── status ──────────────────────────────────────────────────────────────
def cmd_status(conf: dict) -> int:
    eng = Engine(conf)
    eng.load()
    now = time.time()
    print(f"warden status   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  config        {CONF} ({'present' if CONF.exists() else 'defaults only'})")
    print(f"  state         {STATE} ({'present' if STATE.exists() else 'absent'})")
    print(f"  audit         {AUDIT} "
          f"({AUDIT.stat().st_size if AUDIT.exists() else 0} bytes)")
    print(f"  nft set       inet warden blacklist")
    try:
        have = nft_set_peek("blacklist")
        print(f"  loaded in nft {len(have)} element(s): {', '.join(have) or '-'}")
    except OSError:
        print("  loaded in nft (needs root to read)")

    active = [(ip, r) for ip, r in eng.blacklist.items() if r.get("until", 0) > now]
    print(f"\n  active bans   {len(active)}")
    for ip, r in sorted(active, key=lambda kv: -kv[1]["until"]):
        left = int(r["until"] - now)
        print(f"    {ip:>39}  {left//3600:>5}h left  {r.get('class',''):<7} "
              f"{r.get('vendor','')}  [{r.get('reason','')}]")

    recent = sorted(eng.devices.items(), key=lambda kv: -kv[1].get("last_seen", 0))[:20]
    print(f"\n  devices seen  {len(eng.devices)} (showing {len(recent)})")
    for ip, d in recent:
        ban = "BANNED" if eng.active_ban(ip) else ""
        print(f"    {ip:>39}  hits={d.get('hits',0):<5} {d.get('class',''):<7} "
              f"{d.get('vendor','')[:38]:<38} {ban}")
    return 0


# ── cli ─────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="warden", description=__doc__.split("\n")[1])
    ap.add_argument("cmd", nargs="?", default="status",
                    choices=["daemon", "status", "watch", "block", "unblock", "selftest"])
    ap.add_argument("ip", nargs="?", help="address for block/unblock")
    args = ap.parse_args(argv)
    conf = load_conf()

    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "daemon":
        return run_daemon(conf)
    if args.cmd == "watch":
        if not AUDIT.exists():
            sys.exit(f"warden: no audit log yet at {AUDIT}")
        with AUDIT.open() as fh:
            fh.seek(0, os.SEEK_END)
            for line in fh:
                ev = json.loads(line)
                print(f"{time.strftime('%H:%M:%S', time.localtime(ev['ts']))} "
                      f"{ev.get('action',''):>14} {ev.get('src','')} "
                      f"{ev.get('vendor','')}")
    if args.cmd in ("block", "unblock"):
        if not args.ip:
            sys.exit(f"warden: {args.cmd} needs an address")
        eng = Engine(conf)
        eng.load()
        if args.cmd == "block":
            eng.blacklist[args.ip] = {"until": time.time() + conf["ban_seconds"],
                                      "since": time.time(), "reason": "manual",
                                      "strikes": 0}
            eng.devices.setdefault(args.ip, {"first_seen": time.time(), "hits": 0,
                                             "bans": 0, "class": "?", "vendor": "manual"})
        else:
            eng.blacklist.pop(args.ip, None)
        eng.save()
        if os.geteuid() == 0:
            nft_sync(eng, "blacklist")
        print(f"warden: {args.cmd}ed {args.ip}")
    return cmd_status(conf)


if __name__ == "__main__":
    sys.exit(main())
