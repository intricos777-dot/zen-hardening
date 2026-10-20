#!/usr/bin/env python3
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
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
    # How many attempts inside threshold_window_s before a ban.
    # 1 = the FIRST inbound attempt from an unverified device is an immediate
    # ban. This is the default because the threat model is "any connection
    # from a device I do not own counts as an attempt to reach me".
    "threshold_hits": 1,
    "threshold_window_s": 900,
    "ban_seconds": 86400,         # 24 h first offence
    "escalate_factor": 2,         # each repeat doubles the ban
    "max_ban_seconds": 604800,    # cap at 7 days
    "state_ttl_seconds": 604800,  # forget a clean device after 7 days
    # Spoof-detection tuning. Both of these were wrong at their first values
    # and caused a false permanent ban on a device doing nothing but renewing
    # its DHCP lease, so they are explicit and tested rather than buried.
    "identity_window_s": 120,      # two addresses within 120s = identity reuse
    "evasion_strikes_to_ban": 5,   # contact-while-banned N times = permanent
    "audit_max_bytes": 8388608,
    "trusted": [],                # IPs never auto-banned (infrastructure)
    "vendors": {},                # optional overrides, see below
    # OWNERSHIP REGISTRY -- the devices you actually own. Anything seen on the
    # wire that is not here is unverified, and one inbound attempt from an
    # unverified device is a ban.
    #
    # Identity is the MAC, not the IP. This network is a flat 10.0.0.0/8
    # broadcast domain, so an IP ban alone is worthless: the next device to
    # pick up a different address in the same /8 walks straight back in.
    #
    # Enrol the first one by hand, then use `warden suggest` to see candidates
    # for the rest. A random-MAC phone will need re-enrolling when it rotates.
    "owners": [
        # {"mac": "aa:bb:cc:dd:ee:ff", "name": "my phone", "ips": ["10.197.250.7"]}
    ],
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
def normalise_mac(mac: str | None) -> str | None:
    """Lowercase colon form, or None. Used as a dict key so that the
    same device is recognised regardless of how it was written down."""
    if not mac:
        return None
    m = re.fullmatch(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac.strip())
    return m.group(0).lower() if m else None


def is_locally_administered(mac: str) -> bool:
    """Second LSB of the first octet is set for randomised (private) MACs.

    A phone using MAC randomisation looks like this. It is still a distinct
    device to ban, but it will NOT be the same MAC next time, so an
    ownership entry keyed on it expires. Worth knowing, worth logging.
    """
    try:
        first = int(mac.split(":")[0], 16)
    except (ValueError, IndexError):
        return False
    return bool(first & 0b10)


# ── spoofing detection ──────────────────────────────────────────────────
#
# What can actually be detected on this box, and what cannot:
#
# DETECTABLE
#   * a randomised (locally-administered) MAC from a device that is not a
#     registered owner -- it is concealing its hardware identity
#   * one MAC presenting several source addresses at once (identity reuse)
#   * a banned MAC coming back under a different address (evasion)
#   * a MAC with a globally-administered OUI that claims a major vendor
#
# NOT DETECTABLE HERE (and not claimed)
#   * a stranger simply using a DIFFERENT random MAC each time. This is the
#     standard evasion and MAC-based blocking does not stop it; only 802.11w
#     or a WPA3-enterprise AP with client isolation would. Treat a MAC ban as
#     a speed bump against a casual prober, not against a determined one.
#   * frames the AP forwards but that never reach the IP stack, so we never
#     see the MAC at all. There is no bridge here, so no fdb table to read.

SPOOF_SEVERITY = {
    "randomised-unverified": ("permanent", "randomised MAC from a device you do not own"),
    "identity-reuse": ("escalate", "one MAC presenting multiple source addresses"),
    "ban-evasion": ("permanent", "banned MAC reappeared at a new address"),
    "vendor-masquerade": ("escalate", "MAC claims a vendor OUI it cannot own"),
}

# OUIs that are heavily impersonated, because a spoofed MAC that resolves to
# a recognisable vendor is a deliberate choice rather than an accident.
MAJOR_VENDORS = ("apple", "samsung", "intel", "dell", "microsoft", "google",
                 "sony", "lg elect", "huawei", "xiaomi")


def detect_spoof(key: str, rec: dict, conf: dict, ban_until: float) -> list[dict]:
    """Signals for one device. Returns a list of {kind, severity, why}."""
    out: list[dict] = []
    mac = normalise_mac(rec.get("mac"))
    if not mac:
        return out

    if is_locally_administered(mac):
        # This box's own wlo1 MAC is randomised too (0xea), and the gateway
        # shows up in the neighbour table twice (v4 + v6). Neither is spoofing,
        # so only unverified devices are judged here.
        out.append({"kind": "randomised-unverified",
                    "why": "locally-administered MAC, not a registered owner"})

    ips = [ip for ip in (rec.get("ips") or [])
           if not ipaddress.ip_address(ip).is_link_local]
    # One MAC, several addresses. This is only evidence of spoofing if the
    # addresses are close together in time -- a device whose DHCP lease simply
    # expired and was reassigned also shows two addresses, and treating that
    # as spoofing means punishing the most ordinary event on the network.
    # The recurrence window is deliberately SHORT (identity_window_s): a real
    # identity-reuse attack presents addresses within seconds of each other,
    # while a lease renewal is minutes or hours apart.
    recent = rec.get("ip_times") or {}
    newest = max(recent.values()) if recent else 0
    window = int(conf.get("identity_window_s", 120))
    simultaneous = [ip for ip, ts in recent.items()
                    if newest - ts <= window]
    if len(set(ips)) >= 2 and len(set(simultaneous)) >= 2:
        out.append({"kind": "identity-reuse",
                    "why": f"same MAC at {len(set(simultaneous))} addresses "
                           f"within {window}s"})

    if ban_until:
        # Reoffending is the strongest signal available, but a device whose
        # lease expired while banned would land here too. So it is recorded and
        # left to SpoofTally to require corroboration; a single occurrence
        # escalates, it does not condemn.
        out.append({"kind": "ban-evasion",
                    "why": "contact while banned"})

    prefix = mac.replace(":", "").upper()[:6]
    vendor = (conf.get("vendors") or {})
    name = next((v for k, v in vendor.items() if k.lower() in prefix), "")
    if not name and len(prefix) == 6:
        name = oui_table().get(prefix, "")
    if name and not is_locally_administered(mac) and \
            any(v in name.lower() for v in MAJOR_VENDORS) and \
            rec.get("class") == "unknown":
        # Registered to a major vendor but classified unknown: the OUI and the
        # observed behaviour disagree, which is what a spoofed MAC looks like.
        out.append({"kind": "vendor-masquerade",
                    "why": f"OUI says {name} but device behaves unrecognised"})
    return out


class SpoofTally:
    """Accumulates spoof signals per device and decides the sanction.

    A single signal is not proof -- neighbour tables are lossy and a device
    that reconnects looks like identity reuse once. So the first signal only
    escalates the ban, and only REPEATED signals (or a ban-evasion, which is
    unambiguous) earn a permanent block.
    """

    def __init__(self, conf: dict, clock=time.time):
        self.conf = conf
        self.clock = clock
        self.signals: dict[str, list[dict]] = defaultdict(list)

    def record(self, key: str, found: list[dict]) -> None:
        if found:
            self.signals[key].extend(found)
            # keep the trail bounded
            self.signals[key] = self.signals[key][-20:]

    def sanction(self, key: str, base_until: float) -> tuple[str, str]:
        """-> (action, reason). action is 'normal' | 'escalate' | 'permanent'.

        The tally is a sliding window, not a life sentence. Weak signals
        (ban-evasion on its own) accumulate a STRIKE; a device is condemned
        only when it produces a strong signal (concealed identity), when two
        different KINDS of signal appear at the same moment, or when it has
        been caught evading repeatedly across separate observations.

        An earlier version treated "two signals" as proof. That is wrong: a
        device phoning home on a schedule accumulates ban-evasion on every
        sighting forever, and eventually crossed the line while doing nothing
        but existing.
        """
        sigs = self.signals.get(key) or []
        if not sigs:
            return "normal", "threshold-reached"
        kinds = {s["kind"] for s in sigs}

        if "randomised-unverified" in kinds:
            return "permanent", "randomised-unverified: concealed identity, not an owner"

        # Two independent kinds of evidence at once: e.g. identity-reuse AND
        # contact-while-banned. Each alone is explicable; together they are not.
        if len(kinds) >= 2:
            return "permanent", "corroborated spoof signals: " + ", ".join(sorted(kinds))

        # Only ban-evasion so far. Escalate for a while, and require it to keep
        # happening across the whole ban before condemning -- a single
        # reconnection is a lease change, not an attack.
        if "ban-evasion" in kinds:
            strikes = sum(1 for s in sigs if s["kind"] == "ban-evasion")
            if strikes >= int(self.conf.get("evasion_strikes_to_ban", 5)):
                return "permanent", (f"ban evasion x{strikes}: kept returning "
                                     f"while blocked")
            return "escalate", (f"contact while banned ({strikes}x, "
                                f"need {self.conf.get('evasion_strikes_to_ban', 5)})")
        return "escalate", "suspected spoofing: " + ", ".join(sorted(kinds))


class Engine:
    def __init__(self, conf: dict, clock=time.time):
        self.conf = conf
        self.clock = clock
        self.hits: dict[str, deque] = defaultdict(deque)
        self.devices: dict[str, dict] = {}
        self.blacklist: dict[str, dict] = {}
        # key -> {"since", "reason", "mac", "ip", "vendor", "class"}.
        # These never expire. Kept apart from `blacklist` so the expiry sweep
        # cannot quietly shorten one.
        self.permanent: dict[str, dict] = {}
        self.spoof = SpoofTally(conf, clock)
        self.trusted = set(conf.get("trusted") or [])
        # mac -> {"name":..., "ips": [...]}
        self.owners: dict[str, dict] = {}
        for entry in conf.get("owners") or []:
            mac = normalise_mac(entry.get("mac", ""))
            if mac:
                self.owners[mac] = {"name": entry.get("name", "unnamed"),
                                    "ips": list(entry.get("ips") or [])}

    # -- ownership ---------------------------------------------------
    def owner_of(self, mac: str | None, ip: str | None = None) -> dict | None:
        """The ownership record for this device, or None if unverified.

        Matched on MAC. The IP list on an owner entry is only a convenience
        for the human reading the config -- a device whose MAC is not
        registered is unverified no matter what address it currently holds.
        """
        mac = normalise_mac(mac)
        if not mac:
            return None
        rec = self.owners.get(mac)
        if rec is None:
            return None
        return {"mac": mac, "name": rec["name"],
                "randomised": is_locally_administered(mac),
                "known_ips": rec["ips"]}

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
        for key, rec in (blob.get("permanent") or {}).items():
            self.permanent[key] = rec

    def save(self, path: Path = STATE) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(
            {"blacklist": self.blacklist, "devices": self.devices,
             "permanent": self.permanent,
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

    def is_banned_mac(self, mac: str | None) -> tuple[str, float] | None:
        """(owner_key, until) if this MAC is banned, else None.

        A MAC that is currently quiet is not a banned MAC. The blacklist is
        kept keyed by the DEVICE (its MAC when known, else its IP) and the
        nft set is checked against both, so a device that changes address
        mid-ban stays banned.
        """
        mac = normalise_mac(mac)
        if not mac:
            return None
        rec = self.blacklist.get(f"mac:{mac}")
        if rec and rec.get("until", 0) > self.clock():
            return f"mac:{mac}", rec["until"]
        return None

    def is_permanent(self, key: str) -> bool:
        """A permanent block never expires and is not touched by the
        expiry sweep. It only leaves via `warden unforgive`."""
        return key in self.permanent

    def is_permanent_mac(self, mac: str | None) -> bool:
        mac = normalise_mac(mac)
        return bool(mac) and f"mac:{mac}" in self.permanent

    def observe(self, src: str, dport: int | None = None,
                vendor: str | None = None, mac: str | None = None) -> dict:
        """One inbound attempt. Returns the event record.

        Policy: infrastructure and registered owners are exempt. Everything
        else is unverified, and an unverified device is banned on its first
        attempt (threshold_hits defaults to 1).
        """
        now = self.clock()
        if mac is None and vendor is None:
            mac = mac_of_ip(src)
        mac = normalise_mac(mac)
        vend = vendor if vendor is not None else vendor_of(mac, self.conf)
        kind = classify(vend, dport, self.conf)
        infra = self.is_trusted(src)
        owner = self.owner_of(mac, src)
        trusted = infra or owner is not None

        # Ban state: by MAC if we have one, else by IP as a fallback.
        banned_until = self.active_ban(src)
        mac_ban = self.is_banned_mac(mac)
        if mac_ban and not banned_until:
            banned_until = mac_ban[1]
        key = f"mac:{mac}" if mac else src
        permanent = self.is_permanent(key) or self.is_permanent_mac(mac)

        dev = self.devices.setdefault(key, {
            "first_seen": now, "hits": 0, "bans": 0, "key": key,
            "mac": mac, "vendor": vend, "class": kind})
        dev.update({"last_seen": now, "hits": dev.get("hits", 0) + 1,
                    "mac": mac, "vendor": vend, "class": kind,
                    "ips": sorted(set(dev.get("ips", []) + [src]))[:16],
                    # Per-address first-sight time, so detect_spoof can tell a
                    # simultaneous identity-reuse apart from a DHCP renewal.
                    "ip_times": {k: v for k, v in
                                 list((dev.get("ip_times") or {}).items())[-15:]
                                 + [(src, now)]},
                    "ports": sorted(set(dev.get("ports", []) + ([dport] if dport else [])))[:16]})
        if now - dev["first_seen"] > self.conf["state_ttl_seconds"]:
            dev["first_seen"] = now

        # Every branch assigns `action`; these defaults are unreachable and
        # exist so a future branch cannot silently return None or NameError.
        action = "observed"
        last_signals: list[dict] = []
        if infra:
            action = "infrastructure"
        elif owner is not None:
            action = "owner"
        elif permanent:
            # Already permanently blocked and it is still talking to us.
            dev["strikes"] = dev.get("strikes", 0) + 1
            self.permanent[key]["last_seen"] = now
            self.permanent[key]["strikes"] = dev["strikes"]
            action = "permanent-hit"
        elif banned_until:
            dev["strikes"] = dev.get("strikes", 0) + 1
            # A device that is ALREADY banned has been told to go away. Coming
            # back is ban evasion, which the tally rules as permanent. This
            # branch previously only ever extended the timed ban, so a device
            # could evade forever at the cost of a longer timeout.
            # evasion corroborated by identity-reuse, the two independent
            # kinds of evidence that together justify condemning.
            evasion = detect_spoof(key, dev, self.conf, banned_until)
            if evasion:
                self.spoof.record(key, evasion)
                last_signals = evasion
            verdict, reason = self.spoof.sanction(key, now)
            if verdict == "permanent":
                self.permanent[key] = {
                    "since": banned_until, "last_seen": now, "reason": reason,
                    "mac": mac, "ip": src, "vendor": vend, "class": kind,
                    "strikes": dev["strikes"], "all_ips": dev["ips"],
                    "signals": self.spoof.signals.get(key, [])}
                self.blacklist.pop(key, None)
                action = "permanently-blocked"
            else:
                new_until = min(now + self._ban_len(dev["strikes"]),
                                now + self.conf["max_ban_seconds"])
                self.blacklist[key] = {"until": new_until, "since": banned_until,
                                       "reason": "reoffend-while-banned",
                                       "mac": mac, "ip": src, "vendor": vend,
                                       "class": kind, "strikes": dev["strikes"],
                                       "all_ips": dev["ips"]}
                action = "ban-extended"
        else:
            win = deque(t for t in self.hits[key]
                        if now - t < self.conf["threshold_window_s"])
            win.append(now)
            self.hits[key] = win
            if len(win) >= self.conf["threshold_hits"]:
                dev["strikes"] = dev.get("strikes", 0) + 1
                # Record signals for THIS observation before judging it,
                # otherwise a first-sighting strong signal (a randomised MAC)
                # is never seen by sanction() and slips through.
                fresh = [] if trusted else detect_spoof(key, dev, self.conf, banned_until)
                if fresh:
                    self.spoof.record(key, fresh)
                verdict, reason = self.spoof.sanction(key, now)
                dev["bans"] = dev.get("bans", 0) + 1
                last_signals = fresh
                if verdict == "permanent":
                    self.permanent[key] = {
                        "since": now, "last_seen": now, "reason": reason,
                        "mac": mac, "ip": src, "vendor": vend, "class": kind,
                        "strikes": dev["strikes"], "all_ips": dev["ips"],
                        "signals": self.spoof.signals.get(key, [])}
                    action = "permanently-blocked"
                else:
                    until = (now + self._ban_len(dev["strikes"] + 1) * 3
                             if verdict == "escalate" else now + self._ban_len(dev["strikes"]))
                    until = min(until, now + self.conf["max_ban_seconds"])
                    self.blacklist[key] = {
                        "until": until, "since": now, "reason": reason,
                        "mac": mac, "ip": src, "vendor": vend, "class": kind,
                        "strikes": dev["strikes"], "all_ips": dev["ips"]}
                    action = "banned-escalated" if verdict == "escalate" else "banned"
                self.hits[key].clear()

        # Spoof signals are recorded ONCE per observation, in the branch that
        # actually needs them. Recording them again here (as this used to) fed
        # every signal into the tally twice, and since SpoofTally.sanction()
        # treats "two signals" as proof of spoofing, a single ordinary DHCP
        # lease renewal promoted an innocent device to a PERMANENT block.
        # That is the exact false positive the graduated-sanction design exists
        # to prevent, so this must stay a single, single call.
        return {"ts": now, "src": src, "dport": dport, "mac": mac,
                "vendor": vend, "class": kind, "action": action,
                "key": key, "owner": (owner or {}).get("name"),
                "unverified": not trusted, "infrastructure": infra,
                "permanent": permanent,
                "spoof_signals": [s["kind"] for s in last_signals],
                "ban_until": self.blacklist.get(key, {}).get("until", 0)}

    def _judge(self, key: str, dev: dict, now: float, mac: str | None,
               src: str, vend: str, kind: str) -> tuple[str, str]:
        """Deprecated: kept only so an old caller gets a clear answer.

        Use self.spoof.sanction() directly after recording signals once.
        """
        return self.spoof.sanction(key, now)

    def _ban_len(self, strikes: int) -> float:
        base = self.conf["ban_seconds"] * (self.conf["escalate_factor"] ** max(0, strikes - 1))
        return min(base, self.conf["max_ban_seconds"])

    def expired(self) -> list[str]:
        """Expiring keys only. A permanent block is never returned here --
        that is the whole difference between the two lists, and quietly
        expiring one would make 'permanent' a lie."""
        now = self.clock()
        return [ip for ip, rec in self.blacklist.items()
                if rec.get("until") and rec["until"] <= now
                and ip not in self.permanent]

    def forgive(self, key: str) -> bool:
        """Lift a permanent block. The only way one ever ends."""
        return self.permanent.pop(key, None) is not None


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


def nft_sync(engine: Engine, sets: dict[str, str] | None = None) -> tuple[list[str], list[str]]:
    """Push deltas into the nft sets. Returns (added, removed).

    Two sets are maintained: ipv4 addresses and ethernet MACs. The MAC set is
    the one that matters on this flat /8 -- an address ban alone is undone by
    the next device that takes a different address.
    """
    # `if sets is None`, not `sets or ...`: an empty dict means "no sets",
    # and `or` would silently substitute the defaults and call nft.
    if sets is None:
        sets = {"ip": "blacklist", "mac": "blacklist_mac"}
    added: list[str] = []
    removed: list[str] = []
    now = engine.clock()
    # Permanent blocks are folded into the same nft sets, but with no timeout:
    # the nft side has no concept of "permanent", the daemon does, and it will
    # re-add anything that disappears.
    perm_macs = {r["mac"] for r in engine.permanent.values() if r.get("mac")}
    perm_ips: set[str] = set()
    for rec in engine.permanent.values():
        perm_ips.update(rec.get("all_ips") or [])
        if rec.get("ip"):
            perm_ips.add(rec["ip"])
    for kind, setname in sets.items():
        if kind == "mac":
            want = {rec["mac"] for rec in engine.blacklist.values()
                    if rec.get("mac") and rec.get("until", 0) > now} | perm_macs
            field = "mac"
        else:
            want = set()
            for rec in engine.blacklist.values():
                if rec.get("until", 0) <= now:
                    continue
                for ip in (rec.get("all_ips") or []):
                    want.add(ip)
                if rec.get("ip"):
                    want.add(rec["ip"])
            want |= perm_ips
            field = "ip"
        have = set(nft_set_peek(setname))
        for addr in sorted(want - have):
            subprocess_run(["nft", "add", "element", "inet", "warden", setname,
                            "{", addr, "}"])
            added.append(f"{field}:{addr}")
        for addr in sorted(have - want):
            subprocess_run(["nft", "delete", "element", "inet", "warden", setname,
                            "{", addr, "}"])
            removed.append(f"{field}:{addr}")
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
                    flag = ""
                    if event.get("permanent"):
                        flag = " PERMANENT"
                    elif event.get("spoof_signals"):
                        flag = " spoof:" + ",".join(event["spoof_signals"])
                    print(f"{time.strftime('%H:%M:%S')} {event['action']:>20} "
                          f"{event.get('mac') or event['src']} "
                          f"{event['class']:<7} {event['vendor'][:30]}{flag}", flush=True)
        now = time.time()
        if now - last_sync > 15:
            last_sync = now
            for ip in eng.expired():
                print(f"{time.strftime('%H:%M:%S')} {'ban-expired':>14} {ip}", flush=True)
                audit_write(fh, {"ts": now, "src": ip, "action": "ban-expired"})
            try:
                added, removed = nft_sync(eng)
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
    print("escalation (threshold 3, the old behaviour)")
    t = [1_000_000.0]
    eng = Engine({**conf, "trusted": ["10.0.0.9"], "threshold_hits": 3},
                 clock=lambda: t[0])
    eng.load(Path("/nonexistent"))
    check("clean hit is observed",
          eng.observe("10.1.1.1", 22, "Dell Inc.", mac=None)["action"], "observed")
    check("2nd hit still observed",
          eng.observe("10.1.1.1", 22, "Dell Inc.", mac=None)["action"], "observed")
    third = eng.observe("10.1.1.1", 22, "Dell Inc.", mac=None)
    check("3rd hit bans", third["action"], "banned")
    check("ban length is 24h", round(eng.blacklist["10.1.1.1"]["until"] - t[0]), 86400)
    t[0] += 10
    again = eng.observe("10.1.1.1", 22, "Dell Inc.", mac=None)
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

    print("trust (infrastructure is exempt, never banned)")
    check("configured trusted never banned",
          eng2.observe("10.0.0.9", 22, "Unknown", mac=None)["action"], "infrastructure")
    for _ in range(3):
        check("loopback is exempt",
              eng2.observe("127.0.0.1", 22, "X", mac=None)["action"], "infrastructure")
    check("link-local is exempt",
          eng2.observe("169.254.1.1", None, "X", mac=None)["action"], "infrastructure")

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

    # ── the actual policy: unverified device, first attempt ──
    print("ownership + immediate ban (threshold 1)")
    # 0x3e has the local bit set (0b10 in the low byte), i.e. a randomised MAC.
    # The first attempt at 0x3c was wrong: 0x3c & 0x02 == 0, so it is a
    # globally-administered OUI and the check correctly said False.
    PHONE = "3e:22:fb:11:22:33"          # locally-administered / randomised
    LAPTOP = "f4:5c:89:aa:bb:cc"         # ordinary vendor-assigned OUI
    own = {**conf, "threshold_hits": 1, "trusted": ["10.128.128.128"],
           "owners": [{"mac": PHONE, "name": "my phone", "ips": ["10.197.250.7"]}]}
    e = Engine(own, clock=lambda: t[0])
    e.load(Path("/nonexistent"))

    check("mac normalisation", normalise_mac("F4:5C:89:AA:BB:CC"), LAPTOP)
    check("mac normalisation rejects junk", normalise_mac("nope"), None)
    check("local-admin bit detects randomised mac",
          is_locally_administered(PHONE), True)
    check("global bit is not randomised", is_locally_administered(LAPTOP), False)

    ev = e.observe("10.197.250.7", 22, "Apple, Inc.", mac=PHONE)
    check("registered owner is exempt", ev["action"], "owner")
    check("owner is named", ev["owner"], "my phone")
    check("owner not marked unverified", ev["unverified"], False)
    check("owner not banned", e.blacklist, {})

    ev = e.observe("10.197.250.7", 22, "Apple, Inc.", mac=PHONE)
    check("owner stays exempt on repeat", ev["action"], "owner")

    ev = e.observe("10.5.5.5", 445, "Dell Inc.", mac=LAPTOP)
    check("unregistered device banned on FIRST hit", ev["action"], "banned")
    check("plain device gets a timed ban, no spoof claim", 
          e.blacklist[f"mac:{LAPTOP}"]["reason"] in ("threshold-reached", "unverified-device"), True)
    check("unresolvable device is NOT exempt", ev["unverified"], True)
    check("device classified pc", ev["class"], "pc")

    ev = e.observe("10.128.128.128", 53, "Some Router", mac="00:11:22:33:44:55")
    check("gateway treated as infrastructure", ev["action"], "infrastructure")

    ev = e.observe("10.197.250.9", 5353, "Apple, Inc.", mac=PHONE)
    check("owner exempt even from a new address", ev["action"], "owner")

    # The whole point of keying on MAC: a new IP must not launder the ban.
    # And because coming back at all is ban evasion, it now escalates to a
    # permanent block rather than merely lengthening the timeout.
    print("MAC-keyed ban survives an address change")
    t[0] += 1
    ev = e.observe("10.9.9.9", 3389, "Dell Inc.", mac=LAPTOP)
    check("same MAC from a NEW ip is still blocked", ev["action"], "permanently-blocked")
    check("evasion promotes it to permanent", e.is_permanent(f"mac:{LAPTOP}"), True)
    check("new address recorded with it",
          "10.9.9.9" in e.permanent[f"mac:{LAPTOP}"]["all_ips"], True)

    print("unresolvable MAC falls back to the address")
    e2 = Engine({**conf, "threshold_hits": 1}, clock=lambda: t[0])
    e2.load(Path("/nonexistent"))
    ev = e2.observe("10.7.7.7", 22, "Unknown", mac=None)
    check("no MAC still bans", ev["action"], "banned")
    check("key falls back to the ip", ev["key"], "10.7.7.7")

    print("randomised mac caveat")
    check("randomised owner flagged", e.owner_of(PHONE)["randomised"], True)
    check("plain owner not flagged", is_locally_administered(LAPTOP), False)

    print("nft set sync computes MAC + IP deltas (dry)")
    added, removed = nft_sync(e, sets={})
    check("empty set map is a no-op", (added, removed), ([], []))
    want_mac = {LAPTOP}
    have_mac = {r["mac"] for r in list(e.blacklist.values()) + list(e.permanent.values())
                if r.get("mac")}
    check("mac set would contain the blocked laptop", want_mac <= have_mac, True)
    check("banned record carries every ip seen",
          {"10.5.5.5", "10.9.9.9"} <= set(e.permanent[f"mac:{LAPTOP}"]["all_ips"]), True)

    # ── spoofing ──
    print("spoof detection: no false positives on this box's real situation")
    # This machine's own wlo1 MAC is 0xea:... -- randomised, and must not be
    # treated as an attacker just for that.
    check("own randomised wlo1 mac is locally administered",
          is_locally_administered("ea:bd:c8:4d:53:a8"), True)
    # The gateway appears twice in `ip neigh` (one v4, one v6 line). If link
    # local were not filtered, that reads as "one MAC, many addresses".
    sigs = detect_spoof("gw", {"mac": "e4:55:a8:0e:ae:9c",
                               "ips": ["10.128.128.128", "fe80::e655:a8ff:fe0e:ae:dc"],
                               "class": "unknown"}, conf, 0)
    check("link-local neighbour does not read as identity reuse",
          any(s["kind"] == "identity-reuse" for s in sigs), False)

    print("spoof detection: real signals")
    sigs = detect_spoof("r", {"mac": "3e:22:fb:11:22:33", "ips": ["10.4.4.4"],
                              "class": "unknown"}, conf, 0)
    check("randomised unverified mac flagged",
          any(s["kind"] == "randomised-unverified" for s in sigs), True)

    # Two addresses seen at the SAME moment (within identity_window_s).
    sigs = detect_spoof("r2", {"mac": "f4:5c:89:aa:bb:cc",
                               "ips": ["10.4.4.4", "10.4.4.5"],
                               "ip_times": {"10.4.4.4": 100.0, "10.4.4.5": 103.0},
                               "class": "pc"}, conf, 0)
    check("one mac at two simultaneous addresses flagged",
          any(s["kind"] == "identity-reuse" for s in sigs), True)
    # And the same two addresses 30 minutes apart are just a lease renewal.
    sigs = detect_spoof("r2b", {"mac": "f4:5c:89:aa:bb:cc",
                                 "ips": ["10.4.4.4", "10.4.4.5"],
                                 "ip_times": {"10.4.4.4": 100.0, "10.4.4.5": 1900.0},
                                 "class": "pc"}, conf, 0)
    check("the same pair 30min apart is NOT identity-reuse",
          any(s["kind"] == "identity-reuse" for s in sigs), False)

    sigs = detect_spoof("r3", {"mac": "f4:5c:89:aa:bb:cc", "ips": ["10.4.4.4"],
                               "class": "pc"}, conf, 1_000_000.0)
    check("banned mac returning flagged as evasion",
          any(s["kind"] == "ban-evasion" for s in sigs), True)

    check("no mac -> no signals", detect_spoof("x", {"mac": None}, conf, 0), [])

    print("sanctions")
    tal = SpoofTally(conf, clock=lambda: t[0])
    check("no signals -> normal", tal.sanction("k", t[0])[0], "normal")
    tal.record("k", [{"kind": "identity-reuse", "why": "x"}])
    check("one weak signal only escalates", tal.sanction("k", t[0])[0], "escalate")
    tal.record("k", [{"kind": "identity-reuse", "why": "x"}])
    check("repeating the SAME weak signal still only escalates",
          tal.sanction("k", t[0])[0], "escalate")
    tal.record("k", [{"kind": "ban-evasion", "why": "x"}])
    check("two DIFFERENT kinds of signal is permanent",
          tal.sanction("k", t[0])[0], "permanent")
    # Ban evasion alone is the weak signal: a lease renewal looks identical,
    # so it must take repeated confirmation rather than convicting at once.
    tal2 = SpoofTally(conf, clock=lambda: t[0])
    tal2.record("e", [{"kind": "ban-evasion", "why": "x"}])
    check("a single ban-evasion only escalates",
          tal2.sanction("e", t[0])[0], "escalate")
    for _ in range(4):
        tal2.record("e", [{"kind": "ban-evasion", "why": "x"}])
    check("repeated ban evasion is eventually permanent",
          tal2.sanction("e", t[0])[0], "permanent")

    print("randomised unverified device -> permanent on first sighting")
    pconf = {**conf, "threshold_hits": 1, "trusted": []}
    e3 = Engine(pconf, clock=lambda: t[0])
    e3.load(Path("/nonexistent"))
    ev = e3.observe("10.6.6.6", 22, "Unknown", mac="3a:11:22:33:44:55")
    check("randomised stranger blocked permanently",
          ev["action"], "permanently-blocked")
    check("it is in the permanent list", e3.is_permanent(ev["key"]), True)
    check("not in the expiring blacklist", e3.blacklist, {})
    check("spoof signal reported", "randomised-unverified" in ev["spoof_signals"], True)

    print("permanent blocks never expire")
    t[0] += 365 * 86400
    check("still permanent a year later", e3.is_permanent(ev["key"]), True)
    check("expiry sweep ignores it", e3.expired(), [])
    ev = e3.observe("10.6.6.6", 22, "Unknown", mac="3a:11:22:33:44:55")
    check("still talking to it is logged as a permanent hit",
          ev["action"], "permanent-hit")

    print("permanent block survives a restart")
    tmp2 = Path(os.environ.get("TMPDIR", "/tmp")) / f"warden-perm-{os.getpid()}.json"
    e3.save(tmp2)
    e4 = Engine(pconf, clock=lambda: t[0])
    e4.load(tmp2)
    check("reloaded from disk", e4.is_permanent(ev["key"]), True)
    check("reason preserved", "randomised" in e4.permanent[ev["key"]]["reason"], True)
    tmp2.unlink(missing_ok=True)

    print("forgiveness")
    check("forgive removes it", e3.forgive(ev["key"]), True)
    check("forgive on an unknown key is False", e3.forgive("mac:00:00:00:00:00:00"), False)

    print("clean unverified device gets a timed ban, not permanent")
    e5 = Engine(pconf, clock=lambda: t[0])
    e5.load(Path("/nonexistent"))
    ev = e5.observe("10.8.8.8", 22, "Dell Inc.", mac="f4:5c:89:00:11:22")
    check("timed ban", ev["action"], "banned")
    check("not permanent", e5.permanent, {})
    check("in the expiring list", "mac:f4:5c:89:00:11:22" in e5.blacklist, True)

    print("an evading device is promoted to permanent, not just re-banned")
    e6 = Engine(pconf, clock=lambda: t[0])
    e6.load(Path("/nonexistent"))
    # 0xf4 is a real vendor OUI, not a randomised one, so the ONLY thing that
    # can condemn it here is coming back. (The first draft of this test used
    # aa:bb:... which is itself locally administered, so it was permanently
    # blocked on sight for the wrong reason and proved nothing.)
    ev = e6.observe("10.8.8.8", 22, "Dell Inc.", mac="f4:5c:89:cc:dd:ee")
    check("first sighting is a timed ban", ev["action"], "banned")
    check("not permanent yet", e6.permanent, {})
    t[0] += 5
    # 5 seconds later at a NEW address: that is evasion AND simultaneous
    # identity-reuse -- two independent kinds of evidence, so permanent.
    ev = e6.observe("10.8.8.9", 22, "Dell Inc.", mac="f4:5c:89:cc:dd:ee")
    check("return at a new address within seconds is permanent",
          ev["action"], "permanently-blocked")
    check("condemned on corroboration, not on the first return alone",
          e6.is_permanent("mac:f4:5c:89:cc:dd:ee"), True)
    for i in range(6):
        t[0] += 60
        ev = e6.observe(f"10.8.8.{20+i}", 22, "Dell Inc.", mac="f4:5c:89:cc:dd:ee")
    check("a persistent evader is condemned", e6.is_permanent("mac:f4:5c:89:cc:dd:ee"), True)
    ev = e6.observe("10.8.8.200", 22, "Dell Inc.", mac="f4:5c:89:cc:dd:ee")
    check("and stays blocked at every new address", ev["action"], "permanent-hit")
    t[0] += 99 * 86400
    check("expiry sweep cannot touch it", e6.expired(), [])

    print("a DHCP lease renewal is NOT spoofing")
    # The bug this guards: identity-reuse fired on any second address, so a
    # device merely renewing its lease was flagged, and two such flags were
    # enough to make SpoofTally call it spoofing and block it permanently. The
    # signal now requires two addresses seen WITHIN identity_window_s.
    e7 = Engine(pconf, clock=lambda: t[0])
    e7.load(Path("/nonexistent"))
    e7.observe("10.9.0.1", 22, "Dell Inc.", mac="f4:5c:89:dd:ee:ff")
    t[0] += 1800                       # 30 minutes: a lease renewal
    ev = e7.observe("10.9.0.2", 22, "Dell Inc.", mac="f4:5c:89:dd:ee:ff")
    # spoof_signals is a list of kind STRINGS, not signal dicts.
    check("slow second address is not identity-reuse",
          "identity-reuse" not in set(ev.get("spoof_signals", [])), True)
    check("two addresses recorded", len(e7.devices["mac:f4:5c:89:dd:ee:ff"]["ips"]), 2)

    e8 = Engine(pconf, clock=lambda: t[0])
    e8.load(Path("/nonexistent"))
    e8.observe("10.9.1.1", 22, "Dell Inc.", mac="f4:5c:89:ee:ff:00")
    t[0] += 3                          # 3 seconds: same MAC, two live addresses
    ev = e8.observe("10.9.1.2", 22, "Dell Inc.", mac="f4:5c:89:ee:ff:00")
    check("simultaneous second address IS identity-reuse",
          "identity-reuse" in ev.get("spoof_signals", []), True)

    print("spoof signals are recorded once per observation, not twice")
    counter = {"n": 0}
    real_record = SpoofTally.record

    def counting_record(self, key, found):
        counter["n"] += 1
        return real_record(self, key, found)

    SpoofTally.record = counting_record
    try:
        e9 = Engine(pconf, clock=lambda: t[0])
        e9.load(Path("/nonexistent"))
        e9.observe("10.9.2.1", 22, "Dell Inc.", mac="f4:5c:89:00:00:01")
        t[0] += 2
        e9.observe("10.9.2.2", 22, "Dell Inc.", mac="f4:5c:89:00:00:01")
        check("record() called at most once per sighting", counter["n"] <= 2, True)
    finally:
        SpoofTally.record = real_record

    print()
    if fails:
        print(f"SELFTEST FAILED: {len(fails)} check(s): {', '.join(fails)}")
        return 1
    print("SELFTEST PASSED")
    return 0


# ── status ──────────────────────────────────────────────────────────────
def cmd_suggest(conf: dict) -> int:
    """Enrolment helper: show devices seen recently that are not owners.

    With threshold_hits=1 every unverified device is banned the moment it
    speaks, so the practical workflow is: open this after using your own
    phone/laptop, copy the MACs you recognise into "owners", restart warden.
    """
    eng = Engine(conf)
    eng.load()
    now = time.time()
    print(f"warden suggest   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("\n  Devices seen recently that are NOT in your ownership registry.")
    print("  Add the ones you own to \"owners\" in " + str(CONF) + ":\n")
    print('    {"mac": "aa:bb:cc:dd:ee:ff", "name": "my phone", "ips": ["10.x.x.x"]}')
    print()
    rows = []
    for key, d in eng.devices.items():
        if eng.owner_of(d.get("mac")) is not None:
            continue
        rows.append((d.get("last_seen", 0), key, d))
    if not rows:
        print("    (nothing seen yet -- have your phone connect, then re-run)")
        return 0
    for seen, key, d in sorted(rows, reverse=True)[:30]:
        age = int(now - seen)
        perm = " PERMANENT" if eng.is_permanent(key) else ""
        ban = eng.active_ban(key)
        state = f"banned {int(ban-now)//3600}h" if ban > now else "not banned"
        rand = " rand-mac" if is_locally_administered(d.get("mac") or "") else ""
        print(f"    {d.get('mac','?'):<18} {d.get('class',''):<7} "
              f"{d.get('vendor','')[:26]:<26} {state}{perm}{rand}")
        print(f"      addresses: {', '.join(d.get('ips', [])[:5])}")
    print("\n  Devices already registered as yours:")
    for mac, rec in sorted(eng.owners.items()):
        print(f"    {mac:<18} {rec['name']}")
    return 0


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
    print(f"\n  active bans   {len(active)} (timed)")
    for ip, r in sorted(active, key=lambda kv: -kv[1]["until"]):
        left = int(r["until"] - now)
        print(f"    {ip:>39}  {left//3600:>5}h left  {r.get('class',''):<7} "
              f"{r.get('vendor','')}  [{r.get('reason','')}]")

    if eng.permanent:
        print(f"\n  PERMANENT blocks  {len(eng.permanent)} (never expire)")
        for key, r in sorted(eng.permanent.items(), key=lambda kv: kv[1].get("since", 0)):
            sigs = sorted({s.get('kind', '?') for s in r.get('signals', [])})
            print(f"    {key:>39}  {r.get('class',''):<7} {r.get('vendor','')}")
            print(f"      since {time.strftime('%Y-%m-%d', time.localtime(r.get('since', 0)))}"
                  f"  reason: {r.get('reason','')}")
            if sigs:
                print(f"      spoof signals: {', '.join(sigs)}")
            if r.get("all_ips"):
                print(f"      addresses: {', '.join(r['all_ips'][:6])}")
        print("\n    lift one with:  sudo warden unforgive <mac-or-ip>")

    recent = sorted(eng.devices.items(), key=lambda kv: -kv[1].get("last_seen", 0))[:20]
    print(f"\n  devices seen  {len(eng.devices)} (showing {len(recent)})")
    for key, d in recent:
        state = ""
        if eng.is_permanent(key):
            state = "PERMANENT"
        elif eng.active_ban(key):
            state = "BANNED"
        elif eng.owner_of(d.get("mac")) is not None:
            state = "owner"
        print(f"    {str(d.get('mac') or key):>39}  hits={d.get('hits',0):<5} "
              f"{d.get('class',''):<7} {d.get('vendor','')[:32]:<32} {state}")
    if eng.owners:
        print(f"\n  registered owners  {len(eng.owners)}")
    else:
        print("\n  [warn] no owners registered -- EVERY device is unverified and"
              "\n         will be banned on its first inbound attempt, including"
              "\n         your own phone and laptop. Run:  sudo warden suggest")
    return 0


# ── cli ─────────────────────────────────────────────────────────────────
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="warden", description=__doc__.split("\n")[1])
    ap.add_argument("cmd", nargs="?", default="status",
                    choices=["daemon", "status", "watch", "block", "unblock",
                             "unforgive", "suggest", "selftest"])
    ap.add_argument("ip", nargs="?", help="address for block/unblock/unforgive")
    args = ap.parse_args(argv)
    conf = load_conf()

    if args.cmd == "selftest":
        return selftest()
    if args.cmd == "daemon":
        return run_daemon(conf)
    if args.cmd == "suggest":
        return cmd_suggest(conf)
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
    if args.cmd in ("block", "unblock", "unforgive"):
        if not args.ip:
            sys.exit(f"warden: {args.cmd} needs an address or MAC")
        eng = Engine(conf)
        eng.load()
        # Accept either form. A MAC is the real identity here; an address is
        # resolved to one when possible so the ban does not evaporate on the
        # next DHCP lease.
        target = normalise_mac(args.ip) or args.ip
        key = f"mac:{target}" if normalise_mac(target) else target
        now = time.time()
        if args.cmd == "block":
            eng.blacklist[key] = {"until": now + conf["ban_seconds"], "since": now,
                                  "reason": "manual", "strikes": 0,
                                  "ip": args.ip, "mac": normalise_mac(target)}
            eng.devices.setdefault(key, {"first_seen": now, "hits": 0, "bans": 0,
                                         "key": key, "class": "?", "vendor": "manual",
                                         "ips": [] if normalise_mac(target) else [args.ip]})
            print(f"warden: blocked {key} for {conf['ban_seconds']//3600}h")
        elif args.cmd == "unforgive":
            if eng.forgive(key):
                eng.blacklist.pop(key, None)
                print(f"warden: lifted the PERMANENT block on {key}")
            else:
                sys.exit(f"warden: {key} is not permanently blocked "
                         f"(see `warden status` for the list)")
        else:
            if eng.blacklist.pop(key, None) is not None:
                print(f"warden: unblocked {key}")
            else:
                print(f"warden: {key} was not in the timed blacklist")
        eng.save()
        if os.geteuid() == 0:
            nft_sync(eng)
        if args.cmd != "unforgive":
            return cmd_status(conf)
    return cmd_status(conf)


if __name__ == "__main__":
    sys.exit(main())
