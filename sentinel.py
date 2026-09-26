#!/usr/bin/env python3
"""
sentinel.py — integrity anchor system.

Rebuilt 2026-09-26. The previous host ended its last cleanup with
"sentinel posture: 15/15 integrity anchors intact". Those anchors were not
recorded anywhere recoverable: no repo, no session log, and no deleted file in
any git history mentions a sentinel. This is a fresh implementation of the
same idea, with a fresh anchor set derived from THIS machine's verified state.

An anchor is a named fact about the system with an expected value, e.g.
"fail2ban is active" or "no world-writable file in /etc". Sentinel re-checks
every anchor, compares against the recorded baseline, and reports drift. It
never repairs: a watcher that silently fixes what it monitors is a watcher you
cannot trust. Repair is watchman's job, and only on explicit request.

Usage:
    sentinel.py baseline            capture current state as the baseline
    sentinel.py check [--json]      verify anchors against the baseline
    sentinel.py explain [NAME]      show what an anchor checks and why
    sentinel.py list                list anchors
    sentinel.py --selftest          verify the checker itself
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

STATE_DIR = Path(os.environ.get("SENTINEL_STATE", Path.home() / ".local/share/sentinel"))
BASELINE_FILE = STATE_DIR / "baseline.json"
RESULT_FILE = STATE_DIR / "last-result.json"
HISTORY_FILE = STATE_DIR / "history.jsonl"

SEV_ORDER = {"ok": 0, "unverified": 1, "warn": 2, "critical": 3}

# Anchors that cannot be evaluated without root. Reporting these as "ok"
# because they merely match their own unreadable baseline would be a lie: a
# critical control nobody can read is an UNVERIFIED control, not a passing
# one. They are surfaced distinctly and excluded from the intact count.
ROOT_ONLY = {"shadow-root-locked", "no-world-writable-etc", "sudo-requires-password"}


# ------------------------------------------------------------------ helpers

def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as exc:
        return 127, str(exc)


def _service_active(unit: str) -> str:
    rc, out = _run(["systemctl", "is-active", unit])
    return out.strip().splitlines()[0] if out.strip() else "unknown"


def _file_sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return "unreadable"
    return h.hexdigest()


# ------------------------------------------------------------------ anchors
#
# Each anchor returns a comparable string. `severity` is what it means when
# the anchor is NOT as expected — "warn" is drift worth knowing about,
# "critical" is a security regression.

def a_fail2ban_active() -> str:
    return _service_active("fail2ban")


def a_firewalld_active() -> str:
    return _service_active("firewalld")


def a_sshd_disabled() -> str:
    """sshd should stay off: it is not needed and is a standing login surface."""
    s = _service_active("sshd")
    socket_state = _service_active("sshd.socket")
    return "inactive" if (s == "inactive" and socket_state == "inactive") else f"sshd={s} socket={socket_state}"


def a_no_ssh_listener() -> str:
    rc, out = _run(["ss", "-ltnH"])
    hits = [l for l in out.splitlines() if re.search(r":22\b|:2222\b", l)]
    return "none" if not hits else ";".join(h.strip() for h in hits)


def a_sshd_permit_root() -> str:
    rc, out = _run(["sshd", "-T"])
    for line in out.splitlines():
        if line.startswith("permitrootlogin"):
            return line.split(None, 1)[1].strip()
    return "unknown"


def a_faillock_admin_group() -> str:
    """The single-admin policy: this must NOT be present until installed."""
    try:
        for line in Path("/etc/security/faillock.conf").read_text().splitlines():
            if line.strip().startswith("admin_group"):
                return line.split("=", 1)[1].strip()
    except OSError:
        return "unreadable"
    return "unset"


def a_faillock_unlock_time() -> str:
    try:
        for line in Path("/etc/security/faillock.conf").read_text().splitlines():
            if line.strip().startswith("unlock_time"):
                return line.split("=", 1)[1].strip()
    except OSError:
        return "unreadable"
    return "unset"


def a_shadow_root_locked() -> str:
    try:
        for line in Path("/etc/shadow").read_text().splitlines():
            if line.startswith("root:"):
                field = line.split(":")[1]
                return "locked" if field.startswith("!") or field in ("", "*") else "SET"
    except OSError:
        return "unreadable"
    return "no-root-line"


def a_sudo_requires_password() -> str:
    rc, out = _run(["grep", "-rhE", r"^[^#]*\bNOPASSWD\b", "/etc/sudoers", "/etc/sudoers.d/"])
    return "absent" if rc != 0 or not out.strip() else "NOPASSWD-PRESENT"


def a_no_world_writable_etc() -> str:
    bad = []
    for root, dirs, files in os.walk("/etc"):
        # Skip virtual/pseudo filesystems that live under /etc on some setups.
        dirs[:] = [d for d in dirs if not os.path.join(root, d).startswith(("/etc/ssl/private",))]
        for name in files + dirs:
            p = os.path.join(root, name)
            try:
                if os.path.islink(p):
                    continue
                st = os.stat(p)
                if st.st_mode & 0o002 and not name.endswith((".log", ".journal")):
                    bad.append(p)
            except OSError:
                continue
    return "none" if not bad else ";".join(sorted(bad)[:5])


def a_collector_localhost_only() -> str:
    """
    The lia-inbox collector must never be reachable off-box.

    Note this returns "not-listening" when the collector is simply stopped.
    That is a service outage, not an exposure, and watchman reports it as a
    warn via collector-healthy; only a genuinely non-loopback bind is critical.
    """
    rc, out = _run(["ss", "-ltnH"])
    listening = False
    for line in out.splitlines():
        if ":4124" in line:
            listening = True
            host = line.split()[3] if len(line.split()) > 3 else ""
            if not (host.startswith("127.0.0.1") or host.startswith("[::1]")):
                return f"EXPOSED:{host}"
            return "localhost-only"
    return "not-listening" if not listening else "unknown-bind"


def a_collector_token_perms() -> str:
    p = Path.home() / ".lia-cli/inbox/token"
    if not p.exists():
        return "absent"
    return oct(p.stat().st_mode & 0o777)


def a_collector_healthy() -> str:
    try:
        import urllib.request
        with urllib.request.urlopen("http://127.0.0.1:4124/health", timeout=5) as r:
            j = json.loads(r.read().decode())
            return "ok" if j.get("ok") else "unhealthy"
    except Exception as exc:
        return f"unreachable:{type(exc).__name__}"


def a_shield_kitty_active() -> str:
    rc, out = _run(["systemctl", "--user", "is-active", "shield-kitty-watch.service"])
    return out.strip() or "unknown"


def a_evidence_chain_intact() -> str:
    """The forensic chain must still verify; this is the tamper tripwire."""
    ev = Path.home() / ".local/share/shield-kitty/evidence/chain.jsonl"
    script = Path.home() / "Projects/shield-kitty-forensics/evidence.py"
    if not ev.exists() or not script.exists():
        return "unavailable"
    rc, out = _run([sys.executable, str(script), "verify"], timeout=90)
    if rc == 0:
        return "verified"
    for line in reversed(out.splitlines()):
        if "CHAIN BROKEN" in line or "TAMPER" in line.upper():
            return "CHAIN-BROKEN"
    return "verify-error"


def a_rootfs_headroom() -> str:
    rc, out = _run(["df", "-P", "/"])
    if rc != 0:
        return "unknown"
    pct = out.strip().splitlines()[-1].split()[4].rstrip("%")
    try:
        return "ok" if int(pct) < 85 else f"low:{pct}%"
    except ValueError:
        return "unknown"


ANCHORS = [
    ("fail2ban-active", a_fail2ban_active, "warn",
     "fail2ban is the brute-force brake. Inactive means no jail is banning."),
    ("firewalld-active", a_firewalld_active, "critical",
     "firewall off means every listening port is exposed to the network."),
    ("sshd-disabled", a_sshd_disabled, "warn",
     "sshd is not needed on this workstation; leaving it off removes a login surface."),
    ("no-ssh-listener", a_no_ssh_listener, "critical",
     "An open :22 contradicts 'sshd disabled' and means a remote login path exists."),
    ("sshd-permit-root", a_sshd_permit_root, "warn",
     "Records the effective sshd root-login policy. Informational while sshd is off."),
    ("faillock-admin-group", a_faillock_admin_group, "warn",
     "Single-admin policy. 'unset' means the primary user is NOT exempt yet "
     "(install-faillock-admin.sh has not been run)."),
    ("faillock-unlock-time", a_faillock_unlock_time, "warn",
     "Live lockout window. The hardened policy is 1800s; 30 is the stock default."),
    ("shadow-root-locked", a_shadow_root_locked, "critical",
     "A password on root defeats most of the hardening here."),
    ("sudo-requires-password", a_sudo_requires_password, "critical",
     "NOPASSWD anywhere in sudoers makes every other control advisory."),
    ("no-world-writable-etc", a_no_world_writable_etc, "critical",
     "World-writable files in /etc let any local user rewrite system config."),
    ("collector-localhost-only", a_collector_localhost_only, "critical",
     "The collector holds private chat captures and must not be exposed."),
    ("collector-token-perms", a_collector_token_perms, "warn",
     "The bearer token should be 0600."),
    ("collector-healthy", a_collector_healthy, "warn",
     "If the collector is down the Tampermonkey bridge discards every capture silently."),
    ("shield-kitty-active", a_shield_kitty_active, "warn",
     "The intrusion watcher not running means no breach notification."),
    ("evidence-chain-intact", a_evidence_chain_intact, "critical",
     "Forensic chain tamper tripwire. CHAIN-BROKEN means the evidence was edited."),
    ("rootfs-headroom", a_rootfs_headroom, "warn",
     "A full root breaks logging, journals and every service that writes to /var."),
]


# ------------------------------------------------------------------ core

def collect() -> dict:
    out = {}
    for name, fn, _sev, _desc in ANCHORS:
        try:
            out[name] = fn()
        except Exception as exc:
            out[name] = f"error:{type(exc).__name__}:{exc}"[:200]
    return out


def cmd_baseline(args) -> int:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    state = collect()
    BASELINE_FILE.write_text(json.dumps({
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "user": os.environ.get("USER", "?"),
        "values": state,
    }, indent=2))
    print(f"baseline captured: {len(state)} anchors -> {BASELINE_FILE}")
    for k, v in state.items():
        print(f"  {k:28} {v}")
    return 0


def cmd_check(args) -> int:
    if not BASELINE_FILE.exists():
        print("no baseline yet — run: sentinel.py baseline", file=sys.stderr)
        return 2
    base = json.loads(BASELINE_FILE.read_text())["values"]
    cur = collect()

    results, drift, unver = [], 0, 0
    for name, _fn, sev, desc in ANCHORS:
        expected = base.get(name)
        actual = cur.get(name)
        if expected == actual:
            if name in ROOT_ONLY and str(actual).startswith(("unreadable", "unknown", "error")):
                # Matches its own unreadable baseline, but proves nothing.
                status = "unverified"
                why = ("needs root to evaluate — run as root or with "
                       "CAP_SYS_ADMIN; currently unverifiable")
                unver += 1
            else:
                status, why = "ok", "matches baseline"
        else:
            status = sev
            why = f"expected {expected!r}, found {actual!r}"
            drift += 1
        results.append({"anchor": name, "status": status, "expected": expected,
                        "actual": actual, "detail": why, "severity_if_drifted": sev})

    verified = len(results) - unver
    payload = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "total": len(results),
        "verified": verified,
        "intact": sum(1 for r in results if r["status"] == "ok"),
        "unverified": unver,
        "drift": drift,
        "results": results,
    }
    RESULT_FILE.parent.mkdir(parents=True, exist_ok=True)
    RESULT_FILE.write_text(json.dumps(payload, indent=2))
    with HISTORY_FILE.open("a") as fh:
        fh.write(json.dumps({"t": payload["checked_at"], "intact": payload["intact"],
                             "unverified": unver, "drift": drift}) + "\n")

    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        for r in results:
            mark = {"ok": "  ok  ", "warn": " warn ", "critical": "CRIT  ",
                    "unverified": "UNVERF"}[r["status"]]
            print(f"[{mark}] {r['anchor']:28} {r['detail']}")
        print(f"\n{payload['intact']}/{verified} verified anchors intact, "
              f"{drift} drifted, {unver} unverified (need root)")

    # Unverified critical controls are a real gap, so they must not exit 0
    # quietly: return 1 for drift, 3 for "cannot verify", 0 only when clean.
    if any(r["status"] == "critical" for r in results) or drift:
        return 1
    if unver:
        return 3
    return 0


def cmd_explain(args) -> int:
    for name, _fn, sev, desc in ANCHORS:
        if args.name and args.name not in name:
            continue
        print(f"{name}  (severity if drifted: {sev})")
        print(f"    {desc}")
    return 0


def cmd_list(args) -> int:
    for name, _fn, sev, _d in ANCHORS:
        print(f"  {name:28} {sev}")
    print(f"\n{len(ANCHORS)} anchors")
    return 0


def cmd_selftest(args) -> int:
    """Verify the checker detects a planted drift, rather than always passing."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    backup = BASELINE_FILE.read_text() if BASELINE_FILE.exists() else None
    try:
        BASELINE_FILE.write_text(json.dumps({
            "captured_at": "test", "host": "t", "user": "t",
            "values": {n: "PLANTED" for n, _f, _s, _d in ANCHORS},
        }))
        payload = json.loads(subprocess.run(
            [sys.executable, __file__, "check", "--json"],
            capture_output=True, text=True).stdout)
        detected = payload["drift"]
        if detected != len(ANCHORS):
            print(f"FAIL: planted drift on all {len(ANCHORS)} anchors, detected {detected}")
            return 1
        print(f"ok: planted drift on all {len(ANCHORS)} anchors, all {detected} detected")

        # And a matching baseline must produce zero drift.
        real = collect()
        BASELINE_FILE.write_text(json.dumps(
            {"captured_at": "test", "host": "t", "user": "t", "values": real}))
        payload = json.loads(subprocess.run(
            [sys.executable, __file__, "check", "--json"],
            capture_output=True, text=True).stdout)
        if payload["drift"] != 0:
            print(f"FAIL: identical baseline reported {payload['drift']} drift")
            for r in payload["results"]:
                if r["status"] != "ok":
                    print(f"   {r['anchor']}: {r['detail']}")
            return 1
        print("ok: identical baseline reports 0 drift (no false positives)")
        return 0
    finally:
        if backup is not None:
            BASELINE_FILE.write_text(backup)
        elif BASELINE_FILE.exists():
            BASELINE_FILE.unlink()


def main() -> int:
    # --selftest is a top-level flag, not a subcommand: naming it as one makes
    # argparse treat it as a positional and demand a subcommand alongside it.
    if "--selftest" in sys.argv:
        return cmd_selftest(argparse.Namespace())
    ap = argparse.ArgumentParser(description="System integrity anchor checker")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("baseline", help="record current state as the baseline")
    p = sub.add_parser("check", help="verify anchors against the baseline")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("explain", help="describe anchors")
    p.add_argument("name", nargs="?")
    sub.add_parser("list", help="list anchors")
    args = ap.parse_args()
    return {
        "baseline": cmd_baseline, "check": cmd_check, "explain": cmd_explain,
        "list": cmd_list,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
