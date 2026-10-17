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
import tempfile
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
ROOT_ONLY = {"shadow-root-locked", "no-world-writable-etc",
             "sudo-requires-password", "no-empty-passwords"}

# A baseline records what was true when it was captured. Most anchors assert a
# property whose single recorded observation *is* the invariant, but some hold
# in more than one way, and comparing raw strings would then report a security
# regression that never happened.
#
# The collector is the case that bit us: it is stopped cleanly at every
# shutdown and takes a second or two to bind 4124 after login, because it
# starts through npm/tsx. Watchman's first check of a session lands inside that
# window and reads "not-listening". Scored against a "localhost-only"
# baseline that is a *critical* drift, so every boot produced a CRITICAL alert
# naming a service that was about to come up fine. Nine of them in five days.
#
# But "not-listening" is the absence of exposure, not exposure: with no
# listener there is nothing for a remote host to reach, so the loopback-only
# property holds a fortiori. Being down is availability, which collector-healthy
# already reports, and already reports correctly at warn. Only a genuinely
# non-loopback bind is a security regression and must stay critical.
#
# Each entry is (values that also satisfy the anchor, why that is true).
EQUIVALENT = {
    "collector-localhost-only": (
        {"not-listening"},
        "no listener means nothing is reachable off-box; availability is "
        "tracked separately, at warn, by collector-healthy",
    ),
}


# ------------------------------------------------------------------ helpers

def _run(cmd: list[str], timeout: int = 30, env: dict | None = None) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except Exception as exc:
        return 127, str(exc)


def _real_home() -> Path:
    """Return the real user's home directory, even when run as root via sudo."""
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            import pwd
            return Path(pwd.getpwnam(sudo_user).pw_dir)
    return Path.home()


def _systemctl_user(unit: str) -> str:
    """Run systemctl --user as the real user, even when run as root."""
    if os.geteuid() == 0:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user and sudo_user != "root":
            import pwd
            pw = pwd.getpwnam(sudo_user)
            uid = pw.pw_uid
            runtime_dir = f"/run/user/{uid}"
            bus = f"unix:path={runtime_dir}/bus"
            env = dict(os.environ)
            env["DBUS_SESSION_BUS_ADDRESS"] = bus
            env["XDG_RUNTIME_DIR"] = runtime_dir
            rc, out = _run(["setpriv", "--reuid", str(uid), "--regid", str(uid),
                             "--init-groups", "--", "systemctl", "--user", "is-active", unit],
                            env=env)
            return out.strip().splitlines()[0] if out.strip() else "unknown"
    rc, out = _run(["systemctl", "--user", "is-active", unit])
    return out.strip().splitlines()[0] if out.strip() else "unknown"


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


def _active_pam_lines(path: Path):
    """Yield the lines of a PAM stack that are actually in effect.

    A commented line is inert no matter what it names, so counting one as
    active is how a monitor ends up reporting a control that is already gone.
    A leading `-` (optional) still counts as active: it only means "do not fail
    if the module is missing", not "do not run".
    """
    try:
        text = path.read_text()
    except OSError:
        return
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith("#"):
            yield line


def a_pam_no_nullok() -> str:
    """nulllock: `nullok` is the single switch that lets an EMPTY password through.

    fail2ban and firewalld do not cover this. pam_unix's `nullok` argument makes
    an account whose shadow field is empty authenticate successfully with a
    blank password, on every stack that carries it. This replaces the faillock
    anchors, which asserted a lockout window that no longer exists: after
    faillock was removed from every stack there is no counter left, so nulllock
    is the whole of what remains on the authentication side.
    """
    hits = []
    for path in sorted(Path("/etc/pam.d").glob("*")):
        if not path.is_file():
            continue
        for line in _active_pam_lines(path):
            if re.search(r"\bnullok\b", line):
                hits.append(f"{path.name}:{line.strip()}")
    return "none" if not hits else ";".join(hits[:5])


def a_no_empty_passwords() -> str:
    """No account may carry an empty password field.

    This is the other half of nulllock. Stripping `nullok` stops an empty field
    from being *honoured*; this stops one from existing in the first place. An
    account with an empty field is a standing bypass for anything that reaches
    PAM without `nullok` — a console, a custom stack, a service that builds its
    own. Needs root: /etc/shadow is 0640 root:shadow.
    """
    try:
        text = Path("/etc/shadow").read_text()
    except OSError:
        return "unreadable"
    empty = []
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1] == "":
            empty.append(parts[0])
    return "none" if not empty else ";".join(sorted(empty)[:5])


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
    p = _real_home() / ".lia-cli/inbox/token"
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
    return _systemctl_user("shield-kitty-watch.service")


def a_evidence_chain_intact() -> str:
    """The forensic chain must still verify; this is the tamper tripwire."""
    home = _real_home()
    ev = home / ".local/share/shield-kitty/evidence/chain.jsonl"
    script = home / "Projects/shield-kitty-forensics/evidence.py"
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


def a_self_healer_alive() -> str:
    """The self-healing watchdog layer must actually be running.

    This existed for a week while every unit in it was enabled-but-inactive:
    they were symlinked into multi-user.target.wants, a system target that does
    not exist in the user manager, so is-enabled said "enabled" while nothing
    ever started them. Silent, and invisible to a monitor that only watches
    security posture.
    """
    return _systemctl_user("bhm-self-watchdog.service")


def a_healer_state_writable() -> str:
    """The healer must be able to write its own log, or it fails silently."""
    d = _real_home() / ".local/state/kernel-healer"
    probe = d / ".write-probe"
    try:
        if not d.exists():
            return "unwritable:FileNotFoundError"
        probe.write_text("ok")
        probe.unlink()
        return "writable"
    except Exception as exc:
        return f"unwritable:{type(exc).__name__}"


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
    ("pam-no-nullok", a_pam_no_nullok, "critical",
     "nulllock: an active `nullok` anywhere in /etc/pam.d lets an EMPTY "
     "password authenticate. This is the control that replaced faillock."),
    ("no-empty-passwords", a_no_empty_passwords, "critical",
     "An account with an empty /etc/shadow field is a standing bypass for any "
     "stack that reaches PAM without `nullok`. The other half of nulllock."),
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
    ("self-healer-alive", a_self_healer_alive, "warn",
     "The self-healing watchdog layer not running means nothing notices when "
     "it rots — which is exactly how it sat enabled-but-inactive for a week."),
    ("healer-state-writable", a_healer_state_writable, "warn",
     "The kernel healer writes to ~/.local/state/kernel-healer. If that is not "
     "writable it fails on every run and looks like a clean pass."),
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


def classify(name: str, expected, actual, sev: str) -> tuple[str, str, bool]:
    """Decide one anchor's status. Pure, so it can be tested without a live system.

    Returns (status, detail, is_drift).
    """
    # A caller who lacks the privilege to evaluate a ROOT_ONLY anchor has not
    # observed a change in the system — it has observed its own lack of access.
    # Scoring that as drift invents a security regression, and it does so
    # whenever the baseline was captured at a different privilege than the check
    # runs at. Captured as root ("locked") and checked as the operator
    # ("unreadable") is exactly that pair: the two strings differ because the
    # reader changed, not because /etc/shadow changed, and it kept reporting
    # CRITICAL after root's password had genuinely been locked.
    #
    # So this is decided before the equality test and without consulting the
    # baseline. "unverified" is the honest verdict — the file's own rule is that
    # a critical control nobody can read is unverified, not passing — and
    # cmd_check already exits 3 for it, so the gap stays visible rather than
    # being either hidden or dramatised. Root runs are unaffected: a real
    # "SET" against a "locked" baseline still reads as drift.
    if name in ROOT_ONLY and str(actual).startswith(("unreadable", "unknown", "error")):
        return ("unverified",
                "needs root to evaluate — run as root or with "
                "CAP_SYS_ADMIN; currently unverifiable", False)

    if expected == actual:
        return "ok", "matches baseline", False

    if actual in EQUIVALENT.get(name, ({}, ""))[0]:
        # Differs from the recorded observation, but the invariant this anchor
        # exists to assert still holds. Report it intact and say why, rather
        # than inventing a drift that did not happen.
        return ("ok",
                f"invariant holds: {actual!r} satisfies {name} just as the "
                f"recorded {expected!r} does — {EQUIVALENT[name][1]}", False)

    return sev, f"expected {expected!r}, found {actual!r}", True


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
        status, why, is_drift = classify(name, expected, actual, sev)
        if status == "unverified":
            unver += 1
        if is_drift:
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
    """Verify the checker detects a planted drift, rather than always passing.

    Runs entirely inside a throwaway state dir. STATE_DIR is what feeds the
    SENTINEL_STATE env var, so redirecting it here also redirects the check
    subprocesses spawned below. The test used to back up only baseline.json
    while those subprocesses went on to append their planted drift=16 rows to
    the real history.jsonl and overwrite the real last-result.json — a
    self-test corrupting the audit trail it exists to protect. Ten such rows
    had already accumulated.
    """
    global STATE_DIR, BASELINE_FILE, RESULT_FILE, HISTORY_FILE
    real_state = (STATE_DIR, BASELINE_FILE, RESULT_FILE, HISTORY_FILE)
    tmp = tempfile.mkdtemp(prefix="sentinel-selftest.")
    try:
        STATE_DIR = Path(tmp)
        BASELINE_FILE = STATE_DIR / "baseline.json"
        RESULT_FILE = STATE_DIR / "last-result.json"
        HISTORY_FILE = STATE_DIR / "history.jsonl"
        os.environ["SENTINEL_STATE"] = str(STATE_DIR)
        live = collect()
        # Anchors this caller has no privilege to read. A planted baseline must
        # not turn those into drift: "unreadable" carries no information about
        # system state, so no comparison against it can show a change. They are
        # asserted separately below, as unverified.
        denied = {
            n for n, v in live.items()
            if n in ROOT_ONLY and str(v).startswith(("unreadable", "unknown", "error"))
        }
        BASELINE_FILE.write_text(json.dumps({
            "captured_at": "test", "host": "t", "user": "t",
            "values": {n: "PLANTED" for n, _f, _s, _d in ANCHORS},
        }))
        payload = json.loads(subprocess.run(
            [sys.executable, __file__, "check", "--json"],
            capture_output=True, text=True).stdout)
        detected = payload["drift"]
        want = len(ANCHORS) - len(denied)
        if detected != want:
            print(f"FAIL: planted drift on all {len(ANCHORS)} anchors, "
                  f"detected {detected}, expected {want}")
            for r in payload["results"]:
                if r["status"] not in ("ok", "unverified"):
                    print(f"   undetected: {r['anchor']}: {r['detail']}")
            return 1
        print(f"ok: planted drift detected on all {want} evaluable anchors")

        # An anchor this caller cannot read must come back unverified. Not
        # drift — being unable to look proves no change — and not ok either, or
        # a critical control nobody can read would read as a passing one.
        for r in payload["results"]:
            if r["anchor"] in denied and r["status"] != "unverified":
                print(f"FAIL: {r['anchor']} observed {r['actual']!r} scored "
                      f"{r['status']!r}, want 'unverified'")
                return 1
        if denied:
            print(f"ok: {len(denied)} unreadable anchor(s) reported unverified, "
                  f"neither drift nor ok: {', '.join(sorted(denied))}")

        # And a matching baseline must produce zero drift.
        real = live
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

        # A stopped collector must NOT read as a security regression, and a
        # genuinely exposed one still must. Pin both halves: an invariant that
        # is merely too permissive is as broken as one that is too strict.
        # Driven through classify() directly so the result does not depend on
        # whether the collector happens to be running while the test executes.
        name = "collector-localhost-only"
        for actual, want, label in (
            ("localhost-only", "ok", "the normal bound state is ok"),
            ("not-listening", "ok", "a stopped collector is not exposure drift"),
            ("EXPOSED:0.0.0.0", "critical", "a non-loopback bind is still critical"),
            ("EXPOSED:[::]:4124", "critical", "a wildcard bind is still critical"),
        ):
            status, _why, is_drift = classify(name, "localhost-only", actual, "critical")
            if status != want:
                print(f"FAIL: {label} — {actual!r} scored {status!r}, want {want!r}")
                return 1
            print(f"ok: {label}")

        # The widened tolerance must not leak onto other anchors.
        for other, _fn, _sev, _d in ANCHORS:
            if other != name and other in EQUIVALENT:
                print(f"FAIL: unexpected EQUIVALENT entry for {other}")
                return 1
        print("ok: equivalence is scoped to the one anchor that needs it")

        # The pair that had this reporting CRITICAL for days: a baseline
        # captured as root records "locked", and the operator's own check reads
        # "unreadable". The reader changed, not /etc/shadow. A genuine "SET"
        # against a "locked" baseline must still be drift, or the exemption
        # would have blinded the anchor rather than quieted it.
        for expected, actual, want in (
            ("locked", "unreadable", "unverified"),
            ("unreadable", "unreadable", "unverified"),
            ("locked", "locked", "ok"),
            ("locked", "SET", "critical"),
            ("SET", "locked", "critical"),
        ):
            status, _why, is_drift = classify(
                "shadow-root-locked", expected, actual, "critical")
            want_drift = want == "critical"
            if status != want or is_drift != want_drift:
                print(f"FAIL: shadow-root-locked expected={expected!r} "
                      f"actual={actual!r} -> {status!r}/drift={is_drift}, "
                      f"want {want!r}/drift={want_drift}")
                return 1
            print(f"ok: shadow-root-locked expected={expected!r} "
                  f"actual={actual!r} -> {want}")

        # The same privilege rule must not extend to anchors any user can read,
        # or it would excuse real regressions there.
        for other in ("firewalld-active", "collector-healthy"):
            if other in ROOT_ONLY:
                print(f"FAIL: {other} should not be ROOT_ONLY")
                return 1
            status, _why, is_drift = classify(other, "active", "unreadable", "critical")
            if status == "unverified" or not is_drift:
                print(f"FAIL: {other} excused a real drift as {status!r}")
                return 1
        print("ok: privilege exemption does not extend to readable anchors")
        return 0
    finally:
        STATE_DIR, BASELINE_FILE, RESULT_FILE, HISTORY_FILE = real_state
        os.environ.pop("SENTINEL_STATE", None)
        shutil.rmtree(tmp, ignore_errors=True)


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
