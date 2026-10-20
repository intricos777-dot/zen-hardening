#!/usr/bin/env python3
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
"""
watchman.py — service supervisor for Sentinel.

Rebuilt 2026-09-26. The old host's ledger recorded a "watchman active" during
its last cleanup, with no surviving definition of what it watched. This is a
fresh implementation: a supervised loop that runs sentinel.py on an interval,
keeps a bounded history, and notifies you when an anchor drifts.

Division of labour, deliberately:
  sentinel  decides whether the system matches its baseline. Never repairs.
  watchman  decides when to run it, and tells you. Repairs only on --repair
            and only for the specific, safe, reversible actions listed there.

Usage:
    watchman.py run [--interval 300]   loop until stopped (for systemd)
    watchman.py once                  single cycle, non-zero exit on drift
    watchman.py status                 last result + history summary
    watchman.py history [--days 7]     drift timeline
    watchman.py --selftest             verify detection and notification logic
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SENTINEL = HERE / "sentinel.py"
STATE_DIR = Path(os.environ.get("WATCHMAN_STATE", Path.home() / ".local/share/sentinel"))
RESULT_FILE = STATE_DIR / "last-result.json"
HISTORY_FILE = STATE_DIR / "history.jsonl"
WATCHMAN_LOG = STATE_DIR / "watchman.log"
NOTIFY_LOG = STATE_DIR / "notifications.log"

DEFAULT_INTERVAL = 300
MAX_HISTORY_DAYS = 30

_stop = False


def _log(msg: str) -> None:
    line = f"{datetime.now(timezone.utc).isoformat()} {msg}"
    print(line, flush=True)
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with WATCHMAN_LOG.open("a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


def run_sentinel() -> tuple[int, dict | None]:
    """Run one sentinel check. Returns (exit_code, parsed_result_or_None)."""
    try:
        r = subprocess.run([sys.executable, str(SENTINEL), "check", "--json"],
                           capture_output=True, text=True, timeout=180)
    except subprocess.TimeoutExpired:
        _log("sentinel TIMED OUT after 180s")
        return 124, None
    try:
        return r.returncode, json.loads(r.stdout)
    except json.JSONDecodeError:
        _log(f"sentinel produced non-JSON output: {r.stdout[:200]!r}")
        return r.returncode, None


def notify(title: str, body: str, urgency: str = "normal") -> bool:
    """
    Desktop notification. Root cannot reach the user's session bus, so when
    running as root we dispatch as the invoking user via setpriv with the
    right DBUS_SESSION_BUS_ADDRESS — otherwise notify-send silently succeeds
    and nobody is told anything.
    """
    if not shutil.which("notify-send"):
        _log(f"notify-send unavailable, would notify: {title} — {body}")
        _record_notify(title, body, delivered=False)
        return False

    env = dict(os.environ)
    if os.geteuid() == 0:
        user = os.environ.get("SUDO_USER") or os.environ.get("WATCHMAN_USER")
        if not user or user == "root":
            _log(f"running as root and no target user; would notify: {title}")
            _record_notify(title, body, delivered=False)
            return False
        uid = _uid_of(user)
        gid = _gid_of(user)
        runtime = f"/run/user/{uid}"
        if os.path.isdir(runtime):
            bus = f"unix:path={runtime}/bus"
        else:
            bus = ""
        cmd = ["setpriv", "--reuid", str(uid), "--regid", str(gid),
               "--init-groups", "--inh-caps=-all"]
        if bus:
            cmd += ["--ambient-caps=-all", "--"]
        r = subprocess.run(
            cmd + ["notify-send", "--urgency", urgency, "--app-name", "watchman",
                   title, body],
            capture_output=True, text=True, timeout=30,
            env={**env, "DBUS_SESSION_BUS_ADDRESS": bus, "XDG_RUNTIME_DIR": runtime,
                 "DISPLAY": os.environ.get("DISPLAY", ":0")})
    else:
        r = subprocess.run(["notify-send", "--urgency", urgency,
                            "--app-name", "watchman", title, body],
                           capture_output=True, text=True, timeout=30, env=env)

    delivered = r.returncode == 0
    _record_notify(title, body, delivered=delivered)
    if not delivered:
        _log(f"notify-send failed rc={r.returncode}: {(r.stderr or '')[:160]}")
    return delivered


def _uid_of(user: str):
    import pwd
    return pwd.getpwnam(user).pw_uid


def _gid_of(user: str):
    import grp
    primary = _uid_of(user)
    try:
        return grp.getgrgid(primary).gr_gid
    except KeyError:
        return primary


def _record_notify(title: str, body: str, delivered: bool) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        with NOTIFY_LOG.open("a") as fh:
            fh.write(json.dumps({
                "t": datetime.now(timezone.utc).isoformat(),
                "title": title, "body": body[:500], "delivered": delivered}) + "\n")
    except OSError:
        pass


def summarise(res: dict) -> tuple[str, str, str]:
    """(title, body, urgency) from a sentinel result."""
    crit = [r["anchor"] for r in res["results"] if r["status"] == "critical"]
    warn = [r["anchor"] for r in res["results"] if r["status"] == "warn"]
    unver = [r["anchor"] for r in res["results"] if r["status"] == "unverified"]

    if crit:
        return ("Sentinel: CRITICAL drift",
                f"{len(crit)} anchor(s) drifted: {', '.join(crit)}\n"
                f"{res['intact']}/{res['verified']} verified intact.",
                "critical")
    if warn:
        return ("Sentinel: drift detected",
                f"{len(warn)} anchor(s) drifted: {', '.join(warn)}\n"
                f"{res['intact']}/{res['verified']} verified intact.",
                "normal")
    body = f"{res['intact']}/{res['verified']} verified anchors intact."
    if unver:
        body += f"\n{len(unver)} unverified (need root): {', '.join(unver)}"
    return ("Sentinel: all anchors intact", body, "low")


# ------------------------------------------------------------- safe repairs
#
# Only these, only on explicit --repair, and only when sentinel reports the
# specific drift. Nothing here touches authentication or firewall policy:
# a supervisor that "repairs" security policy on its own is an attacker with
# write access.

REPAIRS = {
    "collector-healthy": lambda: subprocess.run(
        ["systemctl", "--user", "restart", "lia-inbox-collector.service"]).returncode == 0,
    "shield-kitty-active": lambda: subprocess.run(
        ["systemctl", "--user", "restart", "shield-kitty-watch.service"]).returncode == 0,
}


def attempt_repairs(res: dict) -> list[str]:
    done = []
    for r in res["results"]:
        if r["status"] in ("ok", "unverified"):
            continue
        fn = REPAIRS.get(r["anchor"])
        if not fn:
            continue
        _log(f"repairing {r['anchor']} (was {r['actual']!r})")
        try:
            if fn():
                done.append(r["anchor"])
                _log(f"repaired {r['anchor']}")
            else:
                _log(f"repair FAILED for {r['anchor']}")
        except Exception as exc:
            _log(f"repair ERROR for {r['anchor']}: {exc}")
    return done


def prune_history() -> None:
    if not HISTORY_FILE.exists():
        return
    cutoff = datetime.now(timezone.utc) - timedelta(days=MAX_HISTORY_DAYS)
    kept = []
    for line in HISTORY_FILE.read_text().splitlines():
        if not line.strip():
            continue
        try:
            t = datetime.fromisoformat(json.loads(line)["t"])
        except Exception:
            continue
        if t >= cutoff:
            kept.append(line)
    if len(kept) != len(HISTORY_FILE.read_text().splitlines()):
        HISTORY_FILE.write_text("\n".join(kept) + ("\n" if kept else ""))


# ------------------------------------------------------------------ commands

def _handle_stop(signum, _frame):
    global _stop
    _stop = True
    _log(f"received signal {signum}, finishing current cycle then exiting")


def cmd_run(args) -> int:
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    prune_history()
    _log(f"watchman started (interval {args.interval}s) as uid={os.geteuid()}")

    last_ship = None
    while not _stop:
        rc, res = run_sentinel()
        if res is None:
            title, body, urg = ("Sentinel: check failed",
                                 f"sentinel exited {rc} without a usable result", "critical")
            notify(title, body, urg)
        else:
            title, body, urg = summarise(res)
            # Only notify on a change of state. A permanently drifted anchor
            # should not re-notify every cycle.
            ship = f"{urg}|{sorted(r['anchor'] for r in res['results'] if r['status'] != 'ok')}"
            if ship != last_ship or urg == "critical":
                notify(title, body, urg)
                last_ship = ship
        if _stop:
            break
        slept = 0
        while slept < args.interval and not _stop:
            time.sleep(min(5, args.interval - slept))
            slept += 5
    _log("watchman exiting")
    return 0


def cmd_once(args) -> int:
    """
    Single cycle. Notifies on drift, like the run loop does.

    An earlier version only printed the summary here, so anyone invoking
    `watchman.py once` as their check got no notification at all — the
    service loop was the only path that alerted. Print-only is fine for a
    human reading a terminal, but silently diverging from `run` is not.
    """
    rc, res = run_sentinel()
    if res is None:
        print(f"sentinel check failed rc={rc}", file=sys.stderr)
        notify("Watchman: check failed", f"sentinel exited {rc} without a usable result",
               "critical")
        return rc or 1
    if res["drift"] and args.repair:
        fixed = attempt_repairs(res)
        if fixed:
            print(f"repaired: {', '.join(fixed)}")
            rc, res = run_sentinel()
            # A repair can leave sentinel unable to produce a result at all;
            # re-check explicitly rather than assuming the second call worked.
            if res is None:
                print("sentinel produced no result after repair; cannot summarise",
                      file=sys.stderr)
                return rc or 1
    title, body, urg = summarise(res)
    if res["drift"]:
        notify(title, body, urg)
    print(f"[{urg}] {title}")
    print(body)
    for r in res["results"]:
        if r["status"] != "ok":
            print(f"  {r['status']:11} {r['anchor']:28} {r['detail']}")
    return rc


def cmd_status(args) -> int:
    if not RESULT_FILE.exists():
        print("no result yet — run: watchman.py once")
        return 2
    res = json.loads(RESULT_FILE.read_text())
    print(f"last check : {res['checked_at']}")
    print(f"host       : {res['host']}")
    print(f"intact     : {res['intact']}/{res['verified']} verified")
    print(f"unverified : {res.get('unverified', 0)}")
    print(f"drift      : {res['drift']}")
    if HISTORY_FILE.exists():
        lines = [l for l in HISTORY_FILE.read_text().splitlines() if l.strip()]
        print(f"checks     : {len(lines)} recorded")
    return 0


def cmd_history(args) -> int:
    if not HISTORY_FILE.exists():
        print("no history yet")
        return 2
    cutoff = datetime.now(timezone.utc) - timedelta(days=args.days)
    rows = []
    for line in HISTORY_FILE.read_text().splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
            if datetime.fromisoformat(d["t"]) >= cutoff:
                rows.append(d)
        except Exception:
            continue
    if not rows:
        print(f"no checks in the last {args.days} day(s)")
        return 0
    print(f"{'when':<26} {'intact':>8} {'unver':>6} {'drift':>6}")
    for d in rows[-args.limit:]:
        print(f"{d['t'][:25]:<26} {d.get('intact', 0):>8} "
              f"{d.get('unverified', 0):>6} {d.get('drift', 0):>6}")
    bad = [d for d in rows if d.get("drift")]
    print(f"\n{len(rows)} checks, {len(bad)} with drift")
    return 0


def cmd_selftest(args) -> int:
    ok = True

    # 1. summarise() must escalate correctly and name the drifted anchors.
    def res(statuses):
        return {"intact": sum(1 for s in statuses.values() if s == "ok"),
                "verified": len(statuses),
                "results": [{"anchor": k, "status": v, "actual": "x",
                             "expected": "y", "detail": "d"}
                            for k, v in statuses.items()]}

    t, b, u = summarise(res({"a": "ok", "firewalld-active": "critical"}))
    if u != "critical" or "firewalld-active" not in b:
        print(f"FAIL: critical not escalated ({u} / {b!r})"); ok = False
    else:
        print("ok: critical drift escalates to 'critical' and names the anchor")

    t, _b, u = summarise(res({"a": "ok", "rootfs-headroom": "warn"}))
    if u != "normal":
        print(f"FAIL: warn should be 'normal' urgency, got {u}"); ok = False
    else:
        print("ok: warn drift is 'normal' urgency")

    t, b, u = summarise(res({"a": "ok", "shadow-root-locked": "unverified"}))
    if "unverified" not in b:
        print(f"FAIL: unverified not surfaced in body: {b!r}"); ok = False
    else:
        print("ok: unverified anchors are surfaced, not hidden")

    # 2. Repairs must refuse anchors with no safe repair, and never touch
    #    authentication or firewall policy.
    for forbidden in ("faillock-admin-group", "firewalld-active",
                      "shadow-root-locked", "sudo-requires-password",
                      "faillock-unlock-time", "collector-localhost-only"):
        if forbidden in REPAIRS:
            print(f"FAIL: {forbidden} has an auto-repair — too dangerous"); ok = False
    if not ok:
        pass
    else:
        print("ok: no auto-repair exists for auth, faillock, or firewall anchors")

    # 3. notify() must record the attempt even when it cannot deliver.
    before = NOTIFY_LOG.read_text().count("\n") if NOTIFY_LOG.exists() else 0
    notify("watchman selftest", "verifying notification path", "low")
    after = NOTIFY_LOG.read_text().count("\n") if NOTIFY_LOG.exists() else 0
    if after <= before:
        print("FAIL: notification attempt was not recorded"); ok = False
    else:
        print("ok: notification attempt is always recorded (delivered or not)")

    # 4. History pruning must drop old rows and keep recent ones.
    tmp = STATE_DIR / "selftest-history.jsonl"
    old = (datetime.now(timezone.utc) - timedelta(days=90)).isoformat()
    tmp.write_text(json.dumps({"t": old, "intact": 1, "drift": 0}) + "\n" +
                   json.dumps({"t": datetime.now(timezone.utc).isoformat(),
                               "intact": 1, "drift": 0}) + "\n")
    real = HISTORY_FILE
    backup = real.read_text() if real.exists() else None
    real.write_text(tmp.read_text())
    prune_history()
    kept = real.read_text().strip().splitlines()
    if len(kept) != 1:
        print(f"FAIL: prune kept {len(kept)} rows, expected 1"); ok = False
    else:
        print("ok: history pruning drops expired rows")
    if backup is not None:
        real.write_text(backup)
    elif real.exists():
        real.unlink()
    tmp.unlink()

    print("\nSELFTEST " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return cmd_selftest(argparse.Namespace())
    ap = argparse.ArgumentParser(description="Sentinel supervisor")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("run"); p.add_argument("--interval", type=int, default=DEFAULT_INTERVAL)
    p = sub.add_parser("once"); p.add_argument("--repair", action="store_true")
    sub.add_parser("status")
    p = sub.add_parser("history"); p.add_argument("--days", type=int, default=7)
    p.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()
    return {"run": cmd_run, "once": cmd_once, "status": cmd_status,
            "history": cmd_history}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
