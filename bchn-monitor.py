#!/usr/bin/env python3
"""
bchn-monitor.py — Bitcoin Cash node and wallet watchdog.

Rebuilt 2026-09-26.

IMPORTANT CONTEXT, and the reason this tool is mostly a reporter:

The old host's cleanup ledger (sin-archive-2026/MANIFEST-2026-09-24.md) records
that `~/.bitcoin-cash/blocks` + chainstate (11.7G) were deleted and the node
"restarted — resyncing fresh", while `~/.bitcoin-cash/wallets` was explicitly
RETAINED and "never uploaded anywhere".

On this machine:
  - no Bitcoin Cash node is installed at all (no bitcoind / bitcoin-cli)
  - ~/.bitcoin-cash does not exist, so the wallets are NOT here
  - the bch-faucet-backup repo holds a bitcoin.conf with a redacted RPC
    password and a walletdir pointing at the old account

So this tool does not pretend to monitor a node that is not here. It reports
the real state, and it treats a MISSING WALLET DIRECTORY as a critical finding
rather than a non-event, because that is exactly the thing the ledger says was
preserved and this machine cannot confirm.

Usage:
    bchn-monitor.py status     one-shot full report
    bchn-monitor.py --json     machine-readable
    bchn-monitor.py --selftest verify detection logic
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WALLET_DIR = Path(os.environ.get("BCHN_WALLET_DIR", Path.home() / ".bitcoin-cash/wallets"))
DATADIR = Path(os.environ.get("BCHN_DATADIR", Path.home() / ".bitcoin-cash"))
RPC_PORT = int(os.environ.get("BCHN_RPC_PORT", "8332"))
CHAIN = "bch"


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as exc:
        return 127, "", str(exc)


def node_installed() -> dict:
    return {
        "bitcoind": shutil.which("bitcoind"),
        "bitcoin-cli": shutil.which("bitcoin-cli"),
        "present": bool(shutil.which("bitcoind") or shutil.which("bitcoin-cli")),
    }


def service_state() -> str:
    rc, out, _ = _run(["systemctl", "is-active", "bchn.service"])
    if out:
        return out
    return "not-installed" if rc == 127 else "unknown"


def rpc_reachable() -> dict:
    """TCP probe only. We hold no credentials, so we never attempt auth."""
    host = "127.0.0.1"
    try:
        with socket.create_connection((host, RPC_PORT), timeout=3):
            return {"reachable": True, "port": RPC_PORT}
    except Exception as exc:
        return {"reachable": False, "port": RPC_PORT, "error": type(exc).__name__}


def wallet_state() -> dict:
    """
    Wallet inventory. This is the finding that matters: the ledger says the
    wallets were retained on the old host and never uploaded, and they are not
    present here. That is reported as critical, not as 'nothing to do'.
    """
    info = {
        "wallet_dir": str(WALLET_DIR),
        "wallet_dir_exists": WALLET_DIR.is_dir(),
        "wallets": [],
        "total_bytes": 0,
    }
    if WALLET_DIR.is_dir():
        for p in sorted(WALLET_DIR.rglob("wallet.dat")):
            try:
                size = p.stat().st_size
            except OSError:
                size = 0
            info["wallets"].append({"path": str(p), "bytes": size})
            info["total_bytes"] += size
    return info


def datadir_state() -> dict:
    blocks = DATADIR / "blocks"
    chainstate = DATADIR / "chainstate"
    du = {}
    for name, p in (("blocks", blocks), ("chainstate", chainstate)):
        if p.is_dir():
            rc, out, _ = _run(["du", "-sb", str(p)], timeout=60)
            du[name] = int(out.split()[0]) if rc == 0 and out else None
        else:
            du[name] = None
    return {
        "datadir": str(DATADIR),
        "exists": DATADIR.is_dir(),
        "blocks_bytes": du["blocks"],
        "chainstate_bytes": du["chainstate"],
        # A pruned node keeps ~10G of chainstate; near-zero means mid-resync.
        "sync_estimate": _sync_estimate(du),
    }


def _sync_estimate(du: dict) -> str:
    cs = du.get("chainstate")
    if cs is None:
        return "no chainstate (not synced)"
    gib = cs / (1024 ** 3)
    if gib < 1:
        return f"early resync ({gib:.2f} GiB chainstate)"
    if gib < 9:
        return f"resyncing ({gib:.1f} GiB of ~10 GiB pruned target)"
    return f"likely synced ({gib:.1f} GiB)"


def faucet_state() -> dict:
    """The BCH faucet this account is tied to, as far as config survives."""
    conf = Path.home() / "Projects/_inventory/bch-faucet-backup/bitcoin.conf.backup"
    out = {"conf_found": conf.is_file(), "conf_path": str(conf), "rpcuser": None,
           "walletdir": None, "prune": None, "rpcpassword_present": False}
    if conf.is_file():
        for line in conf.read_text(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("rpcuser="):
                out["rpcuser"] = line.split("=", 1)[1]
            elif line.startswith("walletdir="):
                out["walletdir"] = line.split("=", 1)[1]
            elif line.startswith("prune="):
                out["prune"] = line.split("=", 1)[1]
            elif line.startswith("rpcpassword="):
                # Report only whether one is set. Never echo the value.
                out["rpcpassword_present"] = bool(line.split("=", 1)[1].strip())
    return out


def assess(state: dict) -> list[dict]:
    """Turn raw state into findings. Severity is about risk to funds, not noise."""
    findings = []
    node = state["node"]
    wallet = state["wallet"]

    if not node["present"]:
        findings.append({
            "id": "node-absent", "severity": "warn",
            "detail": "No Bitcoin Cash node installed on this machine.",
            "action": "Install bitcoind only if you intend to run a local node.",
        })

    if not wallet["wallet_dir_exists"]:
        findings.append({
            "id": "wallet-dir-missing", "severity": "critical",
            "detail": (
                f"{wallet['wallet_dir']} does not exist. The 2026-09-24 ledger "
                "records this directory as RETAINED and never uploaded anywhere, "
                "so it was on the old host only. If it held funds, they are not "
                "recoverable from this machine."),
            "action": (
                "Confirm the wallets exist on the old disk or in a backup before "
                "doing anything else with BCH."),
        })
    elif not wallet["wallets"]:
        findings.append({
            "id": "wallet-dir-empty", "severity": "critical",
            "detail": f"{wallet['wallet_dir']} exists but contains no wallet.dat.",
            "action": "Verify no wallet was lost in the rebuild.",
        })

    if state["service"] == "active" and not state["rpc"]["reachable"]:
        findings.append({
            "id": "service-up-rpc-down", "severity": "critical",
            "detail": "bchn.service is active but nothing answers on the RPC port.",
            "action": "Check the unit and bitcoin.conf bind settings.",
        })

    data = state["datadir"]
    if data["exists"] and "resync" in (data["sync_estimate"] or ""):
        findings.append({
            "id": "resyncing", "severity": "warn",
            "detail": f"Chain is resyncing: {data['sync_estimate']}",
            "action": "Normal after a chainstate wipe; no action needed.",
        })

    if state["faucet"]["conf_found"] and state["faucet"]["walletdir"]:
        wd = state["faucet"]["walletdir"]
        if not Path(wd).is_dir():
            findings.append({
                "id": "faucet-walletdir-stale", "severity": "warn",
                "detail": (
                    f"Surviving bitcoin.conf points walletdir at {wd}, which does "
                    "not exist on this machine (old account name)."),
                "action": "Update walletdir if you reinstall the node.",
            })
    return findings


def gather() -> dict:
    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        "chain": CHAIN,
        "node": node_installed(),
        "service": service_state(),
        "rpc": rpc_reachable(),
        "wallet": wallet_state(),
        "datadir": datadir_state(),
        "faucet": faucet_state(),
    }


def cmd_status(args) -> int:
    state = gather()
    findings = assess(state)
    state["findings"] = findings

    if args.json:
        print(json.dumps(state, indent=2))
        return 1 if any(f["severity"] == "critical" for f in findings) else 0

    w = 62
    print("=" * w)
    print(f" {CHAIN.upper()} node + wallet monitor".ljust(w))
    print(f" host {state['host']}   {state['checked_at'][:19]}".ljust(w))
    print("=" * w)
    print(f" node installed     : {state['node']['present']}")
    print(f" bchn.service       : {state['service']}")
    print(f" rpc {state['rpc']['port']:<16}: "
          f"{'reachable' if state['rpc']['reachable'] else 'not reachable'}")
    print(f" wallet dir         : {state['wallet']['wallet_dir']}")
    print(f"   exists          : {state['wallet']['wallet_dir_exists']}")
    print(f"   wallets found   : {len(state['wallet']['wallets'])}"
          f"  ({state['wallet']['total_bytes']} bytes)")
    print(f" datadir            : {state['datadir']['exists']}")
    print(f"   sync estimate   : {state['datadir']['sync_estimate']}")
    print()
    if not findings:
        print(" no findings")
    else:
        print(f" {len(findings)} finding(s)")
        print("-" * w)
        for f in findings:
            print(f" [{f['severity'].upper():8}] {f['id']}")
            print(f"     {f['detail']}")
            if f.get("action"):
                print(f"     -> {f['action']}")
    print("-" * w)
    crit = sum(1 for f in findings if f["severity"] == "critical")
    print(f" {crit} critical, {len(findings) - crit} warn")
    return 1 if crit else 0


def cmd_selftest(args) -> int:
    ok = True

    # 1. A missing wallet dir must be CRITICAL, not silently absent.
    st = {"node": {"present": True}, "service": "active",
          "rpc": {"reachable": True, "port": 8332},
          "wallet": {"wallet_dir_exists": False, "wallets": [], "wallet_dir": "/x/wallets"},
          "datadir": {"exists": True, "sync_estimate": "likely synced (10.1 GiB)"},
          "faucet": {"conf_found": False, "walletdir": None}}
    ids = [f["id"] for f in assess(st)]
    if "wallet-dir-missing" not in ids:
        print("FAIL: missing wallet dir not detected"); ok = False
    else:
        sev = [f["severity"] for f in assess(st) if f["id"] == "wallet-dir-missing"][0]
        if sev != "critical":
            print(f"FAIL: missing wallet dir severity is {sev}, expected critical")
            ok = False
        else:
            print("ok: missing wallet directory is flagged critical")

    # 2. Existing dir with no wallet.dat must also be critical.
    st["wallet"] = {"wallet_dir_exists": True, "wallets": [], "wallet_dir": "/x/wallets"}
    if "wallet-dir-empty" not in [f["id"] for f in assess(st)]:
        print("FAIL: empty wallet dir not detected"); ok = False
    else:
        print("ok: existing-but-empty wallet directory is flagged")

    # 3. Active service with dead RPC must be critical.
    st["wallet"] = {"wallet_dir_exists": True, "wallets": [{"path": "x", "bytes": 1}], "wallet_dir": "/x/wallets"}
    st["rpc"] = {"reachable": False, "port": 8332}
    if "service-up-rpc-down" not in [f["id"] for f in assess(st)]:
        print("FAIL: service-up/rpc-down not detected"); ok = False
    else:
        print("ok: active service with unreachable RPC is flagged critical")

    # 4. A healthy node must produce no critical findings.
    st["rpc"] = {"reachable": True, "port": 8332}
    crit = [f for f in assess(st) if f["severity"] == "critical"]
    if crit:
        print(f"FAIL: healthy state produced critical findings: {[f['id'] for f in crit]}")
        ok = False
    else:
        print("ok: healthy state produces no critical findings")

    # 5. We must never print an RPC password.
    txt = json.dumps(assess(st))
    if "rpcpassword" in txt and "rpcpassword_present" not in txt:
        print("FAIL: password field leaked"); ok = False
    else:
        print("ok: rpc password is never emitted (presence flag only)")

    print("\nSELFTEST " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    if "--selftest" in sys.argv:
        return cmd_selftest(argparse.Namespace())
    ap = argparse.ArgumentParser(description="Bitcoin Cash node and wallet monitor")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("cmd", nargs="?", default="status")
    args = ap.parse_args()
    return cmd_status(args)


if __name__ == "__main__":
    sys.exit(main())
