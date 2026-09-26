#!/bin/bash
# install-arpwatch-spoof.sh — deploy local ARP spoof detection.
#
# Installs arpwatch wired to the Shield Kitty notifier, on wlo1. Everything
# needs root. Supports --dry-run.
#
# The 1-day ban is NOT part of this. See the header of
# arpwatch-spoof-alert.sh: on this network a flipped MAC is usually Android or
# Windows MAC randomisation, so auto-banning for 24h would cut off innocent
# devices. This notifies; fail2ban keeps the 86400s ban for real connection
# and auth attempts.

set -euo pipefail

DRY=0
[[ "${1:-}" == "--dry-run" ]] && DRY=1

IFACE="${BDE_IFACE:-wlo1}"
DB=/var/lib/arpwatch/arpwatch.dat
LOG=/var/log/arpwatch-spoof.log
HOOK="$HOME/Projects/zen-hardening/arpwatch-spoof-alert.sh"
UNIT_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/arpwatch-spoof.service"
UNIT_DST=/etc/systemd/system/arpwatch-spoof.service

run() { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi; }

echo "=== arpwatch spoof detection installer ==="
echo "  interface : $IFACE"
echo "  database  : $DB"
echo "  log       : $LOG"
[ "$DRY" = 1 ] && echo "  mode      : DRY RUN"

echo "[1/5] checking prerequisites"
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "    ERROR: interface $IFACE does not exist." >&2
    echo "    Check with: ip -br link" >&2
    exit 1
fi
echo "    $IFACE present"
[ -x "$HOOK" ] || { echo "    ERROR: hook not executable: $HOOK" >&2; exit 1; }
echo "    hook executable"

echo "[2/5] installing arpwatch"
if pacman -Qi arpwatch >/dev/null 2>&1; then
    echo "    already installed"
else
    run sudo pacman -S --noconfirm --needed arpwatch
fi

echo "[3/5] preparing state"
# Owned by livings, not root: arpwatch drops to livings via -u before it writes
# either of these, and the exec hook runs as livings so notify-send can reach
# the session bus. Root-owned files here would break the service.
run sudo install -d -m 0750 -o livings -g livings /var/lib/arpwatch
if [ -f "$LOG" ]; then
    echo "    existing $LOG preserved"
else
    run sudo install -m 0640 -o livings -g livings /dev/null "$LOG"
fi

echo "[4/5] installing unit"
# The unit hardcodes this user's home; regenerate it if that changed.
run sudo install -Dm644 "$UNIT_SRC" "$UNIT_DST"

echo "[5/5] enabling"
run sudo systemctl daemon-reload
run sudo systemctl enable --now arpwatch-spoof.service

echo
if [ "$DRY" = 1 ]; then
    echo "[+] DRY RUN complete. Re-run without --dry-run to apply."
else
    echo "[+] Installed. Verify:"
    echo "      systemctl status arpwatch-spoof"
    echo "      tail -f $LOG"
    echo
    echo "    A flip-flop raises a desktop notification. New hosts are logged only."
    echo "    If the first real event shows the wrong fields, arpwatch's argument"
    echo "    order differs from what the hook assumes -- the raw args are logged,"
    echo "    so adjust and re-run."
fi
