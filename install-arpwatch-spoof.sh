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
DB=/var/lib/arpwatch/arp.dat
LOG=/var/log/arpwatch-spoof.log
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Resolve the REAL user's home. Under sudo, $HOME is /root, so every path into
# the user's own ~/Projects silently becomes /root/Projects/... and the script
# reports the hook as missing. SUDO_USER names whoever actually invoked it.
SUDO_USER_NAME="${SUDO_USER:-}"
if [ -n "$SUDO_USER_NAME" ]; then
    TARGET_HOME="$(getent passwd "$SUDO_USER_NAME" | cut -d: -f6)"
else
    TARGET_HOME="$HOME"
fi
[ -n "$TARGET_HOME" ] && [ -d "$TARGET_HOME" ] || {
    echo "ERROR: cannot resolve the invoking user's home (got '$TARGET_HOME')" >&2
    exit 1
}
HOOK="$TARGET_HOME/Projects/zen-hardening/arpwatch-spoof-alert.sh"
SCAN="$TARGET_HOME/Projects/zen-hardening/arpwatch-spoof-scan.sh"
UNIT_DST_DIR=/etc/systemd/system

run() { if [ "$DRY" = 1 ]; then echo "  [dry-run] $*"; else "$@"; fi; }

echo "=== arpwatch spoof detection installer ==="
echo "  interface : $IFACE"
echo "  home      : $TARGET_HOME (from SUDO_USER=${SUDO_USER:-none})"
echo "  database  : $DB"
echo "  log       : $LOG"
[ "$DRY" = 1 ] && echo "  mode      : DRY RUN"

echo "[1/6] checking prerequisites"
if ! ip link show "$IFACE" >/dev/null 2>&1; then
    echo "    ERROR: interface $IFACE does not exist." >&2
    echo "    Check with: ip -br link" >&2
    exit 1
fi
echo "    $IFACE present"
[ -x "$HOOK" ] || { echo "    ERROR: hook not executable: $HOOK" >&2; exit 1; }
echo "    hook executable"

echo "[2/6] installing arpwatch"
if pacman -Qi arpwatch >/dev/null 2>&1; then
    echo "    already installed"
else
    run sudo pacman -S --noconfirm --needed arpwatch
fi

echo "[3/6] preparing state"
# Owned by livings, not root: arpwatch drops to livings via -u before it writes
# either of these, and the exec hook runs as livings so notify-send can reach
# the session bus. Root-owned files here would break the service.
run sudo install -d -m 0750 -o root -g root /var/lib/arpwatch
# arpwatch(8): "an empty arp.dat file must be created before the first run".
run sudo install -m 0644 -o root -g root /dev/null /var/lib/arpwatch/arp.dat
if [ -f "$LOG" ]; then
    echo "    existing $LOG preserved"
else
    run sudo install -m 0640 -o livings -g livings /dev/null "$LOG"
fi

echo "[4/6] installing units"
UNIT_TMP="$(mktemp)"
for u in arpwatch-spoof.service arpwatch-spoof-scan.service arpwatch-spoof-scan.timer; do
    sed -e "s#/home/livings#$TARGET_HOME#g" "$HERE/$u" > "$UNIT_TMP"
    if ! grep -q "^Environment=HOME=" "$UNIT_TMP"; then
        sed -i "/^\[Service\]/a Environment=HOME=$TARGET_HOME" "$UNIT_TMP"
    fi
    run sudo install -Dm644 "$UNIT_TMP" "$UNIT_DST_DIR/$u"
    echo "    installed $u"
done
rm -f "$UNIT_TMP"

echo "[5/6] checking scanner prerequisites"
[ -x "$SCAN" ] || { echo "    ERROR: scanner not executable: $SCAN" >&2; exit 1; }
echo "    scanner executable"
run "$SCAN" --selftest || true

echo "[6/6] enabling"
run sudo systemctl daemon-reload
run sudo systemctl enable --now arpwatch-spoof.service
run sudo systemctl enable --now arpwatch-spoof-scan.timer

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
