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
PIDFILE=/run/arpwatch-spoof.pid
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

# Keep in one place and shared with the unit via the parse-check below, so the
# two cannot drift. -q is deliberately absent: see arpwatch-spoof.service.
ARPWATCH_ARGS="-F -i $IFACE -f $DB -D /var/lib/arpwatch -P $PIDFILE -s -N -z"

# The parse probe must not touch the real datafile, and it must be bounded.
#
# A plain "arpwatch <args>" probe is not safe here. Unprivileged it exits
# immediately on the raw socket, but the installer runs as root, where -F keeps
# it in the foreground with a working socket and it never returns -- the
# install hung on a perfectly healthy arpwatch. timeout 3 caps it, and exit 124
# then means "still running", i.e. the flags were accepted.
ARPWATCH_PROBE_DB="$(mktemp -u)/probe.dat"
ARPWATCH_PROBE_PID="$(mktemp -u)/probe.pid"
mkdir -p "$(dirname "$ARPWATCH_PROBE_DB")"

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

# Parse-check the exact flags the unit will use.
#
# arpwatch(8) is wrong about -q: it lists -q in the synopsis and describes it,
# but the binary rejects it, prints usage and exits 1. arpwatch prints that
# usage BEFORE it tries to open the raw socket, so the check works unprivileged
# and costs nothing. Getting this wrong produced a service stuck in a restart
# loop, twice, because the failure only shows up in the journal.
if command -v arpwatch >/dev/null 2>&1; then
    probe_out=""
    if probe_out="$(timeout 3 arpwatch -F -i "$IFACE" -f "$ARPWATCH_PROBE_DB" -D /var/lib/arpwatch -P "$ARPWATCH_PROBE_PID" -s -N -z 2>&1)"; then
        probe_rc=0
    else
        probe_rc=$?
    fi
    if printf '%s' "$probe_out" | grep -q usage; then
        echo "    ERROR: arpwatch rejects these flags: $ARPWATCH_ARGS" >&2
        echo "           it printed its usage message. Check the man page" >&2
        echo "           against the binary -- they disagree about -q." >&2
        exit 1
    fi
    if [ "$probe_rc" = 124 ]; then
        echo "    flags parse OK: arpwatch $ARPWATCH_ARGS (still running when the probe timed out)"
    else
        echo "    flags parse OK: arpwatch $ARPWATCH_ARGS (probe exited $probe_rc, unprivileged socket denial)"
    fi
    rm -rf "$(dirname "$ARPWATCH_PROBE_DB")"
fi

echo "[3/6] preparing state"
# 0755 so the unprivileged scanner (User=livings) can traverse into the
# directory. It was 0750 root:root, which locks livings out of the dir entirely
# even though the datafile inside is world-readable.
run sudo install -d -m 0755 -o root -g root /var/lib/arpwatch

# arpwatch(8) wants an empty arp.dat before the first run -- but ONLY create it
# when absent. Truncating it here destroyed every address already collected,
# and on a re-run it was truncating a file the running service was appending to.
if [ -f "$DB" ]; then
    echo "    existing $DB preserved ($(wc -l <"$DB" 2>/dev/null || echo '?') entries)"
else
    run sudo install -m 0644 -o root -g root /dev/null "$DB"
    echo "    created empty $DB"
fi

# The scanner rewrites this file on every run, so it must belong to the user the
# scanner runs as. A root-owned state file makes dedup fail with a permission
# error that the script only logs, and then it re-alerts on every single scan.
run sudo install -m 0644 -o livings -g livings /dev/null /var/lib/arpwatch/spoof-state

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
