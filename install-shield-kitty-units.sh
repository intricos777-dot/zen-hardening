#!/usr/bin/env bash
# install-shield-kitty-units.sh — install Shield Kitty's systemd units so the
# watcher and evidence sealer survive a reboot.
#
#   sudo bash install-shield-kitty-units.sh
#   sudo bash install-shield-kitty-units.sh --remove
#
# WHY USER UNITS, NOT SYSTEM UNITS
#
# The shipped units use %h in ExecStart:
#
#     ExecStart=/usr/bin/python3 %h/Projects/shield-kitty/shield-kitty-watch.py
#
# %h is the home of the user the unit runs as. Installed as a system unit that
# is ROOT, so the path would expand to /root/Projects/shield-kitty/... which
# does not exist, and the unit would fail on every start. A system unit also
# cannot easily reach the user's runtime directory to raise a desktop
# notification, which is the whole point of the alert path.
#
# So these go in /etc/systemd/user/ and are enabled globally, plus lingering is
# enabled for the account so the user manager starts at boot without anyone
# logging in. A security monitor that only runs while someone is logged in is
# not a monitor.
#
# This addresses a real gap found in the 2026-09-26 audit: the watcher was
# running as a bare process with no unit installed anywhere, so it would have
# silently stopped existing after the next reboot.

set -euo pipefail

UNITS=(shield-kitty-watch.service evidence-seal.service evidence-seal.timer)
# Resolve the invoking user BEFORE deriving $HOME from it. Under sudo $HOME is
# /root, and pkexec additionally leaves SUDO_USER unset, so a $HOME-based lookup
# finds nothing. Hardcoding a name here would make the script silently target
# the wrong account on any other machine.
if [ -n "${PKEXEC_UID:-}" ]; then
  ACCOUNT="$(getent passwd "$PKEXEC_UID" 2>/dev/null | cut -d: -f1)"
elif [ -n "${SUDO_USER:-}" ]; then
  ACCOUNT="$SUDO_USER"
else
  ACCOUNT="$(logname 2>/dev/null || true)"
fi
[ -z "$ACCOUNT" ] || [ "$ACCOUNT" = root ] && ACCOUNT="$(logname 2>/dev/null || id -un)"
ACCOUNT_HOME="$(getent passwd "$ACCOUNT" 2>/dev/null | cut -d: -f6)"
if [ -z "$ACCOUNT_HOME" ] || [ ! -d "$ACCOUNT_HOME" ]; then
  echo "ERROR: cannot resolve home for '$ACCOUNT' (refusing to install units for the wrong account)" >&2
  exit 1
fi
SRC_WATCH="$ACCOUNT_HOME/Projects/shield-kitty/systemd"
SRC_SEAL="$ACCOUNT_HOME/Projects/shield-kitty-forensics/systemd"
# These MUST be user units, not system units: their ExecStart uses %h, which in
# a system unit expands to /root and yields units that can never start.
# /etc/systemd/user and ~/.config/systemd/user are both read by systemd; the
# live install on this machine is in the latter. Keep this in sync with
# `systemctl --user is-enabled` when checking.
DEST="${SHIELD_KITTY_UNIT_DIR:-/etc/systemd/user}"

if [[ "${1:-}" == "--remove" ]]; then
  echo "Removing Shield Kitty units..."
  for u in "${UNITS[@]}"; do
    systemctl --global disable "$u" >/dev/null 2>&1 || true
    rm -f "$DEST/$u"
  done
  systemctl --user disable shield-kitty-watch.service evidence-seal.timer >/dev/null 2>&1 || true
  loginctl disable-linger "$ACCOUNT" 2>/dev/null || true
  systemctl daemon-reload
  echo "  [ok] removed. Verify with: systemctl --user list-unit-files | grep -E 'shield|evidence'"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "ERROR: needs root: sudo $0" >&2; exit 1; }

# ── preflight ──────────────────────────────────────────────────────────────
missing=0
for f in "$SRC_WATCH/shield-kitty-watch.service" \
         "$SRC_SEAL/evidence-seal.service" \
         "$SRC_SEAL/evidence-seal.timer"; do
  if [ ! -f "$f" ]; then
    echo "  [!!] missing source unit: $f"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "  Refusing to install a partial set: a watcher with no sealer, or a" >&2
  echo "  timer pointing at a missing service, is worse than neither." >&2
  exit 1
fi

install -d -m 0755 "$DEST"
install -m 0644 -o root -g root "$SRC_WATCH/shield-kitty-watch.service" "$DEST/"
install -m 0644 -o root -g root "$SRC_SEAL/evidence-seal.service"        "$DEST/"
install -m 0644 -o root -g root "$SRC_SEAL/evidence-seal.timer"          "$DEST/"
echo "  [ok] installed $(ls -1 "$DEST" | grep -cE 'shield|evidence') unit(s) into $DEST"

# ── lingering: start the user manager at boot, without a login ─────────────
if loginctl enable-linger "$ACCOUNT" 2>/dev/null; then
  echo "  [ok] linger enabled for $ACCOUNT (user manager starts at boot)"
else
  echo "  [!!] could not enable linger; units will only run while $ACCOUNT is logged in" >&2
fi

# ── enable globally so they apply to the account, not just this shell ──────
systemctl daemon-reload
for u in shield-kitty-watch.service evidence-seal.timer; do
  systemctl --global enable "$u" >/dev/null 2>&1 \
    && echo "  [ok] globally enabled: $u" \
    || echo "  [!!] could not globally enable $u" >&2
done

# ── stop the ad-hoc instance so two watchers do not double-alert ──────────
existing=$(pgrep -f 'shield-kitty-watch\.py' | grep -v "^$$\$" || true)
if [ -n "$existing" ]; then
  echo "  found manually started watcher: PID(s) $(echo "$existing" | tr '\n' ' ')"
  echo "  stopping it so the unit is the single owner"
  # shellcheck disable=SC2086
  kill $existing 2>/dev/null || true
  sleep 2
  # shellcheck disable=SC2086
  kill -9 $existing 2>/dev/null || true
  echo "  [ok] stopped"
fi

# ── start now, as the user, so the display socket is reachable ─────────────
echo
echo "  starting under the $ACCOUNT user manager..."
runuser -u "$ACCOUNT" -- systemctl --user daemon-reload 2>/dev/null || true
runuser -u "$ACCOUNT" -- systemctl --user enable --now shield-kitty-watch.service 2>/dev/null || true
runuser -u "$ACCOUNT" -- systemctl --user start evidence-seal.timer 2>/dev/null || true

# ── verify behaviour, not just that the files exist ──────────────────────
echo
echo "  verification:"
fail=0
if runuser -u "$ACCOUNT" -- systemctl --user is-active shield-kitty-watch.service 2>/dev/null | grep -q active; then
  echo "    [ok] shield-kitty-watch.service active"
else
  echo "    [!!] watcher NOT active"
  runuser -u "$ACCOUNT" -- systemctl --user status shield-kitty-watch.service --no-pager 2>&1 | tail -8 | sed 's/^/        /'
  fail=1
fi

if runuser -u "$ACCOUNT" -- systemctl --user is-active evidence-seal.timer 2>/dev/null | grep -q active; then
  echo "    [ok] evidence-seal.timer active"
else
  echo "    [!!] evidence-seal.timer NOT active"
  fail=1
fi

# Exactly one watcher. Two means duplicate alerts, which trains you to ignore them.
count=$(pgrep -fc 'shield-kitty-watch\.py' 2>/dev/null || echo 0)
if [ "${count:-0}" -le 1 ]; then
  echo "    [ok] exactly $count watcher process(es) running"
else
  echo "    [!!] $count watchers running -- would double-alert"
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "  [ok] Shield Kitty will now survive a reboot"
else
  echo "  [!!] some units did not come up cleanly" >&2
fi
echo
echo "  Check after your reboot with:"
echo "    systemctl --user is-active shield-kitty-watch.service evidence-seal.timer"
exit "$fail"
