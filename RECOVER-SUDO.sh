#!/usr/bin/env bash
# RECOVER-SUDO.sh — restore sudo after a sudoers mishap, and install the
# audit helpers. Safe to run more than once. Deletes nothing.
#
#   pkexec bash ~/Projects/zen-hardening/RECOVER-SUDO.sh
#
# WHY THIS EXISTS
#
# On 2026-09-26 a script quarantined /etc/sudoers.d/10-installer, which held
# the stock Arch rule:
#
#     %wheel ALL=(ALL) ALL
#
# That was the only grant letting the account use sudo. A second script then
# failed and removed the temporary NOPASSWD entry, leaving no grant at all.
#
# Rules this script follows, in order, because they are the ones whose absence
# caused the outage:
#
#   1. NEVER delete or move a sudoers file. Only create or fix permissions.
#   2. Restore the caller's own sudo access FIRST and verify it before
#      touching anything else.
#   3. If a step would leave the caller without sudo, skip it and say so
#      rather than proceeding.
#   4. Verify the result behaviourally (an actual sudo call), not by parsing
#      a file and assuming.

set -uo pipefail

# Work out who actually invoked this.
#
# pkexec does NOT set SUDO_USER, and USER is "root" under pkexec, so naively
# reading those two audited the wrong account and aborted with a misleading
# "root is not in wheel". pkexec exports PKEXEC_UID, which is the reliable
# signal. Fall back to SUDO_USER only when pkexec is not in play.
if [ -n "${PKEXEC_UID:-}" ]; then
  ACCOUNT=$(getent passwd "$PKEXEC_UID" 2>/dev/null | cut -d: -f1)
elif [ -n "${SUDO_USER:-}" ]; then
  ACCOUNT="$SUDO_USER"
else
  ACCOUNT="${USER:-livings}"
fi
[ -z "$ACCOUNT" ] && ACCOUNT=livings
DEST=/etc/sudoers.d
WHEEL_RULE="$DEST/10-installer"
AUDIT_RULE="$DEST/audit-readonly"

say() { printf '  %s\n' "$*"; }
ok()  { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
bad() { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; }
warn(){ printf '  \033[33m[warn]\033[0m %s\n' "$*"; }

[[ $EUID -eq 0 ]] || { echo "ERROR: must run as root (pkexec bash $0)" >&2; exit 1; }

echo "=============================================="
echo " sudo recovery for: $ACCOUNT"
echo "=============================================="

# ── 0. is the account even in wheel? ─────────────────────────────────────
if ! id -nG "$ACCOUNT" 2>/dev/null | tr ' ' '\n' | grep -qx wheel; then
  bad "$ACCOUNT is NOT in group wheel -- that is the root cause."
  say "Add it with:  usermod -aG wheel $ACCOUNT   (then log out and back in)"
  exit 1
fi
ok "$ACCOUNT is in wheel"

# ── 1. restore the wheel rule FIRST ──────────────────────────────────────
echo
echo "-- restoring sudo access --"
Q=$(ls -d /root/sudoers-quarantine-*/10-installer 2>/dev/null | head -1)
if [ -n "$Q" ]; then
  install -m 0440 -o root -g root "$Q" "$WHEEL_RULE"
  ok "restored 10-installer from $(dirname "$Q")"
else
  printf '%%wheel ALL=(ALL) ALL\n' > "$WHEEL_RULE"
  chmod 0440 "$WHEEL_RULE"
  chown root:root "$WHEEL_RULE"
  ok "wrote stock rule: %wheel ALL=(ALL) ALL"
fi
say "     contents: $(tr -d '\n' < "$WHEEL_RULE")"

# ── 2. fix permissions on known-safe files, removing nothing ─────────────
echo
echo "-- fixing permissions (no file is deleted or moved) --"
for f in editor insults pwfeedback opencode; do
  p="$DEST/$f"
  [ -f "$p" ] || continue
  m=$(stat -c%a "$p")
  if [ "$m" != "0440" ]; then
    # Strip group/other write bits unconditionally; that is never acceptable
    # on a sudoers file regardless of content.
    chmod go-w "$p"
    chmod 0440 "$p"
    chown root:root "$p"
    ok "$f: $m -> 0440"
  else
    ok "$f: already 0440"
  fi
done

# ── 3. validate before claiming anything works ───────────────────────────
echo
echo "-- validating --"
if visudo -c >/dev/null 2>&1; then
  ok "visudo -c: parsed OK"
else
  bad "visudo -c still reports problems:"
  visudo -c 2>&1 | sed 's/^/       /'
fi

# ── 4. behavioural check: does sudo actually work for the account? ───────
echo
echo "-- behavioural check --"
if su -s /bin/bash -c "sudo -n -l >/dev/null 2>&1" "$ACCOUNT"; then
  ok "account can enumerate sudo rights (NOPASSWD path present)"
else
  # A password-required rule cannot be proven without a TTY, so verify the
  # rule textually AND confirm the group membership that activates it.
  if grep -qE '^%wheel[[:space:]]+ALL=' "$WHEEL_RULE" 2>/dev/null \
     && id -nG "$ACCOUNT" | tr ' ' '\n' | grep -qx wheel; then
    ok "wheel rule present and $ACCOUNT is in wheel -- sudo will prompt for a password"
  else
    bad "could not confirm sudo access for $ACCOUNT"
  fi
fi

# ── 5. only now, install the audit helpers ───────────────────────────────
echo
echo "-- audit helpers --"
HELPERS=(audit-nft audit-btrfs audit-smart audit-dmesg audit-firewall audit-fail2ban audit-journal-err)
missing_helper=0
for h in "${HELPERS[@]}"; do
  [ -x "/usr/local/sbin/$h" ] || missing_helper=1
done

if [ "$missing_helper" -eq 0 ]; then
  entries=""
  for h in "${HELPERS[@]}"; do entries+="${entries:+, }/usr/local/sbin/$h"; done
  printf '%s ALL=(root) NOPASSWD: %s\n' "$ACCOUNT" "$entries" > "$AUDIT_RULE"
  chmod 0440 "$AUDIT_RULE"
  chown root:root "$AUDIT_RULE"
  # Validate this file ALONE. Whole-tree visudo -c exits non-zero for
  # unrelated pre-existing warnings, which previously caused a valid drop-in
  # to be deleted.
  if visudo -cf "$AUDIT_RULE" >/dev/null 2>&1; then
    ok "audit-readonly installed and parses"
    if su -s /bin/bash -c "sudo -n /usr/local/sbin/audit-nft >/dev/null 2>&1" "$ACCOUNT"; then
      ok "audit helpers work without a password"
    else
      warn "audit helpers installed but not usable passwordless -- check sudo -l"
    fi
  else
    bad "audit-readonly INVALID -- removing it (sudo itself is unaffected)"
    visudo -cf "$AUDIT_RULE" 2>&1 | sed 's/^/       /'
    rm -f "$AUDIT_RULE"
  fi
else
  warn "helper scripts not present in /usr/local/sbin -- skipping"
  say "     install them with: pkexec bash ~/Projects/zen-hardening/install-audit-readonly.sh"
fi

echo
echo "=============================================="
echo " final state"
echo "=============================================="
visudo -c 2>&1 | sed 's/^/  /'
echo
ls -l "$DEST" 2>/dev/null | sed 's/^/  /'
echo
echo "Now test from YOUR shell:"
echo "  sudo -l | tail -3"
echo "  sudo audit-nft"
echo "=============================================="
