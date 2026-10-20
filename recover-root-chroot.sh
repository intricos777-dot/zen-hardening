#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
# recover-root-chroot.sh — regain root from inside a chroot on a live USB.
#
#   pkexec bash ~/Projects/zen-hardening/RECOVER-SUDO.sh    # sudo broken, password KNOWN
#   # ...boot Arch ISO, unlock LUKS, mount, chroot, then:
#   bash /mnt/home/livings/Projects/zen-hardening/recover-root-chroot.sh
#
# WHY A CHROOT SCRIPT AND NOT A `su` FLAG
#
# An in-band bypass cannot be the recovery path for a forgotten password.
# sudo, pkexec and su all authenticate with the credential that was lost. If
# any of them could grant root without it, that is not a recovery hatch, it is
# a permanent unauthenticated root backdoor that anything running as this user
# can call. So the forgot-password case is recovered from outside the running
# system, where no credential is required because none is being presented.
#
# WHAT THIS DOES
#   1. Reports which of the four lockout causes is actually present.
#   2. Resets the password for an account.
#   3. Optionally restores the pre-nulllock PAM stacks, for the case where
#      nulllock itself is what is blocking sign-in.
#
# IT CHANGES NOTHING UNTIL YOU ANSWER, and it never deletes.

set -uo pipefail

[[ $EUID -eq 0 ]] || { echo "must run as root inside the chroot" >&2; exit 1; }

say() { printf '  %s\n' "$*"; }
ok()  { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
bad() { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; }
warn(){ printf '  \033[33m[warn]\033[0m %s\n' "$*"; }

echo "=============================================="
echo " root recovery (running inside a chroot)"
echo "=============================================="

# ── 1. diagnose ─────────────────────────────────────────────────────────
echo
echo "-- 1. what is actually blocking you --"

PAM_BK=""
for d in /var/backups/remove-faillock-nulllock-2026-10-13/*/; do
  [ -f "$d/_etc_pam.d_system-auth" ] && PAM_BK="$d"
done

if [ -n "$PAM_BK" ]; then
  ok "pre-nulllock PAM backup found: $PAM_BK"
else
  warn "no PAM backup found — nulllock cannot be rolled back from here"
fi

if visudo -c >/dev/null 2>&1; then
  ok "sudoers parses (sudo is not syntactically broken)"
else
  bad "sudoers does NOT parse — this is the 2026-09-26 outage again"
  say "restore it with:  install -m 0440 -o root -g root /dev/stdin /etc/sudoers.d/10-installer <<< '%wheel ALL=(ALL) ALL'"
fi

# An empty password field plus nulllock is an unbreakable-from-inside account.
EMPTY=$(awk -F: '$2=="" {print $1}' /etc/shadow 2>/dev/null)
if [ -n "$EMPTY" ]; then
  bad "EMPTY password field on: $(echo "$EMPTY" | tr '\n' ' ')"
  say "with nulllock in force these accounts cannot authenticate at all"
else
  ok "no account has an empty password field (nulllock is satisfiable)"
fi

if grep -rqE '^[[:space:]]*[^#[:space:]].*pam_faillock\.so' /etc/pam.d/ 2>/dev/null; then
  warn "pam_faillock.so is still active in /etc/pam.d"
else
  ok "faillock is out of every PAM stack"
fi

# ── 2. act ──────────────────────────────────────────────────────────────
echo
echo "-- 2. reset a password --"
read -rp "   account to reset (blank to list, 'q' to quit): " ACCT
if [ -z "$ACCT" ]; then
  awk -F: '$3>=1000 && $3<65534 {printf "     %s\n", $1}' /etc/shadow
  exit 0
fi
[ "$ACCT" = "q" ] && exit 0

if ! getent passwd "$ACCT" >/dev/null; then
  bad "no such account: $ACCT"; exit 1
fi

if passwd "$ACCT"; then
  ok "password reset for $ACCT"
  # The field is now a hash, not empty, so nulllock cannot be the thing that
  # locks this account out afterwards.
  FIELD=$(awk -F: -v u="$ACCT" '$1==u {print $2}' /etc/shadow)
  if [ -n "$FIELD" ]; then
    ok "shadow field for $ACCT is set (${#FIELD} chars) — not empty, so nulllock admits it"
  else
    bad "shadow field still EMPTY after reset — account cannot authenticate"
  fi
else
  bad "passwd failed for $ACCT"; exit 1
fi

echo
read -rp "   roll PAM back to the pre-nulllock stacks? [y/N] " RB
case "$RB" in
  [yY]*)
    if [ -z "$PAM_BK" ]; then
      bad "no backup available; PAM left exactly as it is"
    else
      # Restore only; never delete. -a keeps mode and ownership.
      install -m 0644 -o root -g root "$PAM_BK/_etc_pam.d_system-auth"     /etc/pam.d/system-auth
      install -m 0644 -o root -g root "$PAM_BK/_etc_pam.d_sddm-autologin"  /etc/pam.d/sddm-autologin
      ok "PAM restored from $PAM_BK"
      warn "this RE-ADDS nullok. Re-check with sentinel once you are back in:"
      say "python3 ~/Projects/lifsea-security-suite/zen-hardening/sentinel.py check"
    fi
    ;;
  *) say "PAM left as-is (nulllock still in force)" ;;
esac

echo
echo "=============================================="
echo " done — unmount and reboot:"
echo "   exit"
echo "   umount -R /mnt"
echo "   reboot"
echo "=============================================="