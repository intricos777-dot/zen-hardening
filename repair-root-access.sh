#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# repair-root-access.sh — restore root/sudo access on this host.
#
# Run it as uid 0, from EITHER:
#   - a root TTY:  Ctrl-Alt-F2, log in as livings, then:  su
#                  (if root has no password, use the chroot route below instead)
#   - a chroot from a live USB, per RECOVER-ROOT.md step B:
#                  bash /mnt/home/livings/Projects/zen-hardening/repair-root-access.sh
#
# Nothing here deletes anything. It only restores permissions and adds one
# missing group entry.

set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }

say() { printf '  %s\n' "$*"; }
ok()  { printf '  \033[32m[ok]\033[0m   %s\n' "$*"; }
bad() { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; }
warn(){ printf '  \033[33m[warn]\033[0m %s\n' "$*"; }

echo "=============================================="
echo " root access repair"
echo "=============================================="

# ── 1. the shadow group ──────────────────────────────────────────────────
# Arch ships /etc/shadow as 640 root:shadow. That GID is what lets pam_unix,
# running during authentication, read the password hash. On this host the
# group does not exist at all, and the files are 600 root:root, so pam_unix
# cannot retrieve the hash for any non-root account and reports
#   "auth could not identify password for [livings]"
# which reads exactly like a wrong password but is not one.
echo
echo "-- 1. shadow group --"
if getent group shadow >/dev/null; then
  ok "shadow group already exists: $(getent group shadow)"
else
  # 42 is Arch's conventional shadow gid. It is unused here (verified), and is
  # only a convention -- what matters is that the name exists and the files
  # carry it.
  if groupadd -r -g 42 shadow 2>/dev/null; then
    ok "created shadow group (gid 42)"
  else
    groupadd -r shadow && ok "created shadow group (kernel-assigned gid)"
  fi
  getent group shadow | sed 's/^/       /'
fi

# ── 2. shadow file permissions ───────────────────────────────────────────
echo
echo "-- 2. shadow file permissions --"
for f in /etc/shadow /etc/gshadow; do
  [ -f "$f" ] || { warn "$f absent"; continue; }
  before=$(stat -c '%a %U:%G' "$f")
  chgrp shadow "$f"
  chmod 640 "$f"
  after=$(stat -c '%a %U:%G' "$f")
  if [ "$after" = "640 root:shadow" ]; then
    ok "$f: $before -> $after"
  else
    bad "$f: still $after (expected '640 root:shadow')"
  fi
done

# ── 3. polkit PAM service ────────────────────────────────────────────────
# /etc/pam.d/polkit-1 is missing. polkit ships /usr/lib/pam.d/polkit-1, but PAM
# only reads /etc/pam.d/, so every GUI privilege prompt silently fell through
# to /etc/pam.d/other, which is pam_deny. That is why the KDE dialog returned
# "Authentication token manipulation error" instead of prompting properly.
echo
echo "-- 3. polkit PAM service --"
if [ -e /etc/pam.d/polkit-1 ]; then
  ok "/etc/pam.d/polkit-1 already present"
elif [ -f /usr/lib/pam.d/polkit-1 ]; then
  ln -s /usr/lib/pam.d/polkit-1 /etc/pam.d/polkit-1
  ok "linked /etc/pam.d/polkit-1 -> /usr/lib/pam.d/polkit-1"
else
  warn "/usr/lib/pam.d/polkit-1 not found - install the polkit package"
fi

# ── 4. verify ────────────────────────────────────────────────────────────
echo
echo "-- 4. verification --"
T="livings"
if [ "$(awk -F: -v u="$T" '$1==u {print $2}' /etc/shadow)" = "" ]; then
  bad "$T has an EMPTY password field - it cannot authenticate under nulllock"
  say "set one with:  passwd $T"
else
  ok "$T password field is set (${#T} chars in name, hash present)"
fi

echo
echo "  now test, as $T, in a NEW shell:"
echo "    sudo -v            # expect: no insult, silent success"
echo "    sudo -n true && echo SUDO_OK"
echo
echo "  if sudo still refuses, capture the exact reason:"
echo "    journalctl -n 20 --no-pager | grep -i pam_unix"
echo "=============================================="