#!/bin/bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Close out the four loose ends from the 2026-09-26 hardening audit.
# Run as:  sudo bash ~/Projects/zen-hardening/closeout-20260926.sh
#
# Safe to re-run: every step is idempotent.
set -euo pipefail

F2B=/etc/fail2ban/jail.d/shield-kitty.conf
MY_IP="$(ip -4 -o addr show wlo1 | awk '{print $4}' | cut -d/ -f1)"
STAMP="$(date +%Y%m%d-%H%M%S)"

echo "=== 1. fail2ban ignoreip: replace the stale address with the live one ==="
# Was 10.197.250.246/32 (an address this machine no longer holds). With
# maxretry=4 and bantime=86400 that is not a self-lockout risk, but it means
# the ONE entry that should cover this machine covers nothing, so a fat-fingered
# password over SSH bans you for a day.
cp -a "$F2B" "$F2B.bak.$STAMP"
OLD_IPS="10.197.250.246/32"
NEW_IPS="$MY_IP/32"

if grep -qF "$OLD_IPS" "$F2B"; then
    sed -i "s|$OLD_IPS|$NEW_IPS|g" "$F2B"
    echo "  replaced $OLD_IPS -> $NEW_IPS"
else
    if ! grep -qF "$NEW_IPS" "$F2B"; then
        sed -i "s|^ignoreip = \(.*\)|ignoreip = \1 $NEW_IPS|" "$F2B"
        echo "  appended $NEW_IPS"
    else
        echo "  already correct ($NEW_IPS present)"
    fi
fi
grep -n '^ignoreip' "$F2B"

echo
echo "=== 2. fail2ban: disable the [sshd] jail (sshd is disabled) ==="
# Dead config. A jail whose backend never logs is not harmless -- it sits in
# `fail2ban-client status` implying protection that does not exist.
if systemctl is-enabled sshd >/dev/null 2>&1; then
    echo "  sshd is ENABLED -- leaving the [sshd] jail alone, it is correct"
else
    python3 - "$F2B" <<'PY'
import re, sys
p = sys.argv[1]
src = open(p).read()
# Flip only the enabled= inside the [sshd] section, not the first match.
def fix(m):
    body = m.group(0)
    return re.sub(r'(?m)^enabled\s*=\s*true', 'enabled  = false', body)
out = re.sub(r'(?ms)^\[sshd\].*?(?=^\[|\Z)', fix, src)
open(p, 'w').write(out)
PY
    grep -n -A2 '^\[sshd\]' "$F2B"
fi

echo
echo "=== 3. fail2ban: validate and reload ==="
fail2ban-client -t
systemctl restart fail2ban
for _ in $(seq 40); do
    fail2ban-client ping >/dev/null 2>&1 && break
    sleep 0.25
done
fail2ban-client ping
fail2ban-client status

echo
echo "=== 4. Shield Kitty USB device policy: actually install it ==="
# This was never run. Without it the enforcement half of Shield Kitty does not
# exist: no /opt/shield-kitty, no udev rule, no state dir. Only the
# notification half (shield-kitty-watch.service) was live.
bash /home/livings/Projects/shield-kitty/device-blacklist/install.sh

echo
echo "=== verify ==="
ls -la /etc/udev/rules.d/99-shield-kitty-devices.rules
ls -la /opt/shield-kitty/ /var/lib/shield-kitty/
fail2ban-client status
echo
echo "DONE."
