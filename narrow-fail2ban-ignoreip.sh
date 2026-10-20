#!/bin/bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# narrow-fail2ban-ignoreip.sh — replace the blanket 10.0.0.0/8 exemption.
#
# WHY THIS EXISTS
#
# The shipped config ignored 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
# That was a deliberate choice on the assumption that this was a shared
# enterprise network, where banning a /8 means 24-hour-banning a colleague who
# mistyped a password five times. On a single-user local-only machine that
# reasoning does not apply: there are no colleagues to protect, and the
# exemption was covering the entire internet-sized address space of your own
# network. Anyone on the network who failed five attempts would walk away
# untouched forever.
#
# The /8 is therefore removed. What is ignored instead is kept deliberately
# narrow and is derived from the live system rather than hardcoded, so it cannot
# silently go stale:
#
#   - loopback, IPv4 and IPv6        (must never be ban-able)
#   - link-local ranges              (169.254/16, fe80::/10)
#   - THIS machine's own address     (a local process must not ban itself)
#   - THE DEFAULT GATEWAY            (banning it would sever all networking)
#
# The gateway entry is the one that is easy to get wrong. It is kept ignored on
# purpose: fail2ban bans at the IP layer, and a ban against the next-hop router
# is indistinguishable from losing the network. If some future gateway ever did
# generate auth failures you would want that visible, not silently dropped.
#
# Neither sshd nor recidive is what makes a ban happen. sshd is inactive and
# recidive only re-bans what another jail already banned, so narrowing this
# value makes future bans possible rather than banning anything right now. See
# the firewall for the part that actually stops someone looking at the machine.
#
# Usage:
#   ./narrow-fail2ban-ignoreip.sh --check   # report, change nothing
#   sudo ./narrow-fail2ban-ignoreip.sh      # back up, edit, validate, reload

set -euo pipefail

CONF=/etc/fail2ban/jail.d/shield-kitty.conf
BACKUP="${CONF}.bak.$(date +%Y%m%d-%H%M%S)"
RUN=1
[ "${1:-}" = "--check" ] && RUN=0

log() { printf '  %s\n' "$*"; }

OWN_IP="$(ip -4 addr show wlo1 2>/dev/null | grep -oP 'inet \K[0-9.]+' | head -1)"
GATEWAY="$(ip route show default 2>/dev/null | grep -oP 'via \K[0-9.]+' | head -1)"
[ -n "$OWN_IP" ] || { echo "ERROR: could not determine own address on wlo1" >&2; exit 1; }
[ -n "$GATEWAY" ] || { echo "ERROR: could not determine default gateway" >&2; exit 1; }

NEW_IGNORED="127.0.0.1/8 ::1 169.254.0.0/16 fe80::/10 ${OWN_IP}/32 ${GATEWAY}/32"

echo "=== fail2ban ignoreip ==="
echo "  own address : ${OWN_IP}/32"
echo "  gateway     : ${GATEWAY}/32"
echo
echo "  REMOVING: 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16"
echo "  KEEPING  : ${NEW_IGNORED}"

# Show what currently parses as ignored, so the change can be eyeballed.
echo
if fail2ban-client -t >/dev/null 2>&1; then
    echo "  current config validates OK"
else
    echo "  WARNING: current config does NOT validate -- refusing to edit a broken file" >&2
    exit 1
fi

[ "$RUN" = 0 ] && { echo; echo "[check only] nothing changed."; exit 0; }

[ -f "$CONF" ] || { echo "ERROR: $CONF not found" >&2; exit 1; }
echo "  backup     : $BACKUP"
install -m 0640 -o root -g root "$CONF" "$BACKUP"

# Rewrite the ignoreip block. It spans two lines with a continuation indent,
# which makes sed fragile, so parse it instead: consume the 'ignoreip' line and
# every following indented continuation line, then substitute the whole thing.
python3 - "$CONF" "$NEW_IGNORED" <<'PY'
import sys, pathlib
conf, new_ignored = pathlib.Path(sys.argv[1]), sys.argv[2]
text = conf.read_text()
lines = text.split('\n')
out, i = [], 0
while i < len(lines):
    # The shipped comment just above the block says "Never ban the local
    # machine or your own LAN", which is exactly the behaviour being removed.
    # Leave a stale contradictory comment sitting in a security config.
    if lines[i].lstrip().startswith('# Never ban the local machine or your own LAN'):
        out.append('# Never ban this machine, loopback, link-local, or the default gateway.')
        out.append('# The network itself is NOT exempt: single-user local-only box, so')
        out.append('# anyone failing five auth attempts is banned for 24 hours.')
        i += 1
        continue
    if lines[i].lstrip().startswith('ignoreip'):
        i += 1
        while i < len(lines) and lines[i].startswith((' ', '\t')):
            i += 1
        out.append(f'ignoreip = {new_ignored}')
    else:
        out.append(lines[i])
        i += 1
conf.write_text('\n'.join(out))
PY

echo
echo "  --- new ignoreip ---"
grep -A1 '^ignoreip' "$CONF" | sed 's/^/    /'
echo
if fail2ban-client -t >/dev/null 2>&1; then
    echo "  validates OK"
else
    echo "  EDIT PRODUCED AN INVALID CONFIG -- restoring backup" >&2
    install -m 0640 -o root -g root "$BACKUP" "$CONF"
    exit 1
fi
systemctl restart fail2ban
sleep 1
fail2ban-client status >/dev/null 2>&1 && echo "  fail2ban restarted OK" || { echo "  ERROR: fail2ban did not restart" >&2; exit 1; }
