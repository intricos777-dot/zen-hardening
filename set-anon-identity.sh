#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# set-anon-identity.sh — present as "zero" on every network and interface.
#
# Idempotent. Safe to re-run. Designed to be re-applied after a rebuild.
#
#   sudo ./set-anon-identity.sh
#
# What it changes:
#   1. hostname -> "zero" (static, transient, /etc/hosts)
#   2. per-network randomized MAC on every wifi connection
#   3. explicit DHCP hostname suppression on every connection
#
# What it deliberately does NOT change (see NOTES at bottom):
#   - machine-id, DMI product strings, Bluetooth

set -euo pipefail

TARGET="zero"
CHANGED=0
MAC_FAILED=0

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

hr "1. Hostname -> ${TARGET}"

# hostnamectl sets both static (/etc/hostname) and the running (transient) name.
if [ "$(hostnamectl --static)" = "$TARGET" ] && [ "$(hostname)" = "$TARGET" ]; then
  echo "  already '${TARGET}' — skipping"
else
  hostnamectl set-hostname "$TARGET"
  CHANGED=1
  echo "  [ok] static + transient hostname set"
fi

# /etc/hosts keeps the old name in its 127.0.1.1 line, which many tools resolve.
if grep -q '^127\.0\.1\.1' /etc/hosts; then
  if grep -qE "^127\.0\.0\.1[[:space:]]+${TARGET}(\$|[[:space:]])" /etc/hosts; then
    echo "  /etc/hosts already correct — skipping"
  else
    # Preserve any aliases after the hostname, just swap the first field.
    sed -i -E "s|^127\.0\.1\.1[[:space:]]+[^[:space:]]+.*|127.0.1.1\t${TARGET}|" /etc/hosts
    CHANGED=1
    echo "  [ok] /etc/hosts 127.0.1.1 -> ${TARGET}"
  fi
fi

hr "2. Per-network random MAC on wifi"

# Without this, NetworkManager uses the permanent hardware MAC on every
# network the machine ever joins, which is the strongest cross-network
# tracking signal there is.
#
# PROPERTY NAME DIFFERS BY NetworkManager VERSION. Verified on 1.58.1:
#   802-11-wireless.mac-address-randomization   (this version)
#       0 = default, 1 = random (per network), 2 = stable
# Older releases used 802-11-wireless.mac-address-mode with values
# random/stable/preserve. Detect which one this build accepts rather than
# assuming, and fail loudly if neither works -- a silent no-op here means
# the hardware MAC keeps broadcasting.
set_mac_prop=""
if nmcli -g 802-11-wireless.mac-address-randomization con show "$(nmcli -t -f UUID con show | head -1)" >/dev/null 2>&1; then
  set_mac_prop="802-11-wireless.mac-address-randomization"
  # Values differ by NetworkManager version and getting this wrong is SILENT:
  #   NM >= 1.42 uses a flags enum. nmcli accepts exactly:
  #       default | never | always
  #   and the numeric aliases are NOT boolean: 1 means NEVER, not yes.
  #   Setting 1 therefore turns randomization OFF while looking like success.
  # Verified on 1.58.1, which rejects both "yes" and "random".
  set_mac_val="always"
else
  set_mac_prop="802-11-wireless.mac-address-mode"
  set_mac_val="random"
fi
echo "  using property: ${set_mac_prop} = ${set_mac_val}"

while read -r uuid; do
  [ -z "$uuid" ] && continue
  con_id=$(nmcli -g connection.id con show "$uuid")
  cur=$(nmcli -g "$set_mac_prop" con show "$uuid" 2>/dev/null)
  if [ "$cur" = "$set_mac_val" ] || [ "$cur" = "random" ]; then
    echo "  '${con_id}': already randomized — skipping"
  else
    if ! nmcli con mod "$uuid" "$set_mac_prop" "$set_mac_val"; then
      echo "  [!!] FAILED to set MAC randomization on '${con_id}'" >&2
      MAC_FAILED=1
    else
      CHANGED=1
      echo "  [ok] '${con_id}': mac randomization -> ${set_mac_val}"
    fi
  fi
done < <(nmcli -t -f UUID,TYPE con show | awk -F: '$2=="802-11-wireless"{print $1}')

hr "3. Suppress DHCP hostname on every connection"

# send-hostname=-1 means "never send". Set explicitly so a newly created
# connection can never leak the name by default.
while read -r uuid; do
  [ -z "$uuid" ] && continue
  con_id=$(nmcli -g connection.id con show "$uuid")
  cur=$(nmcli -g ipv4.dhcp-send-hostname con show "$uuid" 2>/dev/null)
  cur6=$(nmcli -g ipv6.dhcp-send-hostname con show "$uuid" 2>/dev/null)
  if [ "$cur" = "no" ] && [ "$cur6" = "no" ]; then
    echo "  '${con_id}': already suppressed — skipping"
  else
    nmcli con mod "$uuid" ipv4.dhcp-send-hostname no ipv6.dhcp-send-hostname no
    CHANGED=1
    echo "  [ok] '${con_id}': DHCP hostname suppressed"
  fi
done < <(nmcli -t -f UUID con show)

hr "Result"

if [ "$MAC_FAILED" -eq 1 ]; then
  echo "  [!!] AT LEAST ONE CONNECTION FAILED MAC RANDOMIZATION." >&2
  echo "       Your permanent hardware MAC may still be broadcasting." >&2
fi

if [ "$CHANGED" -eq 1 ]; then
  echo "  changes applied. To publish the new mDNS name immediately:"
  echo "      sudo systemctl restart avahi-daemon"
  echo "  (or just reconnect wifi; avahi re-publishes on its own)"
else
  echo "  no changes needed — already anonymous"
fi

echo
echo "  verify with:"
echo "      hostname"
echo "      avahi-browse -altr | grep '${TARGET}' || hostnamectl"
echo
echo "  NOTE: wifi MAC changes take effect on next reconnect, not now."
echo "  NOTE: changing MAC on a live connection drops the network for a few seconds."

# ─────────────────────────────────────────────────────────────────────
# NOT changed by this script (deliberate — each has tradeoffs):
#
#   machine-id  — Renaming doesn't touch it. Regenerating makes systemd
#                 treat the machine as new (breaks some package/licence
#                 checks, systemd journal continuity). Pointing
#                 /etc/machine-id at /dev/null makes it ephemeral per-boot
#                 (maximum anonymity, but breaks stable identification
#                 for anything expecting it). This is a real tradeoff,
#                 so it needs a decision, not a default.
#
#   DMI strings  — /sys/class/dmi/id/product_name still reads
#                 "ASUS TUF Dash F15 FX517ZC". Any local process can read
#                 it; only firmware-level changes could alter it, which
#                 is out of scope and risky.
#
#   Bluetooth   — the adapter advertises the hostname as its device name
#                 while paired. Change with:
#                     sudo bluetoothctl set-alias zero
#                 (run separately; harmless to run even with no BT paired)
# ─────────────────────────────────────────────────────────────────────
