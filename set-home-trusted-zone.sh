#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
# set-home-trusted-zone.sh — allow KDE Connect ONLY on a network you control.
#
# DEFERRED / NOT APPLIED. Prepared so it is ready when you have a home
# network you actually administer. Until then, everything stays in the
# strict `public` zone and kdeconnectd stays blocked.
#
# Usage:
#   ./set-home-trusted-zone.sh                 # dry run, changes nothing
#   sudo ./set-home-trusted-zone.sh --apply "YourHomeSSID"
#
# Why this is deferred: a firewalld "trusted" zone is only meaningful on a
# network where you control the DHCP server and there are no other devices.
# On a network you do not administer, allowing anything is worse than
# blocking everything, because it advertises the exception to you.

set -euo pipefail

ZONE="home-net"
APPLY=0
SSID=""

while [ $# -gt 0 ]; do
  case "$1" in
    --apply) APPLY=1; shift ;;
    *) SSID="$1"; shift ;;
  esac
done

hr() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

if [ "$APPLY" -eq 0 ]; then
  hr "DRY RUN — nothing will be changed"
  echo "  zone to create : ${ZONE}"
  echo "  ssid to bind   : ${SSID:-<not given>}"
  echo "  services opened: kdeconnectd, mdns  (NOTHING else)"
  echo "  target         : default  (drops all unlisted inbound)"
  echo
  echo "  To apply later:"
  echo "    sudo $0 --apply \"YourHomeSSID\""
  exit 0
fi

if [ -z "$SSID" ]; then
  echo "ERROR: --apply requires the SSID of the network you administer." >&2
  exit 1
fi

# ── SAFETY GATE ──────────────────────────────────────────────────────────
# Refuse to trust a network that is not actually encrypted. An open or
# WEP network cannot be considered yours even if you know the password.
hr "Safety gate — verifying the network is encrypted"

conn=$(nmcli -t -f NAME,TYPE con show | awk -F: -v s="$SSID" '$1==s && $2=="802-11-wireless"{print $1; exit}')
if [ -z "$conn" ]; then
  echo "ERROR: no saved connection named '${SSID}'." >&2
  echo "  Connect to it once, or create the profile, then re-run." >&2
  exit 1
fi

sec=$(nmcli -g 802-11-wireless-security.key-mgmt con show "$conn" 2>/dev/null)
echo "  connection : ${conn}"
echo "  key-mgmt   : ${sec:-<none>}"

case "$sec" in
  "wpa-psk"|"sae"|"wpa-eap")
    echo "  [ok] WPA2-AES / WPA3-SAE — acceptable to trust"
    ;;
  "wpa-none"|"owe"|"wpa-open"|"none"|"")
    echo "  [!!] REFUSING: open or unauthenticated network." >&2
    echo "       Anyone can join and impersonate your peers. Not trustworthy." >&2
    exit 1
    ;;
  *)
    echo "  [!!] REFUSING: unrecognised key-mgmt '${sec}'." >&2
    exit 1
    ;;
esac

# ── CREATE ZONE ──────────────────────────────────────────────────────────
# NOTE: target is 'default', NOT 'trusted'. The 'trusted' target accepts
# ALL inbound traffic, which is the opposite of what we want. We want a
# normal dropping zone with a two-service allowlist.
hr "Creating zone '${ZONE}' (target: default, not trusted)"

if firewall-cmd --permanent --get-zones 2>/dev/null | grep -qx "$ZONE"; then
  echo "  zone already exists — reusing"
else
  firewall-cmd --permanent --new-zone="$ZONE"
  echo "  [ok] created"
fi

firewall-cmd --permanent --zone="$ZONE" --set-target=default
firewall-cmd --permanent --zone="$ZONE" --add-service=kdeconnectd
firewall-cmd --permanent --zone="$ZONE" --add-service=mdns
firewall-cmd --permanent --zone="$ZONE" --add-service=dhcpv6-client
firewall-cmd --reload
echo "  [ok] allowed: kdeconnectd, mdns, dhcpv6-client — nothing else"

# ── BIND SSID ────────────────────────────────────────────────────────────
hr "Binding '${SSID}' to ${ZONE}"
# Discover the interface from the connection rather than hardcoding wlo0.
# Interface names are not stable across reboots, machines and adapters
# (wlo1 here, wlo0 on a different host), and a stale name makes the
# firewall bind nothing while still reporting success.
IFACE=$(nmcli -g connection.interface-name con show "$conn" 2>/dev/null)
[ -z "$IFACE" ] && IFACE=$(nmcli -g GENERAL.DEVICE con show "$conn" 2>/dev/null)
[ -z "$IFACE" ] && IFACE=$(nmcli -g IP4.DEVICE con show "$conn" 2>/dev/null)
if [ -z "$IFACE" ] || [ ! -e "/sys/class/net/$IFACE" ]; then
  echo "  [!!] could not determine the interface for '${conn}'." >&2
  echo "       Set the zone by connection name instead, then verify with:" >&2
  echo "         firewall-cmd --get-zone-of-interface=<iface>" >&2
  exit 1
fi
echo "  interface: ${IFACE}"
firewall-cmd --permanent --zone="$ZONE" --change-interface="$IFACE" 2>/dev/null || true
nmcli con mod "$conn" connection.zone "$ZONE"
nmcli con up "$conn" >/dev/null
echo "  [ok] '${conn}' (${IFACE}) now uses zone ${ZONE}"

hr "Result"
echo "  Verify:"
echo "    firewall-cmd --get-zone-of-interface=${IFACE}"
echo "    firewall-cmd --zone=${ZONE} --list-all"
echo
echo "  REVERT (back to fully strict):"
echo "    nmcli con mod \"${conn}\" connection.zone public"
echo "    nmcli con up \"${conn}\""
echo "    sudo firewall-cmd --permanent --zone=${ZONE} --remove-service=kdeconnectd"
