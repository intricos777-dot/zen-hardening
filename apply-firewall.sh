#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# apply-firewall.sh — install and activate the strict workstation zone.
#
# Idempotent. Safe to re-run. Run as root:
#   sudo bash apply-firewall.sh
#
# Works around an Arch packaging bug: fail2ban.service declares
#   PartOf=iptables.service firewalld.service ip6tables.service ...
# PartOf= propagates stop/restart in BOTH directions, so "systemctl restart
# firewalld" makes systemd plan a restart of fail2ban while the same
# transaction stops it -> "Transaction contains conflicting jobs". We work
# around it by sequencing: stop fail2ban, restart firewalld, start fail2ban.
# The unit only needs After=firewalld.service, which it already has.
#
# Exits non-zero unless nft rules are confirmed loaded. A firewall that
# reports "running" while enforcing nothing is worse than a loud failure.

set -euo pipefail

ZONE="workstation"
SRC="/home/livings/Projects/zen-hardening/workstation.xml"
DST="/etc/firewalld/zones/${ZONE}.xml"
CONN="USL - Public"
IFACE="wlo1"

step() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
die()  { printf '\n\033[31mABORT: %s\033[0m\n' "$1" >&2; exit 1; }

# ── 1. install zone ──────────────────────────────────────────────────────
step "1/6  Installing zone"
[ -f "$SRC" ] || die "source zone file not found: $SRC"
install -m 0644 -o root -g root "$SRC" "$DST"
# verify it actually landed — this is what silently failed before
[ -s "$DST" ] || die "zone file did not land at $DST"
echo "  [ok] $DST ($(wc -c < "$DST") bytes)"

# ── 2. offline config check ──────────────────────────────────────────────
step "2/6  Validating configuration"
if ! firewall-offline-cmd --check-config; then
  die "config check failed — refusing to touch the running firewall"
fi
echo "  [ok] config valid"

# ── 3. restart firewalld, working around the fail2ban PartOf= bug ────────
step "3/6  Restarting firewalld (with fail2ban sequencing workaround)"
systemctl stop fail2ban 2>/dev/null || true
if ! systemctl restart firewalld; then
  die "could not restart firewalld"
fi
systemctl start fail2ban 2>/dev/null || echo "  [warn] fail2ban did not start"
echo "  [ok] firewalld=$(systemctl is-active firewalld) fail2ban=$(systemctl is-active fail2ban)"

# ── 4. set default zone ──────────────────────────────────────────────────
step "4/6  Setting default zone"
firewall-cmd --set-default-zone="$ZONE" || die "could not set default zone"
firewall-cmd --zone="$ZONE" --add-interface="$IFACE" --permanent 2>/dev/null || true
echo "  [ok] default zone = $ZONE"

# ── 5. bind the wifi connection to the zone ──────────────────────────────
step "5/6  Binding '${CONN}' to ${ZONE}"
if nmcli con show "$CONN" >/dev/null 2>&1; then
  nmcli con mod "$CONN" connection.zone "$ZONE"
  nmcli con up "$CONN" >/dev/null && echo "  [ok] connection reactivated" \
    || echo "  [warn] nmcli con up failed (zone may still apply on next connect)"
else
  echo "  [warn] connection '${CONN}' not found; interface binding only"
fi

# ── 6. VERIFY enforcement ────────────────────────────────────────────────
step "6/6  Verifying rules are actually loaded"
STATE=$(firewall-cmd --state 2>/dev/null || echo "unknown")
NFT=$(nft list tables 2>/dev/null | grep -ci firewalld || echo 0)
IFZONE=$(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || echo "none")

echo "  firewalld state : $STATE"
echo "  nft firewalld tables : $NFT"
echo "  ${IFACE} zone   : $IFZONE"
echo "  allowed services: $(firewall-cmd --zone="$ZONE" --list-services 2>/dev/null | tr '\n' ' ')"

echo
if [ "$STATE" = "running" ] && [ "$NFT" -gt 0 ] && [ "$IFZONE" = "$ZONE" ]; then
  printf '\033[32mPASS\033[0m  firewall is live and enforcing on %s\n' "$IFACE"
  exit 0
else
  printf '\033[31mFAIL\033[0m  firewall is NOT enforcing:\n' >&2
  [ "$NFT" -eq 0 ] && echo "  - no nft firewalld tables loaded" >&2
  [ "$IFZONE" != "$ZONE" ] && echo "  - ${IFACE} is in zone '${IFZONE}', not '${ZONE}'" >&2
  exit 2
fi
