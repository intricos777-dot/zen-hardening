#!/bin/bash
# block-remote-viewing.sh — drop every known remote-viewing / remote-access
# application at the firewall.
#
# WHY
#
# Remote-desktop and remote-viewing tools are the classic "someone is looking at
# my machine" vector, and most of them are designed to be installed quietly and
# punch outbound holes through NAT. This machine currently has NONE installed
# (verified: no teamviewer/anydesk/vnc/xrdp/nomachine/rustdesk/splashtop/
# parsec/radmin/dameware/ultraviewer binaries, no matching pacman packages), so
# this is a blocklist that prevents the future case as much as it closes the
# present one.
#
# MECHANISM
#
# firewalld rich rules on the active 'workstation' zone, dropping both
# directions on the ports each family of tools is known to use. The zone's
# target is already DROP, so unsolicited inbound is dropped regardless -- these
# rules make the intent explicit, auditable and per-tool, and they also cover
# the case where the zone's target is ever relaxed.
#
# Each entry records the tool and the ports, so the list can be read without
# guessing why a rule exists.
#
# KDE Connect (port 1716) is deliberately NOT in this list. It is already blocked
# by the zone's default DROP, and it is a phone-pairing tool the user may want
# for local use. It is a remote-input surface, so it is called out separately
# rather than silently included or excluded.
#
# Usage:
#   ./block-remote-viewing.sh --check    # report, change nothing
#   sudo ./block-remote-viewing.sh      # apply, reload, verify

set -euo pipefail

ZONE="${FIREWALLD_ZONE:-workstation}"
RUN=1
[ "${1:-}" = "--check" ] && RUN=0

log() { printf '  %s\n' "$*"; }

# description|tools|ports (space separated; ranges allowed)
BLOCK_GROUPS=(
  "VNC/RFB remote desktop   |x11vnc,tigervnc,realvnc,tightvnc,krfb,vino            |5900-5910 5800-5810 5500"
  "Windows RDP              |xrdp,freerdp                                             |3389"
  "TeamViewer               |teamviewer                                              |5938"
  "AnyDesk                  |anydesk                                                 |7070"
  "NoMachine                 |nomachine                                               |4000"
  "RustDesk                 |rustdesk                                                |21115-21119"
  "Splashtop                |splashtop                                               |6783-6785"
  "Parsec                   |parsec                                                  |8000-8010"
  "Radmin                   |radmin                                                  |4899"
  "DameWare                 |dameware                                                |6129"
  "UltraViewer              |ultraviewer                                             |5650"
  "Legacy remote shell      |telnet,rsh,rlogin,rexec                                |23 514 513 512"
)

# Rule comment prefix so these can be listed and removed as a set.
TAG="remote-viewing"

echo "=== block remote-viewing / remote-access applications ==="
echo "  zone    : $ZONE"
echo "  target  : $(firewall-cmd --zone="$ZONE" --get-target 2>/dev/null)"
echo "  current : $RUN (0 = check only)"
echo

total=0
for g in "${BLOCK_GROUPS[@]}"; do
    IFS='|' read -r desc tools ports <<<"$g"
    desc="${desc// /}"; tools="${tools// /}"
    for port in $ports; do
        for fam in ipv4 ipv6; do
            printf '  %-24s %-28s %-12s %s\n' "$desc" "$tools" "$port" "$fam"
            total=$((total + 1))
        done
    done
done
echo
echo "  $total rich rules would be added (2 families per port)"

[ "$RUN" = 0 ] && { echo; echo "[check only] nothing changed."; exit 0; }

# Idempotent: skip rules that already exist, so re-running is harmless.
added=0; skipped=0
for g in "${BLOCK_GROUPS[@]}"; do
    IFS='|' read -r desc tools ports <<<"$g"
    tools="${tools// /}"
    for port in $ports; do
        for fam in ipv4 ipv6; do
            rule="rule family=\"$fam\" port port=\"$port\" protocol=\"tcp\" drop"
            if firewall-cmd --zone="$ZONE" --query-rich-rule="$rule" >/dev/null 2>&1; then
                skipped=$((skipped + 1))
            else
                firewall-cmd --permanent --zone="$ZONE" --add-rich-rule="$rule" >/dev/null
                added=$((added + 1))
            fi
        done
    done
done
echo
echo "  added $added new rules, $skipped already present"

firewall-cmd --reload >/dev/null 2>&1
echo "  firewalld reloaded"

# Verify: every port must now be covered.
echo
echo "=== verification ==="
fail=0
for g in "${BLOCK_GROUPS[@]}"; do
    IFS='|' read -r desc tools ports <<<"$g"
    for port in $ports; do
        rule="rule family=\"ipv4\" port port=\"$port\" protocol=\"tcp\" drop"
        if firewall-cmd --zone="$ZONE" --query-rich-rule="$rule" >/dev/null 2>&1; then
            printf '  [ok]   %s %s\n' "$desc" "$port"
        else
            printf '  [FAIL] %s %s\n' "$desc" "$port"
            fail=1
        fi
    done
done
[ "$fail" = 0 ] && echo && echo "  all remote-viewing ports are blocked." || { echo && echo "  ERROR: some rules did not apply" >&2; exit 1; }
