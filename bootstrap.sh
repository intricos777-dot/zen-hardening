#!/usr/bin/env bash
# bootstrap.sh — reapply the verified security baseline on a fresh Garuda install.
#
#   sudo bash bootstrap.sh
#   sudo bash bootstrap.sh --check     # report only, change nothing
#
# Everything this applies was verified on a live machine on 2026-09-26. See
# fail2ban-coverage.md for what is deliberately NOT protected, and
# workstation.xml for why the firewall uses a custom zone.
#
# IDEMPOTENT: safe to re-run. Every step verifies its own result and the
# script exits non-zero if the machine does not end up in the expected state.
# A security script that reports success while enforcing nothing is worse
# than one that fails loudly.
#
# Order matters:
#   1. packages      (needs a working network; do this first)
#   2. firewall      (workstation zone; everything else depends on it)
#   3. fail2ban      (must be pinned to the workstation zone)
#   4. anonymisation (MAC + hostname)
#   5. verification  (any failure -> non-zero exit)

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK_ONLY=0
[[ "${1:-}" == "--check" ]] && CHECK_ONLY=1

FAILURES=0
step()  { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok()    { printf '  \033[32m[ok]\033[0m   %s\n' "$1"; }
bad()   { printf '  \033[31m[FAIL]\033[0m %s\n' "$1"; FAILURES=$((FAILURES+1)); }
note()  { printf '  \033[33m[note]\033[0m %s\n' "$1"; }
run()   { if [ "$CHECK_ONLY" -eq 1 ]; then note "would run: $*"; return 0; fi; "$@"; }

[[ $EUID -eq 0 ]] || { echo "ERROR: needs root: sudo $0" >&2; exit 1; }

echo "=============================================="
echo " Verified security baseline bootstrap"
echo " mode: $([ "$CHECK_ONLY" -eq 1 ] && echo "CHECK (no changes)" || echo "APPLY")"
echo "=============================================="

# ── 1. packages ───────────────────────────────────────────────────────────
step "1/5  Packages"
for p in fail2ban firewalld tor; do
  if pacman -Qq "$p" >/dev/null 2>&1; then
    ok "$p installed"
  else
    run pacman -S --needed --noconfirm "$p" >/dev/null 2>&1 \
      && ok "$p installed" \
      || bad "$p NOT installed — run: pacman -S $p"
  fi
done
# torbrowser-launcher is optional: it is the correct way to browse over Tor,
# but nothing else here depends on it.
if pacman -Qq torbrowser-launcher >/dev/null 2>&1; then
  ok "torbrowser-launcher installed"
else
  note "torbrowser-launcher not installed. The tor daemon alone does NOT give"
  note "anonymous browsing. Install it if you want a browser: pacman -S torbrowser-launcher"
fi

# ── 2. firewall ───────────────────────────────────────────────────────────
step "2/5  Firewall (workstation zone)"
if [ -f "$HERE/workstation.xml" ]; then
  run install -m 0644 -o root -g root "$HERE/workstation.xml" /etc/firewalld/zones/workstation.xml
  ok "workstation.xml installed"
else
  bad "workstation.xml missing from $HERE — firewall cannot be configured"
fi
# Remove the superseded override. It could never produce an empty allowlist
# (firewalld MERGES same-name zones) and carried two schema defects.
if [ -f /etc/firewalld/zones/public.xml ]; then
  run rm -f /etc/firewalld/zones/public.xml
  note "removed superseded public.xml override"
fi

# Arch's fail2ban.service declares PartOf=firewalld.service, which propagates
# restarts in BOTH directions. "systemctl restart firewalld" then makes systemd
# plan a restart of fail2ban while the same transaction stops it:
#   Transaction contains conflicting jobs 'restart' and 'stop' for fail2ban.service
# The unit only needs After=, which it already has. Sequence around it.
if [ "$CHECK_ONLY" -eq 0 ]; then
  systemctl stop fail2ban 2>/dev/null || true
  if systemctl restart firewalld; then
    ok "firewalld restarted (fail2ban sequenced around PartOf= bug)"
  else
    bad "could not restart firewalld"
  fi
  systemctl start fail2ban 2>/dev/null || note "fail2ban did not start"
fi

if [ "$CHECK_ONLY" -eq 0 ]; then
  firewall-cmd --set-default-zone=workstation >/dev/null 2>&1 \
    && ok "default zone = workstation" \
    || bad "could not set default zone"
  # Bind every active wifi connection, not a hardcoded name.
  while read -r uuid; do
    [ -z "$uuid" ] && continue
    cid=$(nmcli -g connection.id con show "$uuid")
    nmcli con mod "$uuid" connection.zone workstation >/dev/null 2>&1 \
      && ok "'${cid}' bound to workstation" \
      || bad "could not bind '${cid}'"
  done < <(nmcli -t -f UUID,TYPE con show | awk -F: '$2=="802-11-wireless"{print $1}')
fi

# ── 3. fail2ban ───────────────────────────────────────────────────────────
step "3/5  fail2ban"
if [ -f "$HERE/shield-kitty-fail2ban.local" ]; then
  run install -m 0644 -o root -g root "$HERE/shield-kitty-fail2ban.local" \
      /etc/fail2ban/jail.d/shield-kitty.conf
  ok "shield-kitty.conf installed"

  # Set recidive's enabled flag to match reality, in BOTH directions.
  #
  # recidive reads /var/log/fail2ban.log. On a first-ever install that file
  # does not exist, and a jail pointing at a missing log aborts the whole
  # fail2ban startup -- every jail, not just recidive. So the flag must be
  # false until the log exists, and true once it does.
  #
  # The source file may ship with either value (it currently ships true,
  # matching this machine), so this cannot be a one-way "false -> true" sed.
  # It also MUST be scoped to the [recidive] section: 'enabled = true'
  # appears under [sshd] as well, and a blanket substitution would silently
  # disable the sshd jail too.
  if [ -f /var/log/fail2ban.log ]; then RECIDIVE_WANT=true; else RECIDIVE_WANT=false; fi

  if [ "$CHECK_ONLY" -eq 1 ]; then
    note "would set [recidive] enabled = ${RECIDIVE_WANT}"
    note "  (log present: $([ -f /var/log/fail2ban.log ] && echo yes || echo no))"
  else
    CONF=/etc/fail2ban/jail.d/shield-kitty.conf
    RECIDIVE_HAD=$(awk '/^\[recidive\]/{r=1;next} /^\[/{r=0} r&&/^[[:space:]]*enabled[[:space:]]*=/{print $3;exit}' "$CONF")
    awk -v want="$RECIDIVE_WANT" '
      /^\[recidive\]/          { inrec = 1 }
      /^\[/ && !/^\[recidive\]/ { inrec = 0 }
      inrec && /^[[:space:]]*enabled[[:space:]]*=/ { print "enabled  = " want; next }
      { print }
    ' "$CONF" > "$CONF.new" && mv "$CONF.new" "$CONF"

    if [ "$RECIDIVE_WANT" = "true" ]; then
      ok "[recidive] enabled (log exists)"
    else
      ok "[recidive] left disabled — no /var/log/fail2ban.log yet"
      note "re-run this script after fail2ban has started once and the"
      note "recidive jail will be enabled automatically."
    fi
    [ "$RECIDIVE_HAD" != "$RECIDIVE_WANT" ] && \
      note "[recidive] enabled: ${RECIDIVE_HAD} -> ${RECIDIVE_WANT}"
  fi
  if [ "$CHECK_ONLY" -eq 0 ]; then
    if fail2ban-client -t >/dev/null 2>&1; then
      ok "configuration test passed"
    else
      bad "fail2ban-client -t FAILED — jails will not start"
    fi
    systemctl stop fail2ban 2>/dev/null || true
    systemctl restart fail2ban >/dev/null 2>&1
    # Readiness: the socket appears during Python init, and 'ping' answers
    # before jails register. Wait on the jail list itself.
    for _ in $(seq 1 30); do
      fail2ban-client status 2>/dev/null | grep -q "Jail list" && break
      sleep 0.5
    done
  fi
else
  bad "shield-kitty-fail2ban.local missing from $HERE"
fi

# ── 4. anonymisation ──────────────────────────────────────────────────────
step "4/5  Anonymisation (hostname + MAC)"
if [ -x "$HERE/set-anon-identity.sh" ] || [ -f "$HERE/set-anon-identity.sh" ]; then
  if [ "$CHECK_ONLY" -eq 1 ]; then
    note "would run: set-anon-identity.sh"
  else
    bash "$HERE/set-anon-identity.sh" 2>&1 | sed 's/^/  /'
  fi
else
  bad "set-anon-identity.sh missing from $HERE"
fi

# ── 5. verification ───────────────────────────────────────────────────────
step "5/5  Verification"
if [ "$CHECK_ONLY" -eq 0 ]; then
  FWSTATE=$(firewall-cmd --state 2>/dev/null || echo unknown)
  NFT=$(nft list tables 2>/dev/null | grep -ci firewalld || echo 0)
  DEFZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo none)
  F2B=$(systemctl is-active fail2ban 2>/dev/null || echo inactive)
  JAILS=$(fail2ban-client status 2>/dev/null | grep "Jail list" || echo "unreadable")
  HOST=$(hostname)
  SVCS=$(firewall-cmd --zone=workstation --list-services 2>/dev/null | tr '\n' ' ')

  printf '  %-22s %s\n' "firewalld:"        "$FWSTATE"
  printf '  %-22s %s\n' "nft firewalld tables:" "$NFT"
  printf '  %-22s %s\n' "default zone:"    "$DEFZONE"
  printf '  %-22s %s\n' "workstation allows:" "${SVCS:-nothing}"
  printf '  %-22s %s\n' "fail2ban:"         "$F2B"
  printf '  %-22s %s\n' "jails:"            "${JAILS#Jail list: }"
  # Identity. Verify the MAC is actually randomized AND the setting is on.
  # Checking the setting alone is not enough: the value can read 'always'
  # while the interface still carries the permanent hardware MAC, because
  # NM only applies a new address at connection activation. Verify the
  # live address is locally administered (first octet bit 1 set), which
  # is what distinguishes a randomized MAC from a burned-in one.
  IFACE=$(nmcli -g GENERAL.DEVICE con show "$(nmcli -t -f UUID,NAME con show | awk -F: '$2=="USL - Public"{print $1}')" 2>/dev/null)
  [ -z "$IFACE" ] && IFACE=wlo1
  MAC=$(cat "/sys/class/net/$IFACE/address" 2>/dev/null || echo unknown)
  MACRAND=$(nmcli -g 802-11-wireless.mac-address-randomization con show "USL - Public" 2>/dev/null || echo unknown)
  OCTET=$(echo "$MAC" | cut -c1-2)
  case "$OCTET" in
    2*|6*|a*|e*) MACLOC=1 ;;
    *)            MACLOC=0 ;;
  esac

  printf '  %-22s %s\n' "hostname:"         "$HOST"
  printf '  %-22s %s\n' "mac ($IFACE):"     "$MAC"
  printf '  %-22s %s\n' "mac randomization:" "$MACRAND"
  echo

  [ "$FWSTATE" = "running" ] && ok "firewalld running" || bad "firewalld not running"
  # --state reports 'running' even while enforcing nothing, so require tables.
  [ "$NFT" -gt 0 ] && ok "nft rules loaded" || bad "NO nft rules loaded — not enforcing"
  [ "$DEFZONE" = "workstation" ] && ok "default zone correct" || bad "default zone is '$DEFZONE'"
  [ "$HOST" = "zero" ] && ok "hostname is zero" || bad "hostname is '$HOST'"
  [ "$F2B" = "active" ] && ok "fail2ban active" || bad "fail2ban is '$F2B'"

  # Fail closed on identity: a 'passing' baseline that still broadcasts the
  # hardware MAC is not anonymous, so treat this as a hard failure rather
  # than a note. The MAC only changes at activation, so a re-run after a
  # manual 'nmcli con down/up' will go from FAIL to OK.
  if [ "$MACRAND" = "always" ] && [ "$MACLOC" -eq 1 ]; then
    ok "MAC randomized ($MAC, locally administered)"
  else
    bad "MAC NOT randomized — setting='$MACRAND' mac=$MAC (locally-administered=$MACLOC)"
    note "setting='always' with a non-random MAC means the new address has"
    note "not been activated yet. Apply it with:"
    note "  nmcli con down 'USL - Public' && nmcli con up 'USL - Public'"
  fi

  echo
  echo "  NOT covered by this baseline (structural, see fail2ban-coverage.md):"
  echo "    - SDDM greeter brute force: no automated protection exists."
  echo "      pam-generic needs rhost=<IP>; a local console has no IP."
  echo "    - machine-id is still unique; renaming does not anonymise it."
  echo "    - DMI strings still report the hardware model to local processes."
  echo "    - No browser: the tor daemon alone does not give anonymity."
fi

echo
echo "=============================================="
if [ "$FAILURES" -eq 0 ]; then
  printf '\033[32mBASELINE OK\033[0m  %d checks failed\n' "$FAILURES"
  exit 0
else
  printf '\033[31mBASELINE INCOMPLETE\033[0m  %d check(s) failed\n' "$FAILURES"
  exit 1
fi
