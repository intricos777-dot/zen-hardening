#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
# preflight.sh — is this machine ready to reboot?
#
# Read-only. Changes nothing, needs no root for most checks (root-only checks
# are marked and skipped if unavailable). Designed to be run before a manual
# reboot and again afterwards to confirm the services came back.
#
#   ./preflight.sh            check readiness
#   ./preflight.sh --after    check services returned (post-reboot mode)
#
# Exit: 0 = good to go, 1 = something needs attention first.

set -uo pipefail

AFTER=0
[ "${1:-}" = "--after" ] && AFTER=1

FAIL=0
WARN=0
pass() { printf '  \033[32m[ok]  \033[0m %s\n' "$*"; }
warn() { printf '  \033[33m[warn]\033[0m %s\n' "$*"; WARN=$((WARN+1)); }
bad()  { printf '  \033[31m[FAIL]\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[90m[skip]\033[0m %s (needs root)\n' "$*"; }

echo "=== $([ "$AFTER" = 1 ] && echo 'post-reboot verification' || echo 'pre-reboot readiness') ==="
echo "  $(date -Is)   up $(uptime -p 2>/dev/null || uptime | sed 's/.*up //;s/,.*//')"
echo

# ── 1. package state ───────────────────────────────────────────────────
echo "1. package state"
if [ "$AFTER" = 1 ]; then
    pass "booted $(uptime -s 2>/dev/null || echo unknown)"
else
    UP=$(pacman -Qu 2>/dev/null | wc -l)
    if [ "$UP" -eq 0 ]; then
        pass "no pending package upgrades"
    else
        warn "$UP package upgrade(s) pending — reboot first, then upgrade"
    fi
    KRUN=$(uname -r)
    KINST=$(pacman -Q linux-zen 2>/dev/null | awk '{print $2}')
    # pacman reports 7.2.7.zen1-1, uname reports 7.2.7-zen1-1-zen. Compare the
    # numeric VERSION field only, and treat the pkgrel/suffix as noise -- a raw
    # string compare reports a mismatch that does not exist and tells the user
    # to reboot for no reason.
    if [ -z "$KINST" ]; then
        pass "could not read installed kernel version, skipping compare"
    else
        kv() { echo "$1" | grep -oE '^[0-9]+(\.[0-9]+)+' ; }
        if [ "$(kv "$KRUN")" = "$(kv "$KINST")" ]; then
            pass "running kernel matches installed ($(kv "$KRUN"))"
        else
            bad "kernel mismatch: running $KRUN, installed $KINST — reboot needed"
        fi
    fi
    [ -f /run/reboot-required ] && bad "/run/reboot-required exists: a package asked for a reboot" \
                              || pass "no package has requested a reboot"
fi
echo

# ── 2. storage ─────────────────────────────────────────────────────────
echo "2. storage"
while read -r fs size used avail pct mnt; do
    case "$fs" in tmpfs|devtmpfs) continue;; esac
    n=${pct%%\%}
    if [ "$n" -ge 90 ]; then bad "$mnt is ${pct} full"
    elif [ "$n" -ge 80 ]; then warn "$mnt is ${pct} full"
    else pass "$mnt ${pct} used"; fi
done < <(df -h --output=source,size,used,avail,pcent,target -x tmpfs -x devtmpfs 2>/dev/null | tail -n +2)
if [ "$AFTER" = 0 ]; then
    awk '{print $1}' /proc/mounts | grep -q luks && pass "root is encrypted (LUKS)" \
        || warn "root filesystem does not look encrypted"
fi
echo

# ── 3. lockout safety ──────────────────────────────────────────────────
echo "3. account lockout safety"
if command -v faillock >/dev/null; then
    if faillock --user "$(id -un)" 2>/dev/null | grep -qE '^\s*[0-9]'; then
        bad "there is a LIVE faillock tally for $(id -un) — clear it before rebooting"
    else
        pass "no faillock tally for $(id -un)"
    fi
    UT=$(grep -E '^\s*unlock_time' /etc/security/faillock.conf 2>/dev/null | awk '{print $3}')
    case "$UT" in
        0) bad "unlock_time = 0 means PERMANENT lockout. If the exemption is wrong you will not get back in." ;;
        "") pass "faillock.conf has no explicit unlock_time" ;;
        *) pass "unlock_time = ${UT}s (temporary lockout, self-clearing)" ;;
    esac
    GROUP=$(grep -E '^\s*admin_group' /etc/security/faillock.conf 2>/dev/null | awk '{print $3}')
    if [ -n "$GROUP" ] && getent group "$GROUP" >/dev/null; then
        if getent group "$GROUP" | cut -d: -f4 | tr ',' '\n' | grep -qx "$(id -un)"; then
            pass "$(id -un) is exempt via group $GROUP"
        else
            bad "faillock names $GROUP but $(id -un) is NOT in it"
        fi
    fi
else
    pass "faillock not installed"
fi
echo

# ── 4. services that must be running ───────────────────────────────────
echo "4. security services"
check_unit() {  # name, expected-state
    local u="$1" want="$2" en act
    en=$(systemctl is-enabled "$u" 2>/dev/null || echo "?")
    act=$(systemctl is-active "$u" 2>/dev/null || echo "?")
    if [ "$AFTER" = 1 ]; then
        if [ "$act" = "$want" ]; then pass "$u is $act"
        else bad "$u is $act, expected $want"; fi
    else
        if [ "$act" = "$want" ]; then pass "$u is $act"
        elif [ "$act" = "inactive" ]; then warn "$u is inactive right now"
        else bad "$u is $act, expected $want"; fi
    fi
    # A unit that is active but NOT enabled silently dies at the next reboot.
    if [ "$AFTER" = 0 ] && [ "$act" = "active" ] && [ "$en" != "enabled" ]; then
        bad "$u is running but NOT enabled — it will not survive a reboot"
    fi
}
check_unit firewalld.service           active
check_unit fail2ban.service            active
check_unit arpwatch-spoof.service      active
check_unit arpwatch-spoof-scan.timer   active
for u in hermes-gateway.service lia-inbox-collector.service \
         shield-kitty-watch.service watchman.service; do
    a=$(systemctl --user is-active "$u" 2>/dev/null || echo "?")
    e=$(systemctl --user is-enabled "$u" 2>/dev/null || echo "?")
    if [ "$a" = "active" ] && [ "$e" = "enabled" ]; then
        pass "user: $u is active and enabled"
    elif [ "$a" = "active" ] && [ "$e" != "enabled" ]; then
        bad "user: $u is active but NOT enabled — dies at reboot"
    else
        bad "user: $u is $a (expected active)"
    fi
done
for t in business-health.timer evidence-seal.timer; do
    e=$(systemctl --user is-enabled "$t" 2>/dev/null || echo "?")
    [ "$e" = "enabled" ] && pass "user timer $t enabled" || bad "user timer $t is $e"
done
LINGER=$(loginctl show-user "$(id -un)" 2>/dev/null | grep -c 'Linger=yes')
[ "$LINGER" = "1" ] && pass "linger enabled — user units start without a login" \
                   || bad "linger is OFF — user units will not start until you log in"
echo

# ── 5. unit file sanity ────────────────────────────────────────────────
echo "5. unit files"
BADU=0
for u in ~/.config/systemd/user/*.service /etc/systemd/system/arpwatch-spoof*.service; do
    [ -f "$u" ] || continue
    exec_line=$(grep -m1 '^ExecStart=' "$u" | sed 's/^ExecStart=//')
    [ -n "$exec_line" ] || continue
    # Resolve the FIRST token that is an absolute path, skipping the interpreter
    # flags. The interpreter itself is the thing to check, not a later argument:
    #   /usr/bin/python3 script.py   -> check /usr/bin/python3
    #   /usr/bin/env npx tsx x.ts    -> /usr/bin/env exists; npx is on PATH
    #   python -m hermes_cli.main    -> a module, not a path: nothing to check
    target=$(printf '%s\n' "$exec_line" | tr ' ' '\n' | sed 's/^-//' \
             | grep -E '^/' | head -1)
    if [ -n "$target" ]; then
        if [ ! -e "$target" ]; then
            printf '  \033[31m[FAIL]\033[0m %s: ExecStart interpreter missing: %s\n' \
                "$(basename "$u")" "$target"
            BADU=$((BADU+1))
        elif [ ! -x "$target" ] && [ "${target##*.}" != "py" ]; then
            printf '  \033[31m[FAIL]\033[0m %s: ExecStart target not executable: %s\n' \
                "$(basename "$u")" "$target"
            BADU=$((BADU+1))
        fi
    fi
done
[ "$BADU" = 0 ] && pass "every ExecStart target exists" || FAIL=$((FAIL+BADU))
VER=$(for u in ~/.config/systemd/user/*.service /etc/systemd/system/arpwatch-spoof*.service; do
        [ -f "$u" ] && systemd-analyze --user verify "$u" 2>&1
      done | grep -ciE 'error|invalid|unknown key' || true)
[ "${VER:-0}" = "0" ] && pass "systemd-analyze reports no unit errors" \
                      || warn "$VER systemd-analyze complaints"
echo

# ── 6. network exposure ────────────────────────────────────────────────
echo "6. inbound exposure"
ZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "?")
# firewall-cmd talks to firewalld over D-Bus, which needs root. As a normal
# user it returns nothing and the target reads as "?" -- which is NOT evidence
# that inbound is open. Report that as unknown, never as a failure.
TGT=$(firewall-cmd --zone="$ZONE" --get-target 2>/dev/null || echo "")
if [ -n "$TGT" ]; then
    if [ "$TGT" = "DROP" ] || [ "$TGT" = "REJECT" ]; then
        pass "default zone '$ZONE' target is $TGT (inbound denied)"
    else
        bad "default zone '$ZONE' target is $TGT — inbound is NOT denied"
    fi
elif [ "$(id -u)" -eq 0 ]; then
    bad "could not read the zone target as root — firewalld may be misconfigured"
else
    pass "zone '$ZONE' (target needs root: sudo firewall-cmd --zone=$ZONE --get-target)"
fi
EXPOSED=$(ss -tulpnH 2>/dev/null | awk '$5 !~ /^(127\.0\.0\.1|\[::1\])/ {print $1, $5}' | sort -u)
if [ -n "$EXPOSED" ]; then
    while read -r proto addr; do
        [ -z "$addr" ] && continue
        warn "listening on all interfaces: $proto $addr (firewall decides if it is reachable)"
    done <<< "$EXPOSED"
else
    pass "nothing is listening on a non-loopback address"
fi
echo

# ── 7. optional tools ──────────────────────────────────────────────────
echo "7. optional tools"
for t in warden remove-remote-viewing; do
    if [ "$t" = "warden" ] && systemctl is-active warden >/dev/null 2>&1; then
        pass "warden is active"
    elif [ "$t" = "warden" ]; then
        printf '  \033[90m[skip]\033[0m warden not installed (optional: sudo install-warden.sh)\n'
    fi
done
if [ -f /etc/warden-noview/10-block-remote-viewing.hook ]; then
    pass "remote-viewing pacman hook installed"
else
    printf '  \033[90m[skip]\033[0m remote-viewing hook not installed (optional)\n'
fi
echo

# ── verdict ────────────────────────────────────────────────────────────
echo "================================================"
if [ "$FAIL" -gt 0 ]; then
    printf '\033[31m%d FAILURE(S)\033[0m — resolve before rebooting\n' "$FAIL"
elif [ "$WARN" -gt 0 ]; then
    printf '\033[33m0 failures, %d warning(s)\033[0m — safe to reboot\n' "$WARN"
else
    printf '\033[32mALL CLEAR\033[0m — safe to reboot\n'
fi
exit $([ "$FAIL" -gt 0 ] && echo 1 || echo 0)
