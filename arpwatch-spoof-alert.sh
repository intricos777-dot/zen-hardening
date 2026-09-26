#!/bin/bash
# arpwatch-spoof-alert.sh — arpwatch(8) exec hook for local spoof detection.
#
# arpwatch is told to exec this instead of mailing. arpwatch calls it as:
#
#     arpwatch-spoof-alert.sh <start_ip> <start_mac> <stop_ip> <stop_mac>
#
# A "flip-flop" (one IP, two different MACs) is a strong spoofing signal and is
# the only event treated as an intrusion. Everything else — a new host, a host
# going away — is routine on a network with DHCP and is logged, not alerted.
#
# WHY NOT AUTO-BAN
#
# The 1-day ban belongs to fail2ban, which keys on real authentication and
# connection attempts. It is deliberately NOT applied here. On this network
# flip-flops are mostly legitimate: Android and Windows randomise their MAC
# per SSID, DHCP hands out addresses to new hardware, and this machine sits on
# a /8 with 16.7M addresses of other people on it. Auto-banning a flipped
# address for 24h would cut off colleagues and randomising phones, not
# attackers. This script therefore notifies and logs, and a human decides.
#
# To ban, once a flip-flop is confirmed real, use the 1-day fail2ban/firewalld
# path that is already configured:
#     sudo firewall-cmd --zone=workstation --add-rich-rule=...   (see repo)
# or ban the source in fail2ban. Both are 86400s by default.
#
# Notifications reuse the Shield Kitty alert path so spoof alerts look like
# every other security notification instead of inventing a second style.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The alert script is a SIBLING of this script's parent directory:
#   ~/Projects/zen-hardening/arpwatch-spoof-alert.sh   <- this file
#   ~/Projects/shield-kitty/shield-kitty-alert.py      <- the notifier
#
# Deriving it from BASH_SOURCE rather than $HOME is deliberate. This hook runs
# as a child of arpwatch, which systemd starts as root, so $HOME is /root and
# "$HOME/Projects/shield-kitty/..." does not exist. That failure is silent --
# the alert is simply dropped and only a line in the log says why.
ALERT="${BDE_ALERT:-$(dirname "$HERE")/shield-kitty/shield-kitty-alert.py}"
LOG="${BDE_ARPWATCH_LOG:-/var/log/arpwatch-spoof.log}"

# Reconstruct enough of the graphical session for notify-send to work.
#
# arpwatch is started by systemd as root and drops to the user with -u, which
# changes the uid but NOT the environment. The hook therefore inherits neither
# DISPLAY, nor WAYLAND_DISPLAY, nor DBUS_SESSION_BUS_ADDRESS, and every
# notification silently fails -- the alert is written to the log and nothing
# appears. This is not hypothetical: it is what a bare `env -i` run reproduces.
#
# The user bus socket is the only thing that really matters: the notification
# daemon is already listening there, so pointing DBUS_SESSION_BUS_ADDRESS at it
# is enough to deliver. Verified against this machine's layout.
bootstrap_session_env() {
    local uid="${EUID:-$UID}" rt
    rt="${XDG_RUNTIME_DIR:-/run/user/$uid}"

    if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "$rt/bus" ]; then
        export XDG_RUNTIME_DIR="$rt"
        export DBUS_SESSION_BUS_ADDRESS="unix:path=$rt/bus"
    fi

    # Pick up a Wayland socket if one exists and nothing told us otherwise.
    if [ -z "${WAYLAND_DISPLAY:-}" ]; then
        local w
        for w in "$rt"/wayland-*; do
            [ -S "$w" ] || continue
            export WAYLAND_DISPLAY="${w##*/}"
            break
        done
    fi
}
bootstrap_session_env

# arpwatch MACs are colon-separated. Normalise to lowercase for comparison.
norm_mac() { printf '%s' "${1,,}" | tr -d '-' ; }

log() { printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG" 2>/dev/null || \
        printf '%s %s\n' "$(date -Is)" "$*" >&2; }

# The host's own address and the gateway must never be reported as a victim of
# spoofing -- they are the reference points everything else is compared to.
# Infrastructure addresses to exclude from alerting. These default to the
# machine's own addresses and default gateway rather than relying on the
# environment: the systemd unit sets no BDE_SELF_IPS/BDE_GATEWAYS, so the
# exclusion list was ALWAYS empty in production and the router's own
# MAC-randomised transition would alert as a spoof.
_self_ips_detected() {
    ip -4 -o addr show scope global 2>/dev/null |
        awk '{split($4,a,"/"); print a[1]}'
}
_gw_ips_detected() {
    ip route show default 2>/dev/null | awk '{print $3}'
    ip -6 route show default 2>/dev/null | awk '{print $3}' | grep -v '^::$' || true
}

SELF_IPS="${BDE_SELF_IPS:-$(_self_ips_detected)}"
GW_IPS="${BDE_GATEWAYS:-$(_gw_ips_detected)}"

is_infrastructure() {
    local ip="$1" o
    for o in $SELF_IPS $GW_IPS; do
        [ "$ip" = "$o" ] && return 0
    done
    return 1
}

notify() {
    # $1 = severity, $2 = label, $3 = sample detail
    #
    # The payload schema is events=[{label, count, sample}] -- a list of DICTS.
    # shield-kitty-alert.py calls .get() on each element, so a list of plain
    # strings raises AttributeError and the alert is LOST. The headline is
    # generated by the alert script ("SHIELD KITTY"); do not pass one in.
    local payload
    payload=$(python3 - "$1" "$2" "$3" <<'PY'
import json, sys
sev, label, sample = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "severity": sev,
    "timestamp": None,
    "events": [{"label": label, "count": 1, "sample": sample}],
}))
PY
) || { log "could not build alert payload"; return 0; }
    [ -f "$ALERT" ] || { log "alert script missing at $ALERT"; return 0; }
    # --fullscreen is deliberately NOT used: a spoof alert must not take over
    # the screen, consistent with the notification-first policy.
    #
    # Capture the notifier's output rather than redirecting into $LOG: if the log
    # is not writable the redirect itself fails and the real error is lost,
    # which is exactly when you need to read it. log() falls back to stderr.
    #
    # Log BOTH outcomes. Previously a successful send produced no line at all
    # (notify-send is silent on success), so "nothing in the log" was ambiguous
    # between delivered and dropped -- the same ambiguity that hid the root-bus
    # bug, where notifications failed while everything reported healthy.
    local out rc=0
    out="$(python3 "$ALERT" "$payload" 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        log "alert DELIVERY FAILED (rc=$rc): ${out:-<no output>}"
    else
        log "alert delivered ok: ${1}${out:+ | $out}"
    fi
    return 0
}

selftest() {
    echo "=== arpwatch-spoof-alert selftest ==="
    echo "  log target : $LOG"
    echo "  alert path : $ALERT"
    [ -f "$ALERT" ] && echo "  alert      : FOUND" || echo "  alert      : MISSING (notifications disabled, logging still works)"
    echo

    # Exercise the REAL decision path with a scratch log and notifications
    # stubbed out. The previous version of this function only printed the three
    # case names and exited, so it could not fail: it verified nothing about
    # the flip-flop logic it claims to cover.
    local tmp rc fail=0
    tmp="$(mktemp -d)"
    # Redirect both side effects into the scratch dir for the duration.
    LOG="$tmp/spoof.log"
    BDE_ARPWATCH_LOG="$tmp/spoof.log"

    # Redefine notify() to record instead of deliver. This must come AFTER the
    # real notify() definition earlier in the file, which it does: shell uses
    # the most recent definition. Notifying for real would fire desktop
    # popups at the operator on every test run.
    notify() { printf 'NOTIFY:%s:%s\n' "$1" "$2" >>"$tmp/notified"; return 0; }

    check() { # name expected_substr args...
        local name="$1" want="$2"; shift 2
        rm -f "$tmp/notified"
        # main is called in THIS shell, not a subshell: a subshell would
        # inherit the notify stub but its writes would still land in the same
        # file, so the important part is that $tmp stays in scope here.
        main "$@" >/dev/null 2>&1
        local logged notified
        logged="$(cat "$LOG" 2>/dev/null || true)"
        notified="$(cat "$tmp/notified" 2>/dev/null || true)"
        if printf '%s' "$notified" | grep -q "$want"; then
            printf '  PASS  %-22s notified as expected\n' "$name"
        else
            printf '  FAIL  %-22s expected a "%s" notification\n' "$name" "$want"
            printf '        log: %s\n' "$(printf '%s' "$logged" | tail -1)"
            printf '        notified: %s\n' "$(printf '%s' "$notified" | tail -1)"
            fail=1
        fi
    }

    check_quiets() { # name forbidden_substr args...
        local name="$1" forbid="$2"; shift 2
        rm -f "$tmp/notified"
        main "$@" >/dev/null 2>&1
        if grep -q "$forbid" "$tmp/notified" 2>/dev/null; then
            printf '  FAIL  %-22s must NOT notify\n' "$name"
            fail=1
        else
            printf '  PASS  %-22s correctly silent\n' "$name"
        fi
    }

    OWN_IP="$(ip -4 -o addr show scope global 2>/dev/null |
              awk '{split($4,a,"/"); print a[1]; exit}')"

    # 1. flip-flop: same IP, two MACs -> must alert critical
    check "flip-flop alerts" "critical" \
        192.0.2.55 aa:bb:cc:dd:ee:01 192.0.2.55 aa:bb:cc:dd:ee:02

    # 2. new host: different IP -> routine, must never alert
    check_quiets "new host silent" "NOTIFY" \
        198.51.100.7 aa:bb:cc:dd:ee:03 0.0.0.0 00:00:00:00:00:00

    # 3. the real default gateway is infrastructure: must not alert.
    #    Uses the live gateway, not a hardcoded address: this machine's
    #    gateway is 10.128.128.128, so a literal 192.168.1.1 would test
    #    nothing about the exclusion path.
    GW1="$(printf '%s\n' $GW_IPS | head -1)"
    if [ -n "$GW1" ]; then
        check_quiets "gateway silent" "NOTIFY" \
            "$GW1" aa:bb:cc:dd:ee:04 "$GW1" aa:bb:cc:dd:ee:05
    else
        printf '  SKIP  %-22s could not determine gateway\n' "gateway"
    fi

    # 4. own IP must be ignored entirely
    if [ -n "$OWN_IP" ]; then
        check_quiets "own IP silent" "NOTIFY" \
            "$OWN_IP" aa:bb:cc:dd:ee:06 "$OWN_IP" aa:bb:cc:dd:ee:07
    else
        printf '  SKIP  %-22s could not determine own IP\n' "own IP"
    fi

    # 5. malformed call must not alert or crash
    check_quiets "no-args safe" "NOTIFY" main

    rm -rf "$tmp"
    echo
    if [ "$fail" -eq 0 ]; then
        echo "SELFTEST PASS"
    else
        echo "SELFTEST FAIL"
    fi
    return "$fail"
}

# The decision logic lives in a function rather than at the top level so the
# selftest can invoke it repeatedly with different inputs. Bare top-level code
# with `exit` would terminate the selftest on the first case.
handle_event() {
  if [ "$#" -lt 4 ]; then
    log "called with $# args, expected 4 (start_ip start_mac stop_ip stop_mac)"
    return 0
  fi

  local start_ip="$1" start_mac stop_ip stop_mac
  start_mac="$(norm_mac "$2")"
  stop_ip="$3";  stop_mac="$(norm_mac "$4")"

  # --- flip-flop: same IP, different MAC = spoofing signal
  if [ "$start_ip" = "$stop_ip" ] && [ -n "$start_mac" ] && [ -n "$stop_mac" ] \
     && [ "$start_mac" != "$stop_mac" ]; then
    if is_infrastructure "$start_ip"; then
      log "FLIP-FLOP on infrastructure addr $start_ip ($start_mac -> $stop_mac) -- not alerting"
      return 0
    fi
    log "FLIP-FLOP $start_ip $start_mac -> $stop_mac"
    notify "critical" "ARP spoof: $start_ip claimed two MACs" \
        "was $start_mac, now $stop_mac. Not auto-banned: MAC randomisation looks identical. Verify, then ban via the 86400s fail2ban path if real."
    return 0
  fi

  # --- new host: routine. Logged, never alerted.
  log "new host $start_ip $start_mac"
  return 0
}

main() { handle_event "$@"; }

# Dispatch comes LAST: selftest() calls handle_event(), so both it and main
# must already be defined above. Dispatching earlier made the selftest run
# against an undefined function.
if [ "${1:-}" = "--selftest" ]; then selftest; exit 0; fi

main "$@"

