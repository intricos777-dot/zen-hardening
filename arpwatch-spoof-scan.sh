#!/bin/bash
# arpwatch-spoof-scan.sh — detect ARP spoofing from arpwatch's datafile.
#
# WHY THIS EXISTS INSTEAD OF AN EXEC HOOK
#
# arpwatch 3.9 (the build in Arch 'extra') has no exec hook. The original LBL
# arpwatch took -a /path/to/prog, but 3.9 only offers -f datafile, -w/-W for
# email, and syslog. The valid flags are:
#
#     [-CdFNpqsvzZ] [-D arpdir] [-f datafile] [-i interface] [-P pidfile]
#     [-w watcher@email] [-W watchee@email] [-n net[/width]] [-x net[/width]]
#     [-r file]
#
# So detection reads the datafile instead. Format, from arpwatch(8):
#
#     <mac> <ip> <unix-seconds> [hostname]
#
# A spoof signature is one IP claimed by more than one MAC. The previous
# approach also assumed a different interface syntax; 3.9 wants -i INTERFACE,
# not a positional argument, which is why the service exited 1 in a restart
# loop.
#
# NO AUTO-BAN. The 1-day ban stays with fail2ban, which keys on real
# connection and auth attempts. On a DHCP /8, a re-used address is routine and
# Android/Windows per-SSID MAC randomisation is common; banning for 24h would
# cut off colleagues and phones, not attackers. This notifies and logs.
#
# Alerts are deduplicated against a state file: a condition that is still true
# on the next scan does not re-notify, so one persistent anomaly produces one
# alert rather than one every interval.

set -uo pipefail

DATAFILE="${BDE_ARP_DATAFILE:-/var/lib/arpwatch/arp.dat}"
STATE="${BDE_ARP_STATE:-/var/lib/arpwatch/spoof-state}"
LOG="${BDE_ARPWATCH_LOG:-/var/log/arpwatch-spoof.log}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ALERT="${BDE_ALERT:-$(dirname "$HERE")/shield-kitty/shield-kitty-alert.py}"

# Reconstruct the graphical session so notify-send works. The scanner runs from
# a system unit, so it inherits none of DISPLAY/DBUS and every alert would fail
# silently. See the same logic in arpwatch-spoof-alert.sh.
bootstrap_session_env() {
    local uid="${EUID:-$UID}" rt
    rt="${XDG_RUNTIME_DIR:-/run/user/$uid}"
    if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] && [ -S "$rt/bus" ]; then
        export XDG_RUNTIME_DIR="$rt"
        export DBUS_SESSION_BUS_ADDRESS="unix:path=$rt/bus"
    fi
    if [ -z "${WAYLAND_DISPLAY:-}" ]; then
        local w
        for w in "$rt"/wayland-*; do
            [ -S "$w" ] || continue
            export WAYLAND_DISPLAY="${w##*/}"
            break
        done
    fi
}

log() { printf '%s %s\n' "$(date -Is)" "$*" >>"$LOG" 2>/dev/null || \
        printf '%s %s\n' "$(date -Is)" "$*" >&2; }

# Addresses that are supposed to move or be shared, and must never be reported.
# Comma-separated CIDRs or bare IPs.
IGNORE_CIDRS="${BDE_SPOOF_IGNORE:-127.0.0.0/8,0.0.0.0/8,169.254.0.0/16,fe80::/10}"

in_ignore() {
    local ip="$1" c
    for c in ${IGNORE_CIDRS//,/ }; do
        if [[ "$c" == */* ]]; then
            [ "$(python3 -c '
import ipaddress, sys
try:
    a = ipaddress.ip_address(sys.argv[1]); n = ipaddress.ip_network(sys.argv[2])
    print("y" if a in n else "n")
except ValueError:
    print("n")' "$ip" "$c")" = "y" ] && return 0
        else
            [ "$ip" = "$c" ] && return 0
        fi
    done
    return 1
}

selftest() {
    echo "=== arpwatch-spoof-scan selftest ==="
    echo "  datafile : $DATAFILE"
    echo "  state    : $STATE"
    echo "  alert    : $ALERT"
    echo "  ignored  : $IGNORE_CIDRS"
    echo
    if [ -r "$DATAFILE" ]; then
        echo "  datafile readable, $(wc -l < "$DATAFILE") entries"
    else
        echo "  datafile NOT readable yet (arpwatch has not written it)"
    fi
    echo
    echo "  use ./selftest-data.sh to run the full detection suite offline"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit 0; fi

[ -r "$DATAFILE" ] || { log "datafile $DATAFILE not readable; nothing to scan"; exit 0; }

# Build the current anomaly set: "ip mac1,mac2,..." for every IP with more than
# one DISTINCT MAC.
#
# Distinctness matters. Testing for a comma is not enough: arpwatch can list the
# same hardware address twice with different capitalisation, and joining those
# yields "mac,mac" -- a comma, but still one device. Counting unique values is
# the only way to avoid alerting on a formatting difference.
current="$(
    awk 'NF >= 2 {
            ip = $2
            mac = tolower($1)
            if (!(ip in seen)) { seen[ip] = mac; order[ip] = 1; next }
            n = split(seen[ip], arr, " ")
            for (i = 1; i <= n; i++) if (arr[i] == mac) next
            seen[ip] = seen[ip] " " mac
         }
         END {
            for (ip in order) {
                n = split(seen[ip], arr, " ")
                if (n < 2) continue
                s = arr[1]
                for (i = 2; i <= n; i++) s = s "," arr[i]
                print ip " " s
            }
         }' "$DATAFILE" 2>/dev/null | sort
)"

if [ -z "$current" ]; then
    # Clear the state, not just skip. Leaving it stale means a spoof that is
    # resolved and later returns would be silently swallowed as "already seen".
    [ -s "$STATE" ] && { : >"$STATE" 2>/dev/null || log "could not clear state file $STATE"; }
    log "scan: no anomalies"
    exit 0
fi

previous=""
[ -r "$STATE" ] && previous="$(cat "$STATE")"

# Only alert on what is newly anomalous. A condition carried over from the last
# scan has already been reported.
newly=""
while read -r ip macs; do
    [ -n "$ip" ] || continue
    in_ignore "$ip" && { log "scan: $ip ($macs) ignored by BDE_SPOOF_IGNORE"; continue; }
    if ! printf '%s\n' "$previous" | grep -qxF "$ip $macs"; then
        newly+="$ip $macs"$'\n'
    else
        log "scan: $ip ($macs) persists, not re-alerting"
    fi
done <<<"$current"

printf '%s' "$current" >"$STATE" 2>/dev/null || log "could not write state file $STATE"

[ -z "$newly" ] && { log "scan: no new anomalies"; exit 0; }

count=$(printf '%s' "$newly" | grep -c .)
bootstrap_session_env
while read -r ip macs; do
    [ -n "$ip" ] || continue
    n=$(awk -F, '{print NF}' <<<"$macs")
    log "SPOOF $ip claimed by $n MACs: $macs"
    payload=$(python3 - "$ip" "$macs" "$n" <<'PY'
import json, sys
ip, macs, n = sys.argv[1], sys.argv[2], sys.argv[3]
print(json.dumps({
    "severity": "critical",
    "events": [{
        "label": "ARP spoof: {} claimed by {} MACs".format(ip, n),
        "count": 1,
        "sample": "MACs: {}. Not auto-banned: DHCP re-use and MAC randomisation "
                  "look identical. Verify, then ban via the 86400s fail2ban path "
                  "if real.".format(macs),
    }],
}))
PY
)
    [ -f "$ALERT" ] || { log "alert script missing at $ALERT"; continue; }
    out="$(python3 "$ALERT" "$payload" 2>&1)" || log "alert delivery failed"
    [ -n "$out" ] && log "alert: $out"
done <<<"$newly"

log "scan: $count new anomal$( [ "$count" = 1 ] && echo y || echo ies)"
