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

# How long a mac/ip binding counts towards a spoof, in seconds.
#
# arp.dat is append-only, so without a window an ordinary DHCP reassignment
# reads as a permanent two-MAC conflict and the alert can never clear. 3600
# (1h) is deliberately longer than arpwatch's 15-minute flush so a genuine
# attack is seen across several consecutive scans.
WINDOW="${BDE_SPOOF_WINDOW:-3600}"

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
# THE WINDOW IS ESSENTIAL, NOT COSMETIC.
#
# arp.dat is APPEND-ONLY HISTORY, not current state. arpwatch adds a row the
# first time it sees a mac/ip pair and never removes one. So a single ordinary
# DHCP reassignment leaves this forever:
#
#     10.197.250.100  aa:bb:cc:00:00:01   <- laptop A, yesterday
#     10.197.250.100  cc:dd:ee:00:00:02   <- laptop B, today
#
# Reading the whole file calls that a permanent spoof. It alerts once, then
# "persists" on every scan, and because the state is never cleared the alert can
# never go away. On a /8 with constant lease churn that is guaranteed to fire on
# innocent devices, and a monitor that cries wolf gets ignored.
#
# So only bindings FIRST SEEN within WINDOW seconds count. A historical change
# ages out; an attack in progress is inside the window and is reported.
#
# The trade-off, stated plainly: arpwatch does not re-append a pair it already
# knows, so a spoof that is *continuing* is only visible for WINDOW seconds after
# its first sighting, then ages out like anything else. There is no way to tell
# "still spoofing" from "seen once" using the datafile alone. The window is set
# generously to favour catching attacks over suppressing noise, and arpwatch's
# own flip-flop reports keep going to the journal regardless.
#
# BDE_SPOOF_NOW exists so tests can pin the clock; production leaves it unset.
#
# Distinctness matters. Testing for a comma is not enough: arpwatch can list the
# same hardware address twice with different capitalisation, and joining those
# yields "mac,mac" -- a comma, but still one device. Counting unique values is
# the only way to avoid alerting on a formatting difference.
all="$(
    awk -v now="${BDE_SPOOF_NOW:-$(date +%s)}" -v window="$WINDOW" '
    function kept(ts) {
        # Unparseable timestamp: keep the row rather than risk missing a live
        # attack over a formatting surprise.
        if (ts !~ /^[0-9]+$/) return 1
        return (ts + 0) >= (now - window)
    }
    NF >= 3 && kept($3) {
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

# Every IP currently flagged as spoofed, whether or not it alerted.
alerting=""
while read -r ip macs; do
    [ -n "$ip" ] || continue
    if in_ignore "$ip"; then
        log "scan: $ip ($macs) ignored by BDE_SPOOF_IGNORE"
        continue
    fi
    alerting+="$ip $macs"$'\n'
done <<<"$all"

# State holds exactly what we are currently reporting on. Ignored addresses are
# excluded on purpose: if one was recorded while ignored and later removed from
# BDE_SPOOF_IGNORE, matching against state would call it "persists" and it would
# never alert at all.
if [ -z "$alerting" ]; then
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
    if ! printf '%s\n' "$previous" | grep -qxF "$ip $macs"; then
        newly+="$ip $macs"$'\n'
    else
        log "scan: $ip ($macs) persists, not re-alerting"
    fi
done <<<"$alerting"

printf '%s' "$alerting" >"$STATE" 2>/dev/null || log "could not write state file $STATE"

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
    # Log both outcomes. A silent notifier on success previously meant an empty
    # log was ambiguous between delivered and dropped.
    arc=0
    out="$(python3 "$ALERT" "$payload" 2>&1)" || arc=$?
    if [ "$arc" -ne 0 ]; then
        log "alert DELIVERY FAILED for $ip (rc=$arc): ${out:-<no output>}"
    else
        log "alert delivered ok for $ip${out:+ | $out}"
    fi
    unset out arc
done <<<"$newly"

log "scan: $count new anomal$( [ "$count" = 1 ] && echo y || echo ies)"
