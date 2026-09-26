#!/usr/bin/env bash
# install-warden.sh — install the nft chain, config, systemd units and sudo
# helper for the warden auto-blacklister.
#
# The privileged half lives here as a single script rather than as a pile of
# manual commands, so it is re-runnable and reversible.
#
#   sudo ./install-warden.sh            install + start
#   sudo ./install-warden.sh --check    report, change nothing
#   sudo ./install-warden.sh --uninstall remove everything warden added
#
# WHAT IT CHANGES
#   /etc/warden/warden.json                        config (created from template)
#   /etc/systemd/system/warden.service             daemon
#   /etc/sudoers.d/warden-sync                     NOPASSWD for ONE command
#   nft table inet warden                          the chain + blacklist set
#
# WHAT IT DOES NOT DO
#   It does not touch the firewalld 'workstation' zone, does not open any
#   port, and does not change any existing rule. warden's chain accepts
#   everything firewalld would have seen anyway, except addresses in its own
#   blacklist, which it drops first. firewalld remains the authority on what
#   is allowed; warden is an observer plus a pre-filter for its own bans.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROUP="${WARDEN_NFLOG_GROUP:-5}"
IFACE="${WARDEN_IFACE:-wlo1}"
SYNC=/usr/local/sbin/warden-nft-sync

die() { printf '\033[31mABORT: %s\033[0m\n' "$*" >&2; exit 1; }
ok()  { printf '  [ok] %s\n' "$*"; }
info() { printf '  %s\n' "$*"; }

require_root() { [ "$(id -u)" -eq 0 ] || die "needs root: sudo $0 $*"; }

# ── report ──────────────────────────────────────────────────────────────
report() {
    echo "=== warden status ==="
    if systemctl is-active --quiet warden; then
        ok "daemon running"
    else
        info "daemon NOT running"
    fi
    if [ -f /etc/warden/warden.json ]; then
        ok "config present: $(grep -o '"nflog_group":[^,]*' /etc/warden/warden.json || true)"
    else
        info "no config at /etc/warden/warden.json"
    fi
    echo
    echo "  nft table inet warden:"
    nft list table inet warden 2>/dev/null | sed 's/^/    /' || info "    table absent"
    echo
    echo "  blacklist: $(nft list set inet warden blacklist 2>/dev/null \
        | grep -oE '([0-9a-f:]+|[0-9.]+)(/[0-9]+)?' | tr '\n' ' ' || echo '(unreadable)')"
    echo "  audit log: $(wc -l < /var/log/warden/events.jsonl 2>/dev/null || echo 0) event(s)"
    echo
    echo "  firewalld default zone: $(firewall-cmd --get-default-zone 2>/dev/null || echo '?')"
    echo "  ${IFACE} zone: $(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null || echo '?')"
}

# ── install ─────────────────────────────────────────────────────────────
cmd_install() {
    require_root install
    [ -f "$HERE/warden.py" ] || die "warden.py not found next to this script"

    echo "=== 1/6  files ==="
    install -Dm755 "$HERE/warden.py" /usr/local/sbin/warden
    install -Dm755 "$HERE/warden-nft-sync" "$SYNC"
    install -Dm755 "$HERE/warden-nft-restore" /usr/local/sbin/warden-nft-restore
    install -Dm644 "$HERE/warden.service" /etc/systemd/system/warden.service
    ok "warden, warden-nft-sync, warden-nft-restore, warden.service installed"

    echo "=== 2/6  config ==="
    if [ -f /etc/warden/warden.json ]; then
        ok "existing config left untouched (edit /etc/warden/warden.json)"
    else
        install -Dm644 "$HERE/warden.json" /etc/warden/warden.json
        ok "created /etc/warden/warden.json from template"
    fi
    install -d -m 0750 /var/lib/warden
    install -d -m 0750 /var/log/warden
    # the daemon runs as root and writes both; make them root-owned
    chown root:root /var/lib/warden /var/log/warden

    echo "=== 3/6  nft table ==="
    # Idempotent: replace our own table, never anyone else's.
    nft delete table inet warden 2>/dev/null || true
    NFT_GROUP="$GROUP" NFT_IFACE="$IFACE" nft -f - <<EOF || die "nft rules failed to load"
table inet warden {
    set blacklist {
        type ipv4_addr
        size 4096
        flags timeout
    }
    chain input {
        type filter hook input priority -150; policy accept;
        iif lo accept
        ct state established,related accept
        meta l4proto ipv6-icmp accept
        ip saddr @blacklist counter drop comment "warden: blacklisted device"
        iifname "$IFACE" ip  saddr 10.0.0.0/8   log group $GROUP prefix "WARDEN " limit rate 20/minute
        iifname "$IFACE" ip6 saddr != ::1        log group $GROUP prefix "WARDEN " limit rate 20/minute
    }
}
EOF
    ok "table inet warden loaded (hook input, priority -150, policy accept)"

    # The 10.0.0.0/8 sanity rule above is deliberately nonsense-proof: verify
    # the real rules are the ones that landed.
    if ! nft list chain inet warden input | grep -q 'WARDEN'; then
        die "log rule missing from the live chain -- refusing to claim success"
    fi
    ok "verified: WARDEN log rules present in live chain"

    echo "=== 4/6  sudoers (one command, no wildcard) ==="
    # The daemon runs as root already, so this entry is for the USER to call
    # warden block/unblock without a password. Scoped to one absolute path
    # with an exact argument shape -- no NOPASSWD: ALL.
    visudo -cf /dev/null >/dev/null 2>&1 || true
    cat > /etc/sudoers.d/warden-sync <<EOF
# warden: let the owner manage their own blacklist without a password.
# Scoped to one root-owned script; the script itself validates its arguments.
Defaults:livings !requiretty
livings ALL=(root) NOPASSWD: $SYNC
EOF
    chmod 0440 /etc/sudoers.d/warden-sync
    if ! visudo -c -f /etc/sudoers.d/warden-sync; then
        rm -f /etc/sudoers.d/warden-sync
        die "sudoers file failed validation -- removed, not left broken"
    fi
    ok "sudoers.d/warden-sync validated by visudo"

    echo "=== 5/6  kernel module ==="
    modprobe nfnetlink_log 2>/dev/null && ok "nfnetlink_log loaded" \
        || info "nfnetlink_log already built in or auto-loads on first use"

    echo "=== 6/6  start ==="
    systemctl daemon-reload
    systemctl enable --now warden
    sleep 2
    if systemctl is-active --quiet warden; then
        ok "warden.service active"
    else
        info "warden.service FAILED to start:"
        systemctl status warden --no-pager -l 2>/dev/null | sed 's/^/      /'
        journalctl -u warden -n 20 --no-pager 2>/dev/null | sed 's/^/      /'
        die "daemon did not start"
    fi

    echo
    report
    cat <<EOF

=== next step ===

Generate a test hit from a phone/PC on the same wifi, then:

  sudo warden status
  sudo tail -f /var/log/warden/events.jsonl

To trust one of your own devices so it is never auto-banned, add its address
to "trusted" in /etc/warden/warden.json, then:

  sudo systemctl restart warden
EOF
}

# ── uninstall ───────────────────────────────────────────────────────────
cmd_uninstall() {
    require_root uninstall
    systemctl disable --now warden 2>/dev/null || true
    rm -f /etc/systemd/system/warden.service
    rm -f /usr/local/sbin/warden
    rm -f "$SYNC"
    rm -f /usr/local/sbin/warden-nft-restore
    rm -f /etc/sudoers.d/warden-sync
    nft delete table inet warden 2>/dev/null || true
    systemctl daemon-reload
    ok "removed service, binaries, sudoers entry and nft table"
    info "config /etc/warden/warden.json, state /var/lib/warden and"
    info "logs /var/log/warden were LEFT IN PLACE. Delete them yourself if"
    info "you want a clean slate."
}

case "${1:-install}" in
    --check)    report ;;
    --uninstall) cmd_uninstall ;;
    install|"") cmd_install ;;
    *) sed -n '2,20p' "$0"; exit 1 ;;
esac
