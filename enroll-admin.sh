#!/bin/bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# enroll-admin.sh — manage membership of the shield-admin group.
#
# shield-admin is the pam_faillock admin_group. Members of it are NEVER locked
# out of this machine. That makes membership a security control, not a
# convenience, so adding someone is gated here rather than done with a bare
# `usermod -aG`.
#
#   ./enroll-admin.sh status          show who is exempt, and who is not
#   ./enroll-admin.sh add <user>      add a member (asks why; refuses by default)
#   ./enroll-admin.sh remove <user>   remove a member
#
# Refusal policy: `add` REFUSES to enrol anyone other than the primary admin
# while /etc/shield-kitty/enroll.lock exists. To allow another account you must
# deliberately delete that lock file. Nothing enrols anybody by accident.

set -uo pipefail

GROUP="shield-admin"
PRIMARY_ADMIN="livings"
LOCKFILE="/etc/shield-kitty/enroll.lock"
SUDOERS_D="/etc/sudoers.d"

die() { echo "ERROR: $*" >&2; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "needs root: sudo $0 $*"
}

group_exists() { getent group "$GROUP" >/dev/null 2>&1; }

ensure_group() {
    group_exists && return 0
    groupadd --system "$GROUP" || die "could not create group $GROUP"
    echo "created system group $GROUP"
}

cmd_status() {
    echo "=== faillock admin_group ==="
    if grep -qE '^[[:space:]]*admin_group' /etc/security/faillock.conf 2>/dev/null; then
        grep -E '^[[:space:]]*admin_group' /etc/security/faillock.conf
    else
        echo "  (admin_group NOT set in /etc/security/faillock.conf — nobody is exempt)"
    fi

    echo
    echo "=== members of $GROUP (these are NEVER locked out) ==="
    if group_exists; then
        getent group "$GROUP"
    else
        echo "  (group does not exist)"
    fi

    echo
    if [ -e "$LOCKFILE" ]; then
        echo "ENROLLMENT: LOCKED — only $PRIMARY_ADMIN may be a member."
        echo "  (lock file: $LOCKFILE)"
    else
        echo "ENROLLMENT: OPEN — any account may be added."
    fi

    echo
    echo "=== accounts that can become members without this script ==="
    echo "  anyone who can write to $GROUP via:"
    echo "    - root, obviously"
    echo "    - $SUDOERS_D/* granting gpasswd/usermod/groupadd"
    echo "    - any NSS-backed directory service (LDAP/AD) that manages groups"
    ls -l "$SUDOERS_D" 2>/dev/null | tail -n +2 || echo "    (cannot list $SUDOERS_D without root)"
}

cmd_add() {
    local user="${1:-}"
    [ -n "$user" ] || die "usage: $0 add <user>"

    # Policy is checked FIRST, before any other validation. Otherwise an
    # unprivileged run against a nonexistent user reports "no such user"
    # instead of the refusal, and — worse — a real user would reach the
    # usermod call before anyone decided whether they should be allowed.
    if [ "$user" != "$PRIMARY_ADMIN" ] && [ -e "$LOCKFILE" ]; then
        echo "REFUSED: enrolling $user would grant a permanent lockout exemption." >&2
        echo >&2
        echo "  Only $PRIMARY_ADMIN may be in $GROUP while the lock is in place." >&2
        echo "  $user would never be locked out of this machine, and neither" >&2
        echo "  would an attacker who guesses $user's password." >&2
        echo >&2
        echo "  If you genuinely want this, remove the lock and re-run:" >&2
        echo "    sudo rm $LOCKFILE && sudo $0 add $user" >&2
        echo >&2
        echo "  Re-lock afterwards:" >&2
        echo "    sudo $0 lock" >&2
        exit 2
    fi

    id "$user" >/dev/null 2>&1 || die "no such user: $user"
    require_root add "$user"
    ensure_group
    usermod -aG "$GROUP" "$user" || die "usermod failed"
    echo "added $user to $GROUP — this account can no longer be locked out"
    echo "reboot or start a new session for group membership to take effect"
    cmd_status
}

cmd_remove() {
    local user="${1:-}"
    [ -n "$user" ] || die "usage: $0 remove <user>"
    [ "$user" != "$PRIMARY_ADMIN" ] || die "refusing to remove the primary admin ($user) from $GROUP; that is the account this whole control exists for"
    require_root remove "$user"
    group_exists || die "group $GROUP does not exist"
    gpasswd -d "$user" "$GROUP" >/dev/null || die "gpasswd failed"
    echo "removed $user from $GROUP — faillock now applies to this account"
}

cmd_lock() {
    require_root lock
    mkdir -p "$(dirname "$LOCKFILE")"
    printf 'locked %s by %s\n' "$(date -Is)" "$(logname 2>/dev/null || echo root)" > "$LOCKFILE"
    chmod 0644 "$LOCKFILE"
    echo "enrollment locked: only $PRIMARY_ADMIN may be a member of $GROUP"
}

cmd_unlock() {
    require_root unlock
    rm -f "$LOCKFILE"
    echo "enrollment OPEN — any account can be added to $GROUP from now on"
    echo "re-lock with: sudo $0 lock"
}

case "${1:-status}" in
    status)  cmd_status ;;
    add)     shift; cmd_add "$@" ;;
    remove)  shift; cmd_remove "$@" ;;
    lock)    cmd_lock ;;
    unlock)  cmd_unlock ;;
    *)       sed -n '2,20p' "$0"; exit 1 ;;
esac
