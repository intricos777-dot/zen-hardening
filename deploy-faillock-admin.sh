#!/bin/bash
# deploy-faillock-admin.sh — make `livings` the only account that pam_faillock
# will never lock out.
#
# This deploys the "admin exemption" half of the Shield Kitty profile. It does
# NOT enable permanent lockout (unlock_time = 0), because permanent lockout
# with a non-functional exemption is an unrecoverable self-lockout.
#
# The order below is the whole point of this script:
#
#   1. back up the live config
#   2. create shield-admin
#   3. enrol livings
#   4. VERIFY the enrolment actually took
#   5. only then install a config that references admin_group
#   6. close enrollment so nothing else can join
#
# Step 4 is the one that matters. If the config names a group that does not
# exist, or names a group the admin is not in, pam_faillock finds no exempt
# members and locks the admin out along with everyone else. Installing the
# config first and hoping is how that happens.
#
# Usage:
#   sudo ./deploy-faillock-admin.sh            deploy
#   sudo ./deploy-faillock-admin.sh --check    report state, change nothing
#   sudo ./deploy-faillock-admin.sh --revert   restore the backup

set -euo pipefail

GROUP="shield-admin"
PRIMARY_ADMIN="livings"
CONF="/etc/security/faillock.conf"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENROLL="$HERE/enroll-admin.sh"

die() { echo "ERROR: $*" >&2; exit 1; }
ok()  { echo "  [ok] $*"; }
info() { echo "  $*"; }

require_root() { [ "$(id -u)" -eq 0 ] || die "needs root: sudo $0 $*"; }

# --- state reporting, safe to run as anyone ---------------------------

report() {
    echo "=== faillock admin exemption ==="

    if grep -qE '^[[:space:]]*admin_group' "$CONF" 2>/dev/null; then
        info "config admin_group: $(grep -E '^[[:space:]]*admin_group' "$CONF" | tr -s ' ')"
    else
        info "config admin_group: NOT SET -- nobody is exempt"
    fi

    if getent group "$GROUP" >/dev/null 2>&1; then
        info "group $GROUP: $(getent group "$GROUP")"
    else
        info "group $GROUP: DOES NOT EXIST"
    fi

    if [ -e /etc/shield-kitty/enroll.lock ]; then
        info "enrollment: LOCKED (only $PRIMARY_ADMIN may be a member)"
    else
        info "enrollment: OPEN -- any account could be enrolled"
    fi

    echo
    echo "=== is the exemption actually in effect? ==="
    # The only assertion that matters: does the PAM module see an exempt member?
    # getent prints "name:x:gid:mem1,mem2" -- the member list is field 4, comma
    # separated. Splitting on ',' alone leaves the "name:x:gid:" prefix glued to
    # the first member and a `grep -x` comparison never matches.
    if getent group "$GROUP" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -qx "$PRIMARY_ADMIN" \
       && grep -qE '^[[:space:]]*admin_group[[:space:]]*=[[:space:]]*'"$GROUP" "$CONF" 2>/dev/null; then
        ok "$PRIMARY_ADMIN is in $GROUP and the config names it -> NEVER locked out"
    else
        info "NOT in effect: $PRIMARY_ADMIN would be locked out like any other account"
    fi
}

cmd_check() { report; }

# --- deploy -----------------------------------------------------------

cmd_deploy() {
    require_root deploy
    [ -x "$ENROLL" ] || die "enroll-admin.sh not found or not executable at $ENROLL"
    [ -f "$HERE/faillock.conf" ] || die "faillock.conf not found next to this script"

    echo "=== 1/6  backing up $CONF ==="
    if [ -f "$CONF" ]; then
        cp -a "$CONF" "$CONF.orig.$(date +%Y%m%d%H%M%S)"
        ok "backup written (see 'ls ${CONF}.orig.*')"
    else
        info "no existing $CONF, nothing to back up"
    fi

    echo "=== 2/6  group $GROUP ==="
    if getent group "$GROUP" >/dev/null 2>&1; then
        ok "already exists"
    else
        groupadd --system "$GROUP" || die "groupadd failed"
        ok "created system group $GROUP"
    fi

    echo "=== 3/6  enrolling $PRIMARY_ADMIN ==="
    # $ENROLL add is idempotent-ish: it refuses non-primary accounts while the
    # lock is present, which is exactly the guarantee we want here.
    "$ENROLL" add "$PRIMARY_ADMIN" >/dev/null || die "enrollment failed; aborting before the config is touched"
    ok "processed"

    echo "=== 4/6  verifying the enrolment took effect ==="
    # Do not trust the exit status of the enroll script alone; read the group
    # database back. This is the check that stands between "admin exempt" and
    # "admin locked out of their own machine".
    if getent group "$GROUP" | cut -d: -f4 | tr ',' '\n' | grep -qx "$PRIMARY_ADMIN"; then
        ok "$PRIMARY_ADMIN is a member of $GROUP"
    else
        die "enrolment did not take -- $PRIMARY_ADMIN is not in $GROUP.
       Refusing to install a config that names a group you are not in.
       Nothing has been changed beyond the backup and the empty group."
    fi

    echo "=== 5/6  installing faillock.conf ==="
    install -Dm644 "$HERE/faillock.conf" "$CONF" || die "install failed"
    ok "installed $CONF"
    if grep -qE '^[[:space:]]*admin_group[[:space:]]*=[[:space:]]*'"$GROUP" "$CONF"; then
        ok "config names admin_group = $GROUP"
    else
        die "installed config does not name admin_group = $GROUP; leaving it in place for inspection, NOT re-enabling anything"
    fi

    echo "=== 6/6  closing enrollment ==="
    "$ENROLL" lock || die "could not create the enrollment lock"
    ok "enrollment locked to $PRIMARY_ADMIN"

    echo
    report
    cat <<'EOF'

=== next step ===

Group membership is read at process start, so the exemption becomes
effective for NEW logins. Log out and back in (or reboot) before testing.

Do NOT test by typing a wrong password 11 times. To confirm the exemption
safely, check that your account has no faillock tally to begin with:

    sudo faillock --user livings

If you ever DO get locked out, recovery is one root command:

    sudo faillock --user livings --reset

unlock_time is 30s, not 0, so a normal lockout also clears on its own.
EOF
}

# --- revert -----------------------------------------------------------

cmd_revert() {
    require_root revert
    local latest
    latest="$(ls -1t "$CONF".orig.* 2>/dev/null | head -1)" \
        || die "no backup found: ls ${CONF}.orig.*"
    [ -n "$latest" ] || die "no backup found: ls ${CONF}.orig.*"
    echo "restoring $latest -> $CONF"
    cp -a "$latest" "$CONF"
    ok "restored"
    echo "note: the $GROUP group and its membership were left in place."
    echo "      remove them with: sudo groupdel $GROUP   (only if nobody is in it)"
    report
}

case "${1:-deploy}" in
    --check) cmd_check ;;
    --revert) cmd_revert ;;
    deploy|"") cmd_deploy ;;
    *) sed -n '2,25p' "$0"; exit 1 ;;
esac
