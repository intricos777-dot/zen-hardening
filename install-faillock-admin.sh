#!/bin/bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
# install-faillock-admin.sh — apply the single-admin faillock policy.
#
#   sudo ./install-faillock-admin.sh
#   sudo ./install-faillock-admin.sh --uninstall
#
# What it does:
#   1. creates the shield-admin system group (single member: livings)
#   2. adds livings to it
#   3. installs faillock.conf with admin_group = shield-admin
#   4. writes the enrollment lock so nobody else can be added
#   5. backs up whatever was in /etc/security/faillock.conf
#
# Refuses to run if the group would end up with more than one member, and
# refuses to remove livings from the group.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GROUP="shield-admin"
PRIMARY_ADMIN="livings"
CONF="/etc/security/faillock.conf"
LOCKDIR="/etc/shield-kitty"
LOCKFILE="$LOCKDIR/enroll.lock"
BACKUP_DIR="/var/backups/shield-kitty"

die() { echo "ERROR: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "needs root: sudo $0"

if [ "${1:-}" = "--uninstall" ]; then
    echo "Removing single-admin faillock policy..."
    if [ -f "$BACKUP_DIR/faillock.conf.orig" ]; then
        cp "$BACKUP_DIR/faillock.conf.orig" "$CONF"
        echo "  restored original $CONF"
    else
        echo "  no backup at $BACKUP_DIR/faillock.conf.orig — leaving $CONF alone"
    fi
    gpasswd -d "$PRIMARY_ADMIN" "$GROUP" >/dev/null 2>&1 && \
        echo "  removed $PRIMARY_ADMIN from $GROUP" || true
    groupdel "$GROUP" >/dev/null 2>&1 && echo "  deleted group $GROUP" || true
    rm -f "$LOCKFILE"
    systemctl restart sddm.service 2>/dev/null && echo "  restarted sddm"
    echo "Done. $PRIMARY_ADMIN is subject to normal faillock lockout again."
    exit 0
fi

echo "Installing single-admin faillock policy..."

# --- 1. group ---
if ! getent group "$GROUP" >/dev/null 2>&1; then
    groupadd --system "$GROUP" || die "groupadd failed"
    echo "  created system group $GROUP"
else
    echo "  group $GROUP exists"
fi

# --- 2. membership: exactly the primary admin, no one else ---
MEMBERS="$(getent group "$GROUP" | cut -d: -f4)"
if [ -n "$MEMBERS" ]; then
    UNEXPECTED="$(echo "$MEMBERS" | tr ',' '\n' | grep -v "^$PRIMARY_ADMIN$" | grep -v '^$' || true)"
    if [ -n "$UNEXPECTED" ]; then
        echo "  existing members besides $PRIMARY_ADMIN:"
        echo "$UNEXPECTED" | sed 's/^/    /'
        echo "  leaving them in place; remove them with:"
        echo "    sudo gpasswd -d <user> $GROUP"
    fi
fi
usermod -aG "$GROUP" "$PRIMARY_ADMIN" || die "usermod failed"
echo "  $PRIMARY_ADMIN is in $GROUP"

# Post-condition: refuse to continue if the group is not single-member.
MEMBERS_AFTER="$(getent group "$GROUP" | cut -d: -f4 | tr ',' '\n' | grep -v '^$' | sort)"
COUNT="$(echo "$MEMBERS_AFTER" | grep -c .)"
echo "$MEMBERS_AFTER" | sed 's/^/    member: /'
if [ "$COUNT" -ne 1 ] || [ "$MEMBERS_AFTER" != "$PRIMARY_ADMIN" ]; then
    die "$GROUP has $COUNT members, expected exactly 1 ($PRIMARY_ADMIN). Not installing the config — fix membership first."
fi

# --- 3. config ---
mkdir -p "$BACKUP_DIR"
if [ -f "$CONF" ] && [ ! -f "$BACKUP_DIR/faillock.conf.orig" ]; then
    cp "$CONF" "$BACKUP_DIR/faillock.conf.orig"
    echo "  backed up original $CONF -> $BACKUP_DIR/faillock.conf.orig"
fi
install -m 0644 -o root -g root "$REPO_DIR/faillock.conf" "$CONF" || die "could not install $CONF"
echo "  installed $CONF"

# --- 4. enrollment lock ---
mkdir -p "$LOCKDIR"
printf 'locked %s — only %s may be a member of %s\n' "$(date -Is)" "$PRIMARY_ADMIN" "$GROUP" > "$LOCKFILE"
chmod 0644 "$LOCKFILE"
install -m 0755 "$REPO_DIR/enroll-admin.sh" /usr/local/sbin/enroll-admin
echo "  enrollment locked; helper installed at /usr/local/sbin/enroll-admin"

# --- 5. apply ---
# sddm owns the graphical login; PAM config is read per-authentication but the
# greeter caches, so restart it to be sure.
systemctl restart sddm.service 2>/dev/null || true

echo
echo "Applied. Verifying:"
echo "  admin_group : $(grep -E '^[[:space:]]*admin_group' "$CONF" || echo MISSING)"
echo "  group       : $(getent group "$GROUP")"
echo "  lock        : $LOCKFILE"
echo
echo "$PRIMARY_ADMIN cannot be locked out. Every other account can."
echo "To add someone else you must first:  sudo rm $LOCKFILE"
echo "Check status any time with:  enroll-admin status"
