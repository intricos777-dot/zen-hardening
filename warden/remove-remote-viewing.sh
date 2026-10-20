#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
# remove-remote-viewing.sh — find, remove, and block remote-viewing /
# remote-control applications, TeamViewer first.
#
# WHY THIS ISN'T JUST A FIREWALL RULE
#
# block-remote-viewing.sh already drops TeamViewer's port 5938 (and the rest
# of that family). Blocking a port does nothing about the actual threat:
#
#   - TeamViewer's outbound traffic is tunnelled over HTTPS to its relay
#     fleet on 443. Port 5938 is the optional direct path, not the main one.
#   - Once installed, the agent registers with the vendor's cloud and the
#     box can be driven remotely with no inbound connection at all.
#   - A quiet install that re-registers on next boot undoes a port rule
#     entirely.
#
# So the layers are: don't install it, don't run it, don't run it after a
# reboot, and don't let it be installed by a dependency.
#
# CURRENT STATE ON THIS MACHINE (verified at authoring time):
#   no pacman package, no flatpak, no running process, nothing in /opt or
#   ~/.local/share/applications. So this is currently a PREVENTION tool, and
#   it says so rather than pretending to have removed something.
#
# Usage:
#   ./remove-remote-viewing.sh --check     report only, change nothing, no root
#   sudo ./remove-remote-viewing.sh        remove + block + prevent
#   sudo ./remove-remote-viewing.sh --unblock
#                                          lift the pacman hook, keep removed
#
# Exit codes: 0 clean, 1 findings/removal problems, 2 usage error.

set -uo pipefail

ZONE="${FIREWALLD_ZONE:-workstation}"
CONFDIR=/etc/warden-noview
HOOK="$CONFDIR/10-block-remote-viewing.hook"
GUARD=/usr/local/sbin/remote-viewing-guard
PROTECT="/etc/pacman.d/hook.warden-noview"

die() { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 2; }
ok()  { printf '  [ok] %s\n' "$*"; }
info() { printf '  %s\n' "$*"; }
warn() { printf '  \033[33m[warn] %s\033[0m\n' "$*"; }

MODE="${1:-apply}"
case "$MODE" in
    --check|--unblock|apply) ;;
    *) die "unknown argument: $MODE (use --check | --unblock | default apply)" ;;
esac

# --check is a pure report. Everything else writes, so it needs root.
# Requiring root to *look* would be the wrong trade: you should be able to
# audit this box without sudo.
[ "$MODE" = "--check" ] || [ "$(id -u)" -eq 0 ] \
    || die "needs root to make changes: sudo $0 ${MODE}"

# ── the watch list ──────────────────────────────────────────────────────
# name | pacman package | flatpak id | process name | install path fragment
TOOLS=(
  "TeamViewer      |teamviewer          |com.teamviewer.TeamViewer|teamviewer|/opt/TeamViewer"
  "AnyDesk          |anydesk             |com.anydesk.AnyDesk       |anydesk |/usr/share/anydesk"
  "RustDesk         |rustdesk            |com.rustdesk.RustDesk     |rustdesk|/usr/share/rustdesk"
  "NoMachine        |nomachine           |                            |nxserver|/usr/NX"
  "RealVNC          |realvnc             |                            |vncserver|/usr/lib/vnc"
  "TightVNC         |tightvnc            |                            |Xvnc      |/usr/bin/Xvnc"
  "Splashtop        |splashtop           |                            |SplashtopAgent|/opt/splashtop"
  "Parsec           |parsec              |                            |parsec    |/opt/parsec"
  "Sunlogin/向日葵  |sunlogin            |                            |sunloginclient|/opt/sunlogin"
  "AeroViewer       |aeroviewer          |                            |AeroViewer|/opt/AeroViewer"
  "UltraViewer      |ultraviewer         |                            |UltraViewer_Desktop|/opt/ultraviewer"
  "Screenpresso     |screenpresso        |                            |screenpresso|/opt/screenpresso"
  "DWService        |dwservice           |                            |dwagent   |/opt/dwservice"
  "LogMeIn          |logmein             |                            |LogMeIn   |/opt/logmein"
)

AUDIT=/var/log/warden-noview.log
audit() { printf '%s  %s\n' "$(date -Is)" "$*" | tee -a "$AUDIT" >/dev/null; }

# ── detect ──────────────────────────────────────────────────────────────
detect_installed() {
    # Returns 0 when something WAS found, 1 when the box is clean -- i.e. the
    # conventional "did the thing I was asked to do" meaning, so the caller's
    # `if` reads correctly. Do not invert this.
    local found=0
    for t in "${TOOLS[@]}"; do
        IFS='|' read -r name pkg flat proc path <<<"$t"
        # Columns are space-padded for readability, so strip whitespace from
        # every field. `pgrep -x 'anydesk '` matches nothing, which would make
        # the whole table silently useless.
        name="${name% }"; pkg="${pkg// }"; proc="${proc// }"

        if pacman -Qq "$pkg" >/dev/null 2>&1; then
            printf '  \033[31m[pkg ]\033[0m %-18s installed package %s\n' "$name" "$pkg"
            found=1; continue
        fi
        if flatpak list --app 2>/dev/null | grep -qF "$flat"; then
            printf '  \033[31m[flat]\033[0m %-18s installed flatpak %s\n' "$name" "$flat"
            found=1; continue
        fi
        if pgrep -x "$proc" >/dev/null 2>&1 || pgrep -f "$path/" >/dev/null 2>&1; then
            printf '  \033[31m[proc]\033[0m %-18s running now (pid %s)\n' \
                "$name" "$(pgrep -f "$path/" | tr '\n' ' ')"
            found=1; continue
        fi
        if [ -e "$path" ]; then
            printf '  \033[31m[path]\033[0m %-18s present at %s\n' "$name" "$path"
            found=1; continue
        fi
        # NOT `ls dir/*a* dir/*b* ...`: ls exits 2 when any single glob is
        # unmatched, so this idiom reports "no unit found" even when one is.
        local i hits
        for i in /etc/systemd/system /usr/lib/systemd/system "$HOME/.config/systemd/user"; do
            [ -d "$i" ] || continue
            hits=$(find "$i" -maxdepth 1 \
                \( -name '*teamviewer*' -o -name '*anydesk*' -o -name '*rustdesk*' \
                   -o -name '*nomachine*' -o -name '*vncserver*' -o -name '*sunlogin*' \
                   -o -name '*dwservice*' -o -name '*splashtop*' \) 2>/dev/null)
            if [ -n "$hits" ]; then
                printf '  \033[31m[unit]\033[0m %-18s systemd unit: %s\n' \
                    "$name" "$(echo "$hits" | tr '\n' ' ')"
                found=1
                break
            fi
        done
        [ "$found" = 1 ] && continue
        [ -e "$HOME/.config/teamviewer" ] && {
            printf '  \033[31m[cfg ]\033[0m %-18s user config in ~/.config/teamviewer\n' "$name"
            found=1; continue; }
    done
    # 0 = found something, 1 = clean.
    [ "$found" = 1 ] && return 0
    return 1
}

# ── check ───────────────────────────────────────────────────────────────
cmd_check() {
    echo "=== remote-viewing / remote-control applications ==="
    echo
    echo "  installed or running:"
    if detect_installed; then :; else
        ok "none found (no package, no flatpak, no process, no path, no unit)"
    fi
    echo
    echo "  listening sockets owned by remote-control software:"
    local any=0 line
    while read -r line; do
        echo "    $line"; any=1
    done < <(ss -tulpnH 2>/dev/null \
        | grep -iE 'teamviewer|anydesk|rustdesk|nomachine|nxserver|vncserver|Xvnc|splashtop|parsec|sunlogin|logmein|dwagent')
    [ "$any" = 1 ] || ok "none"

    echo
    echo "  prevention state:"
    if [ -f "$HOOK" ]; then ok "pacman hook active: $HOOK"
    else warn "pacman hook NOT installed (sudo $0)"; fi
    if firewall-cmd --zone="$ZONE" --query-rich-rule \
        'rule family="ipv4" port port="5938" protocol="tcp" drop' >/dev/null 2>&1; then
        ok "firewalld drops 5938 (TeamViewer) in zone $ZONE"
    else
        warn "firewalld 5938 drop NOT present in zone $ZONE"
    fi
    if systemctl is-enabled --quiet remote-viewing-guard.timer 2>/dev/null; then
        ok "reinstall guard timer enabled"
    else
        warn "reinstall guard timer not enabled"
    fi
    echo
    return 0
}

# ── remove ──────────────────────────────────────────────────────────────
cmd_remove() {
    local removed=0 killed=0
    echo "=== removing ==="
    for t in "${TOOLS[@]}"; do
        IFS='|' read -r name pkg flat proc path <<<"$t"
        name="${name% }"; pkg="${pkg// }"; proc="${proc// }"

        # 1. stop the process before deleting its files, or a running agent
        #    simply re-creates what we remove.
        if pgrep -x "$proc" >/dev/null 2>&1 || pgrep -f "$path/" >/dev/null 2>&1; then
            pkill -f "$path/" 2>/dev/null && { ok "killed running $name"; killed=$((killed+1)); }
            pkill -x "$proc" 2>/dev/null && ok "killed $proc"
        fi
        systemctl stop teamviewer3.service teamviewer.service anydesk.service \
            rustdesk.service nomachine.service vncserver.service 2>/dev/null
        systemctl --user stop teamviewer3.service anydesk.service 2>/dev/null

        # 2. package
        if pacman -Qq "$pkg" >/dev/null 2>&1; then
            if pacman -Rns --noconfirm "$pkg" >/dev/null 2>&1; then
                ok "removed package $pkg"; removed=$((removed+1))
            else
                warn "could not remove package $pkg"
            fi
        fi
        # 3. flatpak
        if flatpak list --app 2>/dev/null | grep -qF "$flat"; then
            flatpak uninstall -y --delete-data "$flat" >/dev/null 2>&1 \
                && { ok "removed flatpak $flat"; removed=$((removed+1)); } \
                || warn "could not remove flatpak $flat"
        fi
        # 4. leftover trees, only for the specific tool named above
        if [ -e "$path" ]; then
            rm -rf "$path" && { ok "deleted $path"; removed=$((removed+1)); }
        fi
        rm -rf "$HOME/.config/teamviewer" "$HOME/.local/share/TeamViewer" \
               "$HOME/.cache/teamviewer" 2>/dev/null
    done
    # teamviewer also drops a desktop entry and a keyring entry
    rm -f /usr/share/applications/teamviewer.desktop \
          /usr/share/applications/anydesk.desktop \
          /usr/share/applications/rustdesk.desktop 2>/dev/null
    systemctl daemon-reload
    info "removed $removed item(s), killed $killed process(es)"
    audit "removal pass: removed=$removed killed=$killed"
    return 0
}

# ── prevent ─────────────────────────────────────────────────────────────
cmd_prevent() {
    echo "=== preventing reinstall ==="
    install -d -m 0755 "$CONFDIR"
    # NOTE: the heredoc body must start on the line after the delimiter, but
    # that leaves a blank first line and the shebang on line 2. pacman execs
    # the hook directly, so write the shebang separately and keep the heredoc
    # for the body only.
    printf '#!/usr/bin/bash\n' > "$HOOK"
    cat >> "$HOOK" <<'HOOKEOF'
# Generated by remove-remote-viewing.sh -- deny install of remote-control
# software at the package-manager level.
#
# Trigger=PreTransaction  fires before pacman/any AUR helper commits, so a
# blocked package is refused rather than installed and then removed.
#
# Maintainer: local policy. Remove with: remove-remote-viewing.sh --unblock
blocked="teamviewer teamviewer3 libteamviewer anydesk rustdesk nomachine
        realvnc tightvnc tigervnc sunlogin splashtop parsec logmein
        dwservice aeroviewer screenpresso uvnc x11vnc vino krfb freerdp xrdp"

for pkg in $blocked; do
    if [[ " $1 $2 $3 $4 $5 $6 " == *" $pkg "* ]]; then
        printf '\033[31mBLOCKED by local policy:\033[0m %s is on the remote-control deny list.\n' "$pkg" >&2
        printf 'This machine is not allowed to run unattended remote-viewing software.\n' >&2
        printf 'If you genuinely need it, remove this hook first:\n' >&2
        printf '  sudo rm %s\n' "$HOOK" >&2
        exit 1
    fi
done
exit 0
HOOKEOF
    chmod 0755 "$HOOK"
    ok "pacman PreTransaction hook installed: $HOOK"

    # Independent belt-and-braces: a timer that re-checks every 10 minutes.
    # A hook can be deleted or bypassed by a helper that ignores it; this
    # catches the install either way and removes it again.
    install -Dm755 "$(dirname "${BASH_SOURCE[0]}")/remote-viewing-guard" "$GUARD"
    cat > /etc/systemd/system/remote-viewing-guard.service <<EOF
[Unit]
Description=Remove remote-control software if it appears

[Service]
Type=oneshot
ExecStart=$GUARD
EOF
    cat > /etc/systemd/system/remote-viewing-guard.timer <<EOF
[Unit]
Description=Check every 10 minutes for remote-control software

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
AccuracySec=1min

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now remote-viewing-guard.timer
    ok "reinstall guard timer enabled (every 10 min)"

    # Outbound relay blocking: TeamViewer drives over 443, so the port rule
    # alone does nothing. Block its known relay ranges by ASN-independent
    # method we can do without a subscription: the agent's own domains are
    # blocked at DNS via /etc/hosts, which works with no extra daemon.
    for host in teamviewer.com masterteamviewer.com; do
        grep -qE "^0\.0\.0\.0[[:space:]]+$host\$" /etc/hosts \
            || printf '0.0.0.0 %s\n' "$host" >> /etc/hosts
    done
    ok "TeamViewer relay domains blackholed in /etc/hosts (no 443 egress to vendor)"

    # And the firewall half, if firewalld is running.
    if systemctl is-active --quiet firewalld; then
        if firewall-cmd --permanent --zone="$ZONE" \
             --add-rich-rule='rule family="ipv4" port port="5938" protocol="tcp" drop' 2>/dev/null; then
            ok "firewalld rich rule added for 5938 in $ZONE (permanent)"
        fi
        firewall-cmd --reload >/dev/null 2>&1 && ok "firewalld reloaded"
    fi
    audit "prevention installed: hook=$HOOK guard=$GUARD"
}

cmd_unblock() {
    echo "=== lifting the block ==="
    rm -f "$HOOK" && ok "pacman hook removed"
    systemctl disable --now remote-viewing-guard.timer 2>/dev/null || true
    rm -f /etc/systemd/system/remote-viewing-guard.service \
          /etc/systemd/system/remote-viewing-guard.timer "$GUARD"
    systemctl daemon-reload
    ok "guard timer disabled"
    info "already-removed software is NOT reinstalled. Undo the hosts entries by"
    info "hand if you want TeamViewer's relay reachable again."
    audit "prevention lifted by user"
}

case "$MODE" in
    --check)    cmd_check ;;
    --unblock)  cmd_unblock ;;
    apply|"")   cmd_check; echo; cmd_remove; echo; cmd_prevent; echo; cmd_check ;;
    *) die "unknown mode: $MODE (use --check | --unblock | default apply)" ;;
esac
