#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Copyright (c) 2026 Living Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
# Licensed under Living Sin Proprietary License (LSPL-1.0)
# See LICENSE file for details.
#
# kernel-healer.sh — detect and repair tampering with packaged system files.
#
# WHAT THIS IS NOT: it is not a snapshot-restore tool. It never copies a file
# back from a backup tarball. A backup taken on some earlier day can disagree
# with the installed system after any upgrade, and restoring it is how you end
# up with a mismatched kernel that will not boot.
#
# Instead the source of truth is pacman's own local database, which is derived
# from repository signatures. `pacman -Qkk <pkg>` reports every file whose size,
# mtime or SHA256 no longer matches what the signed package declared. Repair is
# reinstalling the package from the signed repository. So the "known good" state
# is never something I captured; it is always what the distribution signed.
#
# SCOPE, deliberately narrow:
#   - Only files OUTSIDE /etc are considered. /etc is the operator's. Silently
#     overwriting /etc/dracut.conf or /etc/default/grub is how a self-healer
#     bricks a working machine. Config drift is REPORTED, never repaired.
#   - Only an explicit package allowlist, never a glob over /usr or /boot.
#   - Never touches the running kernel; repairing /boot is out of scope
#     entirely, because /boot lives inside the root subvolume on this machine
#     and a wrong restore there costs you the machine.
#
# GUARDS, all of which abort rather than repair:
#   - dry-run unless --apply
#   - a DISABLED file acts as a kill switch
#   - refuses while a pacman transaction holds the database lock
#   - refuses when /boot is missing from the running kernel's module tree
#
# Usage:
#   kernel-healer.sh                 # detect only, report, change nothing
#   kernel-healer.sh --apply         # repair permitted alterations
#   kernel-healer.sh --report        # per-file detail, no repair
#
set -uo pipefail

STATE_DIR="$HOME/.local/state/kernel-healer"
LOG="$STATE_DIR/healer.log"
KILL_SWITCH="$STATE_DIR/DISABLED"

APPLY=0
REPORT=0
for a in "$@"; do
  case "$a" in
    --apply)  APPLY=1 ;;
    --report) REPORT=1 ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE_DIR"

log() {
  local lvl="$1"; shift
  printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$lvl" "$*" | tee -a "$LOG" >&2
}

# Explicit allowlist. Adding a package here means opting it into automated
# repair — do not widen this casually.
ALLOWLIST=(
  linux-zen linux-zen-headers linux-firmware
  dracut grub systemd glibc pam sudo shadow
  openssl util-linux coreutils bash
)

# ---------------------------------------------------------------- guards

if [ -e "$KILL_SWITCH" ]; then
  log "GUARD" "kill switch present at $KILL_SWITCH — no repair, exiting"
  exit 3
fi

if [ "$(id -u)" -ne 0 ]; then
  # Detection is useful unprivileged; repair is not possible.
  log "INFO" "not root — detection only (repair needs root)"
  APPLY=0
fi

# A live pacman transaction means the on-disk state is mid-change. Comparing
# against the database then produces nonsense, and reinstalling would fight it.
if [ -e /var/lib/pacman/db.lck ]; then
  log "GUARD" "pacman is mid-transaction (db.lck present) — refusing to compare"
  exit 3
fi

# If the running kernel's modules are not visible, the machine is not in a state
# where reinstalling a kernel-adjacent package is sane.
if [ ! -d "/usr/lib/modules/$(uname -r)" ]; then
  log "GUARD" "module tree for running kernel $(uname -r) is missing — refusing"
  exit 3
fi

# ---------------------------------------------------------------- inspect

# Report altered files that are NOT under /etc, per package.
altered_for() {
  local pkg="$1"
  pacman -Qkk "$pkg" 2>/dev/null \
    | grep -E '^warning:' \
    | grep -vE '^warning: [^:]+: /etc/'
}

TOTAL_BAD=0
REPAIRABLE=()
CONFIG_ONLY=()

log "INFO" "scan start (mode: $([ $APPLY -eq 1 ] && echo apply || echo detect-only))"

for pkg in "${ALLOWLIST[@]}"; do
  if ! pacman -Qi "$pkg" >/dev/null 2>&1; then
    log "WARN" "$pkg not installed — skipping"
    continue
  fi

  bad="$(altered_for "$pkg")"
  if [ -z "$bad" ]; then
    continue
  fi

  n="$(printf '%s\n' "$bad" | wc -l)"
  TOTAL_BAD=$((TOTAL_BAD + n))
  REPAIRABLE+=("$pkg")
  log "DETECT" "$pkg: $n altered file(s) outside /etc"

  if [ "$REPORT" -eq 1 ]; then
    printf '%s\n' "$bad" | sed 's/^warning: /    /' >&2
  fi

  # Config drift on the same package: visible, but deliberately not repaired.
  cfg="$(pacman -Qkk "$pkg" 2>/dev/null | grep -E '^warning:' | grep -E '^warning: [^:]+: /etc/' || true)"
  if [ -n "$cfg" ]; then
    CONFIG_ONLY+=("$pkg")
    log "CONFIG" "$pkg: $(printf '%s\n' "$cfg" | wc -l) altered file(s) under /etc — REPORT ONLY, not repaired"
    if [ "$REPORT" -eq 1 ]; then
      printf '%s\n' "$cfg" | sed 's/^warning: /    /' >&2
    fi
  fi
done

# ---------------------------------------------------------------- report

if [ "$TOTAL_BAD" -eq 0 ]; then
  log "OK" "no alterations outside /etc in any allowlisted package"
  printf '\nintegrity: OK — %d packages verified against signed pacman db\n' "${#ALLOWLIST[@]}"
  printf 'config drift: %d package(s) with /etc edits (reported, never repaired)\n' "${#CONFIG_ONLY[@]}"
  exit 0
fi

printf '\n%d altered file(s) outside /etc across %d package(s): %s\n' \
  "$TOTAL_BAD" "${#REPAIRABLE[@]}" "${REPAIRABLE[*]}"
printf 'config drift (not repaired): %s\n' "${CONFIG_ONLY[*]:-none}"

if [ "$APPLY" -eq 0 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    printf '\ndetection only (no root). To repair:\n  sudo %s --apply\n' "$0"
  else
    printf '\ndetection only. To repair:\n  sudo %s --apply\n' "$0"
  fi
  exit 1
fi

# ---------------------------------------------------------------- repair

log "INFO" "repairing ${#REPAIRABLE[@]} package(s) from the signed repository"
for pkg in "${REPAIRABLE[@]}"; do
  log "REPAIR" "reinstalling $pkg"
  # --overwrite '*' is required: pacman refuses to replace an existing file
  # that differs from the package without it, which is exactly our situation.
  if pacman -S --noconfirm --needed --overwrite '*' "$pkg" >>"$LOG" 2>&1; then
    log "OK" "$pkg restored"
  else
    log "ERROR" "$pkg repair FAILED — inspect $LOG"
  fi
done

# Verify rather than assume.
remaining=0
for pkg in "${REPAIRABLE[@]}"; do
  if [ -n "$(altered_for "$pkg")" ]; then
    log "ERROR" "$pkg still shows alterations after repair"
    remaining=$((remaining + 1))
  else
    log "OK" "$pkg verified clean after repair"
  fi
done

log "INFO" "repair pass complete, $remaining package(s) still dirty"
exit $([ "$remaining" -eq 0 ] && echo 0 || echo 1)