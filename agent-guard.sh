#!/usr/bin/env bash
# Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work
#
# agent-guard.sh — keep the AI agents current, and watch their code for
#                  insecure patterns. Detect by default; update only on request.
#
# SCOPE, and why it stops where it does:
#
#   This tool auto-UPDATES (pulls upstream releases) and auto-SCANS (reports
#   insecure patterns). It deliberately does NOT auto-PATCH source code.
#
#   Updating is safe because upstream did the review and shipped a signed
#   artefact; keeping agents current is the actual mitigation for known CVEs.
#
#   Auto-patching code unattended is a different thing entirely. Vulnerability
#   scanners have high false-positive rates, so an unattended patcher acting on
#   "potential" findings will eventually rewrite working code into broken code,
#   and it does so with persistent write access to the agent that runs you.
#   Findings are surfaced for a human to triage. That is the line.
#
#   Also worth being honest about: neither agent is dependency-auditable here.
#   opencode is a compiled binary with no manifest. hermes installs to
#   /opt/hermes-agent with no lockfile reachable from here. So there is no
#   honest CVE number to report for either — version lag and pattern findings
#   are the signals that actually exist.
#
# Usage:
#   agent-guard.sh              # report only, changes nothing
#   agent-guard.sh --apply      # perform pending updates
#   agent-guard.sh --enable-auto-update    # opt in to unattended updates
#   agent-guard.sh --disable-auto-update
#   agent-guard.sh --scan-only  # pattern scan, skip update check
#
set -uo pipefail

STATE_DIR="$HOME/.local/state/agent-guard"
LOG="$STATE_DIR/agent-guard.log"
VERSION_FILE="$STATE_DIR/versions.tsv"
AUTO_UPDATE_FLAG="$STATE_DIR/AUTO-UPDATE"
HERMES_SRC="$HOME/Projects/hermes-cli"

APPLY=0
SCAN_ONLY=0
for a in "$@"; do
  case "$a" in
    --apply)   APPLY=1 ;;
    --scan-only) SCAN_ONLY=1 ;;
    --enable-auto-update)  mkdir -p "$STATE_DIR"; touch "$AUTO_UPDATE_FLAG";
        echo "auto-update ENABLED — updates will be applied unattended"; exit 0 ;;
    --disable-auto-update) rm -f "$AUTO_UPDATE_FLAG";
        echo "auto-update DISABLED"; exit 0 ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE_DIR"
log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "${*:2}" | tee -a "$LOG" >&2; }

autoupdate_enabled() { [ -e "$AUTO_UPDATE_FLAG" ]; }

# ------------------------------------------------------------------ versions

opencode_version() { opencode --version 2>/dev/null | head -1 | tr -d '\r'; }
hermes_version()   { hermes --version 2>/dev/null | head -1 | tr -d '\r'; }

record_versions() {
  printf 'opencode\t%s\nhermes\t%s\nrecorded\t%s\n' \
    "$(opencode_version)" "$(hermes_version)" "$(date '+%Y-%m-%dT%H:%M:%S')" \
    > "$VERSION_FILE"
}

previous_version() {
  [ -f "$VERSION_FILE" ] || return 1
  awk -F'\t' -v k="$1" '$1==k {print $2; exit}' "$VERSION_FILE"
}

# -------------------------------------------------------------- pattern scan
#
# Focused on real classes of bug in agent tooling, not a generic linter.
# Findings are reported, never auto-fixed.

scan_patterns() {
  [ -d "$HERMES_SRC" ] || { log "INFO" "hermes source not found at $HERMES_SRC — skipping scan"; return 0; }

  local findings=0
  log "INFO" "scanning $HERMES_SRC for insecure patterns"

  # Dangerous dynamic execution.
  local dyn
  dyn=$(grep -rnE '\b(eval|exec)\(' "$HERMES_SRC/src" "$HERMES_SRC/tools" 2>/dev/null \
        | grep -vE '\.pyc|test_|_test\.py' | head -10)
  if [ -n "$dyn" ]; then
    log "FIND" "dynamic execution (eval/exec):"; printf '%s\n' "$dyn" | sed 's/^/    /' >&2
    findings=$((findings + 1))
  fi

  # Shell injection. Informational: config-driven service restarts are by design.
  local sh
  sh=$(grep -rn 'shell=True' "$HERMES_SRC/src" 2>/dev/null | head -5)
  if [ -n "$sh" ]; then
    log "FIND" "shell=True present — verify the command source is operator-owned config:"
    printf '%s\n' "$sh" | sed 's/^/    /' >&2
  fi

  # TLS verification disabled — always a real finding.
  local tls
  tls=$(grep -rn 'verify=False' "$HERMES_SRC/src" 2>/dev/null | head -5)
  if [ -n "$tls" ]; then
    log "FIND" "TLS verification disabled (verify=False):"
    printf '%s\n' "$tls" | sed 's/^/    /' >&2
    findings=$((findings + 1))
  fi

  # Unsafe deserialisation.
  local des
  des=$(grep -rnE '\bpickle\.loads|yaml\.load\((?!.*Loader)' "$HERMES_SRC/src" 2>/dev/null -P | head -5)
  if [ -n "$des" ]; then
    log "FIND" "unsafe deserialisation:"; printf '%s\n' "$des" | sed 's/^/    /' >&2
    findings=$((findings + 1))
  fi

  # Hardcoded credentials. Excludes env lookups and obvious placeholders.
  local sec
  sec=$(grep -rniE '(api[_-]?key|secret|password|token)\s*=\s*["'"'"'][A-Za-z0-9_\-]{16,}' \
        "$HERMES_SRC/src" "$HERMES_SRC/tools" 2>/dev/null \
        | grep -vE 'REPLACE_ME|getenv|environ|example|placeholder' | head -5)
  if [ -n "$sec" ]; then
    log "FIND" "possible hardcoded credential:"; printf '%s\n' "$sec" | sed 's/^/    /' >&2
    findings=$((findings + 1))
  fi

  # The config that feeds shell=True is a trust boundary; alert if it loosened.
  local loose
  loose=$(find "$HOME/.hermes" "$HOME/.config/hermes" -maxdepth 1 -perm /022 2>/dev/null | head -5)
  if [ -n "$loose" ]; then
    log "FIND" "agent config group/world-writable — config drives command execution:"
    printf '%s\n' "$loose" | sed 's/^/    /' >&2
    findings=$((findings + 1))
  fi

  if [ "$findings" -eq 0 ]; then
    log "OK" "pattern scan clean"
  else
    log "WARN" "$findings pattern class(es) flagged — for human triage, not auto-fixed"
  fi
  return "$findings"
}

# ------------------------------------------------------------------ updates

check_updates() {
  [ "$SCAN_ONLY" -eq 1 ] && return 0
  log "INFO" "checking for available updates"

  # Both agents ship their own updater. Prefer theirs: it knows about backups,
  # venv holders, gateway restarts and branch pinning.
  #
  # hermes' updater pulls from git, so it only works if the install is a git
  # checkout. A source tree dropped into /opt has no .git, and the updater
  # then reports "Not a git repository" while still exiting 0 — a silent
  # no-op that looks like success. Detect that explicitly.
  if [ -d /opt/hermes-agent ]; then
    if git -C /opt/hermes-agent rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      if hermes update --check >/dev/null 2>&1; then
        log "INFO" "hermes: update check completed"
      else
        log "WARN" "hermes update --check failed (offline, or updater needs network)"
      fi
    else
      log "GAP" "hermes CANNOT self-update: /opt/hermes-agent is not a git checkout."
      log "GAP" "  'hermes update' pulls from git and will no-op. Reinstall to upgrade:"
      log "GAP" "  see hermes --version ('Install method') and the upstream release channel."
    fi
  fi

  local oc_cur oc_prev
  oc_cur="$(opencode_version)"; oc_prev="$(previous_version opencode)"
  log "INFO" "opencode installed: ${oc_cur:-unknown} (last recorded: ${oc_prev:-none})"
  log "INFO" "hermes installed:   $(hermes_version)"
}

do_updates() {
  if [ "$APPLY" -eq 0 ]; then
    if autoupdate_enabled; then
      log "INFO" "auto-update enabled — proceeding unattended"
    else
      log "INFO" "report-only mode (no --apply, auto-update off) — nothing changed"
      return 0
    fi
  fi

  log "INFO" "updating hermes (its own updater, with backup)"
  if ! git -C /opt/hermes-agent rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    log "SKIP" "hermes update skipped: /opt/hermes-agent is not a git checkout — the updater cannot work"
  elif hermes update --yes --backup >>"$LOG" 2>&1; then
    log "OK" "hermes updated"
  else
    log "ERROR" "hermes update FAILED — see $LOG"
  fi

  log "INFO" "updating opencode"
  if opencode upgrade >>"$LOG" 2>&1; then
    log "OK" "opencode upgraded"
  else
    log "ERROR" "opencode upgrade FAILED — see $LOG"
  fi
}

# ---------------------------------------------------------------------- main

log "INFO" "=== agent-guard start (mode: $([ $APPLY -eq 1 ] && echo apply || echo report)) ==="

SCAN_RC=0
scan_patterns || SCAN_RC=$?
check_updates
do_updates
record_versions

printf '\n== agent-guard summary ==\n'
printf '  opencode : %s\n' "$(opencode_version)"
printf '  hermes   : %s\n' "$(hermes_version)"
printf '  scan     : %s\n' "$([ "$SCAN_RC" -eq 0 ] && echo 'clean' || echo "$SCAN_RC pattern class(es) flagged")"
printf '  auto-update: %s\n' "$(autoupdate_enabled && echo ENABLED || echo disabled)"
printf '  log      : %s\n' "$LOG"

exit "$SCAN_RC"