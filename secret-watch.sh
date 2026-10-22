#!/usr/bin/env bash
# secret-watch.sh — daily compromise detector for tokens / SSH keys / API keys
#
# Compromise signals:
#   [I] inventory file missing, hash mismatch, or readable by group/others
#   [L] a secret-looking file exists in an unexpected location on disk
#   [G] GitHub account SSH/signing keys changed vs baseline (new = prime suspect)
#   [H] ~/.ssh appeared or new entries in it (this machine had none at baseline)
#
# Exit: 0 clean, 1 internal/config error, 2 compromise findings.
#
# Usage:
#   secret-watch.sh init                 create config skeleton + state dirs
#   secret-watch.sh baseline             (re)record inventory hashes + GitHub snapshot
#   secret-watch.sh --add PATH [LABEL]   add secret to inventory then baseline it
#   secret-watch.sh --allow-loc PATH     permanently allow a discovered location
#   secret-watch.sh check                run the daily check (default cmd)
#   secret-watch.sh --install            install systemd user service + timer
#   secret-watch.sh --help
#
set -uo pipefail

STATE="${XDG_STATE_HOME:-$HOME/.local/state}/secret-watch"
CONF="${XDG_CONFIG_HOME:-$HOME/.config}/secret-watch"
SECRETS_CONF="$CONF/secrets.conf"
SUPPRESS_CONF="$CONF/allow-locations.conf"
SUPPRESS_GLOB_CONF="$CONF/allow-patterns.conf"
GH_TOKEN_PATH_CONF="$CONF/github-token-path"
GH_BASELINE="$STATE/github-account-keys.json"
INV="$STATE/inventory.tsv"
TODAY="$(date +%F)"
REPORT="$STATE/report-$TODAY.log"
FINDINGS="$STATE/findings.log"
EXIT_CODE=0

log()  { printf '['"$(date '+%F %T')"'] %s\n' "$*" | tee -a "$FINDINGS"; }
die()  { printf '[FATAL] %s\n' "$*" >&2; exit 1; }

init() {
  mkdir -p "$STATE" "$CONF"
  chmod 700 "$STATE" "$CONF"
  [[ -f "$SECRETS_CONF" ]] || { printf '# path<TAB>label  (one per line; absolute paths)\n' > "$SECRETS_CONF"; chmod 600 "$SECRETS_CONF"; }
  [[ -f "$SUPPRESS_CONF" ]] || { printf '# absolute paths of secret locations you accept (one per line)\n' > "$SUPPRESS_CONF"; chmod 600 "$SUPPRESS_CONF"; }
  : > "$INV"
  echo "init done: $SECRETS_CONF  (then use: $0 --add <secret-file> [label] , $0 baseline , $0 --install)"
}

# --- inventory helpers -------------------------------------------------------
baseline_github() {
  local tokpath
  [[ -f "$GH_TOKEN_PATH_CONF" ]] && tokpath="$(cat "$GH_TOKEN_PATH_CONF")"
  if [[ -z "${tokpath:-}" || ! -f "$tokpath" ]]; then
    echo "github-token-path not set or file missing; skipping GitHub snapshot ($GH_TOKEN_PATH_CONF)"
    return
  fi
  local hfile="$STATE/.gh-header.$$"
  trap 'rm -f "${hfile:-}" 2>/dev/null' EXIT
  printf 'Authorization: Bearer %s\n' "$(cat "$tokpath")" > "$hfile"; chmod 600 "$hfile"

  local base kfile sigfile
  base="$STATE/.gh-keys-serial.$$"
  sigfile="$STATE/github-keys-last-update"
  kfile="$GH_BASELINE"
  curl -sf --max-time 20 --header "@$hfile" 'https://api.github.com/user/keys' -o "$kfile" 2>/dev/null \
    || curl -sf --max-time 20 --header "@$hfile" 'https://api.github.com/user/keys' -o "$kfile"
  if [[ -s "$kfile" ]]; then
    date '+%F %T' > "$sigfile"
    echo "github keys snapshot stored: $kfile"
  else
    echo "warning: could not fetch /user/keys (likely scope/permission); GitHub diff check disabled"
    rm -f "$kfile" "$sigfile"
  fi
  rm -f "$hfile"
}

cmd_baseline() {
  mkdir -p "$STATE" "$CONF"; chmod 700 "$STATE" "$CONF"
  : > "$INV"
  local n=0
  while IFS=$'\t' read -r path label; do
    [[ -z "${path:-}" || "$path" == \#* ]] && continue
    [[ -f "$path" ]] || { echo "warning: secret path not found, skipped: $path"; continue; }
    printf '%s\t%s\t%s\n' "$path" "$label" "$(sha256sum -- "$path" | cut -d' ' -f1)" >> "$INV"
    n=$((n+1))
  done < "$SECRETS_CONF"
  baseline_github
  chmod 600 "$INV" "$GH_BASELINE" 2>/dev/null || true
  echo "baseline recorded: $n secrets -> $INV"
}

# --- checks ------------------------------------------------------------------
F_HEADER=false
note() {
  $F_HEADER || { log "=== secret-watch inventory findings $TODAY ==="; F_HEADER=true; }
  EXIT_CODE=2
  printf '%s %s\n' "$1" "$2" >> "$REPORT"
  log "$1 $2"
}
G_HEADER=false
gnote() {
  $G_HEADER || { log "=== github findings $TODAY ==="; G_HEADER=true; }
  EXIT_CODE=2
  printf '%s %s\n' "$1" "$2" >> "$REPORT"
  log "$1 $2"
}

check_inventory() {
  while IFS=$'\t' read -r path label hash; do
    if [[ ! -f "$path" ]]; then
      note "[I]" "secret MISSING: $path  ($label) — destroyed, moved, or destroyed by someone else"
      continue
    fi
    local now h
    now="$(sha256sum -- "$path" | cut -d' ' -f1)"
    [[ "$now" != "$hash" ]] && note "[I]" "secret HASH MISMATCH: $path ($label) — content changed since baseline"
    local mode tail2
    mode="$(stat -c '%a' -- "$path" 2>/dev/null || stat -f '%OLp' -- "$path" 2>/dev/null)"
    [[ "$mode" =~ ^[0-7]$ ]] && mode="0$mode"
    tail2="${mode: -2}"
    [[ -n "$mode" && "$tail2" =~ ^[4567] ]] && note "[I]" "secret READABLE BY OTHERS: $path ($label) mode=$mode"
  done < "$INV"
}

check_leaked_copies() {
  local -a roots=("$@")
  local r
  local -a valid_roots=()
  for r in "${roots[@]}"; do [[ -d "$r" ]] && valid_roots+=("$r"); done
  (( ${#valid_roots[@]} )) || return 0

  local hits="$STATE/.leaked-hits.$$"
  local TMPCAND="$STATE/.leaked-candidates.$$"
  trap 'rm -f "${TMPCAND:-}" "${hits:-}" 2>/dev/null' EXIT

  local -a ge=(--extended-regexp --recursive --files-with-matches --binary-files=without-match -I -m 1 -s)
  local p ex
  for p in \
    'github_pat_[A-Za-z0-9_]{22,255}' \
    'ghp_[A-Za-z0-9]{36,}' \
    'gho_[A-Za-z0-9]{36,}' \
    'sk-ant-[A-Za-z0-9_-]{20,}' \
    'sk-proj-[A-Za-z0-9_-]{20,}' \
    'xox[bpars]-[A-Za-z0-9-]{10,}' \
    'AKIA[0-9A-Z]{16}' \
    '-----BEGIN OPENSSH PRIVATE KEY-----' \
    '-----BEGIN RSA PRIVATE KEY-----' \
    '-----BEGIN EC PRIVATE KEY-----' \
    'ssh-ed25519 [A-Za-z0-9+/=]{20,}' \
    'ssh-rsa [A-Za-z0-9+/=]{20,}'; do
    ge+=( -e "$p" )
  done
  for ex in node_modules .cache venv .venv target __pycache__; do
    ge+=( --exclude-dir="$ex" )
  done

  grep "${ge[@]}" -- "${valid_roots[@]}" 2>/dev/null > "$hits" || true

  local f inv_allow suppress_ok
  local self0; self0="$(readlink -f -- "$0")"
  while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    f="${f%/}"
    [[ "$f" == "$self0" ]] && continue
    inv_allow=false
    local inv_path
    while IFS=$'\t' read -r inv_path _; do
      [[ "$f" == "$inv_path" ]] && { inv_allow=true; break; }
    done < "$INV"
    $inv_allow && continue
    suppress_ok=false
    [[ -f "$SUPPRESS_CONF" ]] && { grep -qxF -- "$f" "$SUPPRESS_CONF" && suppress_ok=true; }
    if ! $suppress_ok && [[ -f "$SUPPRESS_GLOB_CONF" ]]; then
      local pat
      while IFS= read -r pat; do
        [[ -z "$pat" || "$pat" == \#* ]] && continue
        case "$f" in $pat) suppress_ok=true; break ;; esac
      done < "$SUPPRESS_GLOB_CONF"
    fi
    $suppress_ok && continue
    note "[L]" "secret-like data found in UNEXPECTED location: $f (use '$0 --allow-loc \"$f\"' to accept)"
  done < "$hits"
  rm -f "$TMPCAND" "$hits"
}

check_github() {
  local tokpath sigfile kfile new k
  sigfile="$STATE/github-keys-last-update"
  kfile="$GH_BASELINE"
  [[ -f "$GH_TOKEN_PATH_CONF" ]] && tokpath="$(cat "$GH_TOKEN_PATH_CONF")"
  [[ -z "${tokpath:-}" || ! -f "$tokpath" || ! -f "$kfile" ]] && return 0

  local hfile="$STATE/.gh-header.$$"
  trap 'rm -f "${hfile:-}" "${TMPCAND:-}" "${hits:-}" 2>/dev/null' EXIT
  printf 'Authorization: Bearer %s\n' "$(cat "$tokpath")" > "$hfile"; chmod 600 "$hfile"

  new="$STATE/.gh-keys-now.$$"
  local rc=0
  curl -s --max-time 20 --header "@$hfile" 'https://api.github.com/user/keys' -o "$new" -w '%{http_code}' > "$STATE/.gh-rc.$$" || rc=1
  local code; code="$(cat "$STATE/.gh-rc.$$" 2>/dev/null)"
  local allowed='false'
  grep -qxF -- "$new" <(while IFS=$'\t' read -r p _; do echo "$p"; done < "$INV"; cat "$SUPPRESS_CONF" 2>/dev/null) && allowed='true'
  if [[ "$code" == "200" ]]; then
    if ! diff -q -- "$kfile" "$new" >/dev/null 2>&1; then
      gnote "[G]" "GitHub account keys CHANGED since baseline — diff old/new: $kfile vs $new"
    fi
    cp -- "$new" "$kfile"; chmod 600 "$kfile"
  elif [[ "$code" == "401" ]]; then
    gnote "[G]" "GitHub token REJECTED (401) — revoked, expired, or destroyed: review $tokpath"
  elif [[ "$code" == "403" ]]; then
    echo "github check: insufficient permissions (403) — skipping, not evidence of compromise" | tee -a "$REPORT"
  else
    echo "github check: http $code, network or rate issue — not treated as compromise" | tee -a "$REPORT"
  fi
  rm -f "$hfile" "$new" "$STATE/.gh-rc.$$" 2>/dev/null
}

check_local_ssh() {
  local marker="$STATE/ssh-baseline.txt"
  if [[ ! -e "$HOME/.ssh" ]]; then
    [[ -f "$marker" ]] && note "[H]" "~/.ssh disappearing vs baseline (was expected)" 
    return 0
  fi
  if [[ ! -f "$marker" ]]; then
    printf '%s\n' "dotfiles were created at $(date '+%F %T')" > "$marker"
    note "[H]" "~/.ssh exists although baseline expected none — confirm it is yours (was it? $(date '+%F'))"
  fi
  local f
  while IFS= read -r -d '' f; do
    grep -qxF -- "$f" "$SUPPRESS_CONF" 2>/dev/null && continue
    note "[H]" "ssh file present: $f — confirm legitimate; perms: $(stat -c '%a' -- "$f" 2>/dev/null)"
  done < <(find "$HOME/.ssh" -maxdepth 1 -type f -print0 2>/dev/null)
  local bad
  while IFS= read -r -d '' bad; do
    grep -qxF -- "$bad" "$SUPPRESS_CONF" 2>/dev/null && continue
    note "[I]" "ssh key readable by others: $bad mode=$(stat -c '%a' -- "$bad" 2>/dev/null)"
  done < <(find "$HOME/.ssh" -maxdepth 1 -type f ! -name known_hosts \( -perm -g+r -o -perm -o+r \) -print0 2>/dev/null)
}

# --- entry -------------------------------------------------------------------
cmd_check() {
  : > "$REPORT"
  check_inventory
  local -a roots=("$HOME" /etc)
  if [[ -n "${SECRET_WATCH_ROOTS:-}" ]]; then
    readarray -td ';' roots <<< "${SECRET_WATCH_ROOTS%\n}"
    local -a wr=()
    local rr
    for rr in "${roots[@]}"; do rr="${rr%$'\n'}"; [[ -n "$rr" ]] && wr+=("$rr"); done
    roots=("${wr[@]:-}")
    (( ${#roots[@]} )) || roots=("$HOME" /etc)
  fi
  check_leaked_copies  "${roots[@]}"
  check_github
  check_local_ssh

  if (( EXIT_CODE == 0 )); then
    printf 'secret-watch: CLEAN (%s) — no compromise signals\n' "$(date '+%F %T')" | tee -a "$REPORT" "$FINDINGS"
  else
    printf 'secret-watch: FINDINGS (%s) — exit 2; report: %s\n' "$(date '+%F %T')" "$REPORT" | tee -a "$FINDINGS"
  fi
  return $EXIT_CODE
}

add_secret() {
  local path="$1" label="${2:-secret}"
  [[ -f "$path" ]] || die "no such file: $path"
  path="$(readlink -f -- "$path")"
  mkdir -p "$CONF"; chmod 700 "$CONF"
  grep -qxF -- "$path" "$SECRETS_CONF" 2>/dev/null || printf '%s\t%s\n' "$path" "$label" >> "$SECRETS_CONF"
  chmod 600 "$SECRETS_CONF"
  echo "added $path ($label) to $SECRETS_CONF; re-running baseline..."
  cmd_baseline
}

allow_loc() {
  local path="$(readlink -f -- "$1")"
  mkdir -p "$CONF"; chmod 700 "$CONF"
  grep -qxF -- "$path" "$SUPPRESS_CONF" 2>/dev/null || printf '%s\n' "$path" >> "$SUPPRESS_CONF"
  chmod 600 "$SUPPRESS_CONF"
  echo "allowed: $path (no longer reported)"
}

allow_glob() {
  local pat="$1"
  mkdir -p "$CONF"; chmod 700 "$CONF"
  [[ -f "$SUPPRESS_GLOB_CONF" ]] || { printf '# shell-glob patterns of locations you accept (one per line)\n' > "$SUPPRESS_GLOB_CONF"; chmod 600 "$SUPPRESS_GLOB_CONF"; }
  grep -qxF -- "$pat" "$SUPPRESS_GLOB_CONF" 2>/dev/null || printf '%s\n' "$pat" >> "$SUPPRESS_GLOB_CONF"
  echo "allowed pattern: $pat"
}

gh_set() {
  local path="$(readlink -f -- "$1")"
  [[ -f "$path" ]] || die "no such file: $path"
  mkdir -p "$CONF"; chmod 700 "$CONF"
  printf '%s\n' "$path" > "$GH_TOKEN_PATH_CONF"; chmod 600 "$GH_TOKEN_PATH_CONF"
  echo "github token path set to $path"
}

do_install() {
  local unitdir="$HOME/.config/systemd/user/secret-watcher.d"
  unitdir="$HOME/.config/systemd/user"
  mkdir -p "$unitdir"
  cat > "$unitdir/secret-watch.service" <<UNIT
[Unit]
Description=Daily secrets/keys/API-keys compromise check (secret-watch)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=%h/Projects/zen-hardening/secret-watch.sh check
UNIT
  cat > "$unitdir/secret-watch.timer" <<UNIT
[Unit]
Description=Run secret-watch daily

[Timer]
OnCalendar=*-*-* 10:05:00
Persistent=true
Unit=secret-watch.service

[Install]
WantedBy=timers.target
UNIT
  systemctl --user daemon-reload
  systemctl --user enable --now secret-watch.timer
  echo "installed+enabled: systemctl --user list-timers | grep secret-watch"
}

# --- cli ---------------------------------------------------------------------
main() {
  local cmd="${1:-check}"
  shift || true
  case "$cmd" in
    init)       init ;;
    baseline)   cmd_baseline ;;
    check)      cmd_check "$@" ;;
    --add)      add_secret "${1:?usage: secret-watch.sh --add PATH [LABEL]}" "${2:-secret}" ;;
    --allow-loc) allow_loc "${1:?usage: secret-watch.sh --allow-loc PATH}" ;;
    --allow-glob) allow_glob "${1:?usage: secret-watch.sh --allow-glob PATTERN}" ;;
    --gh-token) gh_set "${1:?usage: secret-watch.sh --gh-token PATH}" ;;
    --install)  do_install ;;
    --help|-h)  printf '%s\n' "secret-watch.sh init | baseline | check | --add PATH [LABEL] | --allow-loc PATH | --install | --help" ;;
    *)          die "unknown command: $cmd"
  esac
}
main "$@"
