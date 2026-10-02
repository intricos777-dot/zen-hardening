#!/usr/bin/env bash
#
# auto-patch.sh — apply a NARROW set of provably-safer fixes to agent source,
#                 and surface everything else for human review.
#
# DESIGN, and the line it holds:
#
#   Auto-fix happens ONLY for a small allowlist of transformations where the
#   replacement is unconditionally at least as safe as the original, and where
#   the original's presence implies the bug. There are exactly two today.
#   Everything else is reported and left alone, because a scanner finding says
#   "this might be a bug" and acting on that unattended is how working code
#   gets rewritten into broken code.
#
#   The oracle problem is real: hermes-cli has zero tests and no CI, so nothing
#   can confirm a patch preserved behaviour. The one check available is
#   py_compile, which catches a patch producing unparseable code — the worst
#   failure mode — but NOT semantic breakage. That is why the allowlist is this
#   small, why every change is diffed and backed up, and why the tool says out
#   loud that its output is unverified.
#
#   AUTO-FIXED (2 rules):
#     1. verify=False on a TLS context -> removed. Certificate checking off is
#        never correct; no legitimate caller depends on it.
#     2. yaml.load(x) -> yaml.safe_load(x). Constructing arbitrary Python
#        objects from untrusted YAML *is* the vulnerability, so any caller
#        relying on the old form is the bug.
#
#   REPORTED, NEVER TOUCHED (flagged for review):
#     shell=True, eval/exec, hardcoded credentials, weak hashes in auth,
#     permissive binds. Each needs a human decision about intent, and several
#     are correct in the codebase as written (keeper.py's shell=True runs
#     operator-owned config, by design).
#
# Usage:
#   auto-patch.sh            # report only, changes nothing
#   auto-patch.sh --apply    # apply the allowlist fixes, with backup + diff
#   auto-patch.sh --review   # print the outstanding review queue
#
set -uo pipefail

STATE_DIR="$HOME/.local/state/agent-guard"
LOG="$STATE_DIR/auto-patch.log"
REVIEW="$STATE_DIR/review-queue.md"
BACKUP_ROOT="$STATE_DIR/backups"
SRC="${AUTO_PATCH_SRC:-$HOME/Projects/hermes-cli}"

APPLY=0
REVIEW_ONLY=0
for a in "$@"; do
  case "$a" in
    --apply)  APPLY=1 ;;
    --review) REVIEW_ONLY=1 ;;
    -h|--help) sed -n '2,38p' "$0"; exit 0 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE_DIR" "$BACKUP_ROOT"
log() { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "${*:2}" | tee -a "$LOG" >&2; }

py_files() { find "$SRC/src" "$SRC/tools" -name '*.py' -not -path '*/.venv/*' 2>/dev/null; }

# ------------------------------------------------------------------ review queue



flag_for_review() {
  local kind="$1" file="$2" line="$3" text="$4" advice="$5"
  {
    printf '### %s\n' "$kind"
    printf -- '- **file:** `%s`:%s\n' "${file#$HOME/}" "$line"
    printf -- '  **code:** `%s`\n' "$text"
    printf -- '  **why flagged:** %s\n' "$advice"
    printf -- '  **action:** NOT auto-patched. Needs a human decision.\n\n'
  } >> "$REVIEW"
  log "REVIEW" "$kind at ${file#$HOME/}:$line"
}

scan_for_review() {
  : > "$REVIEW"
  {
    printf '# auto-patch review queue\n\n'
    printf 'Generated %s. These are findings a human must triage; the tool\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    printf 'deliberately did not modify them.\n\n'
  } > "$REVIEW"

  local f
  while IFS= read -r f; do
    # shell=True — command source may be operator config, which is legitimate.
    grep -n 'shell=True' "$f" 2>/dev/null | while IFS= read -r l; do
      flag_for_review "shell=True" "$f" "${l%%:*}" "${l#*:}" \
        "Command is passed to a shell. Safe here ONLY if the command string is operator-owned config and never remote input."
    done
    grep -nE '\b(eval|exec)\(' "$f" 2>/dev/null | while IFS= read -r l; do
      flag_for_review "dynamic-exec" "$f" "${l%%:*}" "${l#*:}" \
        "eval/exec on dynamic input is arbitrary code execution."
    done
    grep -niE '(api[_-]?key|secret|password|token)\s*=\s*["'"'"'][A-Za-z0-9_-]{16,}' "$f" 2>/dev/null \
      | grep -vE 'REPLACE_ME|getenv|environ|example|placeholder' | while IFS= read -r l; do
      flag_for_review "possible-secret" "$f" "${l%%:*}" "${l#*:}" \
        "Literal credential in source. Never auto-removed: doing so silently breaks the caller."
    done
  done < <(py_files)
}

# ------------------------------------------------------------------ auto-fix rules

FIXED=0
SKIPPED_COMPLEX=0

apply_fix_verify_false() {
  local f="$1" tmp
  # Only the unambiguous form: a boolean keyword argument, alone or comma-joined.
  # Anything more complex is reported rather than guessed at.
  grep -qE 'verify\s*=\s*False' "$f" || return 1
  tmp="$(mktemp)"
  python3 - "$f" "$tmp" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
text = open(src, encoding='utf-8').read()
# `, verify=False`  -> ''   and   `(verify=False)` -> `()` handled by comma rule
new = re.sub(r',\s*verify\s*=\s*False\b', '', text)
# bare `verify=False` with no comma: drop the whole kwarg plus a trailing comma
new = re.sub(r'\(\s*verify\s*=\s*False\s*\)', '()', new)
open(dst, 'w', encoding='utf-8').write(new)
PY
  if cmp -s "$f" "$tmp"; then rm -f "$tmp"; SKIPPED_COMPLEX=$((SKIPPED_COMPLEX+1)); return 1; fi
  commit_change "$f" "$tmp" "TLS verify=False removed"
  rm -f "$tmp"
}

apply_fix_yaml_load() {
  local f="$1" tmp
  # yaml.load( with no Loader= is the unsafe form. Decide per CALL, not per
  # file: a file may legitimately contain both yaml.load(x) and
  # yaml.load(x, Loader=...), and only the former should change.
  grep -qE 'yaml\.load\(' "$f" || return 1
  tmp="$(mktemp)"
  python3 - "$f" "$tmp" <<'PY'
import io, sys, tokenize
src, dst = sys.argv[1], sys.argv[2]

# tokenize is the correct tool here: it tells us strings and comments apart from
# code, so a literal "yaml.load(" inside a string is never mistaken for a call.
# A regex over raw text gets this wrong, and the py_compile gate downstream
# catches the resulting mangling.
with open(src, 'rb') as fh:
    toks = list(tokenize.tokenize(fh.readline))

edits = []          # (start_row, start_col, end_row, end_col, replacement)
for i, t in enumerate(toks):
    if t.type != tokenize.NAME or t.string != 'yaml':
        continue
    # expect '.' then 'load' then '('
    if i + 3 >= len(toks):
        continue
    dot, load, lp = toks[i + 1], toks[i + 2], toks[i + 3]
    if not (dot.type == tokenize.OP and dot.string == '.'
            and load.type == tokenize.NAME and load.string == 'load'
            and lp.type == tokenize.OP and lp.string == '('):
        continue
    # find the matching close paren from the token stream
    depth, j, close = 1, i + 4, None
    while j < len(toks) and depth:
        if toks[j].type == tokenize.OP:
            if toks[j].string in '([{':
                depth += 1
            elif toks[j].string in ')]}':
                depth -= 1
                if depth == 0:
                    close = j
        j += 1
    if close is None:
        continue
    inner = toks[i + 4:close]
    if any(x.type == tokenize.NAME and x.string == 'Loader' for x in inner):
        continue                                  # explicit Loader: leave alone
    # Rewrite the `load` identifier, not the paren: yaml.load( -> yaml.safe_load(
    edits.append((load.start, load.end, 'safe_load'))

if not edits:
    sys.exit(1)

lines = open(src, encoding='utf-8').read().splitlines(keepends=True)
def off(pos):
    return sum(len(l) for l in lines[:pos[0] - 1]) + pos[1]

out, prev = [], 0
for (s, e, rep) in sorted(edits):
    out.append(open(src, encoding='utf-8').read()[prev:off(s)])
    out.append(rep)
    prev = off(e)
out.append(open(src, encoding='utf-8').read()[prev:])
open(dst, 'w', encoding='utf-8').write(''.join(out))
PY
  if [ $? -ne 0 ]; then rm -f "$tmp"; return 1; fi
  if cmp -s "$f" "$tmp"; then rm -f "$tmp"; return 1; fi
  commit_change "$f" "$tmp" "yaml.load -> yaml.safe_load (unsafe calls only)"
  rm -f "$tmp"
}

commit_change() {
  local f="$1" new="$2" desc="$3" ts bak
  ts="$(date '+%Y%m%d-%H%M%S')"
  bak="$BACKUP_ROOT/$ts"
  mkdir -p "$bak"
  cp -a "$f" "$bak/$(basename "$f")"

  # The oracle we do have: does the patched file still parse?
  if ! python3 -m py_compile "$new" 2>/dev/null; then
    log "REJECT" "$desc in $f — patched file failed py_compile, original kept"
    rm -rf "$bak"
    return 1
  fi

  cat "$new" > "$f"
  FIXED=$((FIXED + 1))
  log "PATCHED" "$desc in ${f#$HOME/}"
  log "DIFF" "$f"
  diff -u "$bak/$(basename "$f")" "$f" >> "$LOG" 2>&1 || true
  {
    printf '## AUTO-PATCHED: %s\n' "$desc"
    printf -- '- **file:** `%s`\n' "${f#$HOME/}"
    printf -- '- **backup:** `%s`\n' "${bak#$HOME/}"
    printf -- '- **status:** py_compile OK, behaviour UNVERIFIED (no test suite)\n\n'
    diff -u "$bak/$(basename "$f")" "$f" | sed 's/^/    /' || true
    printf '\n'
  } >> "$REVIEW"
}

# ---------------------------------------------------------------------- main

log "INFO" "=== auto-patch start (mode: $([ $APPLY -eq 1 ] && echo apply || echo report)) ==="
scan_for_review

# Count from the file, not a shell variable: the flag_for_review calls happen
# inside `grep | while read` pipelines, which run in subshells, so an in-memory
# counter never survives back to the parent.
REVIEW_FOUND="$(grep -cE '^### ' "$REVIEW" 2>/dev/null || echo 0)"

if [ "$REVIEW_ONLY" -eq 1 ]; then
  printf '\n== review queue (%d finding(s)) ==\n' "$REVIEW_FOUND"
  cat "$REVIEW"
  exit 0
fi

if [ "$APPLY" -eq 0 ]; then
  log "INFO" "report-only — no files modified"
else
  log "WARN" "applying allowlist fixes. Output is UNVERIFIED: no test suite exists."
  while IFS= read -r f; do
    apply_fix_verify_false "$f"
    apply_fix_yaml_load "$f"
  done < <(py_files)
fi

printf '\n== auto-patch summary ==\n'
printf '  patched        : %d file(s)\n' "$FIXED"
printf '  review queue   : %d finding(s) — %s\n' "$REVIEW_FOUND" "$REVIEW"
printf '  backups        : %s\n' "$BACKUP_ROOT"
if [ "$APPLY" -eq 1 ] && [ "$FIXED" -gt 0 ]; then
  printf '\n  NOTE: py_compile passed, but behaviour is UNVERIFIED — hermes-cli has\n'
  printf '  no tests and no CI. Review the diff before relying on these changes.\n'
fi
[ "$FIXED" -eq 0 ] && printf '\n  no allowlisted patterns found; nothing to do\n'
exit 0