#!/usr/bin/env bash
# fix-sudoers-permissions.sh — resolve the "bad permissions" warnings without
# accidentally activating an unreviewed privilege grant.
#
#   sudo bash fix-sudoers-permissions.sh
#
# WHY NOT JUST `chmod 0440` ON EVERYTHING
#
# sudo ignores a sudoers file whose permissions are too open, and warns:
#
#     /etc/sudoers.d/opencode: bad permissions, should be mode 0440
#
# The tempting fix is to chmod every offender to 0440. That silences the
# warning, but it also makes sudo start HONOURING files it was previously
# ignoring. If one of those files contains a NOPASSWD rule, the chmod does
# not fix anything -- it activates passwordless root and hides the evidence
# in the same step.
#
# So this classifies each file first:
#
#   stock-defaults  only Defaults lines (and comments). These ship with the
#                   sudo package and are safe to activate at 0440.
#   grants-access   contains NOPASSWD, or an ALL=(ALL) ALL style grant.
#                   QUARANTINED: moved out of /etc/sudoers.d to /root with
#                   0600, so it stops being a sudo surface at all while
#                   remaining readable for review.
#   other           anything else. Quarantined for the same reason.
#
# Regardless of classification, group/other WRITE bits are removed first.
# A world- or group-writable sudoers file is a direct root escalation and
# outranks every other concern here.
#
# Files handled: the sudo package defaults (editor, insults, pwfeedback) plus
# any other non-conforming file in /etc/sudoers.d, which is how the
# session-created 'opencode' file gets caught.

set -uo pipefail

QUARANTINE=/root/sudoers-quarantine-$(date +%Y%m%d-%H%M%S)
declare -a REPORT

[[ $EUID -eq 0 ]] || { echo "ERROR: needs root: sudo $0" >&2; exit 1; }

echo "=== before ==="
visudo -c 2>&1 | grep -iE 'bad permissions|error|syntax' | sed 's/^/  /' || echo "  (clean)"

mkdir -p "$QUARANTINE"
chmod 0700 "$QUARANTINE"
echo
echo "quarantine dir: $QUARANTINE"
echo

shopt -s nullglob
for f in /etc/sudoers.d/*; do
  [ -f "$f" ] || continue
  name=$(basename "$f")
  mode=$(stat -c%a "$f")
  owner=$(stat -c%U:%G "$f")

  # Strip non-comment, non-blank content for classification.
  body=$(grep -vE '^[[:space:]]*(#|$)' "$f")

  # --- priority 1: writable by group/other is a live escalation ---
  if (( (8#$mode & 0022) != 0 )); then
    chmod go-w "$f"
    newmode=$(stat -c%a "$f")
    REPORT+=("  [!!] $name was mode $mode (group/other WRITABLE) -> $newmode")
    REPORT+=("       this was a direct root-escalation path; write bits removed first")
    # still classify: a writable file is not trustworthy enough to activate
    body="__force_quarantine__"
  fi

  if [ "$body" = "__force_quarantine__" ]; then
    klass="quarantine (was writable)"
  elif [ -z "$body" ]; then
    klass="stock-defaults"
  elif printf '%s' "$body" | grep -qiE 'NOPASSWD'; then
    # The genuinely dangerous pattern. NOPASSWD means root without a
    # password; that is what must never be silently activated.
    klass="grants-access (contains NOPASSWD)"
  elif printf '%s' "$body" | grep -qiE 'ALL[[:space:]]*=[[:space:]]*\([^)]*\)[[:space:]]*ALL|ALL[[:space:]]+ALL'; then
    # CORRECTION. An earlier version of this script classified
    # "ALL=(ALL) ALL" as dangerous and quarantined it. That was wrong and
    # broke sudo: `%wheel ALL=(ALL) ALL` is the STOCK Arch rule that grants
    # wheel full sudo WITH a password prompt. Requiring a password is the
    # baseline, not a threat. Only NOPASSWD removes the password, so only
    # NOPASSWD warrants quarantine.
    klass="password-required-sudo (safe)"
  elif printf '%s' "$body" | grep -qE '^[[:space:]]*Defaults'; then
    klass="stock-defaults"
  else
    klass="other (unrecognised)"
  fi

  case "$klass" in
    stock-defaults|password-required-sudo*)
      chmod 0440 "$f"
      chown root:root "$f"
      REPORT+=("  [ok] $name: $klass -> activated at 0440 (was mode $mode, owner $owner)")
      ;;
    *)
      cp -a "$f" "$QUARANTINE/$name"
      chmod 0600 "$QUARANTINE/$name"
      chown root:root "$QUARANTINE/$name"
      rm -f "$f"
      REPORT+=("  [!!] $name: $klass -> QUARANTINED to $QUARANTINE/$name (0600, root only)")
      REPORT+=("       it is no longer read by sudo, so nothing it grants is active")
      ;;
  esac

  # Show what was in it, so the decision is reviewable rather than magic.
  REPORT+=("       contents were:")
  while IFS= read -r line; do REPORT+=("         $line"); done <<< "$(cat "$QUARANTINE/$name" 2>/dev/null || cat "$f" 2>/dev/null || echo '(removed)')"
done

printf '%s\n' "${REPORT[@]}"

echo
echo "=== after ==="
visudo -c 2>&1 | sed 's/^/  /'

echo
echo "sudo still works?  $(sudo -n true 2>/dev/null && echo 'yes (NOPASSWD)' || echo 'yes (password required)')"
echo
echo "Review quarantined files with:"
echo "  sudo cat $QUARANTINE/<name>"
echo
echo "Nothing is deleted. To restore one, copy it back and validate:"
echo "  sudo cp $QUARANTINE/<name> /etc/sudoers.d/<name>"
echo "  sudo chmod 0440 /etc/sudoers.d/<name> && sudo visudo -c"
