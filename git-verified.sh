#!/usr/bin/env bash
# git-verified.sh -- run a git command and report its REAL exit status.
#
# WHY THIS EXISTS
#
#     git push origin HEAD 2>&1 | sed 's/^/  /' && echo "[ok] pushed"
#
# reports success when the push failed. The pipeline's exit status is sed's,
# not git's, so a non-zero git failure is discarded and `[ok]` prints. This is
# the same class of defect as every other item in the README's verification
# list: a value that looks like the thing you asked for and is not. It is worse
# than a wrong config value, because it actively asserts a falsehood.
#
# The fix is `${PIPESTATUS[0]}`, or do not pipe the command whose status you
# care about. This script exists so the correct form is the easy one.
#
# Usage:
#   ./git-verified.sh push origin HEAD
#   ./git-verified.sh commit -m "message"
#   ./git-verified.sh fetch origin
#
# Exit status is the git command's own, so it is safe to chain.

set -uo pipefail

if [ "$#" -eq 0 ]; then
    echo "usage: ${0##*/} <git-subcommand> [args...]" >&2
    exit 2
fi

# Show output live, unbuffered, so a long operation is visible.
if git "$@"; then
    status=0
else
    status=$?
fi

if [ "$status" -eq 0 ]; then
    printf '[ok] git %s succeeded\n' "$1" >&2
else
    printf '[FAIL] git %s exited %d -- NOT pushed/committed\n' "$1" "$status" >&2
    printf '       do not report this as done.\n' >&2
fi

exit "$status"
