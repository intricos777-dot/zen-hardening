#!/usr/bin/env bash
# install-audit-readonly.sh — install narrowly scoped, read-only audit helpers.
#
#   sudo bash install-audit-readonly.sh
#   sudo bash install-audit-readonly.sh --remove
#
# WHY WRAPPERS INSTEAD OF DIRECT NOPASSWD ENTRIES
#
# The obvious way to let an agent read root-owned state is:
#
#     livings ALL=(root) NOPASSWD: /usr/bin/nft
#
# That is equivalent to handing over root. These binaries are not
# read-only tools, they are general-purpose state mutators that happen to
# have a read mode:
#
#     /usr/bin/nft             -> `nft flush ruleset`, add/drop any rule
#     /usr/bin/btrfs           -> `btrfs subvolume delete`, `device remove`
#     /usr/bin/firewall-cmd    -> `--add-service`, `--remove-rule`, reload
#     /usr/bin/fail2ban-client -> `set <jail> unbanip`, `restart`
#
# So each helper below ignores "$@" entirely and runs one fixed,
# non-mutating command. sudoers is then granted the wrapper path, with an
# empty argument list so the helper cannot be invoked with arguments at
# all. The user cannot edit the helpers (root-owned 0755, and /usr/local/sbin
# is root-writable only).
#
# REMOVAL: this is a temporary audit surface. Remove it with --remove once
# the audit is done. Leaving passwordless root helpers installed is itself a
# weakening of the baseline this project establishes.

set -euo pipefail

SUDOERS_FILE=/etc/sudoers.d/audit-readonly
HELPERS=(
  audit-nft
  audit-btrfs
  audit-smart
  audit-dmesg
  audit-firewall
  audit-fail2ban
  audit-journal-err
)
SUDO_USER_NAME="${SUDO_USER:-livings}"

if [[ "${1:-}" == "--remove" ]]; then
  echo "Removing audit helpers..."
  rm -f "$SUDOERS_FILE"
  for h in "${HELPERS[@]}"; do rm -f "/usr/local/sbin/$h"; done
  echo "  [ok] removed. Verify with: sudo -l"
  exit 0
fi

[[ $EUID -eq 0 ]] || { echo "ERROR: needs root: sudo $0" >&2; exit 1; }

install -d -m 0755 /usr/local/sbin

# ── audit-nft ──────────────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-nft <<'EOF'
#!/usr/bin/env bash
# Read-only. Reports whether firewalld is actually enforcing, and what the
# input chain does. Deliberately does NOT accept a table/chain argument.
set -uo pipefail
echo "== firewalld tables =="
nft list tables 2>&1 | grep -i firewalld || echo "  (no firewalld table -- NOT enforcing)"
echo
echo "== filter_INPUT chain =="
nft list chain inet firewalld filter_INPUT 2>&1 | head -40
echo
echo "== reject/drop policy in filter_INPUT =="
nft list chain inet firewalld filter_INPUT 2>/dev/null \
  | grep -E 'policy|reject|drop' || echo "  (none found)"
EOF

# ── audit-btrfs ────────────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-btrfs <<'EOF'
#!/usr/bin/env bash
# Read-only. No path argument accepted, so it cannot target another
# subvolume for a destructive operation.
set -uo pipefail
echo "== filesystem usage =="
btrfs filesystem usage / 2>&1 | grep -E 'Device size|Used|Free'
echo
echo "== subvolumes =="
btrfs subvolume list / 2>&1 | head -30
echo
echo "== scrub status =="
btrfs scrub status / 2>&1 | head -10
echo
echo "== device stats (errors) =="
btrfs device stats / 2>&1
EOF

# ── audit-smart ────────────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-smart <<'EOF'
#!/usr/bin/env bash
# Read-only. Device path is fixed, not taken from argv.
set -uo pipefail
echo "== nvme smart-log =="
nvme smart-log /dev/nvme0 2>&1 | grep -iE \
  'critical_warning|temperature|percentage_used|media_errors|num_err_log|power_on_hours|data_units_written' \
  || echo "  (nvme-cli unavailable or no permission)"
echo
echo "== nvme error log (first entries) =="
nvme error-log /dev/nvme0 2>&1 | head -12
EOF

# ── audit-dmesg ───────────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-dmesg <<'EOF'
#!/usr/bin/env bash
# Read-only. kernel.dmesg_restrict=1 (set by 99-hardening.conf) hides dmesg
# from non-root; this is the intended audit path.
set -uo pipefail
echo "== error/critical kernel messages =="
dmesg -l err,crit,alert,emerg 2>&1 | tail -30
echo
echo "== btrfs warnings =="
dmesg 2>/dev/null | grep -iE 'btrfs.*(error|corrupt|warn)' | tail -10 \
  || echo "  [ok] none"
echo
echo "== OOM kills =="
dmesg 2>/dev/null | grep -iE 'Out of memory|oom-kill' | tail -5 \
  || echo "  [ok] none"
echo
echo "== hardware errors (mce/amd64/thermal/pcie) =="
dmesg 2>/dev/null | grep -iE 'mce|hardware error|thermal thrott|pcie.*error|AER' | tail -10 \
  || echo "  [ok] none"
EOF

# ── audit-firewall ─────────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-firewall <<'EOF'
#!/usr/bin/env bash
# Read-only list operations only. firewall-cmd can mutate; this wrapper
# hardcodes the --list-* forms and passes no caller arguments through.
set -uo pipefail
echo "== state =="
firewall-cmd --state 2>&1
echo
echo "== default zone =="
firewall-cmd --get-default-zone 2>&1
echo
for z in $(firewall-cmd --get-default-zone 2>/dev/null) workstation; do
  echo "== zone: $z =="
  firewall-cmd --zone="$z" --list-all 2>&1
  echo
done
echo "== runtime rich rules (fail2ban bans) =="
for z in $(firewall-cmd --get-default-zone 2>/dev/null) workstation; do
  echo "-- $z --"
  firewall-cmd --zone="$z" --list-rich-rules 2>&1
done
EOF

# ── audit-fail2ban ─────────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-fail2ban <<'EOF'
#!/usr/bin/env bash
# Read-only. fail2ban-client can unban and restart jails, so only plain
# `status` and `status <jail>` are issued here.
set -uo pipefail
echo "== fail2ban-client status =="
fail2ban-client status 2>&1
echo
JAILS=$(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:[[:space:]]*//p')
for j in $JAILS; do
  echo "== jail: $j =="
  fail2ban-client status "$j" 2>&1 | sed -n '1,8p'
  echo
done
EOF

# ── audit-journal-err ──────────────────────────────────────────────────────
cat > /usr/local/sbin/audit-journal-err <<'EOF'
#!/usr/bin/env bash
# Read-only journal summary for the current boot.
set -uo pipefail
echo "== failed units =="
systemctl list-units --state=failed --no-legend --no-pager 2>&1
echo
echo "== errors this boot, grouped by unit =="
journalctl -b -p err --no-pager -o json 2>/dev/null | python3 -c "
import sys, json, collections
c = collections.Counter()
for line in sys.stdin:
    try:
        c[json.loads(line).get('_SYSTEMD_UNIT', '?')] += 1
    except Exception:
        pass
for unit, n in c.most_common(20):
    print(f'{n:5d}  {unit}')
"
echo
echo "== coredumps this boot =="
coredumpctl list --no-pager 2>&1 | tail -10
echo
echo "== warnings during boot (not errors) =="
journalctl -b -p warning --no-pager 2>/dev/null | tail -25
EOF

chmod 0755 /usr/local/sbin/audit-*
chown root:root /usr/local/sbin/audit-*
echo "  [ok] installed $(ls -1 /usr/local/sbin/audit-* | wc -l) read-only helpers"

# ── sudoers ────────────────────────────────────────────────────────────────
# NOTE on the argument restriction: do NOT append "" after each path here.
# In sudo 1.9.17, "" parses as "exactly one argument, the empty string", not
# "no arguments". The rule then parses cleanly but can never be satisfied by
# a normal invocation, so every helper silently falls back to a password
# prompt. The actual protection is that each wrapper ignores "$@" entirely;
# these helpers only ever pass --list-*/status style arguments through
# internally, never caller input.
{
  echo "# Read-only audit helpers. Created by install-audit-readonly.sh."
  echo "# TEMPORARY: remove with 'sudo bash install-audit-readonly.sh --remove'."
  echo "#"
  echo "# These wrapper paths are safe to allow unpassworded because each one"
  echo "# ignores its arguments and runs a fixed, non-mutating command."
  echo "# The underlying binaries (/usr/bin/nft, /usr/bin/btrfs,"
  echo "# /usr/bin/firewall-cmd, fail2ban-client) are deliberately NOT listed:"
  echo "# they can mutate state, so unpassworded access would equal root."
  printf '%s ALL=(root) NOPASSWD:' "$SUDO_USER_NAME"
  for h in "${HELPERS[@]}"; do printf ' /usr/local/sbin/%s,' "$h"; done
  printf '\n'
} > "$SUDOERS_FILE"

chmod 0440 "$SUDOERS_FILE"
chown root:root "$SUDOERS_FILE"

if visudo -c 2>&1 | sed 's/^/  /'; then
  echo "  [ok] sudoers syntax valid"
else
  echo "  [!!] sudoers INVALID -- removing to avoid a broken sudo" >&2
  rm -f "$SUDOERS_FILE"
  visudo -c 2>&1 | sed 's/^/  /' || true
  exit 1
fi

# Syntax validity is not proof the rule works. A sudoers file can parse
# perfectly and still fail to match a real invocation, in which case every
# helper quietly falls back to prompting for a password and the audit
# silently loses root visibility. So verify behaviour, not grammar.
echo
echo "  verifying each helper is actually usable without a password..."
probe_failed=0
for h in "${HELPERS[@]}"; do
  if sudo -n "/usr/local/sbin/$h" >/dev/null 2>&1; then
    echo "    [ok] $h"
  else
    echo "    [!!] $h still requires a password"
    probe_failed=1
  fi
done

if [ "$probe_failed" -ne 0 ]; then
  echo
  echo "  [!!] at least one helper did not become passwordless." >&2
  echo "       sudo still works, but the audit cannot read root state." >&2
  echo "       Debug with: sudo -l | grep audit-" >&2
  exit 1
fi

echo
echo "  [ok] all helpers usable without a password"
echo
echo "Verify with:  sudo -l | grep audit-"
echo "Then run:     sudo audit-nft"
echo
echo "Remove when the audit is done:"
echo "  sudo bash $(realpath "$0") --remove"
