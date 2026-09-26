# Handoff — 2026-09-26 system rebuild closeout

Written by Hermes at the user's request, to brief a fresh OpenCode session.
Both repos are **local only** — no remotes, no upstream. Nothing was pushed.

## The session in one line

A full Garuda Linux hardening rebuild, verified end to end, then four loose
ends found during the audit were closed. Verified from `fish_history`
(Konsole keeps no command log) plus live system state.

## Repos touched

### `~/Projects/shield-kitty` — commit `d1b9346` (master, clean)

    fix(devices): a ban that fails to write must be loud, not silent

`device-blacklist/shield-kitty-devices.py` + `test_device_policy.py`,
+100/-4.

`add_ban()` swallowed write failures. The device is unbound at that moment,
so the quarantine is real, and the log line above it says BANNED — but if the
record never reached disk the ban evaporates on reboot and the device walks
back in as a first sighting. The one failure mode a policy enforcer must
never hide, discarded like any other exception.

- `add_ban` returns True only if the record landed. fsyncs, then reads the row
  back and re-parses it: a write that silently truncated or interleaved looks
  persisted but does not match, which is *worse* than no write, because
  `is_banned()` would then disagree with what the operator sees in the file.
- On failure: ALERT-level log naming the device and the path, stating the ban
  will not survive a reboot.
- `handle_add()` no longer reports BANNED in that case. Downgrades to
  `QUARANTINED (BAN FAILED TO PERSIST)` — the accurate description of a device
  unbound now and unblocked next boot — and passes that to the notification.

4 new tests. Suite **28/28**, both files compile.

Note: the suite fails 2/24 if run without `SHIELD_KITTY_STATE` set to a
writable dir — `STATE_DIR` defaults to `/var/lib/shield-kitty`, which does not
exist for a non-root user, so `add_ban` writes fail. That is the old test
artifact, not a regression:

    T=$(mktemp -d) && SHIELD_KITTY_STATE=$T python3 test_device_policy.py; rm -rf $T

The fix is installed and live: `/opt/shield-kitty/shield-kitty-devices.py` is
byte-identical to the repo version (`diff -q` silent) and contains
`ALERT BAN NOT PERSISTED`. That is the copy udev actually invokes.

### `~/Projects/zen-hardening` — commit `2c14eca` (master, clean)

    chore: closeout script for the 2026-09-26 hardening audit

`closeout-20260926.sh`, +79. Idempotent; backs up the f2b config with a
timestamp; validates with `fail2ban-client -t` before restarting so a bad edit
aborts rather than leaving a dead fail2ban. Already run — see below.

## What was fixed and verified live

1. **fail2ban `ignoreip`** — `10.197.250.246/32` (an address this machine no
   longer holds) replaced with the live wlo1 address `10.116.193.112/32`.
   With `maxretry=4` / `bantime=86400` the one entry meant to cover this
   machine was covering nothing.
2. **`[sshd]` jail disabled** — sshd is disabled, and a jail whose backend
   never logs sits in `fail2ban-client status` implying protection that isn't
   there. `[recidive]` untouched. `fail2ban-client -t` → `OK`.
3. **Shield Kitty USB device policy actually installed** — this had never
   been run, so the enforcement half did not exist. Now: udev rule at
   `/etc/udev/rules.d/99-shield-kitty-devices.rules`, `/opt/shield-kitty/`
   (whitelist mode 0600 root:root — root-only, so it isn't user-writable),
   `/var/lib/shield-kitty/{attempts,blacklist}.conf` both empty as expected on
   a fresh install. All 4 attached USB devices are whitelisted plus 2 root
   hubs, so the installer's `udevadm trigger` was safe.
4. **The `add_ban` code fix** (above).

Also confirmed healthy: `shield-kitty-watch.service` active (MainPID 1081,
correctly in `app.slice`), `evidence-seal.timer` firing hourly, firewalld on
`workstation` zone with `lo`+`wlo1` and no ssh, tor active, faillock
`deny=10` with the user in `shield-admin`, arpwatch-spoof active with its scan
timer, 0 failed units, `99-hardening.conf` applied, zram active, lifsea-security-suite
pushed clean.

## Still unverified — needs a sudo password

Nothing was changed for these; they are the three things that could not be
checked without root. One command covers all of them:

    sudo bash -c 'visudo -c && sudo -l | tail -5 && btrfs subvolume list / && nft list tables | grep firewalld && fail2ban-client status'

- sudoers parse correctness (`visudo -c`)
- live nftables ruleset contents
- btrfs subvolume list
- `fail2ban-client status` should show `[recidive]` only (socket is root-only)

## Incidental findings, not fixed

- `arp.dat` holds a malformed MAC `ca:fd:e9:c7:5:f1` (9 hex digits) from a
  manual alert-test invocation. The real one is `ca:fd:e9:c7:05:f1`.
  Cosmetic.
- `udevadm verify` flags a pre-existing style nit in a system rules file
  (`40-usb_modeswitch.rules`). Unrelated to shield-kitty.
- vulkaninfo emits loader warnings about a missing
  `vkGetPhysicalDeviceDisplayPropertiesKHR` export — known NVIDIA/layer
  mismatch in this loader build, harmless.

## Environment notes for whoever picks this up

- Root installs need a sudo password; passwordless sudo is not available.
  Hand the user an exact `sudo <script>` command rather than trying to run it.
- The box is Wayland/KDE Plasma. Steam's bootstrap progress dialog does not
  map a window — the update appears to hang with no UI. It is not stuck; check
  `tail -f ~/.local/share/Steam/logs/console-linux.txt`. `STEAM_USE_X11=1
  steam` forces the X11 path where the dialog renders.
- `pkill -f <script>` matches systemd user units' ExecStart and kills live
  services. Kill by PID.
- Piping a background job inline truncates terminal output capture; write to a
  file and read it.
