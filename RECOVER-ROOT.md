# Root recovery — this machine

Three different failures need three different answers. Pick by symptom.

| symptom | go to |
|---|---|
| `sudo` errors, but you know your password | **A** — in-band, 20 seconds |
| password forgotten / account won't authenticate | **B** — live USB, ~10 minutes |
| signed in, but no auth method works (nulllock blocked you) | **C** — roll PAM back |

---

## A. sudo is broken, password known

```bash
pkexec bash ~/Projects/zen-hardening/RECOVER-SUDO.sh
```

`pkexec` authenticates through polkit, not through sudoers, so it still works
when `/etc/sudoers` is the thing that broke. This happened for real on
2026-09-26, when a script quarantined `/etc/sudoers.d/10-installer` — the only
grant that existed. The script never deletes a sudoers file.

---

## B. Password forgotten

**This is the case there is no in-band answer to.** `sudo`, `pkexec` and `su`
all present the credential that was lost. A flag that granted root without it
would not be a recovery hatch — it would be a permanent unauthenticated root
backdoor callable by anything running as your user.

So this is done from outside the running system, where no credential is
presented because none exists.

Boot the Arch ISO, then:

```bash
# 1. unlock. THE ONE THING YOU MUST REMEMBER IS THE LUKS PASSPHRASE.
#    It is not your login password. Without it, nothing below works.
cryptsetup open /dev/nvme0n1p2 luks-8c39203b-6764-4e5c-b1a9-6dedb64c05c1

# 2. mount root and home — BTRFS SUBDIRS, not one mount
DEV=/dev/mapper/luks-8c39203b-6764-4e5c-b1a9-6dedb64c05c1
mount -o subvol=/@     "$DEV" /mnt
mount -o subvol=/@home "$DEV" /mnt/home

# 3. pseudo-filesystems
mount -t proc proc /mnt/proc
mount -t sysfs sys /mnt/sys
mount --bind /dev  /mnt/dev
mount --bind /dev/pts /mnt/dev/pts

# 4. chroot and reset
chroot /mnt
bash /mnt/home/livings/Projects/zen-hardening/recover-root-chroot.sh
```

The script diagnoses which of the three failures you actually have, resets the
password, and confirms the shadow field is non-empty afterwards — an empty
field plus nulllock is an account that cannot authenticate at all.

Then:

```bash
exit
umount -R /mnt
reboot
```

> Step 2 is the part people get wrong on btrfs. Mounting the top-level `5`/
> subvolume instead of `/@` gets you a filesystem that looks right and has an
> empty `/etc`.

---

## C. nulllock is what's blocking you

Reachable from B's chroot — `recover-root-chroot.sh` offers the rollback — or
directly:

```bash
BK=$(ls -d /var/backups/remove-faillock-nulllock-2026-10-13/*/ | tail -1)
install -m 0644 -o root -g root "$BK/_etc_pam.d_system-auth"    /etc/pam.d/system-auth
install -m 0644 -o root -g root "$BK/_etc_pam.d_sddm-autologin" /etc/pam.d/sddm-autologin
```

This restores the stacks as they were *before* nulllock: faillock commented out,
`nullok` back. You get in, and then you fix the underlying cause rather than
living in the rolled-back state.

Verify once back in:

```bash
python3 ~/Projects/lifsea-security-suite/zen-hardening/sentinel.py check
```

`pam-no-nullok` will drift to critical if you left it rolled back. That is the
checker doing its job — re-apply nulllock once you can authenticate.

---

## The single point of failure

**The LUKS passphrase.** Every control on this box is enforced *inside* the
encrypted volume, so anything that forgets your login password still leaves the
passphrase as the one credential that cannot be reset from the machine itself.

Everything else here is recoverable. Confirm a passphrase-protected slot exists
(both this command and `cryptsetup luksDump` need root):

```bash
sudo cryptsetup luksDump /dev/nvme0n1p2 | grep -E 'Version|Keyslot' -A2
```

A `Version:` line with no usable `Keyslot:` beneath it means the volume has no
passphrase to forget, which is a different problem — and a worse one.

---

## What is verified vs not

- **Verified:** script syntax, non-root refusal, PAM backup contents, partition
  and subvolume layout, `visudo` availability.
- **Not verified:** steps B1–B4 end to end. They cannot be — the only way to
  test them is to actually be locked out. Treat the ISO mount order as
  unexercised until someone tries it on purpose, while they still have working
  credentials.