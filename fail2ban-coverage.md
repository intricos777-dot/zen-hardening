<!-- Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work -->
# fail2ban coverage — what is actually enforced, and what is not

Verified on this machine, 2026-09-26. Read this before assuming you are
protected. Three of the four jails in `shield-kitty.conf` do not work, and
cannot, for structural reasons that no amount of configuration will fix.

## Summary

| Jail | Enabled | Actually bans? | Why |
|---|---|---|---|
| `sshd` | yes | **yes, if sshd is running** | sshd is currently `inactive` — 0 listeners on :22. The jail is correct and dormant. |
| `recidive` | yes | yes, once another jail bans something | Re-bans repeat offenders. Needs at least one working jail. |
| `sddm` | yes | **NO — structurally dead** | See below. |
| `sudo` | yes | **NO — structurally dead** | See below. |

## Why sddm and sudo can never ban anything

Both jails use `filter = pam-generic`. Its failregex is:

```
failregex = ^ruser=<F-ALT_USER>(?:\S*|.*?)</F-ALT_USER> rhost=<HOST>...
```

The filter requires a literal `rhost=<IP>` field to extract an address to ban.
Tested with `fail2ban-regex`:

```
remote line (rhost=203.0.113.5)  -> 1 matched
local  line (rhost=)             -> 0 matched, 1 missed
```

A failure at the SDDM greeter is by definition local: someone physically at
your keyboard. There is no IP to ban, because there is no network involved. The
same is true of a bad `sudo` password — it comes from a local tty.

**This is not a misconfiguration to be repaired.** IP banning is the wrong tool
for both cases, and no filter rewrite makes it the right one. A person standing
at your laptop cannot be banned by IP because they are not coming from an IP.

## What actually protects those two cases

- **`sudo`** — `pam_faillock` with `deny = 10`. Enforced per account. Note that
  if `admin_group` is configured, admin accounts are exempt by design.
- **`sddm` / the physical greeter** — **nothing automated**. This is a real gap
  and no config in this repo closes it. The mitigations that do apply:
  - Strong greeter password.
  - `deny = 10` in faillock applies to the account being guessed, so an
    attacker gets 10 tries per account per `unlock_time`, not unlimited.
  - Automatic screen lock, and physically shutting the lid when away.

If you want the greeter case covered by something automated, the honest options
are a camera or a physical presence sensor — not a log filter.

## Why sshd works but currently does nothing

The `sshd` jail's filter is correct (2 of 4 synthetic attack lines matched; the
other 2 were PAM-format sudo/console lines that belong to the other jail).
But `sshd.service` is `inactive` and nothing listens on port 22, so there is no
sshd traffic to match. The jail exists so that protection is already in place if
sshd is ever enabled — it is not evidence of current protection.

If you enable sshd, the jail will start working immediately with no config
change.

## The self-ban trap

All jails use `bantime = 86400` — 24 hours, then they expire on their own.
`ignoreip` covers loopback and RFC1918, so on your current network
(10.197.250.246) you cannot be banned.

**The moment you connect from a public address — tethering, cafe wifi, airport
— you are no longer in `ignoreip`, and four wrong sudo passwords would ban your
own address on every port for a day.** `unban-self.sh` is the escape hatch.

This is why the `sudo`/`sddm` jails being dead is, right now, the reason you
have not locked yourself out — the ban expires by itself after 24h.

Escape hatch:

```bash
sudo ~/Projects/zen-hardening/unban-self.sh --list    # is my address banned?
sudo ~/Projects/zen-hardening/unban-self.sh          # clear bans on my addresses
```

## Verification commands used

```bash
systemctl is-active sshd                       # inactive
ss -ltn | grep -c ':22 '                        # 0
fail2ban-regex /tmp/remote.log /etc/fail2ban/filter.d/pam-generic.conf   # 1 matched
fail2ban-regex /tmp/local.log  /etc/fail2ban/filter.d/pam-generic.conf   # 0 matched
fail2ban-client -t                              # configuration test is successful
```

`fail2ban-client status` needs root (socket is 0700), so jail state cannot be
read unprivileged.
