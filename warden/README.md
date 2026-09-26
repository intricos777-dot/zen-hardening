# warden — auto-blacklist PCs and phones that connect to this box

Two tools, built on 2026-09-26.

| tool | what it does |
|---|---|
| `warden.py` + `install-warden.sh` | watches for devices trying to connect in, and blacklists repeat offenders |
| `remove-remote-viewing.sh` | finds, removes and blocks TeamViewer and 12 other remote-control tools |

## Install

```sh
cd ~/Projects/zen-hardening/warden
sudo ./install-warden.sh          # warden
sudo ./remove-remote-viewing.sh   # remote-viewing removal + prevention
```

Both need root (there is no passwordless sudo on this box).

## warden

### What was already here

The `workstation` firewalld zone is already `target DROP` with an empty service
list, so **every** unsolicited inbound connection is already dropped before it
reaches a socket. Verified: `firewall-cmd --get-default-zone` → `workstation`,
zone has no services beyond `dhcpv6-client`.

So warden is not the thing that stops strangers. It answers the questions the
firewall cannot:

- **who** was that? (IP → MAC → IEEE vendor → phone / PC / unknown)
- are they **still trying**?
- do I **remember** them if I later open a port for something legitimate?

### How it works

1. `nft` chain at `priority -150` (ahead of firewalld's own filter chain):
   accepts loopback, established/related and ICMPv6; **drops** anything in its
   blacklist set; **logs** the rest to NFLOG group 5, rate-limited 20/min.
2. `warden.py` binds NFLOG group 5, decodes each packet, resolves the source
   IP to a MAC via the neighbour table, looks the OUI up in
   `/usr/share/nmap/nmap-mac-prefixes` (38 930 entries, local, no network),
   and classifies the device.
3. 3 hits within 15 minutes → 24 h ban, pushed into the nft set. Another
   offence while banned → 48 h, then 96 h, capped at 7 days.
4. Everything lands in `/var/log/warden/events.jsonl`.

The chain's policy is `accept` and warden never widens or narrows firewalld's
opinion. Its only enforcement act is dropping its own blacklist, before anyone
else gets a say.

### Use

```sh
sudo warden status                    # tracked devices + active bans
sudo tail -f /var/log/warden/events.jsonl
sudo warden block 10.1.2.3            # manual ban
sudo warden unblock 10.1.2.3
python3 ~/Projects/zen-hardening/warden/warden.py selftest   # no root needed
```

### Config

`/etc/warden/warden.json`. The field you will actually want:

```json
"trusted": ["10.197.250.1", "10.197.250.42"]
```

Addresses listed there are logged but never auto-banned. Use it for your own
phone and laptop, or you will ban yourself. Restart warden after editing.

### Limits, honestly

- **IPv4 only for banning.** The set is `type ipv4_addr`; v6 peers are logged
  and classified but not blockable. The 10.0.0.0/8 in this LAN is IPv4, so
  this is a real gap only for a v6-connected attacker.
- **MAC resolution is best-effort.** If the neighbour entry has expired, the
  device classifies as `unknown` and only the IP is banned. Good enough to stop
  them, not enough to name the hardware.
- **Rate limit 20/min.** A fast scanner produces more packets than that; you
  get a representative sample, not every hit. That is deliberate — NFLOG at
  full rate is expensive — but it means the hit *count* is a sample, so the
  3-hit threshold is more easily reached by a noisy device than a careful one.
- **The nft ruleset is unverified.** `nft -c` needs root, so the syntax was
  never checked on this box. `install-warden.sh` verifies the `WARDEN` log
  rules are present in the *live* chain after loading and aborts if they are
  not, but if nft rejects the syntax outright the install stops there.

## remove-remote-viewing.sh

### Current state

**Nothing was installed.** Verified: no pacman package, no flatpak, no running
process, no install path, no systemd unit, no listening socket. So this tool
did not remove anything — it is a prevention tool, and it says so rather than
implying otherwise.

The pre-existing `../block-remote-viewing.sh` only drops port 5938. That does
not stop TeamViewer: its control channel is HTTPS/443 to a vendor relay fleet,
and once the agent registers, the box is drivable with no inbound connection
at all. A port rule is not a control.

### Four layers

1. **Remove** — stop the process, `pacman -Rns`, uninstall flatpak, delete
   `/opt/TeamViewer` and friends, `systemctl daemon-reload`.
2. **Refuse install** — a pacman `PreTransaction` hook denies 25 package names
   before any AUR helper can commit.
3. **Re-remove** — `remote-viewing-guard.timer` scans every 10 min and removes
   anything that reappears, catching an install that bypassed or deleted the
   hook. Confirmed paths are **moved to quarantine**, not deleted, so a false
   positive is recoverable.
4. **Cut egress** — `teamviewer.com` and `masterteamviewer.com` blackholed in
   `/etc/hosts`, plus the 5938 firewalld drop.

```sh
./remove-remote-viewing.sh --check     # audit, no root needed
sudo ./remove-remote-viewing.sh        # remove + prevent
sudo ./remove-remote-viewing.sh --unblock
```

## Tests actually run

| check | result |
|---|---|
| `warden.py selftest` — 31 assertions: NFLOG decode, OUI classification, escalation, windowing, trust, persistence, audit log | **PASS** |
| pacman hook matching, 10 argv shapes incl. `-U libteamviewer` and the `teamviewer-extra` substring trap | **10/10** |
| `warden-nft-sync` input validation, 16 hostile args incl. `10.0.0.1; rm -rf /`, `$(id)`, embedded newline | **all rejected, no injection** |
| `remove-remote-viewing.sh --check` on this box | clean, correct verdict |
| same script against fake TeamViewer/AnyDesk/Sunlogin trees and a fake unit | **detected all** |
| guard scan: clean box vs fake install tree | clean / 1 found, nothing deleted unprivileged |
| `bash -n` on all 3 shell scripts, `py_compile` on all 3 python files | clean |
| both copies of the nft ruleset compared | byte-identical |
| `nft -c` ruleset syntax check | **NOT RUN — needs root** |
| end-to-end live traffic capture | **NOT RUN — needs root** |

Bugs found and fixed while testing, all caught by the tests rather than by
reading: the NFLOG header was 8 bytes short (`nfulnl_msg_packet_hdr` is 16, not
8); the prefix parser hunted for a NUL terminator that only exists when the
prefix is *absent*, truncating every packet at `\x45\x00`; the address family
was read from `res_id` (the nftables family) instead of `nfgen_family`; the
pacman hook's shebang landed on line 2; `libteamviewer` bypassed the deny list;
`ls dir/*a* dir/*b*` exits 2 when any glob is unmatched, so the systemd-unit
check could never fire; `detect_installed`'s return status was inverted against
its caller, so a clean box printed no verdict; pgrep patterns carried trailing
spaces from the table and could never match.

## Files

```
warden.py               daemon + CLI + selftest
install-warden.sh       nft table, config, systemd unit, sudoers, start
warden-nft-sync         the ONLY NOPASSWD-sudo command; validates its input
warden-nft-restore      ExecStartPre: recreates the table if it went missing
warden.service          system unit
warden.json             config template
remove-remote-viewing.sh  remove + prevent, TeamViewer first
remote-viewing-guard      10-minute re-scan timer target
```
