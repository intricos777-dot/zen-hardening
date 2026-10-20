<!-- Watermark: Living_Sin (intricos777-dot) + AI agents (Hermes, Lia, opencode) - collaborative work -->
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

### Policy

**Any inbound attempt from a device you do not own is a ban on the first
packet.** `threshold_hits` is 1.

| device | outcome |
|---|---|
| registered owner | allowed, logged as `owner` |
| loopback / link-local / gateway | allowed, `infrastructure` |
| unverified, plain vendor MAC | timed ban, 24 h, doubling per repeat to 7 days |
| unverified, **randomised MAC** | **permanent block** |
| any device that comes back after a ban | **permanent block** (ban evasion) |
| permanent block, still talking to us | logged as `permanent-hit` |

Identity is the **MAC**, not the address. This network is a flat
`10.0.0.0/8` broadcast domain (verified: `10.0.0.0/8 dev wlo1 proto kernel`),
so a stranger can pick any address they like. Banning addresses alone would be
worthless; the nft chain drops on `ether saddr @blacklist_mac` first.

### Ownership registry

```json
"owners": [
  {"mac": "3e:11:22:33:44:55", "name": "my phone",  "ips": ["10.197.250.7"]},
  {"mac": "f4:5c:89:aa:00:01", "name": "my laptop", "ips": ["10.197.250.9"]}
]
```

**Enrol your devices before or immediately after installing.** With an empty
registry your own phone is banned on sight, and because phone MACs are
randomised, permanently. The installer prints a warning when the registry is
empty, and `warden status` repeats it on every run.

```sh
sudo warden suggest    # devices seen that are NOT yours; copy the MACs across
```

### Spoofing detection

| signal | meaning |
|---|---|
| `randomised-unverified` | locally-administered MAC (2nd LSB of octet 1 set) from a device you do not own — concealing its hardware identity |
| `identity-reuse` | one MAC presenting several source addresses |
| `ban-evasion` | a banned MAC is back |
| `vendor-masquerade` | OUI claims Apple/Intel/Dell/... but the device behaves unrecognised |

One weak signal escalates the ban rather than condemning the device, because
neighbour tables are lossy and a device that simply reconnects looks like
identity reuse once. Two signals, or ban evasion, are permanent.

**Two false-positive traps, both tested against this box's real state:** this
machine's own `wlo1` MAC is `ea:bd:c8:4d:53:a8`, which is randomised — so
"randomised" alone must never condemn a device, only an unverified one. And
the gateway appears twice in `ip neigh` (a v4 and a v6 line), which reads as
"one MAC, many addresses" unless link-local addresses are excluded. Both
checks are in the selftest.

### What this does not stop

A stranger who uses a **different random MAC every time** is not stopped by
any of this. That is the standard evasion, and MAC-based blocking does not
address it — only 802.11w management-frame protection or a WPA3-enterprise AP
with client isolation would. Treat a permanent block as a speed bump against a
casual prober, not a wall against a determined one. And frames the AP forwards
that never reach the IP stack are never seen here at all (no bridge on wlo1, so
no fdb table to read).

### Use

```sh
sudo warden status                    # owners, timed bans, permanent blocks
sudo warden suggest                   # unrecognised devices, for enrolment
sudo tail -f /var/log/warden/events.jsonl
sudo warden block f4:5c:89:aa:bb:cc   # manual timed ban (MAC or address)
sudo warden unblock f4:5c:89:aa:bb:cc
sudo warden unforgive f4:5c:89:aa:bb:cc   # the ONLY way a permanent block ends
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
| `warden.py selftest` — 86 assertions: NFLOG decode, OUI classification, ownership, MAC-keyed bans, escalation, windowing, spoof signals, sanctions, permanent-block persistence, forgiveness, audit log | **PASS** |
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
