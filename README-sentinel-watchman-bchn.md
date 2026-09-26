# sentinel / watchman / bchn-monitor

Rebuilt 2026-09-26. None of these three existed in any repository or in any
deleted git history — the only surviving reference was one line in
`sin-archive-2026/MANIFEST-2026-09-24.md` ("sentinel posture: 15/15 integrity
anchors intact, watchman active"). These are fresh implementations of the same
intent, with a fresh anchor set derived from this machine.

## sentinel.py — integrity anchors
16 anchors, each a named fact compared against a recorded baseline.
Never repairs: a watcher that silently fixes what it monitors cannot be trusted.

    python3 sentinel.py baseline     # capture current state
    python3 sentinel.py check        # verify (exit 0 clean, 1 drift, 3 unverifiable)
    python3 sentinel.py explain     # what each anchor checks and why
    python3 sentinel.py --selftest   # proves it detects planted drift, and that
                                     # an identical baseline reports no false positives

Honest accounting: 3 anchors need root. Running unprivileged they report
`unverified` and are EXCLUDED from the intact count rather than counted as
passing. `shadow-root-locked` is currently unverifiable, so the posture is
15/15 verified + 1 unverified, not a clean 16/16.

## watchman.py — supervisor
Runs sentinel on an interval, notifies on state change, keeps 30 days of
history, prunes it. Root notification is dispatched as the invoking user via
setpriv, because root `notify-send` silently succeeds and tells nobody.

    python3 watchman.py run --interval 300
    python3 watchman.py once [--repair]
    python3 watchman.py status | history --days 7
    python3 watchman.py --selftest

`--repair` only restarts user services (collector, shield-kitty). It has NO
auto-repair for faillock, firewalld, sshd, sudoers or anything touching auth:
a supervisor that rewrites security policy on its own is an attacker with write
access. The selftest asserts that absence.

## bchn-monitor.py — node and wallet state
Reports rather than fabricates. On this machine there is no BCH node, no
datadir, and no `~/.bitcoin-cash/wallets` — the directory the cleanup ledger
records as RETAINED and "never uploaded anywhere". A missing wallet dir is
reported CRITICAL, because that is the one thing this machine cannot confirm
and the thing most likely to hold funds.

    python3 bchn-monitor.py status [--json]
    python3 bchn-monitor.py --selftest

Never prints an RPC password; reports only whether one is configured.

## services (user units, no root needed)

    cp systemd/{watchman,bchn-monitor}.service ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now watchman.service

State lives in ~/.local/share/sentinel/.
