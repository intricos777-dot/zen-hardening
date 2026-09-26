# stray test artifacts

`false.new` and `true.new` are zero-byte files that got committed in
`54050ec` ("fix: bound the arpwatch parse probe, which hung the install as
root"). They are leftovers from that fix's testing — the `.new` suffix
matches what `install-arpwatch-spoof.sh` writes when it stages a new copy of
a file, so a test run left the staged empties behind and they were swept into
the commit.

They are harmless (empty, not referenced by any unit or script) but they are
noise. Removing them needs a history rewrite or a plain forward delete:

    git rm false.new true.new && git commit -m "chore: remove stray empty test artifacts"

Left in place rather than deleted unilaterally, since touching committed
history is your call.
