#!/bin/sh
# dnsdoh.art-compile until no edit arrived during the run.
# The trigger (filter/.recompile) is a counter dnsdoh.art-edit bumps after each edit; an edit
# that lands while a compile runs changes it, and the loop compiles again.
# Known windows where an edit waits for the next edit or the daily timer:
#  (a) the cap below is hit (trigger changed on 60 consecutive runs; exit 75);
#  (b) an edit whose bump lands between the final "after=" read and systemd re-arming the path
#      watch (milliseconds): PathChanged does not re-detect on re-arm (man systemd.path); the
#      same goes for a read that lands in the in-place truncate of a bump (empty file): rd()
#      retries once after 0.2 s. A trigger that is missing or empty on both reads is "stable"
#      (compile once, exit with its rc), never a reason to loop;
#  (c) a compile run by hand outside systemd holds compile.lock, so a path-started run refuses at
#      once (exit 1) and the edit waits likewise.
T=${TRIGGER:-/etc/dnsdoh.art/filter/.recompile}
C=${COMPILE:-/usr/local/bin/dnsdoh.art-compile}
CFG=${CONFIG:-/etc/dnsdoh.art/compile.toml}
rd() { v=$(cat "$T" 2>/dev/null); [ -n "$v" ] || { sleep 0.2; v=$(cat "$T" 2>/dev/null); }; printf '%s' "$v"; }
n=0
while :; do
  before=$(rd)
  "$C" --config "$CFG"; rc=$?
  after=$(rd)
  [ "$before" = "$after" ] && exit $rc
  n=$((n + 1))
  [ $n -ge 60 ] && { echo "recompile: trigger still changing after 60 runs; the newest edit waits for the next edit or the daily timer" >&2; exit 75; }
done
