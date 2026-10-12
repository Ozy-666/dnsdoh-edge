#!/usr/bin/env bash
# Point /opt/dnsdist/current or /opt/dnsdist/prod at an installed, checked version —
# atomically (symlink + rename, so the link never disappears). Run only after the parity suite
# passed on that version. Rollback = activate the previous version. Services pick it up on their
# next restart.
# Usage: activate.sh [<link>] <version>; <link> = current (default) | prod
# (/opt/dnsdist/prod is the binary dnsdist.service runs: `activate.sh prod <version>` sets it)
set -euo pipefail
if [ $# -ge 2 ]; then L=$1; V=$2; else L=current; V=${1:?version}; fi
case $L in current|prod) ;; *) echo "activate: link must be current or prod, not $L" >&2; exit 1 ;; esac
case $V in current|prod|*.new|*/*) echo "activate: '$V' is not a version" >&2; exit 1 ;; esac
HERE=$(cd "$(dirname "$0")" && pwd); B=${DNSDIST_ROOT:-/opt/dnsdist}   # DNSDIST_ROOT: tests only
[ -d "$B/$V" ] || { echo "activate: $B/$V not installed" >&2; exit 1; }
bash "$HERE/check-build.sh" "$B/$V"
ln -sfn "$V" "$B/$L.new"
mv -T "$B/$L.new" "$B/$L"
echo "activate: $L -> $(readlink "$B/$L")"
