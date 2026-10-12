#!/usr/bin/env bash
# Install dnsdist/conf from a commit (never the working tree) as the prod config, the directory
# dnsdist.service reads. Usage: bash <this script> <sha>. Does not restart dnsdist: that is a
# separate, explicit command.
# Env (tests): PREFIX, DNSDIST, CHECK_SITE (site name or absolute path), OWNER.
set -euo pipefail
ME=${0##*/}; SHA=${1:?usage: $ME <sha>}; R=$(cd "$(dirname "$0")/.." && pwd)
PREFIX=${PREFIX:-/etc/dnsdoh.art/dnsdist}; DNSDIST=${DNSDIST:-/opt/dnsdist/prod/bin/dnsdist}
CHECK_SITE=${CHECK_SITE:-site-example}; OWNER=${OWNER:-root:dnsdist}
full=$(git -C "$R" rev-parse --verify --quiet "$SHA^{commit}") || { echo "$ME: $SHA is not a commit" >&2; exit 1; }
stage=$PREFIX.new; rm -rf "$stage"; mkdir -p "$stage"
git -C "$R" archive "$full" dnsdist/conf | tar -x -C "$stage" --strip-components=2
if ! DNSDOH_CONF_DIR=$stage DNSDOH_SITE=$CHECK_SITE "$DNSDIST" --check-config -C "$stage/dnsdist.lua"; then
  rm -rf "$stage"; echo "$ME: --check-config failed; $PREFIX unchanged" >&2; exit 1
fi
printf 'sha=%s\ninstalled=%s\n' "$full" "$(date -u +%FT%TZ)" > "$stage/DEPLOYED"
chown -R "$OWNER" "$stage"
find "$stage" -type d -exec chmod 0750 {} +; find "$stage" -type f -exec chmod 0640 {} +
if [ -d "$PREFIX" ]; then rm -rf "$PREFIX.prev"; mv -T "$PREFIX" "$PREFIX.prev"; fi
mv -T "$stage" "$PREFIX"
echo "$ME: $PREFIX at $full (restart dnsdist to use it)"
