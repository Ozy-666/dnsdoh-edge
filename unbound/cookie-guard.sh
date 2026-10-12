#!/usr/bin/env bash
# ExecStartPre for unbound. unbound fatal_exits on a missing or malformed cookie-secret-file; an
# EMPTY file starts cleanly and mints no cookies. So: a valid file is left alone; anything else is
# moved aside and replaced with an empty file.
# Valid = regular file (not a symlink), at most 2 lines, each exactly 32 hex digits (a missing
# final newline is fine, as unbound's reader accepts it). Never prints file contents.
# The directory is unbound-owned, so anything in it may be planted by a compromised unbound: the
# guard never chmods/chowns/writes THROUGH a symlink. The aside file is chmodded only if it is a
# regular file; mv -T replaces (never follows) a planted aside name, even one linking a directory;
# install(1) unlinks a planted $F first and creates it O_EXCL. unbound is stopped while this
# ExecStartPre runs (no unbound process is alive), so nothing races these steps. -T on mv and
# install: a planted directory is never used as a target directory.
set -u
F=${1:-/var/lib/unbound/cookie-secrets.txt}; OWNER=${GUARD_OWNER:-unbound:unbound}
valid() {
  [ -f "$F" ] && [ ! -L "$F" ] || return 1
  [ "$(grep -c '' "$F")" -le 2 ] || return 1
  ! grep -qvxE '[0-9a-fA-F]{32}' "$F"
}
valid && exit 0
if [ -e "$F" ] || [ -L "$F" ]; then
  aside="$F.bad.$(date +%Y%m%dT%H%M%S)"
  if mv -fT -- "$F" "$aside"; then
    [ -L "$aside" ] || [ ! -f "$aside" ] || chmod 600 -- "$aside" 2>/dev/null
  fi
  echo "cookie-guard: $F malformed; moved to $aside; cookies OFF until rotation re-adds a secret" >&2
else
  echo "cookie-guard: $F missing; cookies OFF until rotation re-adds a secret" >&2
fi
install -T -m 0600 -o "${OWNER%%:*}" -g "${OWNER##*:}" /dev/null "$F" || { echo "cookie-guard: cannot create $F" >&2; exit 1; }
exit 0
