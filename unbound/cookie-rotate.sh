#!/usr/bin/env bash
# DNS cookie secret rotation (unbound/README.md). Daily from dnsdoh.art-cookie-rotate.timer.
# Idempotent: decisions come from unbound's memory (print_cookie_secrets) and the state file.
# Exit 0 = fine; 1 = needs attention (shows in systemctl --failed). Never prints a secret.
# unbound-control exits 0 on some "error: ..." replies (e.g. a bad secret argument), so every
# mutation (add/activate/drop) is verified against unbound's own memory afterward, never trusted
# from its exit status alone. activate_cookie_secret SWAPS active and staging; to survive a crash
# or a failed state write between a successful activate and recording it, the state file carries
# a fingerprint (sha256, first 16 hex chars — not the secret) of the secret that should end up
# active once staged. If it's already there, the run does not activate again (which would swap
# back and silently undo the rotation).
# Note: the new secret is an unbound-control argument, so for the few milliseconds that process
# runs it is visible in its /proc/<pid>/cmdline, which other local accounts can usually read.
# No behaviour depends on this note.
set -uo pipefail
CONF=${COOKIE_ROTATE_CONF:-/etc/dnsdoh.art/cookie-rotate.conf}
secret_file=/var/lib/unbound/cookie-secrets.txt; state_file=/var/lib/dnsdoh.art-cookies/cookie-rotate.state
file_owner=unbound:unbound; unbound_control=unbound-control; period_days=30; drop_after_s=7200
hook_timeout_s=30; post_rotate_hook=
if [ ! -f "$CONF" ] || [ ! -r "$CONF" ] || ! . "$CONF"; then
  echo "cookie-rotate: cannot read config $CONF; nothing done" >&2; exit 1
fi
# Only known keys: an unknown one (a typo, or a key from before a rename, e.g. the hook key) would
# otherwise be ignored and silently disable what it was meant to set.
KEYS=" secret_file state_file file_owner unbound_control period_days drop_after_s hook_timeout_s post_rotate_hook "
for k in $(sed -nE 's/^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)=.*/\1/p' "$CONF"); do
  case $KEYS in *" $k "*) ;; *)
    echo "cookie-rotate: $CONF: unknown key $k ignored (the hook key is post_rotate_hook); nothing done" >&2; exit 1 ;;
  esac
done
NOW=${COOKIE_ROTATE_NOW:-$(date +%s)}; FORCE=0; [ "${1:-}" = --force ] && FORCE=1; RC=0
log() { echo "cookie-rotate: $*" >&2; }
uc() { $unbound_control "$@"; }
mem() { uc print_cookie_secrets | awk '/^(active|staging)/{print $NF}'; }
act_first() { mem | head -n1; }
newsecret() { od -An -tx1 -N16 /dev/urandom | tr -d ' \n'; }
fp_of() { printf '%s' "$1" | sha256sum | cut -c1-16; }  # fingerprint only, never the secret itself
put_state() {  # $1 phase $2 since $3 fp (may be empty). mktemp (O_EXCL, random name), never a fixed name
  local t; t=$(mktemp "$state_file.XXXXXX") || return 1
  printf 'phase=%s\nsince=%s\nfp=%s\n' "$1" "$2" "${3:-}" > "$t" && mv -fT "$t" "$state_file" || { rm -f "$t"; return 1; }
}
pstate() { put_state "$@" || { log "state file write failed"; RC=1; }; }  # every call site checked
hook() {  # $1 add|drop
  [ -z "$post_rotate_hook" ] && return 0
  [ -x "$post_rotate_hook" ] || { log "post-rotate hook $post_rotate_hook configured but missing"; return 1; }
  timeout -k 5 "$hook_timeout_s" "$post_rotate_hook" "$1" || { log "post-rotate hook $1 failed or timed out (${hook_timeout_s}s)"; return 1; }
}
do_activate() {  # $1 = fingerprint the newly-active secret must match afterward
  local want_fp=$1 got activate_ok=0
  if hook add; then activate_ok=1; fi
  if [ "$activate_ok" != 1 ]; then log "not activated; staying staged (retry next run)"; RC=1; return 1; fi
  uc activate_cookie_secret >/dev/null
  got=$(fp_of "$(act_first)")
  if [ "$got" != "$want_fp" ]; then log "activate did not produce the expected secret"; RC=1; return 1; fi
  return 0
}
fp_matches_active() { [ "$n" = 2 ] && [ -n "$fp" ] && [ "$(fp_of "$(act_first)")" = "$fp" ]; }
check_file() {  # file must equal unbound's memory once this returns; non-zero = it still doesn't.
                # Callers gate the next hook add / do_activate on this return: the post-rotate
                # hook's consumer may read the file, so it must never act on one that failed to sync.
  local m; m=$(mem) || { log "print_cookie_secrets failed"; RC=1; return 1; }
  [ "$m" = "$(cat "$secret_file" 2>/dev/null)" ] && return 0
  log "secret file differs from unbound's memory; rewriting it from memory"
  # Built, chowned and chmodded in the root-only state dir, then renamed into unbound's directory:
  # nothing is written, chowned or chmodded BY PATH there, where a running unbound could swap a
  # path for a symlink between steps. rename(2) replaces a planted link, never follows it. Same
  # filesystem required (a cross-device mv would copy by path instead).
  local t; t=$(mktemp "$SD/secret.XXXXXX") || { log "rewrite failed (mktemp)"; RC=1; return 1; }
  if ! { [ -z "$m" ] || printf '%s\n' "$m" > "$t"; }; then
    log "rewrite failed (write)"; rm -f "$t"; RC=1; return 1
  fi
  if ! chown "$file_owner" "$t"; then
    log "rewrite failed (chown $file_owner)"; rm -f "$t"; RC=1; return 1
  fi
  if ! chmod 600 "$t"; then
    log "rewrite failed (chmod)"; rm -f "$t"; RC=1; return 1
  fi
  if [ "$(stat -c %d "$SD")" != "$(stat -c %d "$(dirname -- "$secret_file")")" ]; then
    log "rewrite failed (cross-fs: state dir and secret dir must share a filesystem)"; rm -f "$t"; RC=1; return 1
  fi
  if ! mv -fT "$t" "$secret_file"; then
    log "rewrite failed (mv)"; rm -f "$t"; RC=1; return 1
  fi
  RC=1
  return 0
}
# The state dir holds the lock and the temp files this root script creates: it must be a real
# directory owned by root and not group/other-writable, or an untrusted writer could plant links
# under those names. Refuse before writing anything or touching unbound.
SD=$(dirname -- "$state_file")
if [ -L "$SD" ] || [ ! -d "$SD" ] || [ "$(stat -c %u "$SD")" != 0 ] || [ $(( 0$(stat -c %a "$SD") & 022 )) != 0 ]; then
  log "state dir $SD must be a root-owned directory, not group/other-writable (uid $(stat -c %u "$SD" 2>/dev/null), mode $(stat -c %a "$SD" 2>/dev/null)); refusing"
  exit 1
fi
exec 9>>"$state_file.lock"
flock -w 60 9 || { log "another rotation is running"; exit 1; }
S=$(mem) || { log "cannot reach unbound (print_cookie_secrets)"; exit 1; }
n=$(printf '%s' "$S" | grep -c .)
phase=$(sed -n 's/^phase=//p' "$state_file" 2>/dev/null)
since=$(sed -n 's/^since=//p' "$state_file" 2>/dev/null)
fp=$(sed -n 's/^fp=//p' "$state_file" 2>/dev/null)
if [ -n "$since" ] && ! [ "$since" -eq "$since" ] 2>/dev/null; then
  log "non-numeric since in state file; treating as 0"; since=0; RC=1
fi
since=${since:-0}
if [ "$FORCE" = 1 ] && [ "$n" = 2 ]; then
  log "force: 2 secrets present (drop pending); nothing done"; exit 1
fi
if [ "$n" = 0 ]; then                                         # guard emptied the file: add one (the only secret is the active one)
  new=$(newsecret); newfp=$(fp_of "$new")
  uc add_cookie_secret "$new" >/dev/null
  if [ "$(mem)" != "$new" ]; then log "add_cookie_secret did not produce the expected secret"; exit 1; fi
  pstate unsynced "$NOW" "$newfp"
  if check_file && hook add; then pstate activated "$NOW" "$newfp"; else RC=1; fi
  log "0 secrets in unbound (file emptied by the guard?): re-added one"; exit 1
fi
case "$phase" in
  unsynced)                                                   # hook only; never add, never drop
    # sync the file BEFORE hook add; a failed sync must gate the hook
    if check_file && hook add; then pstate activated "$since" "$fp"; else RC=1; fi ;;
  staged)
    if [ "$n" != 2 ]; then
      log "state staged but $n secret(s): trusting unbound"; pstate activated "$NOW" ""; RC=1
    elif [ -z "$fp" ]; then
      log "staged with no fingerprint on record (legacy state): trusting unbound, not activating blindly"
      pstate activated "$NOW" ""; RC=1
    elif fp_matches_active; then
      log "active secret already matches the staged fingerprint; resuming (no re-activate)"
      pstate activated "$NOW" "$fp"
    else
      # sync the file BEFORE do_activate (which itself does hook add); a failed sync must gate
      # do_activate
      if check_file && do_activate "$fp"; then pstate activated "$NOW" "$fp"; check_file; fi
    fi ;;
  *)
    if [ "$n" = 2 ] && [ "$phase" != activated ]; then
      log "no state with 2 secrets: treating as activated now"; pstate activated "$NOW" ""; RC=1
    elif [ "$n" = 2 ] && [ $((NOW - since)) -ge "$drop_after_s" ]; then
      pre_active=$(act_first)
      uc drop_cookie_secret >/dev/null
      if [ "$(mem | grep -c .)" = 1 ] && [ "$(act_first)" = "$pre_active" ]; then
        check_file; hook drop || log "post-rotate hook drop failed (advisory)"
      else
        log "drop_cookie_secret did not produce the expected result"; RC=1
      fi
    elif [ "$n" = 1 ] && { [ "$FORCE" = 1 ] || [ -z "$phase" ] || [ $((NOW - since)) -ge $((period_days * 86400)) ]; }; then
      old_active=$(act_first)
      new=$(newsecret); newfp=$(fp_of "$new")
      uc add_cookie_secret "$new" >/dev/null
      if [ "$(mem | sed -n '1p')" = "$old_active" ] && [ "$(mem | sed -n '2p')" = "$new" ]; then
        pstate staged "$NOW" "$newfp"
        # sync BEFORE do_activate; a failed sync must gate it
        if check_file && do_activate "$newfp"; then pstate activated "$NOW" "$newfp"; check_file; fi
      else
        log "add_cookie_secret did not produce the expected result"; RC=1
      fi
    fi ;;
esac
check_file  # every run, even a no-op day (T5 case h)
exit $RC
