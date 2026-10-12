#!/usr/bin/env bash
# On cert renewal: copy cert+key for one dnsdist instance (root:dnsdist 0640), reload them live,
# verify the served serial. Usage: tls-sync.sh <instance-env-file> (see tls-sync.example.env).
# The env file sets SRC DST UNIT BIN CC NGX SNI VERIFY_ADDRS; it is sourced as root, so it must be
# root-owned and not group/other-writable. VERIFY_ADDRS in the caller's environment overrides the
# file's (tests point it at a server with another cert). Install the script outside the working
# tree for prod (e.g. /usr/local/sbin/dnsdoh-tls-sync). SRC is only read, never modified.
set -euo pipefail
ENV=${1:-}
if [ -z "$ENV" ] || [ ! -f "$ENV" ] || [ ! -r "$ENV" ]; then
  echo "tls-sync: usage: tls-sync.sh <instance-env-file>" >&2; exit 2
fi
if [ "$(stat -L -c %u "$ENV")" != 0 ] || [ $(( 0$(stat -L -c %a "$ENV") & 022 )) != 0 ]; then
  echo "tls-sync: $ENV must be root-owned and not group/other-writable; refusing" >&2; exit 2
fi
VERIFY_OVERRIDE=${VERIFY_ADDRS:-}
. "$ENV"
VERIFY_ADDRS=${VERIFY_OVERRIDE:-${VERIFY_ADDRS:-}}
for v in SRC DST UNIT BIN CC SNI VERIFY_ADDRS; do
  [ -n "${!v:-}" ] || { echo "tls-sync: $ENV does not set $v" >&2; exit 2; }
done
NGX=${NGX:-}
T="tls-sync[$UNIT]"
install -d -o root -g dnsdist -m 0750 "$DST"
install -o root -g dnsdist -m 0640 "$SRC/fullchain.pem" "$DST/fullchain.pem.new"
install -o root -g dnsdist -m 0640 "$SRC/privkey.pem"   "$DST/privkey.pem.new"
mv -f "$DST/fullchain.pem.new" "$DST/fullchain.pem"
mv -f "$DST/privkey.pem.new"   "$DST/privkey.pem"
want=$(openssl x509 -in "$DST/fullchain.pem" -noout -serial)
echo "$T: $want $(openssl x509 -in "$DST/fullchain.pem" -noout -enddate)"
# NGX: a web server that reads the certbot live directory itself; only a reload makes it pick up the new cert.
if [ -n "$NGX" ] && systemctl is-active --quiet "$NGX"; then systemctl reload "$NGX"; fi
if ! systemctl is-active --quiet "$UNIT"; then echo "$T: $UNIT not active: files copied, nothing to reload or verify"; exit 0; fi
"$BIN" -C "$CC" -c -e 'reloadAllCertificates()'     # reloads DoT/DoH/DoQ (dnsdist-lua.cc:3078-3092)
# reloadAllCertificates() only logs its errors (dnsdist-lua.cc:3094-3101): prove what is served.
sleep 1; rc=0
for a in $VERIFY_ADDRS; do
  got=$(echo | timeout 5 openssl s_client -connect "$a" -servername "$SNI" 2>/dev/null | openssl x509 -noout -serial 2>/dev/null)
  if [ "$got" = "$want" ]; then echo "$T: $a serves $got"; else echo "$T: MISMATCH $a serves '${got:-nothing}', want $want" >&2; rc=1; fi
done
exit $rc
