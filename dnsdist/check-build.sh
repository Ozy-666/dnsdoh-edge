#!/usr/bin/env bash
# Assert an installed dnsdist build has the features this deployment needs. Exit 1 on the first gap.
# Usage: check-build.sh PREFIX [EXTRA_FEATURE...]   (extra features exist to test the check)
set -uo pipefail
P=$(readlink -f "${1:?prefix}"); shift          # resolve `current` → versioned dir (rpath is absolute)
B="$P/bin/dnsdist"
[ -x "$B" ] || { echo "FAIL: $B missing"; exit 1; }
V=$("$B" --version 2>&1)
fail=0
for f in dns-over-quic "dns-over-tls(openssl)" "dns-over-https(nghttp2)" protobuf lmdb ipcipher "$@"; do
  grep -qF -- " $f" <<<"$(echo "$V" | grep '^Enabled features:' | sed 's/$/ /')" || { echo "FAIL: feature $f"; fail=1; }
done
grep -q 'LuaJIT' <<<"$V" || { echo "FAIL: not LuaJIT"; fail=1; }
if ldd "$B" | grep -q 'not found'; then echo "FAIL: unresolved libs"; ldd "$B" | grep 'not found'; fail=1; fi
ldd "$B" | grep -q "$P/lib/libdnsdist-quiche.so" || { echo "FAIL: quiche not from $P/lib"; fail=1; }
[ $fail = 0 ] && echo "OK: $("$B" --version 2>&1 | head -1)"
exit $fail
