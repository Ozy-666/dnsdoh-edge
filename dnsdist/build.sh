#!/usr/bin/env bash
# Build dnsdist from pinned, verified sources into /opt/dnsdist/<version>. Does NOT touch `current`.
# Nothing system-wide besides that prefix and the build cache. Resumable.
# Run: nice -n19 ionice -c3 bash dnsdist/build.sh
# DNSDIST_VARIANT=pq: into /opt/dnsdist/<version>-pq, DoT on a private OpenSSL in that prefix and quiche on
# BoringSSL $BORINGSSL_COMMIT (both offer X25519MLKEM768 by default; neither needs a group setting).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd); . "$HERE/pins.env"
VARIANT=${DNSDIST_VARIANT:-}
case $VARIANT in ""|pq) ;; *) echo "build: DNSDIST_VARIANT must be empty or pq" >&2; exit 1 ;; esac
PFX=/opt/dnsdist/$DNSDIST_VERSION${VARIANT:+-$VARIANT}
W=/var/cache/dnsdist-build/$DNSDIST_VERSION${VARIANT:+-$VARIANT}
TC=/var/cache/dnsdist-build/toolchain-rust-$RUST_VERSION
mkdir -p "$PFX"/{lib/pkgconfig,include} "$W"; cd "$W"
J=2                                             # production box: leave cores for DNS/nginx
export CFLAGS="-march=native" CXXFLAGS="-march=native" RUSTFLAGS="-C target-cpu=native"

echo "== rust $RUST_VERSION"
RT=rust-$RUST_VERSION-x86_64-unknown-linux-gnu.tar.xz
[ -f $RT ] || curl -sS --fail -o $RT https://downloads.powerdns.com/rust/$RT
echo "$RUST_SHA256_X86_64  $RT" | sha256sum -c -
[ -x "$TC/bin/cargo" ] || { tar -Jxf $RT; ./rust-$RUST_VERSION-x86_64-unknown-linux-gnu/install.sh \
  --prefix="$TC" --components=rustc,rust-std-x86_64-unknown-linux-gnu,cargo >/dev/null; }
export PATH="$TC/bin:$PATH" CARGO_HOME="$TC/cargo-home"

echo "== boost headers (apt-get download + dpkg -x; not installed)"
[ -d "$W/deb/usr/include/boost" ] || { apt-get download libboost1.83-dev >/dev/null; dpkg -x libboost1.83-dev_*.deb "$W/deb"; }
# $PFX/include: meson passes quiche's -I to libdnsdist-common but not to the dnsdist target
export CPATH="$W/deb/usr/include:$PFX/include"

if [ "$VARIANT" = pq ]; then
  echo "== openssl $OPENSSL_VERSION (private, $PFX/lib)"
  OT=openssl-$OPENSSL_VERSION.tar.gz; OU=https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION
  [ -f $OT ] || curl -sSL --fail -O $OU/$OT
  [ -f $OT.asc ] || curl -sSL --fail -O $OU/$OT.asc
  echo "$OPENSSL_SHA256  $OT" | sha256sum -c -
  export GNUPGHOME="$W/gnupg"; mkdir -p -m700 "$GNUPGHOME"
  [ -f openssl-signer.asc ] || curl -sS --fail -o openssl-signer.asc "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$OPENSSL_SIGNER_FPR"
  gpg -q --import openssl-signer.asc
  # VALIDSIG's last field is the primary key's fingerprint: a good signature by any other key stops here
  # (-a: the status stream carries a binary notation, without it grep never matches)
  gpg --status-fd 1 --verify $OT.asc $OT 2>/dev/null | grep -a "^\[GNUPG:\] VALIDSIG .* $OPENSSL_SIGNER_FPR$" >/dev/null
  if [ ! -f "$PFX/lib/pkgconfig/libssl.pc" ]; then
    rm -rf openssl-$OPENSSL_VERSION && tar xzf $OT && cd openssl-$OPENSSL_VERSION
    # openssldir inside the prefix: the system /etc/ssl/openssl.cnf (OpenSSL 3.0) does not apply to this build
    ./Configure linux-x86_64 --prefix="$PFX" --openssldir="$PFX/ssl" --libdir=lib shared no-tests no-docs \
      "-Wl,-rpath,$PFX/lib" $CFLAGS >/dev/null
    make -j$J >/dev/null
    make install_sw >/dev/null
    cd "$W"
  fi
  "$PFX/bin/openssl" version

  echo "== boringssl $BORINGSSL_COMMIT (static, for quiche)"
  BB=$W/boringssl
  [ -d $BB/.git ] || GIT_CONFIG_GLOBAL=/dev/null git clone -q https://boringssl.googlesource.com/boringssl $BB
  git -C $BB -c advice.detachedHead=false checkout -q $BORINGSSL_COMMIT
  [ "$(git -C $BB rev-parse HEAD)" = "$BORINGSSL_COMMIT" ]
  # flags as nginx's BoringSSL for :443 is built (plain Release), plus PIC for the quiche .so; -march=native here
  # trips gcc's -Werror=stringop-overflow in keccak.cc.inc. ninja reports errors on stdout: keep it.
  [ -f $BB/build/libssl.a ] || { env -u CFLAGS -u CXXFLAGS cmake -S $BB -B $BB/build -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_POSITION_INDEPENDENT_CODE=ON >/dev/null
    ninja -C $BB/build -j$J crypto ssl; }
  export BORING_BSSL_PATH=$BB/build BORING_BSSL_INCLUDE_PATH=$BB/include
  export BINDGEN_EXTRA_CLANG_ARGS="-include $HERE/boring-compat.h"   # two removed group IDs, see the header
fi

echo "== quiche $QUICHE_VERSION"
QT=quiche-$QUICHE_VERSION.tar.gz
[ -f $QT ] || curl -sSL --fail -o $QT https://github.com/cloudflare/quiche/archive/$QUICHE_VERSION.tar.gz
echo "$QUICHE_SHA256  $QT" | sha256sum -c -
if [ ! -f "$PFX/lib/libdnsdist-quiche.so" ]; then
  rm -rf quiche-$QUICHE_VERSION && tar xf $QT && cd quiche-$QUICHE_VERSION
  sed -i.bak 's/ffi = \["dep:cdylib-link-lines"\]/ffi = \[\]/' quiche/Cargo.toml
  sed -i.bak 's,cdylib_link_lines::metabuild();,//cdylib_link_lines::metabuild();,' quiche/src/build.rs
  # quiche ships no Cargo.lock: pin the whole crate graph (incl. boring/BoringSSL) to ours
  cp "$HERE/quiche-$QUICHE_VERSION.Cargo.lock" Cargo.lock
  # a global git config may rewrite https to ssh; ignore it for this fetch only
  GIT_CONFIG_GLOBAL=/dev/null CARGO_NET_GIT_FETCH_WITH_CLI=true \
    cargo build --locked -j$J --release --no-default-features --features ffi,boringssl-boring-crate --package quiche
  install -m644 quiche/include/quiche.h "$PFX/include/"
  install -m644 target/release/libquiche.so "$PFX/lib/libdnsdist-quiche.so"
  cd "$W"
fi
cat > "$PFX/lib/pkgconfig/quiche.pc" <<PC
Name: quiche
Description: quiche library
Version: $QUICHE_VERSION
Cflags: -I$PFX/include
Libs: -L$PFX/lib -ldnsdist-quiche
PC

echo "== dnsdist $DNSDIST_VERSION: tarball + signature"
DT=dnsdist-$DNSDIST_VERSION.tar.xz
[ -f $DT ] || curl -sS --fail -O https://downloads.powerdns.com/releases/$DT
[ -f $DT.sig ] || curl -sS --fail -O https://downloads.powerdns.com/releases/$DT.sig
export GNUPGHOME="$W/gnupg"; mkdir -p -m700 "$GNUPGHOME"
[ -f signer.asc ] || curl -sS --fail -o signer.asc "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=0x$DNSDIST_SIGNER_FPR"
gpg -q --import signer.asc
gpg --fingerprint --with-colons "$DNSDIST_SIGNER_FPR" | grep -q "^fpr:::::::::$DNSDIST_SIGNER_FPR:"
gpg --verify $DT.sig $DT                         # set -e: a bad signature stops here
[ -f dnsdist-$DNSDIST_VERSION/build/build.ninja ] || { rm -rf dnsdist-$DNSDIST_VERSION && tar xf $DT; }
cd dnsdist-$DNSDIST_VERSION

echo "== meson + ninja"
export PKG_CONFIG_PATH="$PFX/lib/pkgconfig"
[ -f build/build.ninja ] || meson setup build --prefix="$PFX" --buildtype=release \
  -Dc_args="$CFLAGS" -Dcpp_args="$CXXFLAGS" -Dcpp_link_args="-Wl,-rpath,$PFX/lib" \
  -Dlua=luajit -Dquiche=enabled -Ddns-over-quic=enabled -Ddns-over-http3=enabled \
  -Ddns-over-https=enabled -Ddns-over-tls=enabled -Dnghttp2=enabled -Ddnstap=enabled \
  -Dlmdb=enabled -Dipcipher=enabled \
  -Dtls-libssl=enabled -Dtls-gnutls=disabled -Dsystemd-service=disabled -Dman-pages=false
ninja -C build -j$J
ninja -C build install >/dev/null
# Not activated here: run the parity suite against it first, then dnsdist/activate.sh.
"$PFX/bin/dnsdist" --version
echo BUILD-OK
