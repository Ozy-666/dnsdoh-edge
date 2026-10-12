#!/usr/bin/env bash
# Pinned toolchain from the dnsdist build (no cargo on PATH). A global git config may rewrite
# https to ssh; neutralised here as in dnsdist/build.sh.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/../dnsdist/pins.env"
TC=/var/cache/dnsdist-build/toolchain-rust-$RUST_VERSION
export PATH="$TC/bin:$PATH" CARGO_HOME="$TC/cargo-home" GIT_CONFIG_GLOBAL=/dev/null
cd "$HERE"
exec cargo "$@"
