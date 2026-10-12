# dnsdoh-edge

The old dnsdoh.art edge was four forks: a patched AdGuard Home, patched copies of two libraries inside it, and a patched dnscrypt-proxy. Every upstream release meant reading the changes, carrying our patches across and testing again before it could serve anyone. What runs instead is dnsdist in front and Unbound behind it, both configured rather than patched. This repository shows that setup. It is an export of a private working tree, not the working tree itself, and the section "What is not here, and why" says what is left out.

The story of the switch, with measurements, is in the [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html). This repository is the code and configuration behind it.

## The query path

Users configure one address, 194.180.189.33, and reach it over any of five transports: DoH3, DoH, DoT, DoQ and plain Do53.

    client
      -> traffic filtering
      -> dnsdist   (Do53, DoT, DoQ; DoH3 and DoH arrive via nginx)
      -> Unbound   (cache, DNSSEC validation)
      -> DoT
      -> Cloudflare 1.1.1.1, Quad9 9.9.9.10

dnsdist answers clients and applies the blocklists. Unbound caches and validates. Unbound reaches its upstreams over DoT. dnsdist has been the front end since 2026-09-27, and Unbound has forwarded over DoT since 2026-10-04.

## What is here

| directory | what it is | for what is not here |
|---|---|---|
| `dnsdist/` | dnsdist build pins, build and install scripts, the Lua configuration and its modules, systemd units | nginx TLS front: [nginx-edge](https://github.com/Ozy-666/nginx-edge) |
| `compile/` | the Rust program that turns AdGuard-syntax blocklists into the database dnsdist reads | - |
| `unbound/` | the drop-ins that sit on top of the base configuration | the base `unbound.conf`: [unbound-edge](https://github.com/Ozy-666/unbound-edge/blob/main/conf/unbound.conf) |
| `tests/` | the parity checks that compare answers from the edge against a reference | - |
| `docs/` | architecture, decisions, measurements, privacy, history | - |

There is no second copy of the base Unbound configuration here. It lives in unbound-edge and is linked, so the two cannot drift apart.

## What is not here, and why

- **Real site files.** They hold the server's addresses and local paths. `dnsdist/conf/site-example.lua` shows the shape with documentation addresses.
- **The private dashboard.** The dashboard only ever sees client addresses encrypted with a key that is generated at each start and held in memory; it never receives a real client address from DNS traffic.
- **Abuse filtering.** It happens in front of dnsdist and is not described here. dnsdist itself has no rate limiting or drop rules, because abusive traffic is filtered before a query reaches it.
- **Migration scripts.** They were one-time tools written against a machine that no longer exists in that form.

## Versions

Versions are written once, in [dnsdist/pins.env](dnsdist/pins.env) and [compile/Cargo.toml](compile/Cargo.toml). Nothing else in this repository repeats them, so an upgrade cannot leave a stale number behind.

## Try it

The dnsdist configuration reads a compiled blocklist database. `dnsdist/conf/modules/tables.lua` refuses to start without one, with a message that says so, instead of running with an empty list. So the order is: build the compiler, compile the database for real, then check the configuration.

Before you start:

- `dnsdist/build.sh` must run as root, because it writes `/opt/dnsdist` and `/var/cache/dnsdist-build`, and it was written for Ubuntu 24.04 (it fetches `libboost1.83-dev` with `apt-get`). It builds dnsdist and also downloads the pinned Rust toolchain into `/var/cache/dnsdist-build/toolchain-rust-$RUST_VERSION`, where `RUST_VERSION` is set in `dnsdist/pins.env`. `compile/cargo.sh` uses that toolchain, so run `build.sh` first, or use your own cargo at the version `RUST_VERSION` names.
- The check uses the dnsdist that `build.sh` installs, the one `dnsdist/activate.sh` points the `current` link at. Run it from that install, or put it on your `PATH`.
- The DoT and DoQ listeners load a certificate and key, so the check needs a pair even though nothing connects. A throwaway self-signed P-256 pair is enough:

        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj /CN=localhost -keyout key.pem -out cert.pem

- The configuration also reads a console key file and passes its first line to `setKey`, which expects a base64 string of 32 random bytes. Any throwaway key will do:

        head -c 32 /dev/urandom | base64 > console.key

Build the compiler:

    cd compile
    ./cargo.sh build --release

Copy `compile.example.toml` and repoint four keys at paths you can write to. The example uses `/var/lib/dnsdoh.art/`, and the compiler writes the LMDB file there, plus a status file, `last-commit.json`, a `lists/` directory of fetched copies and a lock file. `db` and `state_dir` are where output goes. `user_rules` and `rewrites` must be files that exist, because the compiler refuses to run without them; empty files are fine. From the `compile/` directory:

    WORK=$PWD/try
    mkdir -p "$WORK/state"
    touch "$WORK/user-rules.txt" "$WORK/rewrites.conf"
    sed -e "s#^db = .*#db = \"$WORK/state/filter.mdb\"#" \
        -e "s#^state_dir = .*#state_dir = \"$WORK/state\"#" \
        -e "s#^user_rules = .*#user_rules = \"$WORK/user-rules.txt\"#" \
        -e "s#^rewrites = .*#rewrites = \"$WORK/rewrites.conf\"#" \
        compile.example.toml > "$WORK/my-compile.toml"

Then compile:

    ./target/release/dnsdoh-art-compile --config "$WORK/my-compile.toml"

`--dry-run` is an optional first look: it compiles without replacing the database, so it writes none, and the check below would still stop at `tables.lua`. `--offline` skips the fetch and uses what is already cached.

In your copy of `dnsdist/conf/site-example.lua`, set `filter_db` to the `db` path above (`$WORK/state/filter.mdb`), `cert` and `key` to the pair you made, and `console_key_file` to `console.key`. Then check the configuration:

    export DNSDOH_CONF_DIR="$PWD/../dnsdist/conf"
    export DNSDOH_SITE="/path/to/your/site-copy.lua"
    dnsdist --check-config -C "$DNSDOH_CONF_DIR/dnsdist.lua"

`DNSDOH_SITE` is required: `dnsdist.lua` stops with an error if it is unset. The example site file uses addresses from the documentation ranges, so edit them before you listen on anything real.

To compare a running instance against a reference, `tests/parity/parity.py` takes its targets as arguments (`--edge-host`, `--edge-doh`, `--edge-doh-ip`, `--peer-host`, `--targets`). No host names are baked into the script.

## How this repository stays true

Code changes are made in the private working tree first. A script then exports the published files, applies the placeholders, and runs a gate that refuses to write anything if a private address or a withheld term shows up in the result. The export is not a copy of the directory: only listed files go in. Each export is recorded with one dated line in [docs/history.md](docs/history.md), so the age of any file here can be read from it.

Prose here avoids numbers that a re-export could change without anyone noticing. Measurements in `docs/` carry their date and the command that produced them.

## Licence

BSD-2-Clause, see [LICENSE](LICENSE). The blocklists belong to their maintainers. They are fetched when the compiler runs and are not redistributed in this repository.

## Links

- [dnsdoh.art](https://dnsdoh.art), the service
- [Migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html): why the forks went, what the switch cost
- [unbound-edge](https://github.com/Ozy-666/unbound-edge): Unbound build, pins and base configuration
- [nginx-edge](https://github.com/Ozy-666/nginx-edge): the nginx TLS front
- [AdGuardHome-edge-spec](https://github.com/Ozy-666/AdGuardHome-edge-spec) (archived): the specification of the previous edge, kept as history
