# compile

A Rust program that reads AdGuard-syntax blocklists, your own rules and a short rewrites file, and writes one LMDB database. dnsdist reads that database to decide which names to block, allow or rewrite. The compiler never serves a query. It writes the database and, beside it, a status file, a record of the last commit, the last good copy of each list and a lock file (see "Files in the state directory").

The version of the program is in [Cargo.toml](Cargo.toml), which also holds the minimum Rust version. The toolchain that `cargo.sh` actually uses is `RUST_VERSION` in [../dnsdist/pins.env](../dnsdist/pins.env). The configuration keys, with example values and the four public lists the service uses, are in [compile.example.toml](compile.example.toml). Build instructions are in the top-level README ("Try it"); where the built files must be installed for the systemd units is under "Triggers" below.

## Running it

    dnsdoh-art-compile --config my-compile.toml [--dry-run] [--offline] [--accept-list ID]

Without `--config` it reads `/etc/dnsdoh.art/compile.toml`. Cargo builds the program as `dnsdoh-art-compile` (`target/release/dnsdoh-art-compile`); the installed name is different, see "Triggers".

| flag | what it does |
|---|---|
| `--dry-run` | does everything except opening the database. The status file is still written, with `dry_run` set, and any list body fetched during the run is discarded |
| `--offline` | does not fetch. A list must already have a cached copy, otherwise the run is refused |
| `--accept-list ID` | skips the per-list safety valve for that list, for this run only. An id that is not an enabled list in the configuration is refused, so a typo cannot look like success |

Two more subcommands read and write single rows, for tests and debugging: `get` and `put`, each with `--db`, `--table` and one of `--name`, `--text` or `--hex`; `put` also takes `--value`. `patterns` reads rules on standard input and prints how each pattern rule is translated.

A second compile refuses at once while one is running. Each run takes a lock on `compile.lock` in the state directory and holds it until it exits. A lock file left behind by a crashed run is not a lock.

## Configuration

Four keys are required: `db` (the LMDB file), `state_dir` (lists, status and lock), `user_rules` (a file of AdGuard-syntax rules) and `rewrites` (a file of fixed answers). Unknown keys are an error.

Lists come from one of two places, never both: inline `[[list]]` tables, or `lists = "path"` pointing at a file that contains them. Setting both, or neither, is refused. Each list has an `id` (unique), a `name`, a `url` and `enabled` (default true).

| key | default | meaning |
|---|---|---|
| `map_size_mib` | 1024 | size of the LMDB map. An existing database whose map size differs from this is refused rather than resized, because dnsdist may be reading it |
| `max_drop` | 0.25 | the safety valve, below |
| `min_block` | 1000 | refuse any result with fewer block names than this, first run included |
| `fetch_timeout_s` | 60 | seconds allowed for one list download |
| `max_list_bytes` | 64 MiB | largest list body accepted |

## What it fetches

Lists are downloaded with curl, over https only, with a conditional request (ETag and modification time) when a copy already exists. A URL with credentials in it is refused. The host name is resolved once, and every address it returns must be public. A host that resolves to loopback, a private or link-local range, carrier-grade NAT, a documentation or reserved range, or the IPv6 equivalents is refused, and curl is then pinned to the address that was checked. The reason: lists can be added from a user interface, and without this check the compiler could be pointed at internal services.

A failed fetch (timeout, over the size cap, a status other than 200 or 304, a refused host) is not an error when a good copy exists. The run uses the last good copy and records the list as `stale` with the reason. With no good copy it is refused.

A downloaded body is also rejected, and the old copy kept, if it is not valid UTF-8, if it starts with `<html` or `<!doctype` before its first rule, or if a non-comment line contains a control character. The HTML and control-character checks are the ones AdGuard Home applies to a list; the UTF-8 check is the compiler's own.

## What it accepts

One rule per line. Blank lines and comments (`!`, and `#` unless it is a cosmetic marker) are skipped silently.

Accepted:

- `||example.com^` and `||example.com^|`: the name and every subdomain.
- `@@||example.com^`: an allow rule. `@@|example.com^|` allows exactly that name.
- Wildcard and host-anchored patterns made of host-name characters and `*`.
- Regular expressions, but only the kind that pins an IPv4 /24 or /16 (for example `/^88\.208\.22\.[1234]$/`). The compiler expands them into the addresses they match and applies them to answers.
- The modifiers `$important`, `$badfilter`, `$dnsrewrite=NXDOMAIN` (on a plain `||name^` rule only) and `$client=` with IP addresses or CIDR ranges, `~` to exclude, `|` between values. A `$client` rule is accepted only on a plain `||name^` or `||name^|` rule.

`$badfilter` removes the rule it names. Precedence is `@@` with `$important`, then `$important`, then `@@`, then a plain block. An allow rule that a higher-level block covers entirely is dropped and counted as `pruned_allows`.

## What it rejects and counts

Lines it understands but cannot honour are counted by class under `unsupported` in the status file, with up to three examples per class. The run carries on.

- cosmetic rules (`##`, `#@#`, `#$#`, `#?#`, `#%#`), which only matter to a browser
- any other modifier, such as `$denyallow` or `$dnstype`; the class names the modifier
- `@@` combined with `$dnsrewrite`
- `$client` with a client name instead of an address, with an empty or malformed value, or on anything but a plain rule
- patterns that match everything, that contain `^` or `|` in the middle, or that can never match a hostname
- names longer than 253 characters or with a label over 63
- regular expressions that are not a pinned IPv4 /24 or /16
- rules whose answer-side effect cannot be expressed exactly, such as a pattern that could match part of an address

Your own rules file is stricter. A line there that the parser cannot accept (an unknown modifier, a cosmetic rule, a bad `$client` value) refuses the whole run and names the line, because you wrote it on purpose. Classes found only after parsing, such as a regular expression that is not a pinned range, are still counted rather than refused. Rewrites must be `name A IPv4-address`, one per line; any other type, a bad name, a bad address or a duplicate name is a refusal naming the line.

Precedence conflicts the tables cannot express, such as an `$important` block below a plain allow, also refuse the run.

Client addresses from `$client` rules never appear in the status file or on standard error. Examples are cut at the first `$` when anything after it mentions `client`, and the status file holds only a count of client rules.

## The safety valve

Three checks stop a bad list from replacing a good database. A refusal leaves the database untouched.

1. **Per list.** A freshly fetched list is compared with the copy from the last successful commit. If its rule count fell by more than `max_drop` (a quarter by default), the new body is discarded, the old copy is used, and the list is marked `stale: valve ...`. The run continues. `--accept-list ID` overrides this for one list on one run.
2. **Floor.** If the final result has fewer than `min_block` block names the run is refused, even on the first run.
3. **Total.** If the block count fell by more than `max_drop` compared with `last-commit.json`, the run is refused. A `last-commit.json` that exists but cannot be parsed is also a refusal; only a missing file (a first run) skips this check. If the set of enabled lists changed since the last commit, the total check is skipped for that run, because the drop is the intended result of enabling or disabling a list. The floor and the per-list check still apply.

## The swap

Names are not added to the live database. The compiler opens the LMDB file and, in one write transaction, empties every table and writes the new rows. Any error aborts the transaction. A reader that has the database open (dnsdist) sees either the complete old contents or the complete new ones, never a mixture, and never an empty table in between.

Only after that commit does the compiler write `last-commit.json` and promote the fetched list bodies from `N.new` to `N.txt`. If a refusal or `--dry-run` ends the run, the staged bodies are deleted instead, so a rejected download cannot be mistaken for a good copy next time. Failures in this bookkeeping after the commit are reported as a `warning` in the status file and do not change the exit code.

## Files in the state directory

All under `/var/lib/dnsdoh.art` in the example configuration:

| file | content |
|---|---|
| `compile-status.json` | written on every run, committed or not: per-list source (`fresh`, `cached`, `stale`, `disabled`), rule and unsupported counts, table sizes, `committed`, `reason` for a refusal, `warning` |
| `last-commit.json` | block count and enabled list ids of the last commit, the baseline for the total check |
| `lists/` | `N.txt` and `N.etag` per list, the last good copy |
| `compile.lock` | the lock described above |

The database itself is the `db` path from the configuration (`filter.mdb` in the example), and LMDB creates `filter.mdb-lock` next to it. It is not in the state directory unless you put it there, as the example does.

## Triggers

Three systemd units run the compiler as the `dnsdoh-compile` user with a restricted filesystem view that can write only `/var/lib/dnsdoh.art`:

- [dnsdoh.art-compile.timer](systemd/dnsdoh.art-compile.timer) starts it daily, with up to an hour of random delay.
- [dnsdoh.art-compile.path](systemd/dnsdoh.art-compile.path) starts it when `/etc/dnsdoh.art/filter/.recompile` changes.
- [dnsdoh.art-compile.service](systemd/dnsdoh.art-compile.service) runs [recompile.sh](recompile.sh), which calls the compiler and repeats it while the trigger file changes during a run, up to 60 times.

On dnsdoh.art a private rule editor writes that trigger file, a counter, after each edit. That editor is not part of this repository. Without it, start a compile yourself in either of two ways: write a new value into the trigger file (`date +%s > /etc/dnsdoh.art/filter/.recompile`), or run `systemctl start dnsdoh.art-compile.service`. Edits made by hand to the rules file are read on the next run, whichever way it starts. `recompile.sh` reads its paths from the environment variables `TRIGGER`, `COMPILE` and `CONFIG`, so the defaults can be changed without editing it. The defaults are `/etc/dnsdoh.art/filter/.recompile`, `/usr/local/bin/dnsdoh.art-compile` and `/etc/dnsdoh.art/compile.toml`.

### Where the units expect things

The names differ from the build output, and nothing renames them for you. The service runs `ExecStart=/usr/local/lib/dnsdoh.art/recompile.sh`, and that script runs `/usr/local/bin/dnsdoh.art-compile`, with a dot, while cargo builds `dnsdoh-art-compile`, with a hyphen. To install them where the units look, from this directory after `./cargo.sh build --release`:

    install -D -m 0755 target/release/dnsdoh-art-compile /usr/local/bin/dnsdoh.art-compile
    install -D -m 0755 recompile.sh /usr/local/lib/dnsdoh.art/recompile.sh
    install -m 0644 systemd/dnsdoh.art-compile.service systemd/dnsdoh.art-compile.path systemd/dnsdoh.art-compile.timer /etc/systemd/system/
    install -D -m 0644 my-compile.toml /etc/dnsdoh.art/compile.toml
    systemctl daemon-reload

The units also expect a `dnsdoh-compile` user and group (`User=` and `Group=`), a `dnsdist` group (`SupplementaryGroups=`), a writable `/var/lib/dnsdoh.art` (`ReadWritePaths=`), and the `user_rules` and `rewrites` files named in the configuration. Then `systemctl enable --now dnsdoh.art-compile.timer dnsdoh.art-compile.path`.

The compiler creates `filter.mdb` and `filter.mdb-lock` with the group `dnsdoh-compile` (the unit's `Group=`), and `SupplementaryGroups=dnsdist` does not change that. dnsdist runs as the `dnsdist` user and its unit allows it to read `/var/lib/dnsdoh.art` and to write `filter.mdb-lock`, but it cannot do either until the group is right. Without this, dnsdist stops with "filter DB missing ... (refusing to serve unfiltered)" although the file exists. Create the directory before the first compile:

    install -d -o dnsdoh-compile -g dnsdist -m 0710 /var/lib/dnsdoh.art

and after the first compile has written the files:

    cd /var/lib/dnsdoh.art
    chgrp dnsdist filter.mdb filter.mdb-lock
    chmod 0640 filter.mdb
    chmod 0660 filter.mdb-lock

Later compiles write `filter.mdb` in place and never recreate it, so the group stays. If you delete the files, set it again.

If a run starts while another is going, for example one you started by hand, the second refuses at once and the edit waits for the next trigger or the daily timer.
