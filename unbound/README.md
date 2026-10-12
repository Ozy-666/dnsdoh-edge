# unbound

The drop-ins that sit on top of the base Unbound configuration. The base file is not here. It lives in [unbound-edge](https://github.com/Ozy-666/unbound-edge/blob/main/conf/unbound.conf), which also builds Unbound, so there is one copy to keep current. What this directory adds is one thing: DNS cookies that are bound to the real client address.

## Why a second listener

A DNS cookie (RFC 7873, "Domain Name System (DNS) Cookies"; server side in RFC 9018, "Interoperable Domain Name System (DNS) Server Cookies") is computed from the client's address and a server secret. A client that sends a valid cookie has shown it can receive replies at the address it claims, as RFC 7873 describes.

On this setup dnsdist receives plain DNS on port 53 and forwards it to Unbound from the same machine. Unbound would see every client as the loopback address, and every cookie it minted would be bound to that address. The queries from dnsdist therefore go to a second Unbound listener that expects a PROXY protocol v2 header, which carries the real client address. dnsdist is configured with `useProxyProtocol = true` for that backend, in `dnsdist/conf/modules/listeners.lua`. Only port 53 traffic (UDP and TCP) takes this path. The other transports use the ordinary backend.

[dnsdoh-cookies.conf](dnsdoh-cookies.conf) defines the listener:

| line | what it does |
|---|---|
| `interface: 127.0.0.1@5354` | binds the extra listener to the loopback address only |
| `proxy-protocol-port: 5354` | every connection on that port must start with a PROXY header |
| `interface-action: 127.0.0.1@5354 allow` | an explicit allow for that interface. Unbound's own manual says interfaces default to refuse |
| `cookie-secret-file: "..."` | the file holding the cookie secrets, one per line |

There is deliberately no fallback in dnsdist to the plain backend: a fallback would silently produce cookies bound to the wrong address.

## Putting it together

1. Copy `dnsdoh-cookies.conf` into Unbound's `unbound.conf.d` directory and add `include: "/etc/unbound/unbound.conf.d/dnsdoh-cookies.conf"` to the main configuration.
2. Install [systemd/unbound-cookies.conf](systemd/unbound-cookies.conf) as a drop-in for `unbound.service`. It runs the guard (below) before every start. The leading `-` on the command means a failing guard never stops Unbound from starting.
3. Install `cookie-guard.sh`, `cookie-rotate.sh` and the rotation service and timer, and copy [cookie-rotate.conf](cookie-rotate.conf) to `/etc/dnsdoh.art/cookie-rotate.conf`. Without that file the script exits 1 with "cannot read config". The unit files call them as `/usr/local/sbin/dnsdoh.art-cookie-guard` and `/usr/local/sbin/dnsdoh.art-cookie-rotate`, and the rotation script reads `/etc/dnsdoh.art/cookie-rotate.conf` unless `COOKIE_ROTATE_CONF` names another file.
4. Do not write the secret file by hand. Start Unbound once: the guard creates an empty secret file, Unbound starts without cookies, and the first rotation run adds the first secret. That first run, on a fresh install with no secret yet, always exits 1, so the rotation unit shows as failed once; this is expected. A line you write yourself has no rotation state behind it, so the first run starts a rotation at once and your line is dropped at a later run.
5. Run `systemctl daemon-reload` and then **restart** Unbound. The listener is new, so restart rather than reload.
6. Run `systemctl enable --now dnsdoh.art-cookie-rotate.timer`. The timer is what starts the rotation; nothing else does. Until the config and a secret exist, the first run fails as described in step 4.

## The secret file and the guard

Unbound refuses to start when `cookie-secret-file` is missing or malformed, but starts normally with an empty file, minting no cookies. [cookie-guard.sh](cookie-guard.sh) turns the first case into the second. A file is valid if it is a regular file (not a symlink), has at most two lines, and each line is exactly 32 hex digits. A valid file is left alone. Anything else is moved aside as `<file>.bad.<timestamp>` with mode 0600 and replaced by an empty file owned by the Unbound user, and the guard prints a line saying cookies are off until rotation adds a secret. It never prints the file's contents. It does not follow symlinks when changing modes or ownership, since the directory is writable by Unbound.

Two lines are two secrets. `unbound-control print_cookie_secrets` lists them as `active` and `staging`, and activating swaps the two, which is why rotation below checks the result after every step.

## Rotation

[cookie-rotate.sh](cookie-rotate.sh) runs daily at 04:17 server time from [dnsdoh.art-cookie-rotate.timer](systemd/dnsdoh.art-cookie-rotate.timer); the [service](systemd/dnsdoh.art-cookie-rotate.service) needs Unbound to be running. It decides everything from Unbound's own memory (`unbound-control print_cookie_secrets`) and a small state file, so running it again before anything is due does nothing. A run that finds two secrets and at least `drop_after_s` seconds since the switch does drop the old one. Its configuration is [cookie-rotate.conf](cookie-rotate.conf), read as shell variables. An unknown key is an error, so a misspelled setting cannot quietly switch something off.

| key | default | meaning |
|---|---|---|
| `secret_file` | the path in `dnsdoh-cookies.conf` | where Unbound reads its secrets |
| `state_file` | in a root-only directory the unit creates | phase and time of the last step. The directory must be root-owned and not writable by group or others, or the script refuses to run |
| `file_owner` | `unbound:unbound` | owner of the rewritten secret file |
| `unbound_control` | path to `unbound-control` | the control program |
| `period_days` | 30 | age at which a secret is replaced |
| `drop_after_s` | 7200 | the minimum time the old secret stays accepted after the switch. It is removed at the first run after that, which with the daily timer is the next day, about 24 hours later |
| `hook_timeout_s` | 30 | time allowed for the hook |
| `post_rotate_hook` | empty | optional program, see below |

One rotation has three steps, each verified against Unbound's memory afterwards because `unbound-control` can exit 0 on an error reply:

1. **Stage.** Generate a new random secret and add it. Unbound now holds two.
2. **Activate.** Make the new one the active secret. The old one stays in Unbound until step 3.
3. **Drop.** At the first run after `drop_after_s` has passed, remove the old one.

The state file keeps a short fingerprint (a truncated SHA-256, never the secret) of the secret that should be active after step 2, so a crash between activating and recording it cannot lead to activating again, which would swap back. The secret file is rewritten from Unbound's memory whenever the two differ, by building it in the state directory and renaming it into place. `--force` starts a rotation now, unless two secrets are already present. The script exits non-zero whenever something needs attention, which shows in `systemctl --failed`.

### The hook

With `post_rotate_hook=` empty, which is the default, nothing else happens. If it names an executable, the script runs it as `hook add` after a new secret is in the secret file and before it becomes active, and as `hook drop` after the old one is removed. `hook add` also runs when the script finds no secret in Unbound and adds the first one, and when an earlier run synced the file but did not finish the hook. Use it when another service must learn the secrets as well, for example a second resolver that should accept the same cookies. A failing or timed-out `add` hook stops the activation, and the script tries again on its next run. A failing `drop` hook is only logged.
