# History

The files in this repository are exported from a private working tree, so a file's commit date here says when it was exported, not when it last changed in production. This page gives the dates that matter: when each part of the edge changed, where the code of the previous edge went, and, at the end, one line per export. Times are UTC+3.

## Timeline

| date | what happened |
|---|---|
| 2026-09-24 | Decision to stop keeping forks of AdGuard Home, dnsproxy, urlfilter and dnscrypt-proxy. The private working tree behind this repository was started that evening. |
| 2026-09-25 | dnsdist built from pinned source. It began running beside the old edge on other ports, reading the same blocklist database, for the parity checks in [parity.md](parity.md). |
| 2026-09-27 | The switch, in three steps between 19:40 and 19:42: forward, rollback drill, forward. dnsdist has been the front end since 19:42. Details in [cutover.md](cutover.md). |
| 2026-09-28 | Plain-DNS traffic on port 53 began reaching Unbound with a PROXY protocol header, so DNS cookies are computed for each client's real address. |
| 2026-10-04 | The dnscrypt-proxy comparison ([measurements.md](measurements.md)). `harden-algo-downgrade` set back to `no` ([decisions.md](decisions.md)). From 18:36 Unbound forwards to Cloudflare and Quad9 over DoT itself. dnscrypt-proxy and the AdGuard Home fork were uninstalled the same day. |
| 2026-10-05 | The public repositories of the old edge were archived on GitHub (below). Eight hourly windows of Unbound's counters were taken to compare against the last stretch on dnscrypt-proxy. |
| 2026-10-10 | The [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html) was published. |
| 2026-10-11 | The [privacy page](https://dnsdoh.art/privacy.html) was corrected; see [privacy.md](privacy.md). |

## Where the old code lives

Nothing was deleted. The public repositories of the old edge are archived: read-only, and kept online so the commits, benchmarks and notes behind earlier articles can still be linked. Each one carries a notice at the top saying it is no longer maintained.

| archived repository | what it was |
|---|---|
| [Ozy-666/dnsproxy](https://github.com/Ozy-666/dnsproxy) | the transport layer under the old front end, forked from AdguardTeam/dnsproxy |
| [Ozy-666/urlfilter](https://github.com/Ozy-666/urlfilter) | the blocklist rule engine inside the old front end, forked from AdguardTeam/urlfilter |
| [Ozy-666/dnscrypt-proxy](https://github.com/Ozy-666/dnscrypt-proxy) | the upstream hop behind Unbound until 2026-10-04, forked from DNSCrypt/dnscrypt-proxy |
| [Ozy-666/AdGuardHome-edge-spec](https://github.com/Ozy-666/AdGuardHome-edge-spec) | the specification and measurement logs of the old edge: every change the AdGuard Home fork carried, and what each one measured |

The AdGuard Home fork itself, Ozy-666/AdGuardHome-Edge, was always a private repository, so it is named here but not linked.

Two repositories of the current edge stay active beside this one: [unbound-edge](https://github.com/Ozy-666/unbound-edge), the Unbound build, pins and base configuration, and [nginx-edge](https://github.com/Ozy-666/nginx-edge), the nginx that terminates DoH3 and DoH.

## Exports

| date | private commit | files |
|---|---|---|
| 2026-10-12 20:11 | `89a4174` | 62 (50 code, 12 prose) |
