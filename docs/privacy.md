# Privacy

Until 11 October 2026 the service's privacy page said less was kept than actually was. Client addresses were held longer than intended by the defence layers and by system diagnostics, short DNS captures were kept on disk, and off-site backups that held some of those records were not encrypted. The page was corrected that day, with the correction at the top: [https://dnsdoh.art/privacy.html](https://dnsdoh.art/privacy.html#correction).

That page is the canonical statement. This file restates it for readers of this repository, in the same words and numbers, and adds what the code here shows. If the two ever disagree, the page is right and this file is out of date.

## What the code in this repository shows

- **No query logs in dnsdist or Unbound.** Unbound's base configuration sets `log-queries: no`, `log-replies: no`, `log-servfail: no` and `log-local-actions: no`. The dnsdist configuration published here writes no log of queries or responses.
- **Production loads more than is published here.** Production dnsdist loads more modules than are published here; they are not part of this repository. There is also a private dashboard. The dashboard only ever sees client addresses encrypted with a key that is generated at each start and held in memory; it never receives a real client address from DNS traffic.
- **No client address is sent upstream.** Unbound's `module-config` is `"validator iterator"`: the subnet module, which is what would add EDNS Client Subnet (RFC 7871) to upstream queries, is compiled in but not loaded. dnsdist has no ECS option set, so it adds none either. Cloudflare and Quad9 see the name being looked up and this server's address, not yours.
- **The client address does not reach Unbound.** dnsdist forwards every query, on every transport, to Unbound over loopback without passing the client's address on, so Unbound only ever sees `127.0.0.1`.

These were checked on 2026-10-15 against the running configuration: Unbound's in `/etc/unbound/unbound.conf.d/`, whose base file is published as [unbound-edge/conf/unbound.conf](https://github.com/Ozy-666/unbound-edge/blob/main/conf/unbound.conf), and dnsdist's in [dnsdist/conf/](../dnsdist/conf/).

## What is not kept

As published on the privacy page (shortened, see the page for the full text):

> **No query logs.** dnsdist and Unbound, the programs that answer you, log no queries and no replies.
>
> **No accounts, no history, nothing sold.** There is nothing to sign up for. No history of what you look up is built, and nothing is sold or shared for money.

Everything else that is kept is in the retention table below.

## What the defence layers keep

As published on the privacy page, the complete list as of 11 October 2026:

| record | what it contains | kept for |
|---|---|---|
| live block lists | addresses currently blocked | in memory only, never on disk |
| defence system log | full source addresses of traffic the defence acted on | 2 weeks |
| defence decision logs | address, time and reason of each block | at most 30 days |
| reputation store | addresses the defence has acted on, with a score | until the score decays, usually weeks |
| rate-limit observations | network prefix only (the last part of the address is removed) | until the file reaches its size limit |
| short DNS packet captures | source address and query name, taken only for short periods when traffic looks wrong | 7 days |
| blocked-packet log | source and destination addresses and ports, mostly probes of closed ports | about 8 days |
| web server error and crawler logs | address of requests the web server rejected, and of requests that claim to be search-engine crawlers | about 3 days |

Everything in this table is deleted automatically when its period ends.

## Backups

As published on the privacy page: once a week the server's configuration and some of its data are backed up, and six days a week its configuration alone. All scheduled backups are encrypted with age on the server, before anything is uploaded; the only key that can decrypt them is held by the operator, off the server. Logs are not included. The weekly backups are stored with cloud storage providers, and the last four are kept; the daily ones stay on the server, and the last seven are kept. Backups made before 11 October were not encrypted. All of them have been deleted.

## Encryption in transit

As published on the privacy page: DoH3, DoH, DoT and DoQ are encrypted, so your network operator cannot read or change those queries. DoH3 and DoQ run over QUIC, which uses TLS 1.3. DoH and DoT support TLS 1.2 and 1.3. Plain DNS on port 53 is also offered, for devices that support nothing else. It is not encrypted, by the nature of the protocol.
