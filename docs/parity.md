# Parity

A replacement front end can answer every test query and still behave differently in ways nobody listed: a flag that used to be cleared, a size limit that used to be lower, an empty answer that used to carry one more record. Before anything moved, every behaviour the forks added was written down and given an answer: rebuilt in configuration, already built in, or knowingly dropped. Then a test suite compared the old edge and the new one field by field, and the switch waited for zero unexplained differences.

## Where each job of the forks went

The first four columns are from the [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html), where they were checked from a second server on 2026-10-10. The last column was re-run on 2026-10-11 from the resolver's own machine against its public address, 194.180.189.33.

| behaviour | before | now | checked from outside, 2026-10-10 | re-run 2026-10-11 |
|---|---|---|---|---|
| UDP answers limited to 1232 bytes, so the resolver is a poor amplifier | fork patch | Unbound settings, passed through by dnsdist | asked for 4096, offered `udp: 1232` | same |
| Authority flag (`aa`) cleared on relayed answers | fork patch | one dnsdist response rule | `flags: qr rd ra ad`, no `aa` | same; `localhost A` also has no `aa` |
| ANY queries refused | fork setting | dnsdist rule | `status: NOTIMP` | same |
| Encrypted-resolver discovery (DDR, RFC 9462): three ranked records with an IPv4 hint | fork patch | dnsdist rule answers the record itself | 3 records: DoH3 and DoH, then DoQ, then DoT | same |
| Blocklists in AdGuard syntax | AdGuard Home and urlfilter forks | compiled into a database dnsdist reads | `doubleclick.net` answers `0.0.0.0` | same |
| AAAA queries answered with no addresses | fork setting | dnsdist rule, carried over unchanged | NOERROR, empty answer | same |
| Truncated UDP answers sent empty | fork patch | built into dnsdist | parity suite, not re-run that day | not re-run |
| DNSSEC-failed names refused | Unbound | Unbound, unchanged | SERVFAIL, `EDE: 6 (DNSSEC Bogus)` | same |
| A malformed query answered with FORMERR | fork patch | dropped: no reply | 13-byte malformed query: no reply in 3 s; well-formed control answered | see below |

The malformed-packet re-run on 2026-10-11 used `tests/parity/malformed.py 194.180.189.33:53`:

    194.180.189.33:53      good-control     reply rcode=NOERROR len=61
    194.180.189.33:53      truncated-label  NO REPLY (2s)
    194.180.189.33:53      empty-question   reply rcode=NOTIMP len=12
    194.180.189.33:53      pointer-loop     NO REPLY (2s)

A packet that cannot be parsed gets no reply. A well-formed header with no question in it is not the same case: it gets a 12-byte NOTIMP. "Malformed queries are dropped" is true for the two broken packets, not for every odd one.

## The 19 checks

`tests/parity/parity.py` sends each case to one or two targets. With two, it compares the normalised answers: response code, flags other than RD, the EDNS buffer size offered, the answer records (with TTLs where the case asks for them), and the types in the authority section.

| check | transport | query |
|---|---|---|
| `xport-udp` | UDP | `example.com A` |
| `xport-tcp` | TCP | `example.com A` |
| `xport-dot` | DoT | `example.com A` |
| `xport-doq` | DoQ | `example.com A` |
| `xport-doh2` | DoH over HTTP/2 | `example.com A` |
| `xport-doh3` | DoH3 | `example.com A` |
| `ddr-svcb` | UDP | `_dns.resolver.arpa SVCB`, TTLs compared |
| `ddr-a` | UDP | `_dns.resolver.arpa A` |
| `any` | UDP | `example.com ANY` |
| `aaaa` | UDP | `google.com AAAA` |
| `aa-cleared` | UDP | `localhost A` |
| `large-txt` | UDP | `google.com TXT` |
| `tc-txt` | UDP | `microsoft.com TXT` |
| `blocked-a` | UDP | `doubleclick.net A`, TTLs compared |
| `blocked-https` | UDP | `doubleclick.net HTTPS` |
| `blocked-sub` | UDP | `x.y.doubleclick.net A`, TTLs compared |
| `blocked-mixed-case` | UDP | `DoubleClick.NET. A`, TTLs compared |
| `allow-over-block` | UDP | `api.ads.tvb.com A` |
| `blocked-parent` | UDP | `ads.tvb.com A`, TTLs compared |

Malformed packets are not among the 19. `tests/parity/malformed.py` sends them separately over UDP and prints the reply code or `NO REPLY`.

## The 3 accepted differences

Three differences remained before the switch, all in the shape of an empty answer. Each was accepted on purpose, and the suite reports them as `ALLOWED` rather than as failures:

- **`ddr-a`.** The old edge answered "no data" for the discovery name's A record without the SOA record that tells a client how long to remember that. dnsdist includes the SOA, so the negative answer can be cached.
- **`blocked-https`.** For a blocked name's HTTPS record, the old edge left out that same SOA, although it sent it for AAAA. dnsdist sends it for both.
- **`any`.** The old edge's refusal of ANY advertised a 1452-byte EDNS buffer while every other answer said 1232. dnsdist says 1232.

The old edge no longer runs, so these differences can no longer be observed. They are recorded here, and in the suite's `ALLOWED` table, as decisions.

## Running the suite

The script needs Python 3 and dnspython, with dnspython's optional `doq` and `doh` extras for the DoQ, DoH and DoH3 checks. No host names are written into it; the targets come from the command line:

| flag | meaning |
|---|---|
| `--edge-host HOST` | address of the reference target for plain DNS (port 53), DoT (853) and DoQ (853) (required) |
| `--edge-doh URL` | DoH URL of the reference target, for example `https://resolver.example/dns-query` (required). Its host name is also the TLS server name used for DoT and DoQ on every target |
| `--edge-doh-ip ADDR` | connect DoH to this address instead of resolving the URL's host name |
| `--peer-host HOST` | a second instance to compare against; omit it to check one target |
| `--peer-ports DO53,DOT,DOH` | the peer's ports, default `53,853,443`. DoQ uses the DoT port number over UDP |
| `--targets LIST` | one or two of `edge`, `closed` and, when `--peer-host` is given, `peer`, comma-separated; the default is `edge` |
| `--strict` | when comparing two targets, count the `ALLOWED` differences as failures too |
| `--only PREFIX` | run only the checks whose name starts with `PREFIX`, for example `blocked` |

The targets the script builds:

- **`edge`**: `--edge-host` on ports 53 and 853, and DoH at the `--edge-doh` URL.
- **`peer`**: `--peer-host` on the `--peer-ports` ports. Its DoH URL is the `--edge-doh` URL with the host name kept and the port replaced by the peer's DoH port, connected to `--peer-host`.
- **`closed`**: a negative control. It is the edge address on port 5399 for every transport (for DoH, the `--edge-doh-ip` address if that is given), a port where nothing should listen. Compared against a live target with `--strict`, every check must come out as `DIFF`.

### One target: does every check answer?

    python3 tests/parity/parity.py --edge-host 194.180.189.33 --edge-doh https://dnsdoh.art/dns-query

With one target each case is sent once. A check passes if the query returns any DNS answer at all, whatever its response code or content; it fails only if the query raises an error, such as a timeout or a refused connection. So this run shows that every transport and case gets an answer. It does not show that the answers are right. For that, compare against a second instance.

### Two targets: do they answer the same?

    python3 tests/parity/parity.py --edge-host 194.180.189.33 --edge-doh https://dnsdoh.art/dns-query --peer-host 192.0.2.1 --targets edge,peer

Here `192.0.2.1` stands for any host running the second instance; add `--peer-ports` if it listens on other ports. Each check prints `PASS` (identical normalised answers), `ALLOWED` (one of the three accepted differences, with both answers), `DIFF` (with both answers) or `ERROR` (both targets failed the same way). The last line counts the failures, and the exit code is non-zero if there are any.

### First, prove it can fail

A suite that cannot fail proves nothing. Before the switch, each run first checked itself against a known-good target and a closed port, so a broken test could not report a pass. The `closed` target does that here:

    python3 tests/parity/parity.py --edge-host 194.180.189.33 --edge-doh https://dnsdoh.art/dns-query --targets edge,closed --strict

Every check should print `DIFF`, and the run should exit non-zero. Without `--strict`, any difference on the three accepted checks is reported as `ALLOWED`, so those three would not show the failure. If it passes, the test is broken, not the resolver.
