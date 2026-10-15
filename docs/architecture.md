# Architecture

The old edge did almost everything inside one forked program, so the question "where does this happen" had a single answer that explained nothing. Since 2026-09-27 each job belongs to a program that does one thing, and this page says which program owns which job. Everything below was checked on the server on 2026-10-11 unless another date is given.

## The query path

    client
      -> traffic filtering
      -> nginx     (DoH3, DoH on 443; passes each query to dnsdist)
      -> dnsdist   (Do53, DoT, DoQ; blocklists; answers it makes itself)
      -> Unbound   (cache, DNSSEC validation)
      -> DoT
      -> Cloudflare, Quad9

DoT and DoQ clients and plain-DNS clients reach dnsdist directly. Only DoH3 and DoH go through nginx first.

## Public ports

These are the ports the DNS service answers on. Measured on 2026-10-11 with `ss -ltnup | grep -E ':(53|853|443) '`:

| port | protocol | transport | program |
|---|---|---|---|
| 443 | UDP | DoH3 (DNS over HTTP/3) | nginx |
| 443 | TCP | DoH (DNS over HTTP/2) | nginx |
| 853 | TCP | DoT, RFC 7858 | dnsdist |
| 853 | UDP | DoQ, RFC 9250 | dnsdist |
| 53 | UDP and TCP | plain DNS | dnsdist |

All of them answer on the one service address, 194.180.189.33. The machine's other services, such as the website on the same 443 listeners, are not part of this page.

## nginx: TLS for DoH3 and DoH

nginx terminates DoH3 and DoH (RFC 8484). It is built and documented in [nginx-edge](https://github.com/Ozy-666/nginx-edge), not here, so this page describes only what it does:

- DoH3 runs over QUIC, which uses TLS 1.3. DoH supports TLS 1.2 and 1.3. X25519MLKEM768 is offered first for key exchange; on 2026-10-11 a client asking for it negotiated `TLSv1.3 / TLS_AES_256_GCM_SHA384 / X25519MLKEM768`.
- Encrypted Client Hello with two keys loaded at once, the current one and the previous one, so a client still holding the previous ECH configuration can connect while the keys rotate.
- DoH over HTTP/2 and DoH3 over HTTP/3 on the same `/dns-query` path.
- Each query goes to dnsdist with `grpc_pass`, to a DoH listener on loopback that has no TLS of its own. nginx adds the client's address in a header, and that listener is configured to trust it, so dnsdist sees the real client.

nginx-edge applies two small patches at build time: server-side ECH for BoringSSL builds, and a fix for the QUIC handshake deadlock reported as [nginx/nginx#1616](https://github.com/nginx/nginx/issues/1616). On 2026-10-11 that issue was open, and so was the separate pull request [nginx/nginx#1617](https://github.com/nginx/nginx/pull/1617); it has not been merged.

## dnsdist: every client-facing answer

[dnsdist](https://dnsdist.org) runs as released, built from pinned source. The pins are in [dnsdist/pins.env](../dnsdist/pins.env) and the configuration is in [dnsdist/conf/](../dnsdist/conf/). Its jobs:

- **Listeners.** The loopback DoH listener that nginx feeds with DoH3 and DoH queries, DoT and DoQ on 853, and plain DNS on 53. DoQ runs over QUIC, which uses TLS 1.3; DoT supports TLS 1.2 and 1.3.
- **Answers it makes itself.** ANY queries get NOTIMP. A query for `_dns.resolver.arpa` SVCB gets three ranked records (DoH3 and DoH, then DoQ, then DoT), which is how clients discover the encrypted transports (RFC 9462). AAAA queries get an empty NOERROR answer.
- **Blocklists.** Each name is looked up in an LMDB database built by the compiler in [compile/](../compile/). An A query for a blocked name such as `doubleclick.net` answers `0.0.0.0`; rules that ask for NXDOMAIN get NXDOMAIN. The compiler runs beside the query path, not in it: if it fails, dnsdist keeps answering from the last good database.
- **Clearing the authority flag.** Unbound marks answers it holds locally as authoritative. A response rule clears `aa`, because a public resolver relaying answers is not the authority for them.
- **One backend.** Every transport, plain DNS on port 53 included, is forwarded to Unbound's single listener on loopback, `127.0.0.1:5353`. No client address is passed on, so Unbound sees every query as coming from `127.0.0.1`.

dnsdist has no packet cache. Unbound does the caching.

Abusive traffic is filtered before a query reaches dnsdist, so dnsdist itself has no rate limits, dynamic blocks or drop rules.

## Unbound: cache, validation, upstream

Unbound runs as released. Its build, pins and base configuration live in [unbound-edge](https://github.com/Ozy-666/unbound-edge), and the base configuration is [conf/unbound.conf](https://github.com/Ozy-666/unbound-edge/blob/main/conf/unbound.conf) there. It is linked rather than copied, so the two cannot drift apart.

- **Cache and DNSSEC.** `module-config: "validator iterator"`. A name whose signatures fail validation is answered SERVFAIL with Extended DNS Error 6 (DNSSEC Bogus).
- **Upstream.** A forward zone for `.` with `forward-tls-upstream: yes` sends every cache miss over DoT to Cloudflare and Quad9. The addresses and certificate names are in the base configuration linked above. Because it is a forward zone, the upstreams receive the full query name.

Since 2026-10-04 Unbound talks DoT to its upstreams itself. Before that a fork of dnscrypt-proxy did it. Why it went is in [decisions.md](decisions.md), and the measurements are in [measurements.md](measurements.md).

## Checking it from outside

These run from any machine with `dig`. Output from 2026-10-13 (the `example.com` one from 2026-10-15), trimmed:

    dig @194.180.189.33 _dns.resolver.arpa SVCB +short
    1 dnsdoh.art. alpn="h3,h2" port=443 ipv4hint=194.180.189.33 key7="/dns-query{?dns}"
    2 dnsdoh.art. alpn="doq" port=853 ipv4hint=194.180.189.33
    3 dnsdoh.art. alpn="dot" port=853 ipv4hint=194.180.189.33

    dig @194.180.189.33 example.com +bufsize=4096 +noall +comments
    ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
    ; EDNS: version: 0, flags:; udp: 1232

No `aa` in the flags, and 1232 bytes offered although 4096 was asked for.
