# Decisions

Every upstream release of AdGuard Home, dnsproxy, urlfilter and dnscrypt-proxy meant reading the changes, carrying our patches across, and testing again before the result could serve anyone. Often the honest conclusion of that work was that the release held nothing for us, and it still cost the time. On 2026-09-24 we decided to stop keeping forks. This page records what replaced them, what we considered and turned down, and one setting of ours that turned out to be wrong.

None of this is a criticism of those projects. The cost was ours, because we chose to keep copies.

## Why dnsdist

The model was the one Unbound already followed on this server: software that is configured, not patched, and updated by installing the new release. For the front end, dnsdist fit that model.

- It is a DNS front end and nothing else. It does not resolve, so Unbound stays behind it doing what it already did.
- It speaks every transport this service offers: DoH3, DoH, DoT, DoQ and plain DNS. Here nginx terminates DoH3 and DoH and passes those queries on to it.
- Almost everything the forks had been patched to do turned out to be configuration: answering ANY with NOTIMP, answering the discovery query with ranked records, clearing the authority flag, passing the client address to Unbound. The one behaviour given up, a FORMERR reply to malformed queries, was dropped on purpose. The full list is in [parity.md](parity.md).
- Blocklist lookups are a few Lua modules reading an LMDB file, and the program that builds the file runs beside dnsdist rather than inside it.

Speed was not the reason. The resolver averaged about 18 queries a second over the four days and eleven hours before the [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html) was published on 2026-10-10. Every candidate was close to idle at that load, so we make no speed claim.

nginx already terminated DoH3 and DoH with ECH and X25519MLKEM768 before the switch, so it kept that job, and dnsdist's DoH listener sits behind it without TLS.

## Rejected: Unbound alone

Unbound could have faced clients directly, with no new program. It was turned down on 2026-09-24, mainly over the blocklists: they are written in AdGuard's rule syntax, and Unbound takes blocking data as RPZ or local zones instead. A translator was needed either way. We chose to leave Unbound with the jobs it already did here, caching and validation, and to put the rules of our own in a separate front end. We did not build the Unbound-only version to compare, so this was a judgement, not a measurement.

## Rejected: our own server in Rust

A server of our own would have given full control. It would also have meant owning every line of every transport, DoH3 and DoQ included, and every security fix in them. That is a different maintenance burden, not a smaller one, and avoiding maintenance was the point. Rust is used where it is a tool beside the query path: the blocklist compiler in [compile/](../compile/).

## Dropping dnscrypt-proxy

After the switch, Unbound still sent its upstream queries through a fork of dnscrypt-proxy. The question was whether Unbound could encrypt them itself with DoT. A test on 2026-10-04 compared the two with the live Unbound settings, 500 real names per round, cold caches each round and the setups alternating. Once both sides had the same warm-up, DoT had the lower median in 4 of 7 rounds and the lower 95th percentile in 6 of 7. Seven rounds is fewer than we accept as a finding, so we read it as no regression, not as faster. The tables, the run we discarded and the setting we tried and rejected are in [measurements.md](measurements.md).

What changed for users: a name whose own servers do not answer now fails slowly instead of quickly. dnscrypt-proxy gave up on such names early and answered SERVFAIL. Unbound kept trying for longer than the 3-second client timeout the test used. Names that work are not affected.

Unbound has forwarded over DoT since 18:36 (UTC+3) on 2026-10-04, and dnscrypt-proxy was removed the same day.

## harden-algo-downgrade: no

Unbound runs with `harden-algo-downgrade: no`, the default. It had been set to `yes` by us before the migration: the configuration backed up on 2026-09-28 already has it. The review of Unbound's settings during the move found it on 2026-10-04, when names under `.top` were failing validation.

The reason it was wrong: with `yes`, Unbound expects valid signatures for every algorithm the parent's DS records list, and rejects the zone if one is missing. That day the root zone listed two algorithms for `.top` while the zone was signed with one, and `.top` names were among the most frequent SERVFAIL answers here, while Cloudflare and Quad9 answered them correctly. The algorithm detail is from the [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html), as it stood on 2026-10-04. Unbound's own manual says the option "violates RFC 6840 for DNSSEC validation and should only be used to perform a signature completeness test to support troubleshooting". RFC 6840 tells validators to accept any single valid path.

We set it back to `no` on 2026-10-04, between 17:43 and 18:36 (UTC+3), by the timestamps of the configuration backups taken that afternoon. The base configuration in [unbound-edge](https://github.com/Ozy-666/unbound-edge/blob/main/conf/unbound.conf) carries `no`. On 2026-10-11 the root zone listed only one algorithm for `.top`, so the failure cannot be reproduced against the live zone any more. No guide on it has been published yet. Until one is, this section is the record.
