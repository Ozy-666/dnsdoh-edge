# Measurements

The first run of the dnscrypt-proxy comparison said Unbound's own DoT was slower, by a median of 20.4 ms against 16.2. That run was biased, and the result reversed once the bias was removed. This page keeps both, because the discarded run is what makes the later ones believable.

Every figure here was recomputed on 2026-10-11 from the raw per-query results or the raw counter snapshots, not copied from earlier notes. The raw data, the test harness and the analysis scripts stay in the private working tree. The commands are given so the method can be read, and repeated on your own data.

Two rules apply to every table. A result from fewer than 8 repetitions is not reported as a finding. And the numbers to trust are the per-round win counts, not the gap between two medians: single-round medians moved between 10.7 and 23.2 ms for the same setup in the same run.

## Does Unbound still need dnscrypt-proxy? (2026-10-04)

### The setups

| setup | Unbound's upstream path |
|---|---|
| A | through the live dnscrypt-proxy, as production ran that day |
| B | Unbound DoT to Cloudflare `1.0.0.1` and Quad9 `9.9.9.10` |
| B11 | as B, with Cloudflare `1.1.1.1`, the address production uses now |
| Bcf | Cloudflare `1.0.0.1` only |
| Btuned | B with `infra-cache-max-rtt: 800` and `outbound-msg-retry: 2` |
| Bg | B11 with `infra-cache-max-rtt: 2000` |

### Method

- Each run used a full test stack on the resolver's own machine: a test dnsdist, then a test Unbound with the live `server:` settings, then the upstream. Only listeners, paths and the forward zone differed from production.
- The same 500 real domain names every round, sent as A queries over UDP with an EDNS buffer of 1232 and a 3-second client timeout. From run 2 on, 50 other names were queried first as a warm-up and not recorded.
- dnsdist and Unbound started with empty caches every round, and the order of the setups rotated each round.
- Round 1 is left out of every summary, because the upstreams' own caches warm up on the sample during it.
- Each round also checked DNSSEC: `cloudflare.com` had to carry `ad` and `dnssec-failed.org` had to return SERVFAIL. All 82 checks across the four runs passed.

The summaries below come from the analysis scripts run over the extracted results, one directory per run:

    python3 -I analyze2.py <run-dir>
    python3 -I rounds.py <run-dir> <baseline-setup> <candidate-setup>
    python3 -I pername.py <run-dir> <baseline-setup> <candidate-setup>

### Run 1, discarded: no warm-up, A against B, 9 rounds

| setup | median of round medians | median p95 | SERVFAIL | timeouts | lower median than A | lower p95 than A |
|---|---|---|---|---|---|---|
| A | 16.2 ms | 80.8 ms | 75 | 4 | - | - |
| B | 20.4 ms | 139.5 ms | 57 | 18 | 1 of 8 | 2 of 8 |

Rounds 2-9, n = 8 rounds of 500 queries per setup.

B looked worse, and the cause was the test, not B. Setup A used the live dnscrypt-proxy, already warm from production traffic. B started cold every round. A first explanation was that B paid for new TLS handshakes all the time. That was never tested directly: run 1 kept no packet capture. The only capture is from run 3, a different setup (B11, 16 queries in flight, with warm-up). It counted new TCP connections to the upstreams' port 853, which are connection attempts, not completed TLS handshakes: 70 inside the cold first round's measured window, 12 to 28 inside each measured 500-query window in rounds 2-8, and another 7 to 13 in the seconds before each window, when the warm-up ran. So in run 3 Unbound reused its upstream connections across queries. It says nothing about how many run 1 opened, and the handshake explanation stays untested. The fix was to give every setup the same warm-up, which is run 2.

### Run 2: warm-up for every setup, 8 rounds

| setup | median of round medians | median p95 | SERVFAIL | timeouts | lower median than A | lower p95 than A |
|---|---|---|---|---|---|---|
| A | 15.9 ms | 106.8 ms | 63 | 2 | - | - |
| B | 15.1 ms | 89.3 ms | 49 | 14 | 4 of 7 | 6 of 7 |
| Bcf | 13.2 ms | 160.3 ms | 56 | 13 | 4 of 7 | 2 of 7 |
| Btuned | 15.6 ms | 96.9 ms | 85 | 1 | 3 of 7 | 4 of 7 |

Rounds 2-8, n = 7 rounds of 500 queries per setup.

- **B against A: no regression.** B had the lower median in 4 of 7 rounds, a coin flip, and the lower 95th percentile in 6 of 7. Seven rounds is below our bar for a finding, so this supports "no worse", not "faster".
- **The failures changed shape.** B had fewer SERVFAIL answers (49 against 63) and more timeouts (14 against 2). All 14 of B's timeouts in rounds 2-8 came from two names whose own servers did not answer, `samr.gov.cn` and `edgecastcdn.net`, 7 each: Unbound kept trying past the 3-second client timeout. Through dnscrypt-proxy the same two names got SERVFAIL in 12 of 14 queries, each within 1.7 s, and timed out twice.
- **One provider, a worse tail in these rounds.** Bcf, Cloudflare alone, had the highest median 95th percentile, 160.3 ms. Against B it had the lower 95th percentile in only 1 of 7 rounds, and the lower median in 5 of 7. That is an observation from 7 rounds, not a finding. It does not support an earlier guess, that splitting queries onto the slower Quad9 hurt B, but 7 rounds cannot rule that guess out either.
- **Btuned rejected.** Shorter timeouts cut the timeouts from 14 (B) to 1, so the two dead names mostly came back as SERVFAIL instead, and total SERVFAIL rose from 49 to 85. The setup also failed names that work: 12 names answered in all 7 rounds by B returned SERVFAIL in 1 to 5 of 7 rounds under Btuned, among them `connectips.com` (5 of 7), `3.cn` (4 of 7) and `tcylgslb.com` (3 of 7).

### Run 3: 16 queries in flight, A against B11, 8 rounds

| setup | median of round medians | median p95 | median p99 | SERVFAIL | timeouts | lower median than A | lower p95 than A |
|---|---|---|---|---|---|---|---|
| A | 15.1 ms | 65.2 ms | 197.7 ms | 64 | 0 | - | - |
| B11 | 14.8 ms | 67.2 ms | 126.1 ms | 63 | 0 | 5 of 7 | 3 of 7 |

Rounds 2-8, n = 7 rounds of 500 queries per setup.

Under concurrency the two were level: B11 had the lower median in 5 of 7 rounds, A the lower 95th percentile in 4 of 7. Neither timed out. The dead-name gap from run 2 did not appear: in this run both setups answered those two names with SERVFAIL. Whether a dead name times out depends on the upstreams' state at the time, so the slow-failure cost is real but not constant.

### Run 4, rejected: a gentler cap, B11 against Bg, 8 rounds

The question was whether a cap between the default and Btuned's would give dead names a fast SERVFAIL without failing working names. Bg differs from B11 in that one line.

| rounds | setup | SERVFAIL | timeouts | median of all queries |
|---|---|---|---|---|
| 2-8 | B11 | 56 | 8 | 18.0 ms |
| 2-8 | Bg | 165 | 11 | 16.1 ms |
| 2, 3, 5-8 | B11 | 46 | 8 | 17.6 ms |
| 2, 3, 5-8 | Bg | 47 | 9 | 17.1 ms |

Bg failed badly in two rounds. In rounds 1 and 4, right after `samr.gov.cn` timed out as the 388th of 500 queries, every one of the remaining 112 queries got SERVFAIL, each within 1.2 ms. B11 never did this. The reading that fits is that the cap marked both forwarders unsuitable for all names, because a forward zone for `.` sends every name to the same two; that is inferred from Unbound's source and the timing, not observed directly, since the test instance's cache state was not dumped. Outside those two rounds Bg gained nothing: `samr.gov.cn` still timed out in 5 of 6 rounds. Production leaves both settings at Unbound's defaults.

### What the test does not show

- One vantage point, the resolver's own machine. It measures the upstream path, not what clients see.
- Setup A shared the live dnscrypt-proxy with production traffic; B had its upstream connections to itself.
- It compared dnscrypt-proxy as configured against Unbound's own DoT. It says nothing for or against the patches in our dnscrypt-proxy fork.

## Eight hourly windows after the switch (2026-10-05)

After Unbound began forwarding over DoT at 18:36 (UTC+3) on 2026-10-04, its own counters were snapshotted every hour on 2026-10-05 with `unbound-control stats_noreset`, and the per-hour deltas computed with `python3 -I deltas.py <snapshot-dir>`. Unbound had last restarted at 21:44:56 (UTC+3) on 2026-10-04, read from the first snapshot's `time.now` minus `time.up`.

| window (UTC+3) | queries | cache misses | SERVFAIL | SERVFAIL share | median recursion time |
|---|---|---|---|---|---|
| 10:12-11:12 | 62,615 | 16,188 | 317 | 0.506% | 10.46 ms |
| 11:12-12:12 | 67,755 | 16,133 | 226 | 0.334% | 13.63 ms |
| 12:12-13:12 | 74,012 | 18,277 | 287 | 0.388% | 11.32 ms |
| 13:12-14:12 | 73,563 | 18,535 | 335 | 0.455% | 11.85 ms |
| 14:12-15:12 | 85,009 | 20,678 | 240 | 0.282% | 10.75 ms |
| 15:12-16:12 | 81,630 | 20,491 | 444 | 0.544% | 10.10 ms |
| 16:12-17:12 | 79,608 | 19,179 | 393 | 0.494% | 13.55 ms |
| 17:12-18:12 | 85,771 | 22,110 | 325 | 0.379% | 13.08 ms |

n = 8 windows. Median SERVFAIL share 0.42%, median of the eight recursion medians 11.6 ms. The recursion median is Unbound's own figure for cache misses, interpolated from its histogram.

The comparison point is the last stretch on dnscrypt-proxy, on 2026-10-04 before the switch to DoT. It is one window, n = 1, and its raw counters were not kept, so its figures are not repeated here; they are in the [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html). Against it:

- **Latency: no claim.** One baseline window cannot show a change in either direction.
- **SERVFAIL: lower in all 8 windows.** The cause is not proven. The baseline came from a different day, a different cache state and different traffic, and any of those could account for it.
