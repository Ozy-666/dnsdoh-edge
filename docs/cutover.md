# Cutover

dnsdist and the old edge could not share ports 53 and 853, so the switch had to be: stop one, start the other. A script that does that in about two seconds is easy to time. What clients saw during those seconds is a different number, and it turned out to be larger. This page describes how the switch was prepared, how it ran, and what the gap measurements can and cannot tell you.

All numbers on this page were measured on 2026-09-27 and published on 2026-10-10 in the [migration guide](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html). They are quoted from there, not re-derived. They cannot be measured again, because the old edge no longer exists.

## Side by side

For two days before the switch, dnsdist ran beside the old edge on other ports, reading the same blocklist database. The parity suite in [parity.md](parity.md) asked both the same 19 questions from a second server and compared the answers field by field. The rule was that the switch would happen only at zero unexplained differences. Three differences remained, and each was accepted on purpose; they are described in [parity.md](parity.md#the-3-accepted-differences).

## The three-step switch

On 2026-09-27 the switch ran three times on purpose: forward, back as a rollback drill, and forward again. That way the way back had been tested on the real system before it could be needed.

| step (UTC+3) | script ran | check afterwards |
|---|---|---|
| forward, 19:40:33 | 2.3 s | 19 questions, 0 unexplained differences |
| rollback drill, 19:42:14 | 2.7 s | the old edge's three known differences were back, which proved it was answering |
| forward, final, 19:42:39 | 2.4 s | 0 unexplained differences |

dnsdist has been the front end since that final step.

## The rollback no longer exists

The rollback was tested, and then retired. The old edge was uninstalled on 2026-10-04, so there is no way back to it on this machine. Its code is archived, not lost: the public repositories are listed in [history.md](history.md), and the guide's [table of where the old code lives](https://dnsdoh.art/guides/adguard-home-to-dnsdist-and-unbound.html#old-code) describes each one.

## What clients saw

A script's run time is not what a client sees. A probe on the second server sent a query every 200 milliseconds per transport for 15 minutes, across all three steps, and recorded the longest silence on each:

| transport | longest gap | during | failed queries / sent |
|---|---|---|---|
| plain DNS, UDP | 4.2 s | final forward | 3 / 4,440 |
| plain DNS, TCP | 1.4 s | rollback drill | 14 / 4,051 |
| DNS over TLS | 2.0 s | rollback drill | 15 / 1,801 |
| DNS over HTTPS (h2) | 2.8 s | rollback drill | 11 / 1,879 |
| DNS over QUIC | 5.2 s | final forward | 9 / 800 |

## The limits of those numbers

- **Two gaps are longer than the switch.** UDP was silent for 4.2 seconds and DoQ for 5.2, against a 2.4-second script. We do not know where the extra time went. A client waiting out its own timeout before retrying would explain it, and so would a QUIC client reconnecting. We tested neither.
- **One number per transport.** The probe kept only the longest gap per transport across the whole 15 minutes. The first forward step's gaps are hidden under the larger ones from the later steps.
- **DoH3 was not probed at all.** Nothing in the table says how DoH3 clients fared.
- **One evening, one vantage point.** The probe ran once, from one server. It is a record of that switch, not a general figure for how long a dnsdist cutover takes.

The number to plan around is the one clients saw, up to 5.2 seconds in this run, not the 2.4 seconds the script reported.
