# tests/parity

Two scripts that send DNS queries from outside the server and print what comes back. [parity.py](parity.py) runs 19 named checks over every transport and, given two targets, compares the answers field by field. [malformed.py](malformed.py) sends broken packets and shows whether anything replies.

What each check is, which differences were accepted before the switch and why, and the results of the runs, are in [docs/parity.md](../../docs/parity.md). This page only says how to run them.

## Requirements

Python 3 and dnspython. The DoQ, DoH and DoH3 checks need dnspython's optional extras:

    python3 -m venv .venv
    .venv/bin/pip install "dnspython[doh,doq]"

`malformed.py` uses only the standard library.

The suite is written to run from a vantage outside the server, so that the path it tests is the one a client uses.

## parity.py

    python3 parity.py --edge-host HOST --edge-doh URL [options]

| flag | meaning |
|---|---|
| `--edge-host HOST` | address for plain DNS (port 53), DoT (853) and DoQ (853). Required |
| `--edge-doh URL` | DoH URL, for example `https://resolver.example/dns-query`. Required. Its host name is also the TLS server name for DoT and DoQ on every target |
| `--edge-doh-ip ADDR` | connect DoH to this address instead of resolving the URL's host name |
| `--peer-host HOST` | a second instance to compare against. Omit it to check one target |
| `--peer-ports DO53,DOT,DOH` | the peer's ports; default `53,853,443`. DoQ uses the DoT number over UDP |
| `--targets LIST` | one or two of `edge`, `peer` and `closed`, comma-separated; default `edge`. `peer` needs `--peer-host` |
| `--strict` | count the differences listed as accepted in the script as failures too |
| `--only PREFIX` | run only checks whose name starts with `PREFIX` (`xport`, `blocked`, `ddr`) |

Output has one line per check: `PASS`, `ALLOWED`, `DIFF` or `ERROR`, and a last line with the count of failures. The exit code is 1 if that count is not zero. Each query waits at most 4 seconds.

### One target

    python3 parity.py --edge-host 192.0.2.1 --edge-doh https://resolver.example/dns-query

Every case is sent once. A check passes if any DNS answer comes back, whatever its response code, and fails if the query raises an error such as a timeout or refused connection. It shows that every transport and case gets an answer, not that the answers are right.

### Two targets

    python3 parity.py --edge-host 192.0.2.1 --edge-doh https://resolver.example/dns-query \
        --peer-host 192.0.2.10 --targets edge,peer

Each case goes to both, and the normalised answers are compared: response code, flags other than RD, the EDNS buffer size, the answer records (with TTLs for the cases that ask for them) and the record types in the authority section. The first name in `--targets` is printed as `ref`, the last as `test`. The peer's DoH requests go to the `--peer-host` address with the host name of `--edge-doh`, so both are asked for the same server name.

### The negative control

`closed` is a built-in target: the `--edge-host` address on port 5399 for every transport (for DoH, the `--edge-doh-ip` address if that is given), where nothing should be listening. Compared against a live target it must fail on every check:

    python3 parity.py --edge-host 192.0.2.1 --edge-doh https://resolver.example/dns-query \
        --targets edge,closed --strict

Every line should be `DIFF` and the exit code 1. If any check passes, the comparison cannot fail and a clean two-target run means nothing. Allow time for it: every query to the closed port waits for its timeout. Without `--strict` the checks listed as accepted differences print `ALLOWED` even here, so they would not show the failure.

## malformed.py

    python3 malformed.py HOST:PORT [HOST:PORT ...]

For each target it sends four UDP packets and waits 2 seconds for each:

| case | the packet |
|---|---|
| `good-control` | a well-formed query for `example.com A` |
| `truncated-label` | a label that claims 63 bytes and supplies 3 |
| `empty-question` | a valid header that says there are no questions |
| `pointer-loop` | a name that is a compression pointer to itself |

It prints `reply rcode=... len=...` or `NO REPLY (2s)`. The control must answer; otherwise the target is down or unreachable and the other three lines mean nothing. What a reference run printed, and what it shows, is in [docs/parity.md](../../docs/parity.md).
