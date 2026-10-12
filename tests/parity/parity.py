#!/usr/bin/env python3
"""DNS parity suite: the same cases over every transport, run from a vantage outside the server.
With one target, every case must answer (an error fails it). With two, normalised answers must
also match unless listed in ALLOWED.
Usage: parity.py --edge-host HOST --edge-doh URL [--edge-doh-ip IP] [--peer-host HOST]
                 [--peer-ports DO53,DOT,DOH] [--targets edge|edge,peer|edge,closed] [--strict] [--only PREFIX]"""
import argparse, sys, urllib.parse, dns.message, dns.query, dns.rdatatype, dns.rcode, dns.flags

def make_targets(edge_host, edge_doh, edge_doh_ip=None, peer_host=None, peer_ports=(53, 853, 443)):
    """Target table. DoT/DoQ use the DoH URL's host name as SNI. "closed" is a negative control
    (a port nothing listens on): compared against a live target it must DIFF."""
    u = urllib.parse.urlsplit(edge_doh)
    sni = u.hostname
    def on_port(port):
        return urllib.parse.urlunsplit(u._replace(netloc=f"{sni}:{port}"))
    boot = edge_doh_ip or edge_host
    t = {
        "edge":   {"sni": sni, "do53": (edge_host, 53), "dot": (edge_host, 853), "doq": (edge_host, 853),
                   "doh": (edge_doh, edge_doh_ip)},
        "closed": {"sni": sni, "do53": (edge_host, 5399), "dot": (edge_host, 5399), "doq": (edge_host, 5399),
                   "doh": (on_port(5399), boot)},
    }
    if peer_host:
        do53, dot, doh = peer_ports   # DoQ shares the DoT port number (UDP)
        t["peer"] = {"sni": sni, "do53": (peer_host, do53), "dot": (peer_host, dot), "doq": (peer_host, dot),
                     "doh": (on_port(doh), peer_host)}
    return t

# id, transport, qname, qtype, check_ttl
CASES = [
    ("xport-udp",  "udp",  "example.com", "A", False),
    ("xport-tcp",  "tcp",  "example.com", "A", False),
    ("xport-dot",  "dot",  "example.com", "A", False),
    ("xport-doq",  "doq",  "example.com", "A", False),
    ("xport-doh2", "doh2", "example.com", "A", False),
    ("xport-doh3", "doh3", "example.com", "A", False),
    ("ddr-svcb",   "udp",  "_dns.resolver.arpa", "SVCB", True),
    ("ddr-a",      "udp",  "_dns.resolver.arpa", "A", False),
    ("any",        "udp",  "example.com", "ANY", False),
    ("aaaa",       "udp",  "google.com", "AAAA", False),
    ("aa-cleared", "udp",  "localhost", "A", False),
    ("large-txt",  "udp",  "google.com", "TXT", False),
    ("tc-txt",     "udp",  "microsoft.com", "TXT", False),
    ("blocked-a",          "udp", "doubleclick.net", "A", True),
    ("blocked-https",      "udp", "doubleclick.net", "HTTPS", False),
    ("blocked-sub",        "udp", "x.y.doubleclick.net", "A", True),
    ("blocked-mixed-case", "udp", "DoubleClick.NET.", "A", True),
    ("allow-over-block",   "udp", "api.ads.tvb.com", "A", False),
    ("blocked-parent",     "udp", "ads.tvb.com", "A", True),
]
ALLOWED = {   # id -> reason; only differences this deployment accepts
    "ddr-a": "AGH answers NODATA without SOA; we add SOA so the negative answer is cacheable",
    "any":   "AGH's synthetic answers advertise EDNS 1452; our policy is 1232 everywhere",
    "blocked-https": "AGH omits the SOA on blocked HTTPS NODATA (but sends it for AAAA); we send it consistently",
}

def query(tgt, xport, name, qtype):
    if xport.startswith("doh") and tgt["doh"] is None:
        return "SKIP"
    q = dns.message.make_query(name, qtype, use_edns=0, payload=4096)
    host, port = tgt["do53"]
    try:
        if xport == "udp":  return dns.query.udp(q, host, port=port, timeout=4, ignore_trailing=True)
        if xport == "tcp":  return dns.query.tcp(q, host, port=port, timeout=4)
        if xport == "dot":  return dns.query.tls(q, tgt["dot"][0], port=tgt["dot"][1], timeout=4, server_hostname=tgt["sni"])
        if xport == "doq":  return dns.query.quic(q, tgt["doq"][0], port=tgt["doq"][1], timeout=4, server_hostname=tgt["sni"])
        url, boot = tgt["doh"]
        hv = dns.query.HTTPVersion.H3 if xport == "doh3" else dns.query.HTTPVersion.H2
        return dns.query.https(q, url, timeout=4, http_version=hv, bootstrap_address=boot)
    except Exception as e:
        return f"ERROR {type(e).__name__}"

def norm(r, check_ttl):
    if isinstance(r, str):
        return r
    flags = sorted(f for f in dns.flags.to_text(r.flags).split() if f != "RD")
    ans = sorted(f"{rr.rdtype}:{rd.to_text()}" + (f":ttl{rr.ttl}" if check_ttl else "")
                 for rr in r.answer for rd in rr)
    auth = sorted(dns.rdatatype.to_text(rr.rdtype) for rr in r.authority)
    return (f"rcode={dns.rcode.to_text(r.rcode())} flags={','.join(flags)} "
            f"edns={r.payload} ans={ans} auth={auth}")

def ports(s):
    p = tuple(int(x) for x in s.split(","))
    if len(p) != 3 or not all(0 < x < 65536 for x in p):
        raise argparse.ArgumentTypeError("expected DO53,DOT,DOH, e.g. 53,853,443")
    return p

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--edge-host", required=True, help="address for Do53/DoT/DoQ")
    ap.add_argument("--edge-doh", required=True, help="DoH URL, e.g. https://resolver.example/dns-query")
    ap.add_argument("--edge-doh-ip", default=None, help="connect DoH to this address instead of resolving the URL")
    ap.add_argument("--peer-host", default=None, help="second instance to compare against; omit to check one target")
    ap.add_argument("--peer-ports", default="53,853,443", type=ports, help="peer's Do53,DoT/DoQ,DoH ports")
    ap.add_argument("--targets", default="edge")
    ap.add_argument("--strict", action="store_true", help="compare two instances; ALLOWED differences count as failures")
    ap.add_argument("--only", default="")
    a = ap.parse_args()
    targets = make_targets(a.edge_host, a.edge_doh, a.edge_doh_ip, a.peer_host, a.peer_ports)
    names = a.targets.split(",")
    if len(names) not in (1, 2) or any(n not in targets for n in names):
        ap.error(f"--targets: one or two of {sorted(targets)}")
    ref, test = targets[names[0]], targets[names[-1]]
    bad = 0
    for cid, xport, name, qtype, ttl in CASES:
        if not cid.startswith(a.only):
            continue
        x = norm(query(ref, xport, name, qtype), ttl)
        y = x if len(names) == 1 else norm(query(test, xport, name, qtype), ttl)
        if "SKIP" in (x, y):
            print(f"SKIP    {cid:20} (target has no {xport})")
        elif x.startswith("ERROR") and x == y:
            bad += 1
            print(f"ERROR   {cid:20} {x}")
        elif x == y:
            print(f"PASS    {cid:20} {x}")
        elif cid in ALLOWED and not a.strict:
            print(f"ALLOWED {cid:20} ({ALLOWED[cid]})\n        ref:  {x}\n        test: {y}")
        else:
            bad += 1
            print(f"DIFF    {cid:20}\n        ref:  {x}\n        test: {y}")
    print(f"--- {bad} unallowed difference(s)")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
