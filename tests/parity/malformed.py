#!/usr/bin/env python3
"""Send hand-built bad DNS packets over UDP; print the reply rcode or NO REPLY.
Usage: malformed.py HOST:PORT [HOST:PORT ...]"""
import socket, struct, sys
HDR = lambda qd: struct.pack(">HHHHHH", 0x1234, 0x0100, qd, 0, 0, 0)
CASES = {
    "good-control":    HDR(1) + b"\x07example\x03com\x00" + struct.pack(">HH", 1, 1),
    "truncated-label": HDR(1) + b"\x3fabc",
    "empty-question":  HDR(0),
    "pointer-loop":    HDR(1) + b"\xc0\x0c" + struct.pack(">HH", 1, 1),
}
RC = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
for target in sys.argv[1:]:
    host, port = target.rsplit(":", 1)
    for name, pkt in CASES.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
        s.sendto(pkt, (host, int(port)))
        try:
            r = s.recv(4096)
            print(f"{target:22} {name:16} reply rcode={RC.get(r[3] & 0x0f, r[3] & 0x0f)} len={len(r)}")
        except socket.timeout:
            print(f"{target:22} {name:16} NO REPLY (2s)")
