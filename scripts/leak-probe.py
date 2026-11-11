#!/usr/bin/env python3
"""Network probes for scripts/leak-test.sh. Each probe sends traffic bound to one interface (IP_BOUND_IF /
IPV6_BOUND_IF, the macOS socket options behind `curl --interface`), so it goes around the routing table
exactly like an app that binds to the physical network. Exit status 0 means an answer came back.

  leak-probe.py tcp   IFACE ADDR PORT          TCP handshake completes
  leak-probe.py dns   IFACE ADDR udp|tcp       DNS query for example.com is answered
  leak-probe.py ntp   IFACE ADDR               NTP (UDP 123) request is answered
  leak-probe.py resolve NAME                   prints one IPv4 and one IPv6 address (or "-")
  leak-probe.py watch IFACE STOPFILE LOGFILE PROBE...
      runs the probes ("tcp|ADDR|PORT", "dns|ADDR|udp", "ntp|ADDR") in a loop until STOPFILE exists and
      writes "<unix time> <probe> ok|blocked" per attempt to LOGFILE.
  leak-probe.py coverage LOGFILE START END     checks that the attempts cover START..END with no gap over
                                               1.5 s; prints a summary; exit 1 if any attempt got through
                                               or the coverage is incomplete.
"""
import os
import socket
import struct
import sys
import time

IP_BOUND_IF = 25      # <netinet/in.h>
IPV6_BOUND_IF = 125   # <netinet6/in6.h>
TIMEOUT = 2.5        # single probes; the outage watcher uses WATCH_TIMEOUT
WATCH_TIMEOUT = 0.7  # an answer from Cloudflare or the router takes well under 0.1 s


def sock(iface, addr, kind):
    fam = socket.AF_INET6 if ":" in addr else socket.AF_INET
    s = socket.socket(fam, kind)
    s.settimeout(TIMEOUT)
    idx = socket.if_nametoindex(iface)
    if fam == socket.AF_INET:
        s.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, idx)
    else:
        s.setsockopt(socket.IPPROTO_IPV6, IPV6_BOUND_IF, idx)
    return s


def dns_query():
    qname = b"".join(bytes([len(p)]) + p for p in b"example.com".split(b".")) + b"\0"
    return struct.pack(">HHHHHH", 0x4f57, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 1, 1)


def probe_tcp(iface, addr, port):
    s = sock(iface, addr, socket.SOCK_STREAM)
    try:
        s.connect((addr, int(port)))
        return True
    finally:
        s.close()


def probe_dns(iface, addr, proto):
    q = dns_query()
    if proto == "udp":
        s = sock(iface, addr, socket.SOCK_DGRAM)
        try:
            s.sendto(q, (addr, 53))
            data, _ = s.recvfrom(4096)
        finally:
            s.close()
    else:
        s = sock(iface, addr, socket.SOCK_STREAM)
        try:
            s.connect((addr, 53))
            s.sendall(struct.pack(">H", len(q)) + q)
            data = s.recv(4096)[2:]
        finally:
            s.close()
    return len(data) >= 12 and data[:2] == q[:2]


def probe_ntp(iface, addr):
    s = sock(iface, addr, socket.SOCK_DGRAM)
    try:
        s.sendto(b"\x23" + b"\0" * 47, (addr, 123))
        data, _ = s.recvfrom(512)
    finally:
        s.close()
    return len(data) >= 48


def run(iface, spec):
    kind, *args = spec.split("|")
    try:
        if kind == "tcp":
            return probe_tcp(iface, *args)
        if kind == "dns":
            return probe_dns(iface, *args)
        if kind == "ntp":
            return probe_ntp(iface, *args)
    except OSError:
        return False
    raise SystemExit("unknown probe " + spec)


def main(argv):
    cmd = argv[1]
    if cmd in ("tcp", "dns", "ntp"):
        return 0 if run(argv[2], "|".join([cmd] + argv[3:])) else 1
    if cmd == "resolve":
        v4 = v6 = "-"
        for fam, var in ((socket.AF_INET, "v4"), (socket.AF_INET6, "v6")):
            try:
                a = socket.getaddrinfo(argv[2], None, fam, socket.SOCK_DGRAM)[0][4][0]
            except OSError:
                continue
            if var == "v4":
                v4 = a
            else:
                v6 = a
        print(v4, v6)
        return 0
    if cmd == "watch":
        global TIMEOUT
        TIMEOUT = WATCH_TIMEOUT
        iface, stop, log, probes = argv[2], argv[3], argv[4], argv[5:]
        with open(log, "w") as f:
            while not os.path.exists(stop):
                for p in probes:
                    t = time.time()
                    ok = run(iface, p)
                    f.write("%.3f %s %s\n" % (t, p, "ok" if ok else "blocked"))
                    f.flush()
                    if not ok:
                        time.sleep(0.05)
        return 0
    if cmd == "coverage":
        start, end = float(argv[3]), float(argv[4])
        rows = [l.split() for l in open(argv[2]) if l.strip()]
        times = sorted(float(r[0]) for r in rows)
        leaks = [r for r in rows if r[2] == "ok" and start <= float(r[0]) <= end]
        inside = [t for t in times if start <= t <= end]
        gaps = [b - a for a, b in zip([start] + inside, inside + [end])]
        gap = max(gaps) if gaps else end - start
        print("%d attempts in %.1f s (%.1f s to %.1f s after the kill), longest gap %.2f s, %d got through"
              % (len(inside), end - start, (inside[0] - start) if inside else 0, (inside[-1] - start) if inside else 0,
                 gap, len(leaks)))
        for r in leaks[:5]:
            print("  got through: %s at +%.2f s" % (r[1], float(r[0]) - start))
        return 0 if not leaks and inside and gap <= 1.5 else 1
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
