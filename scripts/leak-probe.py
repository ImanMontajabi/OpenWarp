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
  leak-probe.py stream IFACE|- HOST PATH LOGFILE
      downloads https://HOST/PATH (certificate verified) bound to IFACE ("-": unbound, so through the
      routing table) at about 256 KB/s with a small receive buffer, and writes "status CODE ADDR", then
      "<unix time> <bytes so far>" about every 0.25 s while data arrives (every second while it stalls),
      then "end REASON". Runs until killed, the end of the body, an error, or 15 minutes.
  leak-probe.py bytes LOGFILE T0 T1           prints the bytes a stream received between T0 and T1, its HTTP
                                               status and how it ended ("-" while running).
  leak-probe.py routes-diff BEFORE AFTER TUNIFACES PREFIX...
      compares two `netstat -rn` snapshots (destination gateway flags interface) and prints each difference
      as "openwarp|other -|+ LINE": "openwarp" when OpenWarp's route commands touch that destination (one
      of the PREFIXes, an edge host route, a route on one of the comma-separated TUNIFACES), "other"
      otherwise. Exit 1 if they differ.
"""
import errno
import ipaddress
import os
import re
import socket
import ssl
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


LAST_REASON = ""  # why the last probe failed: an errno name ("EHOSTUNREACH"), "timeout" or "no answer"


def reason(e):
    """A short name for a probe's OSError: the errno name, or "timeout"."""
    if isinstance(e, socket.timeout) or e.errno is None:
        return "timeout"
    return errno.errorcode.get(e.errno, "errno%d" % e.errno)


def run(iface, spec):
    global LAST_REASON
    kind, *args = spec.split("|")
    LAST_REASON = ""
    try:
        if kind == "tcp":
            ok = probe_tcp(iface, *args)
        elif kind == "dns":
            ok = probe_dns(iface, *args)
        elif kind == "ntp":
            ok = probe_ntp(iface, *args)
        else:
            raise SystemExit("unknown probe " + spec)
    except OSError as e:
        LAST_REASON = reason(e)
        return False
    if not ok:
        LAST_REASON = "no answer"
    return ok


STREAM_RATE = 256 * 1024   # bytes per second
STREAM_RCVBUF = 32 * 1024  # so that almost nothing is buffered when the flow is cut
STREAM_MAX = 900.0


def stream(iface, host, path, log):
    start = time.time()
    with open(log, "w") as f:
        def note(line):
            f.write(line + "\n")
            f.flush()
        try:
            addr = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
            if iface == "-":
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TIMEOUT)
            else:
                s = sock(iface, addr, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, STREAM_RCVBUF)
            s.settimeout(5)
            s.connect((addr, 443))
            t = ssl.create_default_context().wrap_socket(s, server_hostname=host)
            t.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: openwarp-leak-test\r\nConnection: close\r\n\r\n"
                       % (path, host)).encode())
            head = b""
            while b"\r\n\r\n" not in head:
                chunk = t.recv(4096)
                if not chunk:
                    raise EOFError("connection closed before the response headers")
                head += chunk
                if len(head) > 65536:
                    raise ValueError("response headers too long")
            words = head.split(b"\r\n", 1)[0].decode("latin-1").split()
            code = words[1] if len(words) > 1 else "?"
            note("status %s %s" % (code, addr))
            if code != "200":
                note("end http %s" % code)
                return 3
            total = len(head.split(b"\r\n\r\n", 1)[1])
            t.settimeout(1.0)
            last = 0.0
            while time.time() - start < STREAM_MAX:
                try:
                    chunk = t.recv(16384)
                except socket.timeout:
                    chunk = None
                if chunk == b"":
                    note("end eof")
                    return 0
                now = time.time()
                if chunk:
                    total += len(chunk)
                if now - last >= 0.25 or not chunk:
                    note("%.3f %d" % (now, total))
                    last = now
                if chunk:
                    time.sleep(len(chunk) / STREAM_RATE)
            note("end time limit")
            return 0
        except (OSError, EOFError, ValueError) as e:
            note("end error %s: %s" % (type(e).__name__, str(e)[:120]))
            return 1


def stream_bytes(log, t0, t1):
    """Bytes received between t0 and t1, the HTTP status and how the stream ended."""
    status, end, samples = "-", "-", []
    try:
        lines = open(log).readlines()
    except OSError:
        return 0, "-", "not started"
    for line in lines:
        w = line.split()
        if not w:
            continue
        if w[0] == "status":
            status = w[1] if len(w) > 1 else "?"
        elif w[0] == "end":
            end = " ".join(w[1:])
        else:
            samples.append((float(w[0]), int(w[1])))

    def total(t):
        n = 0
        for ts, b in samples:
            if ts <= t:
                n = b
        return n
    return total(t1) - total(t0), status, end


def netstat_prefix(dest, flags):
    """The prefix a `netstat -rn` destination stands for ("10" is 10.0.0.0/8, "172.16/12", "fe80::%lo0/64")."""
    if dest == "default":
        return None
    d, _, bits = dest.partition("/")
    d = d.split("%")[0]
    if ":" in d:
        return ipaddress.ip_network("%s/%s" % (d, bits or 128), strict=False)
    octets = d.split(".")
    n = int(bits) if bits else (32 if "H" in flags else 8 * len(octets))
    return ipaddress.ip_network("%s/%d" % (".".join((octets + ["0", "0", "0"])[:4]), n), strict=False)


EDGES = [ipaddress.ip_network("162.159.0.0/16"), ipaddress.ip_network("2606:4700::/32")]


def routes_diff(before, after, tun, prefixes):
    tuns = set(x for x in tun.split(",") if x)
    managed = set()
    for p in prefixes:
        managed.add(ipaddress.ip_network(p, strict=False))
    old = set(l.strip() for l in open(before) if l.strip())
    new = set(l.strip() for l in open(after) if l.strip())
    out = []
    for sign, lines in (("-", old - new), ("+", new - old)):
        for line in sorted(lines):
            w = line.split()
            kind = "other"
            try:
                net = netstat_prefix(w[0], w[2] if len(w) > 2 else "")
            except ValueError:
                net = None
            if len(w) > 3 and w[3] in tuns:
                kind = "openwarp"
            elif net is not None and net in managed:
                kind = "openwarp"
            elif net is not None and net.num_addresses == 1 and any(net.subnet_of(e) for e in EDGES if e.version == net.version):
                kind = "openwarp"
            out.append("%s %s %s" % (kind, sign, line))
    return out


def pf_delta(before, after):
    """[(packets, rule)] for the rules whose packet counter grew between two `pfctl -vv -s rules` outputs of
    one anchor (rules matched by position and text)."""
    old = {(i, r): pk for i, (r, _, pk) in enumerate(pf_counters(before))}
    out = []
    for i, (r, _, pk) in enumerate(pf_counters(after)):
        was = old.get((i, r))
        if pk is not None and was is not None and pk > was:
            out.append((pk - was, r))
    return out


def pf_counters(text):
    """[(rule, evaluations, packets)] from `pfctl -a ANCHOR -v -s rules` output.

    pfctl prints each rule on a line of its own (with -vv prefixed by "@N "), followed by indented lines such
    as "  [ Evaluations: 12        Packets: 3         Bytes: 180         States: 0     ]".
    """
    out = []
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace():
            out.append([re.sub(r"^@\d+\s+", "", line.strip()), None, None])
            continue
        m = re.search(r"Evaluations:\s*(\d+)\s+Packets:\s*(\d+)", line)
        if m and out:
            out[-1][1], out[-1][2] = int(m.group(1)), int(m.group(2))
    return [tuple(r) for r in out]


def main(argv):
    cmd = argv[1]
    if cmd in ("tcp", "dns", "ntp"):
        t = time.time()
        if run(argv[2], "|".join([cmd] + argv[3:])):
            return 0
        sys.stderr.write("blocked: %s after %.3f s\n" % (LAST_REASON, time.time() - t))
        return 1
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
                    f.write("%.3f %s %s\n" % (t, p, "ok" if ok else "blocked " + LAST_REASON.replace(" ", "-")))
                    f.flush()
                    if not ok:
                        time.sleep(0.05)
        return 0
    if cmd == "stream":
        return stream(argv[2], argv[3], argv[4], argv[5])
    if cmd == "pf-delta":
        # One line per rule whose packet counter grew: "PACKETS RULE".
        for n, rule in pf_delta(open(argv[2]).read(), open(argv[3]).read()):
            print(n, rule)
        return 0
    if cmd == "pf-counters":
        # One line per rule: "EVALUATIONS PACKETS RULE" ("-" when pfctl printed no counters for it).
        for rule, ev, pk in pf_counters(open(argv[2]).read()):
            print("%s %s %s" % ("-" if ev is None else ev, "-" if pk is None else pk, rule))
        return 0
    if cmd == "bytes":
        n, status, end = stream_bytes(argv[2], float(argv[3]), float(argv[4]))
        print(n, status, end)
        return 0
    if cmd == "routes-diff":
        out = routes_diff(argv[2], argv[3], argv[4], argv[5:])
        for line in out:
            print(line)
        return 1 if out else 0
    if cmd == "coverage":
        start, end = float(argv[3]), float(argv[4])
        rows = [l.split() for l in open(argv[2]) if l.strip()]
        times = sorted(float(r[0]) for r in rows)
        leaks = [r for r in rows if r[2] == "ok" and start <= float(r[0]) <= end]
        inside = [t for t in times if start <= t <= end]
        gaps = [b - a for a, b in zip([start] + inside, inside + [end])]
        gap = max(gaps) if gaps else end - start
        why = {}
        for r in rows:
            if r[2] == "blocked" and start <= float(r[0]) <= end:
                k = r[3] if len(r) > 3 else "?"
                why[k] = why.get(k, 0) + 1
        print("%d attempts in %.1f s (%.1f s to %.1f s after the kill), longest gap %.2f s, %d got through%s"
              % (len(inside), end - start, (inside[0] - start) if inside else 0, (inside[-1] - start) if inside else 0,
                 gap, len(leaks),
                 ("; blocked as " + ", ".join("%s %d" % kv for kv in sorted(why.items()))) if why else ""))
        for r in leaks[:5]:
            print("  got through: %s at +%.2f s" % (r[1], float(r[0]) - start))
        return 0 if not leaks and inside and gap <= 1.5 else 1
    raise SystemExit(__doc__)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
