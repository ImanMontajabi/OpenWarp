#!/usr/bin/env python3
"""Offline tests for the parsing helpers of scripts/leak-probe.py (run by `go test ./cmd/openwarp`).

  python3 -I scripts/leak-probe-test.py
"""
import importlib.machinery
import importlib.util
import ipaddress
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # no __pycache__ in scripts/
HERE = os.path.dirname(os.path.abspath(__file__))
_loader = importlib.machinery.SourceFileLoader("leak_probe", os.path.join(HERE, "leak-probe.py"))
_spec = importlib.util.spec_from_loader("leak_probe", _loader)
probe = importlib.util.module_from_spec(_spec)
_loader.exec_module(probe)

# Real lines in the format leak-test.sh's routes() writes (destination gateway flags interface), macOS 27.
BEFORE = """127 127.0.0.1 UCS lo0
169.254 link#14 UCS en0
192.168.178 link#14 UCS en0
2001:1438:909:40fc::/64 link#14 UC en0
224.0.0/4 link#14 UmCS en0
255.255.255.255/32 link#14 UCS en0
default 192.168.178.1 UGScg en0
"""

SPLIT = ["10.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16", "255.255.255.255/32", "fd00::/8", "0.0.0.0/1",
         "128.0.0.0/1", "::/1", "8000::/1"]


def write(text):
    f = tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt")
    f.write(text)
    f.close()
    return f.name


class RoutesDiff(unittest.TestCase):
    def diff(self, after):
        return probe.routes_diff(write(BEFORE), write(after), "utun4,utun6", SPLIT)

    def test_same_table(self):
        self.assertEqual(self.diff(BEFORE), [])

    def test_the_missing_link_local_route_is_openwarps(self):
        # The 2026-11-11 run: 169.254/16 (a split-tunnel exclusion) was gone after recover and disconnect.
        out = self.diff(BEFORE.replace("169.254 link#14 UCS en0\n", ""))
        self.assertEqual(out, ["openwarp - 169.254 link#14 UCS en0"])

    def test_leftovers_are_openwarps(self):
        out = self.diff(BEFORE + "0/1 utun4 UScg utun4\n10 192.168.178.1 UGSc en0\n"
                        "162.159.198.2 192.168.178.1 UGHS en0\n::/1 ::1 UGRS lo0\n")
        self.assertEqual(sorted(out), sorted([
            "openwarp + 0/1 utun4 UScg utun4",
            "openwarp + 10 192.168.178.1 UGSc en0",
            "openwarp + 162.159.198.2 192.168.178.1 UGHS en0",
            "openwarp + ::/1 ::1 UGRS lo0",
        ]))

    def test_routes_on_any_of_the_test_tunnels_are_openwarps(self):
        # The utun number changes when the daemon restarts; a route left on the second one is OpenWarp's too.
        self.assertEqual(self.diff(BEFORE + "17.1.2.0/24 utun6 USc utun6\n"), ["openwarp + 17.1.2.0/24 utun6 USc utun6"])

    def test_unrelated_changes_are_other(self):
        out = self.diff(BEFORE.replace("2001:1438:909:40fc::/64", "2001:1438:909:40fd::/64"))
        self.assertEqual(sorted(out), ["other + 2001:1438:909:40fd::/64 link#14 UC en0",
                                       "other - 2001:1438:909:40fc::/64 link#14 UC en0"])
        # A host route outside the edge ranges is not OpenWarp's either.
        self.assertEqual(self.diff(BEFORE + "17.1.2.3 192.168.178.1 UGHS en0\n"),
                         ["other + 17.1.2.3 192.168.178.1 UGHS en0"])


class NetstatPrefix(unittest.TestCase):
    def test_abbreviations(self):
        n = probe.netstat_prefix
        self.assertEqual(n("10", "UGSc"), ipaddress.ip_network("10.0.0.0/8"))
        self.assertEqual(n("169.254", "UCS"), ipaddress.ip_network("169.254.0.0/16"))
        self.assertEqual(n("192.168.178", "UCS"), ipaddress.ip_network("192.168.178.0/24"))
        self.assertEqual(n("172.16/12", "UGSc"), ipaddress.ip_network("172.16.0.0/12"))
        self.assertEqual(n("128.0/1", "UScg"), ipaddress.ip_network("128.0.0.0/1"))
        self.assertEqual(n("0/1", "UScg"), ipaddress.ip_network("0.0.0.0/1"))
        self.assertEqual(n("162.159.198.2", "UGHS"), ipaddress.ip_network("162.159.198.2/32"))
        self.assertEqual(n("fe80::%lo0/64", "UcI"), ipaddress.ip_network("fe80::/64"))
        self.assertEqual(n("::/1", "UGRS"), ipaddress.ip_network("::/1"))
        self.assertIsNone(n("default", "UGScg"))


class StreamBytes(unittest.TestCase):
    def test_counts_only_the_window(self):
        log = write("status 200 172.66.0.218\n100.0 1000\n101.0 5000\n102.0 9000\n103.0 9000\n104.0 9000\n")
        self.assertEqual(probe.stream_bytes(log, 100.5, 102.5), (8000, "200", "-"))
        # Stalled after 102: nothing arrived in 102..104.
        self.assertEqual(probe.stream_bytes(log, 102.0, 104.5)[0], 0)
        # Before the first sample nothing had arrived.
        self.assertEqual(probe.stream_bytes(log, 50, 100.0)[0], 1000)

    def test_missing_log(self):
        self.assertEqual(probe.stream_bytes("/nonexistent/hold.log", 0, 1), (0, "-", "not started"))

    def test_failed_start(self):
        log = write("status 403 172.66.0.218\nend http 403\n")
        self.assertEqual(probe.stream_bytes(log, 0, 1e12), (0, "403", "http 403"))


if __name__ == "__main__":
    unittest.main()
