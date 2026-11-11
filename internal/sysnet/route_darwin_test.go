//go:build darwin

package sysnet

import (
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

// fakeTable is a routing table driven by route(8) arguments, with macOS's behaviour: route exits 0 even when
// the kernel refuses ("File exists", "not in table"), an add for a destination and mask that already have a
// route fails, and a delete removes the route at that destination and mask whatever its gateway.
type fakeTable struct {
	routes map[string]fakeRoute // key: prefix
	cmds   []string
}

type fakeRoute struct {
	gw, iface string
	reject    bool
	owner     string
}

func newFakeTable() *fakeTable {
	return &fakeTable{routes: map[string]fakeRoute{
		"169.254.0.0/16":     {iface: "en0", owner: "macos"},
		"255.255.255.255/32": {iface: "en0", owner: "macos"},
		"192.168.178.0/24":   {iface: "en0", owner: "macos"},
	}}
}

func (t *fakeTable) install(tb testing.TB) {
	old := runCmd
	runCmd = t.run
	tb.Cleanup(func() { runCmd = old })
}

func (t *fakeTable) run(name string, args ...string) (string, error) {
	t.cmds = append(t.cmds, name+" "+strings.Join(args, " "))
	if name != "route" {
		return "", nil // ifconfig, networksetup, ...: nothing to model
	}
	if len(args) >= 3 && args[1] == "get" && args[len(args)-1] == "default" {
		if args[2] == "-inet6" {
			return "   route to: ::\ndestination: default\n       mask: default\n    gateway: fe80::1%en0\n  interface: en0\n", nil
		}
		return "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.178.1\n  interface: en0\n", nil
	}
	cmd := args[1]
	var key, shown string
	switch args[3] {
	case "-net":
		key = netip.MustParsePrefix(args[4]).Masked().String()
		shown = netip.MustParsePrefix(args[4]).Addr().String()
	case "-host":
		a := netip.MustParseAddr(args[4])
		key, shown = netip.PrefixFrom(a, a.BitLen()).String(), args[4]
	}
	kind := "net"
	if args[3] == "-host" {
		kind = "host"
	}
	switch cmd {
	case "add":
		r := fakeRoute{owner: "openwarp"}
		rest := args[5:]
		if rest[0] == "-interface" {
			r.iface, rest = rest[1], rest[2:]
		} else {
			r.gw, r.iface, rest = rest[0], "en0", rest[1:]
		}
		r.reject = len(rest) > 0 && rest[0] == "-reject"
		via := r.gw
		if via == "" {
			via = r.iface
		}
		if _, ok := t.routes[key]; ok {
			return fmt.Sprintf("route: writing to routing socket: File exists\nadd %s %s: gateway %s: File exists\n", kind, shown, via), nil
		}
		t.routes[key] = r
		return fmt.Sprintf("add %s %s: gateway %s\n", kind, shown, via), nil
	case "delete":
		if _, ok := t.routes[key]; !ok {
			return fmt.Sprintf("route: writing to routing socket: not in table\ndelete %s %s: not in table\n", kind, shown), nil
		}
		delete(t.routes, key) // by destination and mask only, like the kernel
		return fmt.Sprintf("delete %s %s\n", kind, shown), nil
	case "get":
		r, ok := t.routes[key]
		if !ok {
			return "route: writing to routing socket: not in table\n", nil
		}
		p := netip.MustParsePrefix(key)
		var b strings.Builder
		fmt.Fprintf(&b, "   route to: %s\ndestination: %s\n", p.Addr(), p.Addr())
		if !p.IsSingleIP() {
			fmt.Fprintf(&b, "       mask: %s\n", maskString(p))
		}
		if r.gw != "" {
			fmt.Fprintf(&b, "    gateway: %s\n", r.gw)
		}
		flags := "UP,DONE,STATIC"
		if r.gw != "" {
			flags = "UP,GATEWAY,DONE,STATIC"
		}
		if r.reject {
			flags += ",REJECT"
		}
		fmt.Fprintf(&b, "  interface: %s\n      flags: <%s>\n", r.iface, flags)
		return b.String(), nil
	}
	return "", fmt.Errorf("fake route: unexpected %v", args)
}

func maskString(p netip.Prefix) string {
	n := p.Addr().BitLen() / 8
	b := make([]byte, n)
	for i := 0; i < p.Bits(); i++ {
		b[i/8] |= 0x80 >> (i % 8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a.String()
}

func tunConfig(t *testing.T, split ...string) TunConfig {
	var ps []netip.Prefix
	for _, s := range split {
		ps = append(ps, netip.MustParsePrefix(s))
	}
	return TunConfig{
		Iface: "utun9", V4: netip.MustParseAddr("172.16.0.2"), Endpoint: netip.MustParseAddr("162.159.198.2"),
		SplitMode: "exclude", Split: ps, Journal: filepath.Join(t.TempDir(), "journal.json"),
	}
}

// The regression: route(8) reported "File exists" with exit status 0, Apply recorded macOS's 169.254/16 and
// 255.255.255.255/32 routes as its own, and Undo deleted them.
func TestUndoKeepsRoutesThatExistedBefore(t *testing.T) {
	ft := newFakeTable()
	ft.install(t)
	a, err := Apply(tunConfig(t, "10.0.0.0/8", "169.254.0.0/16", "192.168.0.0/16", "255.255.255.255/32"))
	if err != nil {
		t.Fatal(err)
	}
	if ft.routes["10.0.0.0/8"].owner != "openwarp" || ft.routes["0.0.0.0/1"].iface != "utun9" {
		t.Fatalf("routes not added: %v", ft.routes)
	}
	for _, r := range a.routes {
		if strings.Contains(strings.Join(r, " "), "169.254.0.0/16") {
			t.Fatalf("an existing route was recorded as OpenWarp's: %v", r)
		}
	}
	a.Undo()
	for _, k := range []string{"169.254.0.0/16", "255.255.255.255/32", "192.168.178.0/24"} {
		if ft.routes[k].owner != "macos" {
			t.Errorf("macOS's route %s was removed (commands: %v)", k, ft.cmds)
		}
	}
	for k, r := range ft.routes {
		if r.owner == "openwarp" {
			t.Errorf("OpenWarp's route %s was left behind", k)
		}
	}
}

// A route OpenWarp added and something else replaced afterwards (here: configd putting the link route back
// after a network change) must not be deleted, neither by Undo nor by Recover after a crash.
func TestUndoLeavesRoutesReplacedByOthers(t *testing.T) {
	for _, viaJournal := range []bool{false, true} {
		ft := newFakeTable()
		ft.install(t)
		cfg := tunConfig(t, "10.0.0.0/8", "172.16.0.0/12")
		a, err := Apply(cfg)
		if err != nil {
			t.Fatal(err)
		}
		ft.routes["10.0.0.0/8"] = fakeRoute{iface: "en1", owner: "other"}
		if viaJournal {
			if err := Recover(cfg.Journal); err != nil {
				t.Fatal(err)
			}
		} else {
			a.Undo()
		}
		if ft.routes["10.0.0.0/8"].owner != "other" {
			t.Errorf("journal=%v: another program's 10.0.0.0/8 route was deleted", viaJournal)
		}
		if _, ok := ft.routes["172.16.0.0/12"]; ok {
			t.Errorf("journal=%v: OpenWarp's 172.16.0.0/12 route was left behind", viaJournal)
		}
	}
}

func TestRouteResult(t *testing.T) {
	cases := map[string]string{
		"add net 10.0.0.0: gateway 192.168.178.1\n":                                                                "",
		"add net 0.0.0.0: gateway utun4\n":                                                                         "",
		"add host 162.159.198.2: gateway 192.168.178.1\n":                                                          "",
		"add net ::: gateway fe80::e208:55ff:fec1:e2ba%en0\n":                                                      "",
		"add net 169.254.0.0: gateway 192.168.178.1: File exists\n":                                                "exists",
		"route: writing to routing socket: File exists\nadd net 169.254.0.0: gateway 192.168.178.1: File exists\n": "exists",
		"add net 8000::: gateway ::1: File exists\n":                                                               "exists",
		"delete net 10.0.0.0: gateway 192.168.178.1: not in table\n":                                               "not in table",
		"route: writing to routing socket: Network is unreachable\n":                                               "Network is unreachable",
	}
	for out, want := range cases {
		err := routeResult(out)
		switch {
		case want == "" && err != nil:
			t.Errorf("%q: unexpected error %v", out, err)
		case want == "exists" && err != errRouteExists:
			t.Errorf("%q: got %v, want errRouteExists", out, err)
		case want != "" && want != "exists" && (err == nil || err.Error() != want):
			t.Errorf("%q: got %v, want %q", out, err, want)
		}
	}
}

func TestParseRouteGet(t *testing.T) {
	// Real outputs (macOS 27).
	lan := "   route to: 192.168.178.0\ndestination: 192.168.178.0\n       mask: 255.255.255.0\n  interface: en0\n      flags: <UP,DONE,CLONING,STATIC>\n"
	e, ok := parseRouteGet(lan, false)
	if !ok || e.prefix != netip.MustParsePrefix("192.168.178.0/24") || e.iface != "en0" || e.gw.IsValid() {
		t.Fatalf("lan = %+v %v", e, ok)
	}
	if _, ok := parseRouteGet("route: writing to routing socket: not in table\n", false); ok {
		t.Fatal("not in table parsed as a route")
	}
	v6 := "   route to: fe80::\ndestination: ::\n       mask: default\n    gateway: fe80::e208:55ff:fec1:e2ba%en0\n  interface: en0\n      flags: <UP,GATEWAY,DONE,PRCLONING,GLOBAL>\n"
	e, ok = parseRouteGet(v6, true)
	if !ok || e.prefix != netip.MustParsePrefix("::/0") || e.gw != netip.MustParseAddr("fe80::e208:55ff:fec1:e2ba") {
		t.Fatalf("v6 default = %+v %v", e, ok)
	}
	rej := "   route to: ::\ndestination: ::\n       mask: 8000::\n    gateway: ::1\n  interface: lo0\n      flags: <UP,GATEWAY,DONE,STATIC,REJECT>\n"
	e, _ = parseRouteGet(rej, true)
	spec, ok := parseRouteArgs([]string{"-n", "delete", "-inet6", "-net", "::/1", "::1", "-reject"})
	if !ok || !spec.owns(e) {
		t.Fatalf("reject route %+v not recognised as %+v", e, spec)
	}
	host := "   route to: 162.159.198.2\ndestination: 162.159.198.2\n    gateway: 192.168.178.1\n  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n"
	e, _ = parseRouteGet(host, false)
	spec, ok = parseRouteArgs([]string{"-n", "delete", "-inet", "-host", "162.159.198.2", "192.168.178.1"})
	if !ok || !spec.owns(e) {
		t.Fatalf("host route %+v not recognised as %+v", e, spec)
	}
	// A longest-match answer for another prefix is not the route OpenWarp added.
	spec, _ = parseRouteArgs([]string{"-n", "delete", "-inet6", "-net", "fd00::/8", "fe80::e208:55ff:fec1:e2ba%en0"})
	if e, _ := parseRouteGet(v6, true); spec.owns(e) {
		t.Fatal("the default route was taken for fd00::/8")
	}
}

func TestRouteToNotInTableExitsZero(t *testing.T) {
	ft := newFakeTable()
	ft.install(t)
	runCmd = func(name string, args ...string) (string, error) {
		return "route: writing to routing socket: not in table\n", nil
	}
	if _, ok, err := RouteTo(netip.MustParseAddr("2606:4700:4700::1111")); ok || err != nil {
		t.Fatalf("RouteTo with no route = ok %v, err %v", ok, err)
	}
}
