//go:build darwin

// Package sysnet configures macOS networking for a utun-based tunnel:
// interface addresses, split-tunnel routes and system DNS. It shells out to
// ifconfig/route/networksetup, the same primitives the official client's
// route log (cfwarp_route_change_log.txt) reflects.
package sysnet

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
)

type Gateway struct {
	Addr  netip.Addr
	Iface string
}

type TunConfig struct {
	Iface     string
	V4, V6    netip.Addr
	MTU       int
	Endpoint  netip.Addr // edge IP; must bypass the tunnel
	SplitMode string     // "exclude" or "include"
	Split     []netip.Prefix
	DNS       []netip.Addr // nil = leave system DNS alone
	// Journal is a file that records the changes so Recover can undo them after a crash ("" = none).
	Journal string
}

// IPv6 handling reported by Applied.IPv6.
const (
	IPv6Tunnel  = "tunnel"  // IPv6 goes through the tunnel
	IPv6Blocked = "blocked" // the tunnel has no IPv6: IPv6 outside the exclusions is rejected, not leaked
	IPv6System  = "system"  // include mode: IPv6 outside the included ranges uses the physical network
)

// run executes a command and returns its combined output. Tests replace runCmd.
func run(name string, args ...string) (string, error) { return runCmd(name, args...) }

var runCmd = func(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return string(out), nil
}

var reGw = regexp.MustCompile(`(?m)^\s*gateway:\s*(\S+)`)
var reIf = regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)`)

// DefaultGateway returns the physical default route for the address family,
// ignoring routes through utun interfaces.
func DefaultGateway(v6 bool) (Gateway, error) {
	args := []string{"-n", "get", "default"}
	if v6 {
		args = []string{"-n", "get", "-inet6", "default"}
	}
	out, err := run("route", args...)
	if err != nil {
		return Gateway{}, err
	}
	g := reGw.FindStringSubmatch(out)
	i := reIf.FindStringSubmatch(out)
	if g == nil || i == nil {
		return Gateway{}, fmt.Errorf("no default route (v6=%v)", v6)
	}
	if strings.HasPrefix(i[1], "utun") {
		return Gateway{}, fmt.Errorf("default route already via %s", i[1])
	}
	addr, err := netip.ParseAddr(strings.Split(g[1], "%")[0])
	if err != nil {
		return Gateway{}, err
	}
	return Gateway{Addr: addr, Iface: i[1]}, nil
}

func gwArg(g Gateway) string {
	if g.Addr.Is6() && g.Addr.IsLinkLocalUnicast() {
		return g.Addr.String() + "%" + g.Iface
	}
	return g.Addr.String()
}

// Applied holds what was changed so it can be undone.
type Applied struct {
	mu      sync.Mutex
	routes  [][]string // "route" args to delete
	kept    []string   // destinations that already had a route, left alone
	dns     map[string][]string
	journal string
	ipv6    string
}

// IPv6 reports how IPv6 is handled (IPv6Tunnel, IPv6Blocked, IPv6System; "" for DNS-only changes).
func (a *Applied) IPv6() string {
	if a == nil {
		return ""
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ipv6
}

func (a *Applied) save() {
	if a.journal == "" {
		return
	}
	a.mu.Lock()
	j := &journal{Routes: a.routes, DNS: a.dns}
	err := writeJournal(a.journal, j)
	a.mu.Unlock()
	if err != nil {
		log.Printf("sysnet: journal: %v", err)
	}
}

func Apply(c TunConfig) (*Applied, error) {
	a := &Applied{dns: map[string][]string{}, journal: c.Journal}
	fail := func(err error) (*Applied, error) { a.Undo(); return nil, err }

	if c.V4.IsValid() {
		if _, err := run("ifconfig", c.Iface, "inet", c.V4.String(), c.V4.String(), "netmask", "255.255.255.255", "up"); err != nil {
			return fail(err)
		}
	}
	v6 := false
	if c.V6.IsValid() {
		if _, err := run("ifconfig", c.Iface, "inet6", c.V6.String(), "prefixlen", "128"); err != nil {
			log.Printf("sysnet: ipv6 address: %v (IPv6 will be blocked instead)", err)
		} else {
			v6 = true
		}
	}
	if c.MTU > 0 {
		run("ifconfig", c.Iface, "mtu", fmt.Sprint(c.MTU))
	}

	gw4, err4 := DefaultGateway(false)
	gw6, err6 := DefaultGateway(true)
	if err4 != nil && err6 != nil {
		return fail(fmt.Errorf("no physical default route: %v", err4))
	}

	// via is a gateway, an interface (iface) or, for reject routes, the loopback address.
	add := func(prefix netip.Prefix, via string, iface bool, extra ...string) {
		fam := "-inet"
		if prefix.Addr().Is6() {
			fam = "-inet6"
		}
		args := []string{"-n", "add", fam, "-net", prefix.String()}
		if prefix.IsSingleIP() {
			args = []string{"-n", "add", fam, "-host", prefix.Addr().String()}
		}
		if iface {
			args = append(args, "-interface", via)
		} else {
			args = append(args, via)
		}
		args = append(args, extra...)
		if err := runRoute(args...); err != nil {
			// A route for this destination already exists (macOS's own link-local, broadcast or LAN route, or
			// another program's): it is not ours, so it is neither recorded nor ever deleted by Undo.
			if errors.Is(err, errRouteExists) {
				a.mu.Lock()
				a.kept = append(a.kept, prefix.String())
				a.mu.Unlock()
			} else {
				log.Printf("sysnet: %v", err)
			}
			return
		}
		del := append([]string{}, args...)
		del[1] = "delete"
		a.mu.Lock()
		a.routes = append(a.routes, del)
		a.mu.Unlock()
	}

	// The tunnel's own UDP flow must not loop back into the tunnel.
	if c.Endpoint.IsValid() {
		if c.Endpoint.Is4() && err4 == nil {
			add(netip.PrefixFrom(c.Endpoint, 32), gwArg(gw4), false)
		} else if c.Endpoint.Is6() && err6 == nil {
			add(netip.PrefixFrom(c.Endpoint, 128), gwArg(gw6), false)
		}
	}

	if c.SplitMode == "include" {
		for _, p := range c.Split {
			add(p, c.Iface, true)
		}
		a.ipv6 = IPv6System
	} else {
		// Two halves beat the existing default route without replacing it.
		add(netip.MustParsePrefix("0.0.0.0/1"), c.Iface, true)
		add(netip.MustParsePrefix("128.0.0.0/1"), c.Iface, true)
		if v6 {
			add(netip.MustParsePrefix("::/1"), c.Iface, true)
			add(netip.MustParsePrefix("8000::/1"), c.Iface, true)
			a.ipv6 = IPv6Tunnel
		} else {
			// No IPv6 in the tunnel: reject IPv6 instead of letting it use the physical network. Apps get
			// an immediate "no route" and fall back to IPv4 (Happy Eyeballs); exclusions below still work.
			add(netip.MustParsePrefix("::/1"), "::1", false, "-reject")
			add(netip.MustParsePrefix("8000::/1"), "::1", false, "-reject")
			a.ipv6 = IPv6Blocked
		}
		for _, p := range c.Split {
			switch {
			case p.Addr().Is4() && err4 == nil:
				add(p, gwArg(gw4), false)
			case p.Addr().Is6() && err6 == nil && !p.Addr().IsLinkLocalUnicast() && !p.Addr().IsMulticast():
				add(p, gwArg(gw6), false)
			}
		}
	}

	if c.DNS != nil {
		if err := a.setDNS(c.DNS); err != nil {
			log.Printf("sysnet: dns: %v", err)
		}
	}
	a.save()
	a.mu.Lock()
	if len(a.kept) > 0 {
		log.Printf("sysnet: added %d routes; %d destinations already had a route, left alone: %s",
			len(a.routes), len(a.kept), strings.Join(a.kept, ", "))
	}
	a.mu.Unlock()
	return a, nil
}

func networkServices() ([]string, error) {
	out, err := run("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var svcs []string
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "An asterisk") || strings.HasPrefix(l, "*") {
			continue
		}
		svcs = append(svcs, l)
	}
	return svcs, nil
}

func (a *Applied) setDNS(servers []netip.Addr) error {
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	args := make([]string, 0, len(servers))
	for _, s := range servers {
		args = append(args, s.String())
	}
	for _, svc := range svcs {
		out, err := run("networksetup", "-getdnsservers", svc)
		if err != nil {
			continue
		}
		var prev []string
		if !strings.Contains(out, "aren't any") {
			prev = strings.Fields(out)
		}
		if _, err := run("networksetup", append([]string{"-setdnsservers", svc}, args...)...); err == nil {
			a.dns[svc] = prev
		}
	}
	run("dscacheutil", "-flushcache")
	run("killall", "-HUP", "mDNSResponder")
	return nil
}

func (a *Applied) Undo() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var skipped []string
	for i := len(a.routes) - 1; i >= 0; i-- {
		if why := notOurs(a.routes[i]); why != "" {
			skipped = append(skipped, why)
			continue
		}
		runRoute(a.routes[i]...)
	}
	if len(skipped) > 0 {
		log.Printf("sysnet: left %d routes alone that are no longer OpenWarp's: %s", len(skipped), strings.Join(skipped, "; "))
	}
	a.routes = nil
	for svc, prev := range a.dns {
		if len(prev) == 0 {
			prev = []string{"Empty"}
		}
		run("networksetup", append([]string{"-setdnsservers", svc}, prev...)...)
	}
	if len(a.dns) > 0 {
		run("dscacheutil", "-flushcache")
		run("killall", "-HUP", "mDNSResponder")
	}
	a.dns = map[string][]string{}
	if a.journal != "" {
		os.Remove(a.journal)
	}
}

// SetSystemDNS points every network service at servers (used by DNS-only
// modes, where there is no tunnel interface).
func SetSystemDNS(servers []netip.Addr, journalPath string) (*Applied, error) {
	a := &Applied{dns: map[string][]string{}, journal: journalPath}
	err := a.setDNS(servers)
	a.save()
	return a, err
}

// Recover undoes the changes recorded in a journal left by a daemon that did not shut down cleanly:
// it deletes the routes it had added and restores each network service's previous DNS servers.
func Recover(journalPath string) error {
	j, err := readJournal(journalPath)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNoJournal
	}
	if err != nil {
		// Unreadable or unexpected: leave it for a person to look at rather than run anything from it.
		return err
	}
	a := &Applied{routes: j.Routes, dns: j.DNS, journal: journalPath}
	if a.dns == nil {
		a.dns = map[string][]string{}
	}
	a.Undo()
	return nil
}

// Route is where the routing table sends a destination.
type Route struct {
	Iface  string
	Reject bool // a reject or blackhole route: the packet is dropped
}

var reFlags = regexp.MustCompile(`(?m)^\s*flags:\s*<([^>]*)>`)

// RouteTo asks the routing table where traffic to dst goes (`route -n get`). ok is false when there is no
// route at all.
func RouteTo(dst netip.Addr) (r Route, ok bool, err error) {
	args := []string{"-n", "get", dst.String()}
	if dst.Is6() {
		args = []string{"-n", "get", "-inet6", dst.String()}
	}
	out, err := run("route", args...)
	// macOS's route exits 0 when the lookup fails; only its output says so.
	if strings.Contains(out, "not in table") || (err != nil && strings.Contains(err.Error(), "not in table")) {
		return Route{}, false, nil
	}
	if err != nil {
		return Route{}, false, err
	}
	if rerr := routeResult(out); rerr != nil {
		return Route{}, false, fmt.Errorf("route %s: %w", strings.Join(args, " "), rerr)
	}
	return parseRoute(out), true, nil
}

func parseRoute(out string) (r Route) {
	if m := reIf.FindStringSubmatch(out); m != nil {
		r.Iface = m[1]
	}
	if m := reFlags.FindStringSubmatch(out); m != nil {
		r.Reject = strings.Contains(m[1], "REJECT") || strings.Contains(m[1], "BLACKHOLE")
	}
	return r
}

// SystemResolvers returns the DNS servers of the system's primary resolver, including loopback ones (the
// local DNS proxy), as `scutil --dns` reports them.
func SystemResolvers() ([]netip.Addr, error) {
	out, err := run("scutil", "--dns")
	if err != nil {
		return nil, err
	}
	return parseResolvers(out), nil
}

func parseResolvers(out string) []netip.Addr {
	block := out
	if i := strings.Index(out, "resolver #2"); i > 0 {
		block = out[:i]
	}
	var res []netip.Addr
	for _, m := range reNS.FindAllStringSubmatch(block, -1) {
		if a, err := netip.ParseAddr(strings.Split(m[1], "%")[0]); err == nil {
			res = append(res, a)
		}
	}
	return res
}

var reNS = regexp.MustCompile(`nameserver\[\d+\]\s*:\s*(\S+)`)

// CurrentResolvers returns the system's current upstream DNS servers (first
// scutil resolver), used for Local Domain Fallback.
func CurrentResolvers() []netip.Addr {
	out, err := run("scutil", "--dns")
	if err != nil {
		return nil
	}
	var res []netip.Addr
	block := out
	if i := strings.Index(out, "resolver #2"); i > 0 {
		block = out[:i]
	}
	for _, m := range reNS.FindAllStringSubmatch(block, -1) {
		if a, err := netip.ParseAddr(strings.Split(m[1], "%")[0]); err == nil && !a.IsLoopback() {
			res = append(res, a)
		}
	}
	return res
}

var reSSID = regexp.MustCompile(`(?m)^\s*SSID\s*:\s*(.+)$`)

// NetworkKind reports whether the primary interface is Wi-Fi or wired, and
// the SSID when available.
func NetworkKind() (kind, ssid string) {
	gw, err := DefaultGateway(false)
	if err != nil {
		if gw, err = DefaultGateway(true); err != nil {
			return "", ""
		}
	}
	ports, _ := run("networksetup", "-listallhardwareports")
	kind = "ethernet"
	sc := bufio.NewScanner(strings.NewReader(ports))
	var port string
	for sc.Scan() {
		l := sc.Text()
		if strings.HasPrefix(l, "Hardware Port:") {
			port = strings.TrimSpace(strings.TrimPrefix(l, "Hardware Port:"))
		}
		if strings.TrimSpace(strings.TrimPrefix(l, "Device:")) == gw.Iface && strings.HasPrefix(l, "Device:") {
			if port == "Wi-Fi" || port == "AirPort" {
				kind = "wifi"
			}
		}
	}
	if kind == "wifi" {
		if out, err := run("ipconfig", "getsummary", gw.Iface); err == nil {
			if m := reSSID.FindStringSubmatch(out); m != nil {
				ssid = strings.TrimSpace(m[1])
				if ssid == "<redacted>" { // needs Location Services permission
					ssid = ""
				}
			}
		}
	}
	return kind, ssid
}
