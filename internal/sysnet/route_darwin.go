//go:build darwin

package sysnet

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// macOS's route(8) exits with status 0 even when the kernel refuses the change: newroute() prints
// "add net 169.254.0.0: gateway 192.168.178.1: File exists" and main() then calls exit(0) (checked in the
// /sbin/route of macOS 27: the exit after newroute is unconditional). The exit status therefore says
// nothing; the output does. A route that was reported as added when it already existed was recorded as
// OpenWarp's, and deleting it later removed macOS's own route (the kernel deletes by destination and mask,
// whatever the gateway): that is how the 169.254 link-local route went missing after a disconnect.

// errRouteExists means a route for that destination and mask was already in the table.
var errRouteExists = errors.New("a route for this destination already exists")

// reRouteSock matches "route: writing to routing socket: File exists" (stderr).
var reRouteSock = regexp.MustCompile(`(?m)^route: writing to routing socket: (.+)$`)

// routeResult reads route(8)'s output for the outcome of an add, delete or change. Its report line is
// "add net DEST[: gateway GW][: ERROR]"; strerror texts contain no ": ".
func routeResult(out string) error {
	msg := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "add ") && !strings.HasPrefix(l, "delete ") && !strings.HasPrefix(l, "change ") {
			continue
		}
		parts := strings.Split(l, ": ")
		parts = parts[1:] // "add net DEST"
		if len(parts) > 0 && strings.HasPrefix(parts[0], "gateway ") {
			parts = parts[1:]
		}
		if len(parts) > 0 {
			msg = strings.Join(parts, ": ")
		}
	}
	if msg == "" {
		if m := reRouteSock.FindStringSubmatch(out); m != nil {
			msg = strings.TrimSpace(m[1])
		}
	}
	switch msg {
	case "":
		return nil
	case "File exists":
		return errRouteExists
	}
	return errors.New(msg)
}

// runRoute runs route(8) and reports failures from its output as well as its exit status.
func runRoute(args ...string) error {
	out, err := run("route", args...)
	if rerr := routeResult(out); rerr != nil {
		if errors.Is(rerr, errRouteExists) {
			return rerr
		}
		return fmt.Errorf("route %s: %w", strings.Join(args, " "), rerr)
	}
	return err
}

// routeSpec is a route OpenWarp added, read back from the arguments that delete it.
type routeSpec struct {
	prefix netip.Prefix
	gw     netip.Addr // the gateway, for gateway routes
	iface  string     // the interface, for `-interface` routes
	reject bool
}

// parseRouteArgs reads the `route -n delete …` arguments Apply records: -inet|-inet6, -net PREFIX|-host ADDR,
// then a gateway, `-interface IFACE`, and optionally `-reject`.
func parseRouteArgs(args []string) (routeSpec, bool) {
	if len(args) < 6 || args[0] != "-n" || args[1] != "delete" || (args[2] != "-inet" && args[2] != "-inet6") {
		return routeSpec{}, false
	}
	var s routeSpec
	switch args[3] {
	case "-net":
		p, err := netip.ParsePrefix(args[4])
		if err != nil {
			return routeSpec{}, false
		}
		s.prefix = p.Masked()
	case "-host":
		a, err := netip.ParseAddr(args[4])
		if err != nil {
			return routeSpec{}, false
		}
		s.prefix = netip.PrefixFrom(a, a.BitLen())
	default:
		return routeSpec{}, false
	}
	rest := args[5:]
	if rest[0] == "-interface" {
		if len(rest) < 2 {
			return routeSpec{}, false
		}
		s.iface, rest = rest[1], rest[2:]
	} else {
		a, err := netip.ParseAddr(rest[0])
		if err != nil {
			return routeSpec{}, false
		}
		s.gw, rest = a.WithZone(""), rest[1:]
	}
	for _, x := range rest {
		if x != "-reject" {
			return routeSpec{}, false
		}
		s.reject = true
	}
	return s, true
}

// routeEntry is what `route -n get` reports for a destination.
type routeEntry struct {
	prefix netip.Prefix
	gw     netip.Addr
	iface  string
	flags  []string
}

var (
	reDest = regexp.MustCompile(`(?m)^\s*destination:\s*(\S+)`)
	reMask = regexp.MustCompile(`(?m)^\s*mask:\s*(\S+)`)
)

// parseRouteGet reads `route -n get` output for an IPv4 or IPv6 (v6) lookup. It returns false when there is no
// route ("not in table") or the output cannot be read.
func parseRouteGet(out string, v6 bool) (routeEntry, bool) {
	if strings.Contains(out, "not in table") {
		return routeEntry{}, false
	}
	d := reDest.FindStringSubmatch(out)
	if d == nil {
		return routeEntry{}, false
	}
	var dest netip.Addr
	switch {
	case d[1] == "default" && v6:
		dest = netip.IPv6Unspecified()
	case d[1] == "default":
		dest = netip.IPv4Unspecified()
	default:
		a, err := netip.ParseAddr(d[1])
		if err != nil || a.Is6() != v6 {
			return routeEntry{}, false
		}
		dest = a.WithZone("")
	}
	var err error
	bits := dest.BitLen() // no mask line: a host route
	if m := reMask.FindStringSubmatch(out); m != nil {
		if bits, err = maskBits(m[1], dest.Is4()); err != nil {
			return routeEntry{}, false
		}
	}
	e := routeEntry{prefix: netip.PrefixFrom(dest, bits).Masked()}
	if g := reGw.FindStringSubmatch(out); g != nil {
		if a, err := netip.ParseAddr(g[1]); err == nil {
			e.gw = a.WithZone("")
		}
	}
	if i := reIf.FindStringSubmatch(out); i != nil {
		e.iface = i[1]
	}
	if f := reFlags.FindStringSubmatch(out); f != nil {
		e.flags = strings.Split(f[1], ",")
	}
	return e, true
}

// maskBits converts route(8)'s mask ("255.255.0.0", "ffff:ffff::", "8000::", "default") to a prefix length.
func maskBits(m string, v4 bool) (int, error) {
	if m == "default" {
		return 0, nil
	}
	a, err := netip.ParseAddr(m)
	if err != nil || a.Is4() != v4 {
		return 0, fmt.Errorf("unexpected mask %q", m)
	}
	bits := 0
	for _, b := range a.AsSlice() {
		for i := 7; i >= 0; i-- {
			if b&(1<<i) == 0 {
				return bits, nil
			}
			bits++
		}
	}
	return bits, nil
}

// owns reports whether the route in the table is the one s describes.
func (s routeSpec) owns(e routeEntry) bool {
	if e.prefix != s.prefix {
		return false
	}
	switch {
	case s.reject:
		for _, f := range e.flags {
			if f == "REJECT" || f == "BLACKHOLE" {
				return true
			}
		}
		return false
	case s.iface != "":
		return e.iface == s.iface
	default:
		return e.gw.IsValid() && e.gw == s.gw
	}
}

// notOurs checks, before Undo deletes a route, that the route at that destination is still the one OpenWarp
// added. The kernel deletes a route by destination and mask, whatever its gateway, so deleting blindly would
// remove a route that something else (configd, another VPN, the user) put there since. It returns why the
// route is left alone, or "" when it may be deleted.
func notOurs(del []string) string {
	s, ok := parseRouteArgs(del)
	if !ok {
		return fmt.Sprintf("%s (unexpected arguments)", strings.Join(del, " "))
	}
	kind := "-net"
	dest := s.prefix.String()
	if s.prefix.IsSingleIP() {
		kind, dest = "-host", s.prefix.Addr().String()
	}
	out, _ := run("route", "-n", "get", del[2], kind, dest)
	e, ok := parseRouteGet(out, del[2] == "-inet6")
	if !ok {
		return dest + " (no longer in the table)"
	}
	if !s.owns(e) {
		via := e.iface
		if e.gw.IsValid() {
			via = e.gw.String() + " on " + e.iface
		}
		return fmt.Sprintf("%s (now %s via %s)", dest, e.prefix, via)
	}
	return ""
}
