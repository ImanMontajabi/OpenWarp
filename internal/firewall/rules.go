// Package firewall implements OpenWarp's kill switch: a pf (packet filter) ruleset that blocks every packet
// that does not go through the tunnel interface, except what the tunnel itself needs to come up (the edge's UDP
// ports, the API fallback addresses), DHCP and IPv6 neighbour discovery, and the split-tunnel exclusions the
// user configured.
//
// The rules are loaded into the sub-anchor com.apple/openwarp, which macOS's stock /etc/pf.conf evaluates
// through its `anchor "com.apple/*"` line, so /etc/pf.conf is never edited. pf is enabled with a reference
// (`pfctl -E`, released with `pfctl -X`), so OpenWarp never turns pf off for anything else that uses it.
//
// Rule generation (this file) is plain Go and tested on every platform. Applying the rules needs root and
// macOS; see pf.go.
package firewall

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"
)

// Anchor is the pf anchor that holds OpenWarp's rules.
const Anchor = "com.apple/openwarp"

// Policy is what the kill switch lets through. Everything else is dropped, in both directions, for IPv4
// and IPv6.
type Policy struct {
	// TunnelIface is the tunnel's utun interface. Empty while no tunnel is up: then nothing but the
	// connection attempt itself can leave the machine ("blocking").
	TunnelIface string
	// Edges are the Cloudflare edge addresses and ports the transport may use (UDP; MASQUE is QUIC).
	Edges []netip.AddrPort
	// API are the API's fallback addresses (TCP 443), used when DNS is blocked.
	API []netip.Addr
	// Bypass are the exclude-mode split-tunnel prefixes (by default the private, link-local and multicast
	// ranges). Traffic to and from them may use the physical network.
	Bypass []netip.Prefix
	// BlockBypassDNS drops DNS (53, 853) to the bypass prefixes, so a resolver on the local network (for
	// example the router) cannot be used around the tunnel's DNS. Set it in the modes that manage DNS.
	BlockBypassDNS bool
	// DNSAllowed are resolvers that may still be reached on port 53 despite BlockBypassDNS: the network's
	// own resolvers, which the local DNS proxy uses only for the Local Domain Fallback domains.
	DNSAllowed []netip.Addr
}

var reIface = regexp.MustCompile(`^utun[0-9]{1,4}$`)

// Rules renders the policy as pf rules. The output is deterministic (sorted, de-duplicated), so callers can
// compare it to skip reloading an unchanged ruleset.
func Rules(p Policy) (string, error) {
	if p.TunnelIface != "" && !reIface.MatchString(p.TunnelIface) {
		return "", fmt.Errorf("firewall: unexpected tunnel interface name %q", p.TunnelIface)
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f+"\n", a...) }

	w("# OpenWarp kill switch (generated; do not edit). Remove with: sudo pfctl -a %s -F all", Anchor)
	bypass := uniqPrefixes(p.Bypass)
	if len(bypass) > 0 {
		w("table <openwarp_bypass> const { %s }", join(bypass))
	}
	dnsOK := uniqAddrs(p.DNSAllowed)
	if p.BlockBypassDNS && len(dnsOK) > 0 && len(bypass) > 0 {
		w("table <openwarp_dns> const { %s }", join(dnsOK))
	}

	w("pass quick on lo0 all")
	if p.TunnelIface != "" {
		w("pass quick on %s all", p.TunnelIface)
	}

	// The tunnel's own packets to the edge, over the physical interface.
	for _, g := range groupPorts(p.Edges) {
		w("pass out quick %s proto udp from any to %s port { %s } keep state", family(g.addr), g.addr, g.ports)
	}
	for _, a := range uniqAddrs(p.API) {
		w("pass out quick %s proto tcp from any to %s port 443 flags S/SA keep state", family(a), a)
	}

	// Getting and keeping an address on the physical network.
	w("pass out quick inet proto udp from any port 68 to any port 67 keep state")
	w("pass in quick inet proto udp from any port 67 to any port 68 keep state")
	w("pass out quick inet6 proto udp from any port 546 to any port 547 keep state")
	w("pass in quick inet6 proto udp from any port 547 to any port 546 keep state")
	w("pass quick inet6 proto icmp6 all icmp6-type { 133, 134, 135, 136, 137 } no state")

	if len(bypass) > 0 {
		if p.BlockBypassDNS {
			if len(dnsOK) > 0 && len(bypass) > 0 {
				w("pass out quick proto { tcp, udp } from any to <openwarp_dns> port 53 keep state")
			}
			w("block drop quick proto { tcp, udp } from any to <openwarp_bypass> port { 53, 853 }")
		}
		w("pass out quick from any to <openwarp_bypass> keep state")
		w("pass in quick from <openwarp_bypass> to any keep state")
	}

	w("block drop quick all")
	return b.String(), nil
}

// ErrUnsupported means the kill switch cannot run here (not macOS, not root, or pf without the com.apple
// anchor point).
var ErrUnsupported = errors.New("the kill switch is not available")

func family(a netip.Addr) string {
	if a.Is4() {
		return "inet"
	}
	return "inet6"
}

type portGroup struct {
	addr  netip.Addr
	ports string
}

// groupPorts merges endpoints per address: "to 162.159.198.1 port { 443, 500 }".
func groupPorts(eps []netip.AddrPort) []portGroup {
	byAddr := map[netip.Addr][]uint16{}
	for _, ep := range eps {
		a := ep.Addr().Unmap()
		if !a.IsValid() || ep.Port() == 0 || a.IsUnspecified() {
			continue
		}
		if !slices.Contains(byAddr[a], ep.Port()) {
			byAddr[a] = append(byAddr[a], ep.Port())
		}
	}
	addrs := make([]netip.Addr, 0, len(byAddr))
	for a := range byAddr {
		addrs = append(addrs, a)
	}
	slices.SortFunc(addrs, func(x, y netip.Addr) int { return x.Compare(y) })
	out := make([]portGroup, 0, len(addrs))
	for _, a := range addrs {
		ports := byAddr[a]
		slices.Sort(ports)
		s := make([]string, len(ports))
		for i, p := range ports {
			s[i] = fmt.Sprint(p)
		}
		out = append(out, portGroup{a, strings.Join(s, ", ")})
	}
	return out
}

func uniqAddrs(in []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range in {
		a = a.Unmap()
		if a.IsValid() && !a.IsUnspecified() && !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	slices.SortFunc(out, func(x, y netip.Addr) int { return x.Compare(y) })
	return out
}

func uniqPrefixes(in []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range in {
		if !p.IsValid() {
			continue
		}
		p = p.Masked()
		// A bypass of everything would switch the kill switch off; refuse it silently rather than
		// generate a rule that lets all traffic out.
		if p.Bits() == 0 {
			continue
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return x.Bits() - y.Bits()
	})
	return out
}

func join[T fmt.Stringer](xs []T) string {
	s := make([]string, len(xs))
	for i, x := range xs {
		s[i] = x.String()
	}
	return strings.Join(s, ", ")
}
