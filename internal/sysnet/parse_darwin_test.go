//go:build darwin

package sysnet

import (
	"net/netip"
	"slices"
	"testing"
)

func TestParseRoute(t *testing.T) {
	tun := `   route to: 1.1.1.1
destination: 0.0.0.0
       mask: 128.0.0.0
  interface: utun5
      flags: <UP,DONE,STATIC>
`
	if r := parseRoute(tun); r.Iface != "utun5" || r.Reject {
		t.Fatalf("tunnel route = %+v", r)
	}
	rej := `   route to: 2606:4700:4700::1111
destination: ::
       mask: 8000::
    gateway: ::1
  interface: lo0
      flags: <UP,GATEWAY,DONE,STATIC,REJECT>
`
	if r := parseRoute(rej); r.Iface != "lo0" || !r.Reject {
		t.Fatalf("reject route = %+v", r)
	}
}

func TestParseResolvers(t *testing.T) {
	out := `DNS configuration

resolver #1
  nameserver[0] : 127.0.0.1
  nameserver[1] : 2606:4700:4700::1111
  nameserver[2] : fe80::1%en0
  flags    : Request A records

resolver #2
  domain   : local
  nameserver[0] : 192.168.1.1
`
	want := []netip.Addr{netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("2606:4700:4700::1111"), netip.MustParseAddr("fe80::1")}
	if got := parseResolvers(out); !slices.Equal(got, want) {
		t.Fatalf("resolvers = %v", got)
	}
}
