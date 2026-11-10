package daemon

import (
	"net/netip"
	"testing"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

// Compatibility: the edge addresses and port order OpenWarp tries, from the registration's peer endpoint.
// These mirror the official client (CLAUDE.md, "Protocol facts"); a change here is a protocol change and must
// be deliberate.
func TestEndpointCandidatesCompat(t *testing.T) {
	cfg := func(v4 string, ports []int) *api.Config {
		var c api.Config
		c.Peers = []api.Peer{{PublicKey: "k", Endpoint: api.Endpoint{V4: v4, Ports: ports}}}
		return &c
	}
	v4s := func(c []netip.AddrPort) (out []string) {
		for _, a := range c {
			if a.Addr().Is4() {
				out = append(out, a.String())
			}
		}
		return out
	}
	eq := func(got, want []string) bool {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}

	masque := state.Settings{Protocol: state.ProtoMasque}
	got, err := endpointCandidates(masque, cfg("162.159.198.2:0", nil))
	want := []string{"162.159.198.2:443", "162.159.198.2:500", "162.159.198.2:1701", "162.159.198.2:4500",
		"162.159.198.2:4443", "162.159.198.2:8443", "162.159.198.2:8095"}
	if err != nil || !eq(v4s(got), want) {
		t.Fatalf("MASQUE candidates = %v, %v", v4s(got), err)
	}

	wg := state.Settings{Protocol: state.ProtoWireGuard}
	got, _ = endpointCandidates(wg, cfg("162.159.192.5:0", nil))
	if want := []string{"162.159.192.5:2408", "162.159.192.5:500", "162.159.192.5:1701", "162.159.192.5:4500"}; !eq(v4s(got), want) {
		t.Fatalf("WireGuard candidates = %v", v4s(got))
	}
	// Ports the API lists win for WireGuard.
	got, _ = endpointCandidates(wg, cfg("162.159.192.5:0", []int{4500, 2408}))
	if want := []string{"162.159.192.5:4500", "162.159.192.5:2408"}; !eq(v4s(got), want) {
		t.Fatalf("API ports ignored: %v", v4s(got))
	}
	// No usable address in the answer: the documented default edge.
	got, _ = endpointCandidates(masque, cfg("", nil))
	if len(got) == 0 || got[0].String() != "162.159.198.1:443" {
		t.Fatalf("default MASQUE edge = %v", got)
	}
	// The override is used alone; a bad one is an error, not a guess.
	got, err = endpointCandidates(state.Settings{Protocol: state.ProtoMasque, EndpointOverride: "203.0.113.9:8443"}, cfg("162.159.198.2:0", nil))
	if err != nil || len(got) != 1 || got[0].String() != "203.0.113.9:8443" {
		t.Fatalf("override = %v %v", got, err)
	}
	if _, err := endpointCandidates(state.Settings{EndpointOverride: "not-an-address"}, cfg("", nil)); err == nil {
		t.Fatal("bad override accepted")
	}
	// A registration without peers is an error (the API changed or the answer was cut).
	if _, err := endpointCandidates(masque, &api.Config{}); err == nil {
		t.Fatal("config without peers accepted")
	}
}
