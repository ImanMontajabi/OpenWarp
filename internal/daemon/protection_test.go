package daemon

// Leak protection: the kill switch follows the connection (and fails closed), and verification reports
// only what it checked. The firewall and the system probes are fakes, so nothing here needs root or
// touches pf, routes or DNS.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/dnsproxy"
	"github.com/ImanMontajabi/OpenWarp/internal/firewall"
	"github.com/ImanMontajabi/OpenWarp/internal/keys"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
	"github.com/ImanMontajabi/OpenWarp/internal/sysnet"
	"github.com/ImanMontajabi/OpenWarp/internal/tunnel"
)

type fakeFW struct {
	mu        sync.Mutex
	applied   []firewall.Policy
	clears    int
	active    bool
	applyErr  error
	verifyErr error
	log       []string
}

func (f *fakeFW) Apply(p firewall.Policy) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "apply")
	if f.applyErr != nil {
		return f.applyErr
	}
	f.applied = append(f.applied, p)
	f.active = true
	return nil
}

func (f *fakeFW) Verify() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.active {
		return errors.New("the kill switch rules are not loaded")
	}
	return f.verifyErr
}

func (f *fakeFW) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.log = append(f.log, "clear")
	f.clears++
	f.active = false
	return nil
}

func (f *fakeFW) last() (firewall.Policy, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.applied) == 0 {
		return firewall.Policy{}, 0, f.active
	}
	return f.applied[len(f.applied)-1], len(f.applied), f.active
}

type fakeProbe struct {
	routes    map[netip.Addr]sysnet.Route
	resolvers []netip.Addr
	trace     map[string]string
	traceErr  error
	traced    atomic.Int32
}

func (p *fakeProbe) RouteTo(dst netip.Addr) (sysnet.Route, bool, error) {
	r, ok := p.routes[dst]
	return r, ok, nil
}
func (p *fakeProbe) Resolvers() ([]netip.Addr, error) { return p.resolvers, nil }
func (p *fakeProbe) Trace(context.Context, func(context.Context, string, string) (net.Conn, error)) (map[string]string, error) {
	p.traced.Add(1)
	return p.trace, p.traceErr
}

// tunSession is a connected tun-mode session as startSession would leave it (without a real utun).
func tunSession(mode state.Mode) *session {
	return &session{mode: mode, iface: "utun9", tr: transportStub{}, idle: make(chan error)}
}

type transportStub struct{ tunnel.Transport }

func (transportStub) Stats() tunnel.Stats {
	return tunnel.Stats{Protocol: "masque", Endpoint: "162.159.198.7:443"}
}
func (transportStub) Done() <-chan error { return nil }
func (transportStub) Close() error       { return nil }

// countingAPI answers every call with 500 and counts them: an API call means the engine tried to connect.
func countingAPI(t *testing.T) (*api.Client, *atomic.Int32) {
	var n atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(ts.Close)
	return &api.Client{BaseURL: ts.URL, Identity: api.MacIdentity, HTTP: ts.Client()}, &n
}

// protectedEngine runs the connection loop, for tests that go through Connect.
func protectedEngine(t *testing.T, fw *fakeFW, probe *fakeProbe, mutate func(*state.State)) (*Engine, *atomic.Int32) {
	t.Helper()
	return newProtectedEngine(t, fw, probe, mutate, false)
}

// manualEngine has no connection loop: for tests that set the session and status by hand. With the loop
// running, it would race them (it saw want=true and set "connecting" over a hand-set "connected" on a slow
// CI runner).
func manualEngine(t *testing.T, fw *fakeFW, probe *fakeProbe, mutate func(*state.State)) (*Engine, *atomic.Int32) {
	t.Helper()
	return newProtectedEngine(t, fw, probe, mutate, true)
}

func newProtectedEngine(t *testing.T, fw *fakeFW, probe *fakeProbe, mutate func(*state.State), manual bool) (*Engine, *atomic.Int32) {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store.S.Settings.KillSwitch = true
	ec, _ := keys.NewECDSA()
	wg, _ := keys.NewWireGuard()
	store.S.Registration = &api.Registration{ID: "test-reg", Token: "test-token"}
	store.S.ECDSAKey, store.S.WireGuardKey = ec, wg
	if mutate != nil {
		mutate(&store.S)
	}
	store.Lock()
	store.Save()
	store.Unlock()
	client, calls := countingAPI(t)
	var f Firewall
	if fw != nil {
		f = fw
	}
	if probe == nil {
		probe = &fakeProbe{}
	}
	e := NewEngineWithOptions(store, client, Options{Firewall: f, FirewallErr: errors.New("test: no firewall"), Probe: probe, manual: manual})
	t.Cleanup(e.Shutdown)
	return e, calls
}

func (e *Engine) setWant(v bool) {
	e.mu.Lock()
	e.want = v
	e.mu.Unlock()
}

func (e *Engine) setConnected(s *session) {
	e.mu.Lock()
	e.sess, e.status = s, StatusConnected
	e.mu.Unlock()
}

func TestKillSwitchFollowsTheConnection(t *testing.T) {
	fw := &fakeFW{}
	e, _ := manualEngine(t, fw, nil, nil)
	set := e.Settings()

	if st := e.Status().Protection; st.KillSwitch != KSStandby || st.State != ProtUnprotected {
		t.Fatalf("idle: %+v", st)
	}

	// Connecting: everything but the edge, the API fallback and the exclusions is blocked.
	e.setWant(true)
	if err := e.syncKillSwitch(set, nil, false); err != nil {
		t.Fatal(err)
	}
	p, _, active := fw.last()
	if !active || p.TunnelIface != "" {
		t.Fatalf("connecting policy: active=%v %+v", active, p)
	}
	if !slices.Contains(p.Edges, netip.MustParseAddrPort("162.159.198.1:443")) || !slices.Contains(p.Edges, netip.MustParseAddrPort("162.159.198.1:8095")) {
		t.Fatalf("default MASQUE edge not allowed: %v", p.Edges)
	}
	if !slices.Contains(p.API, netip.MustParseAddr("162.159.192.1")) || !p.BlockBypassDNS || len(p.Bypass) != len(state.DefaultExcludes) {
		t.Fatalf("policy: %+v", p)
	}
	if st := e.Status().Protection; st.State != ProtBlocking || st.KillSwitch != KSBlocking {
		t.Fatalf("while connecting: %+v", st)
	}

	// Connected: the tunnel interface is let through, and the edge actually in use.
	s := tunSession(state.ModeWarp)
	e.setConnected(s)
	if err := e.syncKillSwitch(set, s, false); err != nil {
		t.Fatal(err)
	}
	p, _, _ = fw.last()
	if p.TunnelIface != "utun9" || !slices.Contains(p.Edges, netip.MustParseAddrPort("162.159.198.7:443")) {
		t.Fatalf("connected policy: %+v", p)
	}
	if st := e.Status().Protection; st.KillSwitch != KSProtecting || st.State != ProtUnverified {
		t.Fatalf("connected: %+v", st)
	}

	// The tunnel dies: back to blocking, not to the open network.
	e.mu.Lock()
	e.sess, e.status = nil, StatusConnecting
	e.mu.Unlock()
	e.syncKillSwitch(set, nil, false)
	if p, _, active = fw.last(); !active || p.TunnelIface != "" {
		t.Fatalf("after tunnel loss: active=%v iface=%q", active, p.TunnelIface)
	}

	// A manual disconnect removes the rules, and nothing loads them again.
	e.Disconnect()
	_, n, active := fw.last()
	if active || fw.clears == 0 {
		t.Fatalf("rules left after disconnect (clears=%d)", fw.clears)
	}
	e.syncKillSwitch(set, nil, false)
	if _, n2, active := fw.last(); active || n2 != n {
		t.Fatal("rules loaded again while disconnected")
	}
	if st := e.Status().Protection; st.State != ProtUnprotected || st.KillSwitch != KSStandby {
		t.Fatalf("after disconnect: %+v", st)
	}
}

func TestKillSwitchOffClearsRules(t *testing.T) {
	fw := &fakeFW{}
	e, _ := manualEngine(t, fw, nil, nil)
	e.setWant(true)
	set := e.Settings()
	e.syncKillSwitch(set, nil, false)
	set.KillSwitch = false
	e.syncKillSwitch(set, nil, false)
	if _, _, active := fw.last(); active {
		t.Fatal("switching the kill switch off left the rules")
	}
	if ks, _ := e.killSwitchState(); ks != KSOff {
		t.Fatalf("state %q", ks)
	}
}

// With the kill switch on, the engine does not try to connect until the rules are in place.
func TestKillSwitchFailsClosed(t *testing.T) {
	fw := &fakeFW{applyErr: errors.New("pfctl: permission denied")}
	e, calls := protectedEngine(t, fw, nil, nil)
	e.Connect()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(e.Status().Reason, "Kill switch") {
		time.Sleep(20 * time.Millisecond)
	}
	st := e.Status()
	if st.Reason != "Kill switch could not be enabled" || !strings.Contains(st.Error, "permission denied") {
		t.Fatalf("status %q / %q", st.Reason, st.Error)
	}
	if st.Protection.KillSwitch != KSError {
		t.Fatalf("kill switch state %+v", st.Protection)
	}
	time.Sleep(200 * time.Millisecond)
	if n := calls.Load(); n != 0 {
		t.Fatalf("the engine called the API %d times (tried to connect) without the kill switch", n)
	}
	e.Disconnect()

	// Positive control: with a working firewall the same engine does go on to connect (and reaches the API).
	fw.mu.Lock()
	fw.applyErr = nil
	fw.mu.Unlock()
	e.Connect()
	for i := 0; i < 100 && calls.Load() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Fatal("no connection attempt with a working kill switch")
	}
	if _, _, active := fw.last(); !active {
		t.Fatal("no rules while connecting")
	}
}

// Without a firewall (no root, not macOS) the kill switch is an error in the tun modes, never silently off.
func TestKillSwitchWithoutFirewallIsAnError(t *testing.T) {
	e, _ := manualEngine(t, nil, nil, nil)
	e.setWant(true)
	err := e.syncKillSwitch(e.Settings(), nil, false)
	if err == nil || !strings.Contains(err.Error(), "test: no firewall") {
		t.Fatalf("err = %v", err)
	}
	if ks, detail := e.killSwitchState(); ks != KSError || detail == "" {
		t.Fatalf("state %q %q", ks, detail)
	}
}

func TestKillSwitchScope(t *testing.T) {
	for _, tc := range []struct {
		mode  state.Mode
		split state.SplitMode
		want  bool
	}{
		{state.ModeWarp, state.SplitExclude, true},
		{state.ModeWarpDoH, state.SplitExclude, true},
		{state.ModeWarpDoT, state.SplitExclude, true},
		{state.ModeTunnelOnly, state.SplitExclude, true},
		{state.ModeProxy, state.SplitExclude, false},
		{state.ModeDoH, state.SplitExclude, false},
		{state.ModeDoT, state.SplitExclude, false},
		{state.ModeWarp, state.SplitInclude, false},
	} {
		fw := &fakeFW{}
		e, _ := manualEngine(t, fw, nil, nil)
		set := e.Settings()
		set.Mode, set.SplitMode = tc.mode, tc.split
		e.setWant(true)
		if err := e.syncKillSwitch(set, nil, false); err != nil {
			t.Fatalf("%s/%s: %v", tc.mode, tc.split, err)
		}
		_, _, active := fw.last()
		ks, detail := e.killSwitchState()
		if active != tc.want {
			t.Errorf("%s/%s: rules active = %v, want %v", tc.mode, tc.split, active, tc.want)
		}
		if !tc.want && (ks != KSUnavailable || detail == "") {
			t.Errorf("%s/%s: state %q %q, want unavailable with a reason", tc.mode, tc.split, ks, detail)
		}
		// DNS to the local network is blocked only where OpenWarp manages DNS.
		if p, _, _ := fw.last(); tc.want && p.BlockBypassDNS != (tc.mode != state.ModeTunnelOnly) {
			t.Errorf("%s: BlockBypassDNS = %v", tc.mode, p.BlockBypassDNS)
		}
	}
}

func TestKillSwitchPausesOnTrustedNetworks(t *testing.T) {
	fw := &fakeFW{}
	e, _ := manualEngine(t, fw, nil, nil)
	e.setWant(true)
	set := e.Settings()
	e.syncKillSwitch(set, nil, false)
	e.syncKillSwitch(set, nil, true)
	if _, _, active := fw.last(); active {
		t.Fatal("rules kept on a trusted network")
	}
	if ks, detail := e.killSwitchState(); ks != KSStandby || !strings.Contains(detail, "trusted") {
		t.Fatalf("state %q %q", ks, detail)
	}
}

func TestKillSwitchPolicyUsesEnrolledEdges(t *testing.T) {
	fw := &fakeFW{}
	e, _ := manualEngine(t, fw, nil, func(s *state.State) {
		var c api.Config
		c.Peers = []api.Peer{{PublicKey: "k", Endpoint: api.Endpoint{V4: "162.159.198.2:0", V6: "[2606:4700:103::2]:0"}}}
		s.MasqueConfig = &c
		var w api.Config
		w.Peers = []api.Peer{{PublicKey: "k", Endpoint: api.Endpoint{V4: "162.159.192.9:0"}}}
		s.WireGuardConfig = &w
		s.Settings.SplitIPs = []string{"192.168.0.0/16", "203.0.113.5"}
	})
	e.setWant(true)
	set := e.Settings()
	s := tunSession(state.ModeWarpDoH)
	s.dns = &dnsproxy.Server{FallbackServers: []netip.Addr{netip.MustParseAddr("192.168.1.1")}}
	set.Mode = state.ModeWarpDoH
	e.syncKillSwitch(set, s, false)
	p, _, _ := fw.last()
	for _, want := range []string{"162.159.198.2:443", "162.159.198.2:4443", "[2606:4700:103::2]:443"} {
		if !slices.Contains(p.Edges, netip.MustParseAddrPort(want)) {
			t.Errorf("edge %s not allowed: %v", want, p.Edges)
		}
	}
	if slices.ContainsFunc(p.Edges, func(a netip.AddrPort) bool { return a.Addr() == netip.MustParseAddr("162.159.192.9") }) {
		t.Errorf("WireGuard edge allowed while MASQUE is selected: %v", p.Edges)
	}
	if !slices.Contains(p.Bypass, netip.MustParsePrefix("203.0.113.5/32")) || !slices.Equal(p.DNSAllowed, s.dns.FallbackServers) {
		t.Errorf("bypass %v, dns %v", p.Bypass, p.DNSAllowed)
	}

	// WireGuard: its own edge and ports.
	set.Protocol = state.ProtoWireGuard
	e.syncKillSwitch(set, nil, false)
	p, _, _ = fw.last()
	if !slices.Contains(p.Edges, netip.MustParseAddrPort("162.159.192.9:2408")) || slices.Contains(p.Edges, netip.MustParseAddrPort("162.159.198.2:443")) {
		t.Errorf("WireGuard edges: %v", p.Edges)
	}
}

// After a crash the rules stay; on the next start they are removed unless a connection with the kill
// switch is wanted, in which case the engine keeps blocking and goes straight to connecting.
func TestStartupRemovesLeftoverRules(t *testing.T) {
	fw := &fakeFW{active: true}
	protectedEngine(t, fw, nil, nil) // AlwaysOn is false
	if fw.clears != 1 || fw.active {
		t.Fatalf("leftover rules not removed at startup (clears=%d)", fw.clears)
	}

	fw2 := &fakeFW{active: true}
	_, calls := protectedEngine(t, fw2, nil, func(s *state.State) { s.Settings.AlwaysOn = true })
	for i := 0; i < 100 && calls.Load() == 0; i++ {
		time.Sleep(20 * time.Millisecond)
	}
	fw2.mu.Lock()
	log := slices.Clone(fw2.log)
	fw2.mu.Unlock()
	if len(log) == 0 || log[0] != "apply" {
		t.Fatalf("firewall calls at startup with Always On = %v, want the rules replaced, never cleared", log)
	}
}

func TestVerifyConnection(t *testing.T) {
	tunIf := sysnet.Route{Iface: "utun9"}
	good := func() *fakeProbe {
		return &fakeProbe{
			routes:    map[netip.Addr]sysnet.Route{probeV4: tunIf, probeV6: {Iface: "lo0", Reject: true}},
			resolvers: dnsproxy.Families("off").IPs,
			trace:     map[string]string{"warp": "on", "colo": "FRA"},
		}
	}
	verify := func(t *testing.T, probe *fakeProbe, mode state.Mode, trace bool, mutate func(*state.State)) (*Verification, *Engine) {
		t.Helper()
		fw := &fakeFW{}
		e, _ := manualEngine(t, fw, probe, func(s *state.State) {
			s.Settings.Mode = mode
			if mutate != nil {
				mutate(s)
			}
		})
		e.setWant(true)
		s := tunSession(mode)
		e.setConnected(s)
		e.syncKillSwitch(e.Settings(), s, false)
		v, err := e.Verify(context.Background(), trace)
		if err != nil {
			t.Fatal(err)
		}
		return v, e
	}
	check := func(v *Verification, name string) Check {
		for _, c := range v.Checks {
			if c.Name == name {
				return c
			}
		}
		return Check{}
	}

	t.Run("all good", func(t *testing.T) {
		probe := good()
		v, e := verify(t, probe, state.ModeWarp, true, nil)
		if v.Result != "verified" {
			t.Fatalf("result %s: %+v", v.Result, v.Checks)
		}
		for _, name := range []string{"tunnel", "ipv4_route", "ipv6_route", "dns", "kill_switch", "cloudflare"} {
			if c := check(v, name); c.Status != "pass" {
				t.Errorf("%s = %+v", name, c)
			}
		}
		if st := e.Status().Protection; st.State != ProtVerified || st.Verification == nil {
			t.Fatalf("status: %+v", st)
		}
		// A new connection is not covered by the old verification.
		e.setConnected(tunSession(state.ModeWarp))
		if st := e.Status().Protection; st.State != ProtUnverified || st.Verification != nil {
			t.Fatalf("stale verification shown: %+v", st)
		}
	})
	t.Run("no Cloudflare request unless asked", func(t *testing.T) {
		probe := good()
		v, _ := verify(t, probe, state.ModeWarp, false, nil)
		if probe.traced.Load() != 0 || check(v, "cloudflare").Name != "" {
			t.Fatal("trace requested without the user asking")
		}
		if v.Result != "verified" { // the routes prove the tunnel locally
			t.Fatalf("result %s", v.Result)
		}
	})
	for _, tc := range []struct {
		name, check string
		probe       func(*fakeProbe)
	}{
		{"ipv4 outside", "ipv4_route", func(p *fakeProbe) { p.routes[probeV4] = sysnet.Route{Iface: "en0"} }},
		{"ipv6 outside", "ipv6_route", func(p *fakeProbe) { p.routes[probeV6] = sysnet.Route{Iface: "en0"} }},
		{"foreign dns", "dns", func(p *fakeProbe) { p.resolvers = append(p.resolvers, netip.MustParseAddr("192.168.1.1")) }},
		{"no dns", "dns", func(p *fakeProbe) { p.resolvers = nil }},
		{"warp off", "cloudflare", func(p *fakeProbe) { p.trace = map[string]string{"warp": "off"} }},
		{"trace error", "cloudflare", func(p *fakeProbe) { p.traceErr = errors.New("timeout") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe := good()
			tc.probe(probe)
			v, e := verify(t, probe, state.ModeWarp, true, nil)
			if c := check(v, tc.check); c.Status != "fail" || c.Detail == "" {
				t.Fatalf("%s = %+v", tc.check, c)
			}
			if v.Result != "failed" || e.Status().Protection.State != ProtFailed {
				t.Fatalf("result %s", v.Result)
			}
		})
	}
	t.Run("kill switch rules missing", func(t *testing.T) {
		probe := good()
		fw := &fakeFW{}
		e, _ := manualEngine(t, fw, probe, nil)
		e.setWant(true)
		s := tunSession(state.ModeWarp)
		e.setConnected(s)
		e.syncKillSwitch(e.Settings(), s, false)
		fw.mu.Lock()
		fw.verifyErr = errors.New("pf is disabled")
		fw.mu.Unlock()
		v, _ := e.Verify(context.Background(), false)
		if c := check(v, "kill_switch"); c.Status != "fail" || v.Result != "failed" {
			t.Fatalf("kill_switch = %+v, result %s", c, v.Result)
		}
	})
	t.Run("ipv6 through the tunnel", func(t *testing.T) {
		probe := good()
		probe.routes[probeV6] = tunIf
		v, _ := verify(t, probe, state.ModeWarp, false, nil)
		if c := check(v, "ipv6_route"); c.Status != "pass" {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("encrypted dns modes expect the local proxy", func(t *testing.T) {
		probe := good()
		probe.resolvers = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		v, _ := verify(t, probe, state.ModeWarpDoH, false, nil)
		if c := check(v, "dns"); c.Status != "pass" {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("tunnel only does not claim dns", func(t *testing.T) {
		probe := good()
		probe.resolvers = []netip.Addr{netip.MustParseAddr("192.168.1.1")}
		v, _ := verify(t, probe, state.ModeTunnelOnly, false, nil)
		if c := check(v, "dns"); c.Status != "skip" || !strings.Contains(c.Detail, "not managed") {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("proxy mode needs the Cloudflare check", func(t *testing.T) {
		probe := good()
		v, _ := verify(t, probe, state.ModeProxy, false, func(s *state.State) { s.Settings.KillSwitch = false })
		if v.Result != "incomplete" || check(v, "ipv4_route").Status != "skip" {
			t.Fatalf("result %s: %+v", v.Result, v.Checks)
		}
		v, _ = verify(t, probe, state.ModeProxy, true, func(s *state.State) { s.Settings.KillSwitch = false })
		if v.Result != "verified" {
			t.Fatalf("with trace: %s %+v", v.Result, v.Checks)
		}
	})
	t.Run("not connected", func(t *testing.T) {
		e, _ := manualEngine(t, &fakeFW{}, good(), nil)
		if _, err := e.Verify(context.Background(), false); err == nil {
			t.Fatal("verified without a connection")
		}
	})
}

func TestParseTrace(t *testing.T) {
	m := parseTrace(strings.NewReader("fl=1\nh=www.cloudflare.com\nip=192.0.2.1\ncolo=FRA\nwarp=on\ngateway=off\n"))
	if m["warp"] != "on" || m["colo"] != "FRA" {
		t.Fatalf("%v", m)
	}
}
