package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

// traceSequence answers trace requests in order (the last answer repeats) and counts them.
type traceSequence struct {
	fakeProbe
	mu      sync.Mutex
	answers []traceAnswer
	calls   atomic.Int32
}

type traceAnswer struct {
	m   map[string]string
	err error
}

func (p *traceSequence) Trace(context.Context, func(context.Context, string, string) (net.Conn, error)) (map[string]string, error) {
	n := int(p.calls.Add(1)) - 1
	p.mu.Lock()
	defer p.mu.Unlock()
	a := p.answers[min(n, len(p.answers)-1)]
	return a.m, a.err
}

var dusTrace = map[string]string{"ip": "198.51.100.7", "colo": "DUS", "loc": "DE", "warp": "on"}

func noExitWaits(t *testing.T) {
	t.Helper()
	saved := exitRetry
	exitRetry = []time.Duration{0, 0, 0}
	t.Cleanup(func() { exitRetry = saved })
}

func exitEngine(t *testing.T, probe Probe, mutate func(*state.State)) *Engine {
	t.Helper()
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		mutate(&store.S)
	}
	client, _ := countingAPI(t)
	e := NewEngineWithOptions(store, client, Options{Probe: probe, manual: true})
	t.Cleanup(e.Shutdown)
	e.setWant(true)
	return e
}

func TestExitFromTrace(t *testing.T) {
	cases := []struct {
		name string
		m    map[string]string
		want ExitLocation
		ok   bool
	}{
		{"warp on", dusTrace, ExitLocation{"DUS", "DE"}, true},
		{"warp plus", map[string]string{"colo": "FRA", "loc": "DE", "warp": "plus"}, ExitLocation{"FRA", "DE"}, true},
		{"not through WARP", map[string]string{"colo": "AMS", "loc": "NL", "warp": "off"}, ExitLocation{}, false},
		{"no warp field", map[string]string{"colo": "AMS", "loc": "NL"}, ExitLocation{}, false},
		{"unknown country", map[string]string{"colo": "DUS", "loc": "XX", "warp": "on"}, ExitLocation{}, false},
		{"Tor", map[string]string{"colo": "DUS", "loc": "T1", "warp": "on"}, ExitLocation{}, false},
		{"lower case", map[string]string{"colo": "dus", "loc": "de", "warp": "on"}, ExitLocation{}, false},
		{"long colo", map[string]string{"colo": "DUSS", "loc": "DE", "warp": "on"}, ExitLocation{}, false},
		{"markup", map[string]string{"colo": "<b>", "loc": "DE", "warp": "on"}, ExitLocation{}, false},
		{"nil", nil, ExitLocation{}, false},
	}
	for _, c := range cases {
		got, ok := exitFromTrace(c.m)
		if ok != c.ok || got != c.want {
			t.Errorf("%s: got %+v %v, want %+v %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestStatusPublishesTheExit(t *testing.T) {
	noExitWaits(t)
	probe := &traceSequence{answers: []traceAnswer{{m: dusTrace}}}
	e := exitEngine(t, probe, nil)
	s := tunSession(state.ModeWarp)
	e.setConnected(s)
	if st := e.Status(); st.Colo != "" || st.Loc != "" {
		t.Fatalf("exit before any lookup: %q %q", st.Colo, st.Loc)
	}
	e.lookupExit(context.Background(), s)
	st := e.Status()
	if st.Colo != "DUS" || st.Loc != "DE" {
		t.Fatalf("status = %q %q, want DUS DE", st.Colo, st.Loc)
	}
	// The JSON a companion app reads; the address Cloudflare saw is not published.
	b, _ := json.Marshal(st)
	var m map[string]any
	json.Unmarshal(b, &m)
	if m["colo"] != "DUS" || m["loc"] != "DE" {
		t.Fatalf("json colo/loc = %v %v", m["colo"], m["loc"])
	}
	for k, v := range m {
		if s, ok := v.(string); ok && s == dusTrace["ip"] {
			t.Fatalf("status publishes the public address in %q", k)
		}
	}
	// One lookup per session: a second call does not ask again.
	e.lookupExit(context.Background(), s)
	if n := probe.calls.Load(); n != 1 {
		t.Fatalf("%d trace requests, want 1", n)
	}
}

func TestExitBelongsToItsSession(t *testing.T) {
	noExitWaits(t)
	probe := &traceSequence{answers: []traceAnswer{{m: dusTrace}}}
	e := exitEngine(t, probe, nil)
	first := tunSession(state.ModeWarp)
	e.setConnected(first)
	e.lookupExit(context.Background(), first)
	next := tunSession(state.ModeWarp)
	e.setConnected(next) // reconnected: maybe to another data centre
	if st := e.Status(); st.Colo != "" || st.Loc != "" {
		t.Fatalf("a new session shows the old exit: %q %q", st.Colo, st.Loc)
	}
	// An answer for a session that is gone is dropped.
	e.recordExit(first, ExitLocation{"FRA", "DE"})
	if st := e.Status(); st.Colo != "" {
		t.Fatalf("a stale session's answer was kept: %q", st.Colo)
	}
	e.mu.Lock()
	e.status = StatusConnecting
	e.mu.Unlock()
	e.recordExit(next, ExitLocation{"DUS", "DE"})
	if st := e.Status(); st.Colo != "" {
		t.Fatalf("exit shown while not connected: %q", st.Colo)
	}
}

func TestExitLookupRetriesAndGivesUp(t *testing.T) {
	noExitWaits(t)
	probe := &traceSequence{answers: []traceAnswer{{err: errors.New("timeout")}, {m: dusTrace}}}
	e := exitEngine(t, probe, nil)
	s := tunSession(state.ModeWarp)
	e.setConnected(s)
	e.lookupExit(context.Background(), s)
	if st := e.Status(); st.Colo != "DUS" || probe.calls.Load() != 2 {
		t.Fatalf("after a failed first attempt: colo %q, %d calls", st.Colo, probe.calls.Load())
	}

	failing := &traceSequence{answers: []traceAnswer{{err: errors.New("timeout")}}}
	e = exitEngine(t, failing, nil)
	s = tunSession(state.ModeWarp)
	e.setConnected(s)
	e.lookupExit(context.Background(), s)
	if st := e.Status(); st.Colo != "" || failing.calls.Load() != int32(len(exitRetry)) {
		t.Fatalf("failing lookups: colo %q, %d calls", st.Colo, failing.calls.Load())
	}

	// A request that went around the tunnel is not retried and gives no exit.
	around := &traceSequence{answers: []traceAnswer{{m: map[string]string{"colo": "AMS", "loc": "NL", "warp": "off"}}}}
	e = exitEngine(t, around, nil)
	s = tunSession(state.ModeWarp)
	e.setConnected(s)
	e.lookupExit(context.Background(), s)
	if st := e.Status(); st.Colo != "" || around.calls.Load() != 1 {
		t.Fatalf("warp=off: colo %q, %d calls", st.Colo, around.calls.Load())
	}
}

func TestExitLookupRespectsTheSetting(t *testing.T) {
	noExitWaits(t)
	probe := &traceSequence{answers: []traceAnswer{{m: dusTrace}}}
	e := exitEngine(t, probe, func(s *state.State) { s.Settings.DisableLocationLookup = true })
	s := tunSession(state.ModeWarp)
	e.setConnected(s)
	e.lookupExit(context.Background(), s)
	if n := probe.calls.Load(); n != 0 {
		t.Fatalf("%d trace requests with the lookup switched off", n)
	}
	// Switched on: looked up at once, without a reconnect.
	if _, err := e.UpdateSettings(func(x *state.Settings) error { x.DisableLocationLookup = false; return nil }); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for e.Status().Colo == "" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if st := e.Status(); st.Colo != "DUS" {
		t.Fatalf("after switching the lookup on: colo %q", st.Colo)
	}
	e.mu.Lock()
	same := e.sess == s
	e.mu.Unlock()
	if !same {
		t.Fatal("switching the lookup on reconnected")
	}
	// Switched off: forgotten at once.
	if _, err := e.UpdateSettings(func(x *state.Settings) error { x.DisableLocationLookup = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if st := e.Status(); st.Colo != "" || st.Loc != "" {
		t.Fatalf("after switching the lookup off: %q %q", st.Colo, st.Loc)
	}
}

func TestDNSOnlyHasNoExit(t *testing.T) {
	noExitWaits(t)
	probe := &traceSequence{answers: []traceAnswer{{m: dusTrace}}}
	e := exitEngine(t, probe, nil)
	s := &session{mode: state.ModeDoH, idle: make(chan error)}
	e.setConnected(s)
	e.lookupExit(context.Background(), s)
	if n := probe.calls.Load(); n != 0 {
		t.Fatalf("%d trace requests in a DNS-only mode", n)
	}
}

func TestVerifyWithCloudflareRecordsTheExit(t *testing.T) {
	probe := &fakeProbe{trace: dusTrace}
	e, _ := manualEngine(t, &fakeFW{}, probe, nil)
	e.setWant(true)
	s := tunSession(state.ModeWarp)
	e.setConnected(s)
	if _, err := e.Verify(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if st := e.Status(); st.Colo != "DUS" || st.Loc != "DE" {
		t.Fatalf("after verify --cloudflare: %q %q", st.Colo, st.Loc)
	}
}

func TestOldStateFilesKeepTheLookupOn(t *testing.T) {
	var s state.Settings
	if err := json.Unmarshal([]byte(`{"mode":"warp","protocol":"masque"}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.DisableLocationLookup || state.DefaultSettings().DisableLocationLookup {
		t.Fatal("the lookup is off without the user switching it off")
	}
}
