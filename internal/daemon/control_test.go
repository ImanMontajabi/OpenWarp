package daemon

// Control API tests: the HTTP handlers the CLI (and through it the app) use,
// exercised in-process against an engine with an empty state directory. The
// API client points at a server that fails the test if anything calls it, so
// these tests prove the handlers stay offline.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

type controlHarness struct {
	t   *testing.T
	dir string
	eng *Engine
	h   http.Handler
}

func newControlHarness(t *testing.T) *controlHarness {
	t.Helper()
	noAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected Cloudflare API call: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(noAPI.Close)
	dir := t.TempDir()
	store, err := state.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngineWithAPI(store, &api.Client{BaseURL: noAPI.URL, Identity: api.MacIdentity, HTTP: noAPI.Client()})
	t.Cleanup(eng.Shutdown)
	return &controlHarness{t, dir, eng, eng.Handler()}
}

func (c *controlHarness) do(method, path, body string) (int, map[string]any) {
	c.t.Helper()
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		c.t.Fatalf("%s %s: response is not a JSON object: %q", method, path, rec.Body.String())
	}
	return rec.Code, m
}

func (c *controlHarness) savedSettings() state.Settings {
	c.t.Helper()
	b, err := os.ReadFile(filepath.Join(c.dir, "state.json"))
	if err != nil {
		c.t.Fatal(err)
	}
	var s state.State
	if err := json.Unmarshal(b, &s); err != nil {
		c.t.Fatal(err)
	}
	return s.Settings
}

func TestControlStatusBeforeRegistration(t *testing.T) {
	c := newControlHarness(t)
	code, st := c.do("GET", "/v1/status", "")
	if code != 200 || st["status"] != StatusDisconnected || st["registered"] != false ||
		st["mode"] != "warp" || st["mode_label"] != "Traffic and DNS (UDP)" || st["protocol"] != "masque" {
		t.Fatalf("initial status: %d %v", code, st)
	}
}

func TestControlRequiresRegistration(t *testing.T) {
	c := newControlHarness(t)
	for _, r := range []struct{ method, path string }{
		{"POST", "/v1/connect"},
		{"GET", "/v1/registration"},
		{"GET", "/v1/registration/devices"},
		{"GET", "/v1/registration/account"},
		{"PUT", "/v1/registration/license"},
		{"POST", "/v1/tunnel/rotate-keys"},
	} {
		code, body := c.do(r.method, r.path, `{}`)
		if code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "not registered") {
			t.Errorf("%s %s without a registration: %d %v", r.method, r.path, code, body)
		}
	}
	if _, st := c.do("GET", "/v1/status", ""); st["status"] != StatusDisconnected {
		t.Fatalf("a refused connect must leave the engine disconnected: %v", st)
	}
	if c.eng.Settings().AlwaysOn {
		t.Fatal("a refused connect must not turn on always_on")
	}
	if _, err := os.Stat(filepath.Join(c.dir, "state.json")); err == nil {
		t.Fatal("refused requests must not write state.json")
	}
}

func TestControlRegistrationRequiresToS(t *testing.T) {
	c := newControlHarness(t)
	code, body := c.do("POST", "/v1/registration", `{"accept_tos":false}`)
	if code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "Terms of Service") {
		t.Fatalf("registration without ToS: %d %v", code, body)
	}
}

func TestControlSettingsPatchAndPersistence(t *testing.T) {
	c := newControlHarness(t)
	code, s := c.do("PATCH", "/v1/settings", `{"mtu":1400,"families":"malware","protocol":"wireguard","endpoint_override":"192.0.2.1:2408"}`)
	if code != 200 || s["mtu"] != 1400.0 || s["families"] != "malware" || s["protocol"] != "wireguard" || s["endpoint_override"] != "192.0.2.1:2408" {
		t.Fatalf("patch: %d %v", code, s)
	}
	if _, got := c.do("GET", "/v1/settings", ""); got["mtu"] != 1400.0 || got["protocol"] != "wireguard" {
		t.Fatalf("GET after PATCH: %v", got)
	}
	saved := c.savedSettings()
	if saved.MTU != 1400 || saved.Families != state.FamiliesMalware || saved.Protocol != state.ProtoWireGuard {
		t.Fatalf("not persisted to state.json: %+v", saved)
	}
	if info, err := os.Stat(filepath.Join(c.dir, "state.json")); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json must be 0600 (it holds keys and the token): %v %v", info.Mode(), err)
	}
	// Status reflects the selected protocol.
	if _, st := c.do("GET", "/v1/status", ""); st["protocol"] != "wireguard" {
		t.Fatalf("status protocol: %v", st)
	}
}

func TestControlSettingsPatchRejectsBadInput(t *testing.T) {
	c := newControlHarness(t)
	c.do("PATCH", "/v1/settings", `{"mtu":1400}`)
	for _, body := range []string{
		`{"no_such_setting":1}`,
		`{"mode":"bogus"}`,
		`{"protocol":"openvpn"}`,
		`{"mtu":"big"}`,
		`not json`,
	} {
		code, resp := c.do("PATCH", "/v1/settings", body)
		if code != http.StatusBadRequest || resp["error"] == "" {
			t.Errorf("PATCH %s: want 400 with an error, got %d %v", body, code, resp)
		}
	}
	// A rejected patch leaves the previous settings in place, in memory and on disk.
	if _, s := c.do("GET", "/v1/settings", ""); s["mtu"] != 1400.0 || s["mode"] != "warp" || s["protocol"] != "masque" {
		t.Fatalf("settings changed by a rejected patch: %v", s)
	}
	if saved := c.savedSettings(); saved.MTU != 1400 || saved.Mode != state.ModeWarp {
		t.Fatalf("rejected patch reached state.json: %+v", saved)
	}
}

func TestControlEveryModeIsSelectable(t *testing.T) {
	c := newControlHarness(t)
	for _, m := range state.AllModes {
		code, s := c.do("PATCH", "/v1/settings", `{"mode":"`+string(m)+`"}`)
		if code != 200 || s["mode"] != string(m) {
			t.Fatalf("mode %s: %d %v", m, code, s)
		}
		if _, st := c.do("GET", "/v1/status", ""); st["mode"] != string(m) || st["mode_label"] != m.Label() {
			t.Fatalf("status after mode %s: %v", m, st)
		}
	}
}

func TestControlSettingsResetKeepsAlwaysOn(t *testing.T) {
	c := newControlHarness(t)
	c.eng.setAlwaysOn(true)
	c.do("PATCH", "/v1/settings", `{"mode":"proxy","mtu":1300,"split_ips":[]}`)
	code, s := c.do("POST", "/v1/settings/reset", "")
	def := state.DefaultSettings()
	if code != 200 || s["mode"] != string(def.Mode) || s["mtu"] != float64(def.MTU) || s["always_on"] != true {
		t.Fatalf("reset: %d %v", code, s)
	}
	if ips, _ := s["split_ips"].([]any); len(ips) != len(state.DefaultExcludes) {
		t.Fatalf("reset should restore the default exclude list, got %d entries", len(ips))
	}
}

func TestControlDisconnectWhenIdle(t *testing.T) {
	c := newControlHarness(t)
	if code, _ := c.do("POST", "/v1/disconnect", ""); code != 200 {
		t.Fatalf("disconnect: %d", code)
	}
	if _, st := c.do("GET", "/v1/status", ""); st["status"] != StatusDisconnected || st["reason"] != "Manual Disconnection" {
		t.Fatalf("status after disconnect: %v", st)
	}
}
