package main

// CLI tests run the real openwarp main() in a child process (the test binary
// re-executes itself) against a fake daemon on a unix socket. They check what
// the CLI sends to the daemon, what it prints, and its exit codes, without
// touching a real daemon, the network or Cloudflare.

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

func TestMain(m *testing.M) {
	if os.Getenv("OPENWARP_TEST_RUN_MAIN") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type request struct {
	Method, Path string
	Body         map[string]any
}

type route func(body map[string]any) (int, any)

// fakeDaemon answers the control API from a route table and records requests.
type fakeDaemon struct {
	sock   string
	mu     sync.Mutex
	reqs   []request
	routes map[string]route
}

func newFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	// Unix socket paths must stay short (104 bytes on macOS), so not t.TempDir().
	dir, err := os.MkdirTemp("", "owcli")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	f := &fakeDaemon{sock: filepath.Join(dir, "d.sock"), routes: map[string]route{}}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fakeDaemon) on(methodPath string, r route) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.routes[methodPath] = r
}

func (f *fakeDaemon) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	data, _ := io.ReadAll(r.Body)
	var body map[string]any
	json.Unmarshal(data, &body)
	key := r.Method + " " + r.URL.Path
	// Handlers run under the lock: they share state with the test goroutine.
	f.mu.Lock()
	f.reqs = append(f.reqs, request{r.Method, r.URL.Path, body})
	code, v := http.StatusNotFound, any(map[string]string{"error": "no route for " + key})
	if h := f.routes[key]; h != nil {
		code, v = h(body)
	}
	f.mu.Unlock()
	if v == nil {
		v = map[string]bool{"ok": true}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeDaemon) requests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

// lastPatch returns the body of the last PATCH /v1/settings.
func (f *fakeDaemon) lastPatch(t *testing.T) map[string]any {
	t.Helper()
	reqs := f.requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].Method == "PATCH" && reqs[i].Path == "/v1/settings" {
			return reqs[i].Body
		}
	}
	t.Fatalf("no PATCH /v1/settings in %+v", reqs)
	return nil
}

// settingsRoutes serves GET/PATCH /v1/settings backed by an in-memory copy.
func (f *fakeDaemon) settingsRoutes(s state.Settings) {
	cur := s
	f.on("GET /v1/settings", func(map[string]any) (int, any) { return 200, cur })
	f.on("PATCH /v1/settings", func(body map[string]any) (int, any) {
		m := map[string]any{}
		b, _ := json.Marshal(cur)
		json.Unmarshal(b, &m)
		for k, v := range body {
			m[k] = v
		}
		b, _ = json.Marshal(m)
		var next state.Settings
		json.Unmarshal(b, &next)
		cur = next
		return 200, cur
	})
}

type result struct {
	stdout, stderr string
	code           int
}

func runCLI(t *testing.T, sock string, args ...string) result {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	// GORACE: the race runtime otherwise sleeps 1s at every child exit.
	cmd.Env = append(os.Environ(), "OPENWARP_TEST_RUN_MAIN=1", "OPENWARP_SOCKET="+sock, "GORACE=atexit_sleep_ms=0")
	cmd.Stdin = strings.NewReader("")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running CLI: %v", err)
	}
	return result{out.String(), errb.String(), code}
}

func TestCLIVersionHelpAndUnknownInput(t *testing.T) {
	f := newFakeDaemon(t)
	if r := runCLI(t, f.sock, "-V"); r.code != 0 || r.stdout != "openwarp "+version+"\n" {
		t.Fatalf("-V: %+v", r)
	}
	if r := runCLI(t, f.sock, "help"); r.code != 0 || !strings.Contains(r.stdout, "Usage: openwarp") {
		t.Fatalf("help: %+v", r)
	}
	if r := runCLI(t, f.sock); r.code != 2 || !strings.Contains(r.stdout, "Usage: openwarp") {
		t.Fatalf("no arguments should print usage and exit 2: %+v", r)
	}
	if r := runCLI(t, f.sock, "--bogus"); r.code != 1 || !strings.Contains(r.stderr, "Error: unknown flag --bogus") {
		t.Fatalf("unknown flag: %+v", r)
	}
	if r := runCLI(t, f.sock, "frobnicate"); r.code != 1 || !strings.Contains(r.stderr, `unknown command "frobnicate"`) {
		t.Fatalf("unknown command: %+v", r)
	}
	if n := len(f.requests()); n != 0 {
		t.Fatalf("local commands must not call the daemon, got %d requests", n)
	}
}

func TestCLIModeAcceptsAllSevenModes(t *testing.T) {
	if len(state.AllModes) != 7 {
		t.Fatalf("expected the seven official modes, have %v", state.AllModes)
	}
	f := newFakeDaemon(t)
	f.settingsRoutes(state.DefaultSettings())
	for _, m := range state.AllModes {
		r := runCLI(t, f.sock, "mode", string(m))
		if r.code != 0 || r.stdout != "Success\n" {
			t.Fatalf("mode %s: %+v", m, r)
		}
		if got := f.lastPatch(t); len(got) != 1 || got["mode"] != string(m) {
			t.Fatalf("mode %s sent %v", m, got)
		}
	}
	// With -j the CLI prints the settings the daemon returned.
	r := runCLI(t, f.sock, "-j", "mode", "proxy")
	var s state.Settings
	if err := json.Unmarshal([]byte(r.stdout), &s); err != nil || s.Mode != state.ModeProxy {
		t.Fatalf("-j mode output: %v %q", err, r.stdout)
	}
}

func TestCLIRejectsInvalidInputBeforeCallingDaemon(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"mode", "bogus"}, `invalid mode "bogus"`},
		{[]string{"mode"}, "missing argument: mode"},
		{[]string{"proxy", "port", "0"}, "usage: openwarp proxy port <1-65535>"},
		{[]string{"proxy", "port", "65536"}, "usage: openwarp proxy port <1-65535>"},
		{[]string{"proxy", "port", "abc"}, "usage: openwarp proxy port <1-65535>"},
		{[]string{"tunnel", "mtu", "1279"}, "mtu must be 1280-1500"},
		{[]string{"tunnel", "mtu", "1501"}, "mtu must be 1280-1500"},
		{[]string{"dns", "families", "everything"}, "families must be off, malware or full"},
		{[]string{"tunnel", "split-mode", "sideways"}, "split-mode must be exclude or include"},
		{[]string{"registration", "license"}, "missing argument: license key"},
		{[]string{"tunnel", "warp-speed"}, `unknown tunnel command "warp-speed"`},
	}
	for _, c := range cases {
		f := newFakeDaemon(t)
		r := runCLI(t, f.sock, c.args...)
		if r.code != 1 || !strings.Contains(r.stderr, c.want) {
			t.Errorf("%v: want exit 1 with %q, got %+v", c.args, c.want, r)
		}
		if n := len(f.requests()); n != 0 {
			t.Errorf("%v: invalid input reached the daemon (%d requests)", c.args, n)
		}
	}
}

func TestCLIValidBoundaryValues(t *testing.T) {
	f := newFakeDaemon(t)
	f.settingsRoutes(state.DefaultSettings())
	for _, c := range []struct {
		args []string
		key  string
		want any
	}{
		{[]string{"tunnel", "mtu", "1280"}, "mtu", 1280.0},
		{[]string{"tunnel", "mtu", "1500"}, "mtu", 1500.0},
		{[]string{"proxy", "port", "1"}, "proxy_port", 1.0},
		{[]string{"proxy", "port", "65535"}, "proxy_port", 65535.0},
		{[]string{"tunnel", "protocol", "set", "WireGuard"}, "protocol", "wireguard"},
		{[]string{"tunnel", "protocol", "reset"}, "protocol", "masque"},
		{[]string{"tunnel", "pq", "off"}, "post_quantum", false},
		{[]string{"tunnel", "endpoint", "set", "192.0.2.1:2408"}, "endpoint_override", "192.0.2.1:2408"},
		{[]string{"tunnel", "endpoint", "reset"}, "endpoint_override", ""},
		{[]string{"dns", "families", "malware"}, "families", "malware"},
		{[]string{"trusted", "wifi", "enable"}, "disable_wifi", true},
		{[]string{"trusted", "ethernet", "disable"}, "disable_ethernet", false},
	} {
		if r := runCLI(t, f.sock, c.args...); r.code != 0 {
			t.Fatalf("%v: %+v", c.args, r)
		}
		if got := f.lastPatch(t)[c.key]; got != c.want {
			t.Errorf("%v: sent %s=%v, want %v", c.args, c.key, got, c.want)
		}
	}
}

func TestCLIConnectionCommands(t *testing.T) {
	f := newFakeDaemon(t)
	f.on("POST /v1/connect", func(map[string]any) (int, any) { return 200, nil })
	f.on("POST /v1/disconnect", func(map[string]any) (int, any) { return 200, nil })
	f.on("POST /v1/tunnel/rotate-keys", func(map[string]any) (int, any) { return 200, nil })
	f.on("POST /v1/settings/reset", func(map[string]any) (int, any) { return 200, state.DefaultSettings() })
	for _, c := range []struct{ args, path string }{
		{"connect", "/v1/connect"},
		{"disconnect", "/v1/disconnect"},
		{"tunnel rotate-keys", "/v1/tunnel/rotate-keys"},
		{"settings reset", "/v1/settings/reset"},
	} {
		r := runCLI(t, f.sock, strings.Fields(c.args)...)
		reqs := f.requests()
		if r.code != 0 || r.stdout != "Success\n" || reqs[len(reqs)-1].Path != c.path || reqs[len(reqs)-1].Method != "POST" {
			t.Fatalf("%s: %+v, last request %+v", c.args, r, reqs[len(reqs)-1])
		}
	}
}

func TestCLIReportsDaemonErrors(t *testing.T) {
	f := newFakeDaemon(t)
	f.on("POST /v1/connect", func(map[string]any) (int, any) {
		return 400, map[string]string{"error": "not registered: run `openwarp registration new`"}
	})
	r := runCLI(t, f.sock, "connect")
	if r.code != 1 || r.stderr != "Error: not registered: run `openwarp registration new`\n" || r.stdout != "" {
		t.Fatalf("daemon error not reported: %+v", r)
	}
	// A non-JSON error body is shown as text.
	f.on("POST /v1/disconnect", func(map[string]any) (int, any) { return 500, "boom" })
	if r := runCLI(t, f.sock, "disconnect"); r.code != 1 || !strings.Contains(r.stderr, "boom") {
		t.Fatalf("plain error body not reported: %+v", r)
	}
}

func TestCLIDaemonUnreachable(t *testing.T) {
	missing := filepath.Join(os.TempDir(), "openwarp-test-missing.sock")
	os.Remove(missing)
	r := runCLI(t, missing, "status")
	if r.code != 1 || !strings.Contains(r.stderr, "cannot reach the openwarp daemon at "+missing) {
		t.Fatalf("unreachable daemon: %+v", r)
	}
}

func TestCLIListEditing(t *testing.T) {
	f := newFakeDaemon(t)
	f.settingsRoutes(state.DefaultSettings())

	runCLI(t, f.sock, "tunnel", "ip", "add", "203.0.113.0/24")
	ips := toStrings(f.lastPatch(t)["split_ips"])
	if len(ips) != len(state.DefaultExcludes)+1 || ips[len(ips)-1] != "203.0.113.0/24" {
		t.Fatalf("add did not append: %v", ips)
	}
	// Adding an existing entry does not duplicate it.
	runCLI(t, f.sock, "tunnel", "ip", "add", "203.0.113.0/24")
	if ips := toStrings(f.lastPatch(t)["split_ips"]); len(ips) != len(state.DefaultExcludes)+1 {
		t.Fatalf("duplicate added: %v", ips)
	}
	runCLI(t, f.sock, "tunnel", "ip", "remove", "10.0.0.0/8")
	if ips := toStrings(f.lastPatch(t)["split_ips"]); slices.Contains(ips, "10.0.0.0/8") {
		t.Fatalf("remove kept the entry: %v", ips)
	}
	r := runCLI(t, f.sock, "tunnel", "ip", "list")
	if r.code != 0 || !strings.Contains(r.stdout, "203.0.113.0/24\n") || strings.Contains(r.stdout, "10.0.0.0/8\n") {
		t.Fatalf("list: %+v", r)
	}
	runCLI(t, f.sock, "tunnel", "ip", "reset")
	if ips := toStrings(f.lastPatch(t)["split_ips"]); !slices.Equal(ips, state.DefaultExcludes) {
		t.Fatalf("reset in exclude mode should restore the defaults: %v", ips)
	}

	runCLI(t, f.sock, "tunnel", "split-mode", "include")
	p := f.lastPatch(t)
	if p["split_mode"] != "include" || len(toStrings(p["split_ips"])) != 0 {
		t.Fatalf("include mode should start with an empty list: %v", p)
	}
	runCLI(t, f.sock, "tunnel", "ip", "reset")
	if ips := toStrings(f.lastPatch(t)["split_ips"]); len(ips) != 0 {
		t.Fatalf("reset in include mode should clear the list: %v", ips)
	}

	runCLI(t, f.sock, "dns", "fallback", "add", "corp.example")
	runCLI(t, f.sock, "dns", "fallback", "reset")
	if d := toStrings(f.lastPatch(t)["fallback_domains"]); !slices.Equal(d, state.DefaultFallbackDomains) {
		t.Fatalf("fallback reset: %v", d)
	}
	runCLI(t, f.sock, "trusted", "ssid", "add", "Home WiFi")
	if s := toStrings(f.lastPatch(t)["trusted_ssids"]); !slices.Equal(s, []string{"Home WiFi"}) {
		t.Fatalf("trusted ssid add: %v", s)
	}
}

func TestCLIRegistrationCommands(t *testing.T) {
	f := newFakeDaemon(t)
	f.on("POST /v1/registration", func(b map[string]any) (int, any) {
		if b["accept_tos"] != true {
			return 400, map[string]string{"error": "you must accept the Cloudflare WARP Terms of Service"}
		}
		return 200, fixtureRegistration()
	})
	f.on("PUT /v1/registration/license", func(map[string]any) (int, any) { return 200, map[string]any{"license": "x"} })
	f.on("DELETE /v1/registration", func(map[string]any) (int, any) { return 200, nil })

	if r := runCLI(t, f.sock, "registration", "new", "--accept-tos"); r.code != 0 || r.stdout != "Success\n" {
		t.Fatalf("registration new: %+v", r)
	}
	// Without --accept-tos and no "y" on stdin, the ToS is declined.
	r := runCLI(t, f.sock, "registration", "new")
	if r.code != 1 || !strings.Contains(r.stdout, "Accept? [y/N]") || !strings.Contains(r.stderr, "Terms of Service") {
		t.Fatalf("declined ToS: %+v", r)
	}
	if b := f.requests()[1].Body; b["accept_tos"] != false {
		t.Fatalf("declined ToS sent %v", b)
	}
	runCLI(t, f.sock, "registration", "license", "TEST0000-TEST0000-TEST0000")
	last := f.requests()[len(f.requests())-1]
	if last.Method != "PUT" || last.Body["license"] != "TEST0000-TEST0000-TEST0000" {
		t.Fatalf("license request: %+v", last)
	}
	if r := runCLI(t, f.sock, "registration", "delete"); r.code != 0 {
		t.Fatalf("delete: %+v", r)
	}
}

func toStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

// ---------- JSON contract with the SwiftUI app ----------

var update = flag.Bool("update", false, "rewrite the JSON contract fixtures in testdata/contract")

// TestCLIJSONContract records the exact `openwarp -j …` output the SwiftUI app
// decodes (ui/macos/Models.swift). The Swift tests decode the same files, so a
// change to a Go json tag that would break the app fails one of the suites.
// Regenerate with: go test ./cmd/openwarp -run TestCLIJSONContract -update
func TestCLIJSONContract(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "contract")
	cases := []struct {
		file  string
		args  []string
		route string
		body  any
	}{
		{"status-connected.json", []string{"-j", "status"}, "GET /v1/status", fixtureStatusConnected()},
		{"status-connecting-error.json", []string{"-j", "status"}, "GET /v1/status", fixtureStatusRetrying()},
		{"status-unregistered.json", []string{"-j", "status"}, "GET /v1/status", fixtureStatusUnregistered()},
		{"settings-default.json", []string{"-j", "settings"}, "GET /v1/settings", state.DefaultSettings()},
		{"registration.json", []string{"-j", "registration", "show"}, "GET /v1/registration", fixtureRegistration()},
		{"devices.json", []string{"-j", "registration", "devices"}, "GET /v1/registration/devices", fixtureDevices()},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f := newFakeDaemon(t)
			body := c.body
			f.on(c.route, func(map[string]any) (int, any) { return 200, body })
			r := runCLI(t, f.sock, c.args...)
			if r.code != 0 {
				t.Fatalf("%v: %+v", c.args, r)
			}
			path := filepath.Join(dir, c.file)
			if *update {
				os.MkdirAll(dir, 0o755)
				if err := os.WriteFile(path, []byte(r.stdout), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (run with -update to create it)", err)
			}
			if string(want) != r.stdout {
				t.Fatalf("`openwarp %s` output changed; update the Swift models and run -update.\n--- want\n%s\n--- got\n%s",
					strings.Join(c.args, " "), want, r.stdout)
			}
		})
	}
}
