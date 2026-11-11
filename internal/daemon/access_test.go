package daemon

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// serveWith runs the engine's control socket with the given access policy and returns a client for it.
func serveWith(t *testing.T, c *controlHarness, a Access) (do func(method, path, body string) (int, string), sock string) {
	t.Helper()
	c.eng.SetAccess(a)
	// Unix socket paths must stay under 104 bytes; t.TempDir() includes the (long) test name.
	dir, err := os.MkdirTemp("", "ow")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = dir + "/c.sock"
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		if err := c.eng.Serve(ctx, sock); err != nil {
			t.Errorf("Serve: %v", err)
		}
		close(done)
	}()
	t.Cleanup(func() { cancel(); <-done })
	ctl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", sock)
	}}}
	return func(method, path, body string) (int, string) {
		t.Helper()
		for i := 0; i < 100; i++ {
			req, _ := http.NewRequest(method, "http://openwarp"+path, strings.NewReader(body))
			resp, err := ctl.Do(req)
			if err != nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp.StatusCode, string(b)
		}
		t.Fatal("control socket unreachable")
		return 0, ""
	}, sock
}

// A local user the policy does not admit can read the status and nothing else. In particular it cannot
// switch the kill switch off, change the mode or split-tunnel lists, disconnect, or read the registration
// (which holds the license key). The identity comes from the kernel (the socket's peer credentials), not
// from anything the client sends.
func TestControlSocketRefusesUnauthorizedUsers(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is always allowed; run the tests as a normal user")
	}
	c := newControlHarness(t)
	if code, _ := c.do("PATCH", "/v1/settings", `{"kill_switch": true}`); code != 200 {
		t.Fatalf("enabling the kill switch: %d", code)
	}
	do, _ := serveWith(t, c, Access{}) // nobody but root

	if code, body := do("GET", "/v1/status", ""); code != 200 || !strings.Contains(body, `"status"`) {
		t.Fatalf("status: %d %s", code, body)
	}
	for _, r := range []struct{ method, path, body string }{
		{"PATCH", "/v1/settings", `{"kill_switch": false}`},
		{"PATCH", "/v1/settings", `{"mode": "proxy"}`},
		{"PATCH", "/v1/settings", `{"split_ips": ["0.0.0.0/1", "128.0.0.0/1"]}`},
		{"POST", "/v1/settings/reset", ""},
		{"GET", "/v1/settings", ""},
		{"POST", "/v1/connect", ""},
		{"POST", "/v1/disconnect", ""},
		{"POST", "/v1/verify", ""},
		{"GET", "/v1/registration", ""},
		{"DELETE", "/v1/registration", ""},
		{"PUT", "/v1/registration/license", `{"license": "x"}`},
		{"GET", "/v1/registration/devices", ""},
		{"POST", "/v1/tunnel/rotate-keys", ""},
		{"GET", "/v1/status/../settings", ""},
	} {
		code, body := do(r.method, r.path, r.body)
		if code != http.StatusForbidden || !strings.Contains(body, "not allowed") {
			t.Errorf("%s %s: %d %s, want 403", r.method, r.path, code, body)
		}
	}
	if s := c.savedSettings(); !s.KillSwitch || s.Mode == "proxy" {
		t.Fatalf("a refused request changed the settings: %+v", s)
	}
}

// The user the policy admits (here the test's own user, as for the user who installed the service) has full
// control over the same socket.
func TestControlSocketAdmitsListedUser(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run the tests as a normal user")
	}
	c := newControlHarness(t)
	do, _ := serveWith(t, c, Access{UIDs: []uint32{uint32(os.Getuid())}})
	if code, body := do("PATCH", "/v1/settings", `{"kill_switch": true}`); code != 200 {
		t.Fatalf("PATCH: %d %s", code, body)
	}
	if code, body := do("GET", "/v1/settings", ""); code != 200 || !strings.Contains(body, `"kill_switch":true`) {
		t.Fatalf("GET settings: %d %s", code, body)
	}
}

// A daemon that is not root keeps its socket private to its user.
func TestUserDaemonSocketIsPrivate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("run the tests as a normal user")
	}
	c := newControlHarness(t)
	do, sock := serveWith(t, c, DefaultAccess())
	do("GET", "/v1/status", "")
	fi, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("socket mode %v, want 0600", perm)
	}
}

func TestAccessPolicy(t *testing.T) {
	groups := func(uid uint32) ([]uint32, error) {
		switch uid {
		case 501:
			return []uint32{20, 12, 61, 80}, nil // an administrator
		case 502:
			return []uint32{20, 12, 61}, nil // a standard user
		}
		return nil, errors.New("no such user")
	}
	root := Access{Admins: true, groups: groups}
	for uid, want := range map[uint32]bool{0: true, 501: true, 502: false, 503: false} {
		if err := root.Allows(Peer{UID: uid}); (err == nil) != want {
			t.Errorf("root service, uid %d: %v", uid, err)
		}
	}
	// The installing user is admitted without being an administrator.
	owner := Access{UIDs: []uint32{502}, Admins: true, groups: groups}
	if err := owner.Allows(Peer{UID: 502}); err != nil {
		t.Errorf("installing user refused: %v", err)
	}
	// Without Admins, group membership counts for nothing.
	user := Access{UIDs: []uint32{502}, groups: groups}
	if err := user.Allows(Peer{UID: 501}); !errors.Is(err, ErrForbidden) {
		t.Errorf("administrator admitted to a user daemon: %v", err)
	}
	if def := DefaultAccess(); os.Geteuid() != 0 && (def.Admins || len(def.UIDs) != 1 || def.UIDs[0] != uint32(os.Geteuid())) {
		t.Errorf("DefaultAccess for a user daemon = %+v", def)
	}
}

// Without peer credentials (a connection that is not a unix socket) only the status is served.
func TestAccessWithoutPeerCredentials(t *testing.T) {
	c := newControlHarness(t)
	h := Access{UIDs: []uint32{uint32(os.Getuid())}}.Wrap(c.eng.Handler())
	for path, want := range map[string]int{"/v1/status": 200, "/v1/settings": 403} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("GET %s: %d, want %d", path, rec.Code, want)
		}
	}
}

// A refused request is logged with its method and path quoted, so a client cannot forge log lines (a path with
// a newline would otherwise start a new, fake entry in /var/log/openwarp.log).
func TestRefusalLogCannotBeForged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	c := newControlHarness(t)
	h := Access{}.Wrap(c.eng.Handler())
	req := httptest.NewRequest("GET", "/v1/settings", nil)
	req.URL.Path = "/v1/settings\n2026/11/11 01:00:00 kill switch: off"
	h.ServeHTTP(httptest.NewRecorder(), req)
	out := buf.String()
	if strings.Count(strings.TrimSpace(out), "\n") != 0 || !strings.Contains(out, `\n2026/11/11`) {
		t.Fatalf("log line not escaped: %q", out)
	}
}
