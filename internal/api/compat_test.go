package api

// Compatibility tests: the client against recorded response shapes (testdata/compat, synthetic values) and
// against the ways a changed or failing API can answer. All offline. The upstream monitor runs these daily
// (TestAPICompat*), so a regression in how OpenWarp reads the API shows up even without a code change.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func compatFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "compat", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// serve answers every request with status and body, counting requests.
func serve(t *testing.T, status int, body []byte) (*Client, *atomic.Int32) {
	t.Helper()
	n := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	c := New()
	c.BaseURL = srv.URL
	return c, n
}

// Every field the engine reads from a registration or key enrollment.
func checkUsable(t *testing.T, name string, reg *Registration, wantPorts bool) {
	t.Helper()
	cfg := reg.Config
	switch {
	case reg.ID == "":
		t.Errorf("%s: id not read", name)
	case len(cfg.Peers) == 0 || cfg.Peers[0].PublicKey == "":
		t.Errorf("%s: peer public key not read", name)
	case cfg.Peers[0].Endpoint.V4 == "":
		t.Errorf("%s: endpoint v4 not read", name)
	case cfg.Interface.Addresses.V4 == "" || cfg.Interface.Addresses.V6 == "":
		t.Errorf("%s: interface addresses not read", name)
	case cfg.ClientID == "":
		t.Errorf("%s: client_id (WireGuard reserved bytes) not read", name)
	case wantPorts && len(cfg.Peers[0].Endpoint.Ports) == 0:
		t.Errorf("%s: endpoint ports not read", name)
	}
}

func TestAPICompatFixtures(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		file, devType string
		ports         bool
	}{{"register-v0a4471.json", "Android", false}, {"register-v0.json", "macOS", true}, {"register-extra-fields.json", "macOS", false}} {
		c, _ := serve(t, 200, compatFixture(t, tc.file))
		reg, err := c.Register(ctx, "key", tc.devType, "Mac16,8", "en_US")
		if err != nil {
			t.Fatalf("%s: %v", tc.file, err)
		}
		if reg.Token == "" {
			t.Errorf("%s: token not read", tc.file)
		}
		checkUsable(t, tc.file, reg, tc.ports)
	}

	c, _ := serve(t, 200, compatFixture(t, "key-patch-masque-v0.json"))
	c.Identity = MacIdentity
	reg, err := c.SetKey(ctx, "id", "tok", "pub", KeyTypeMasque, TunTypeMasque)
	if err != nil {
		t.Fatal(err)
	}
	checkUsable(t, "key-patch", reg, false)
	if !strings.HasPrefix(reg.Config.Peers[0].PublicKey, "-----BEGIN PUBLIC KEY-----") {
		t.Errorf("MASQUE peer key should be PEM (pinned edge key): %q", reg.Config.Peers[0].PublicKey)
	}

	c, _ = serve(t, 200, compatFixture(t, "account-v0.json"))
	c.Identity = MacIdentity
	acc, err := c.Account(ctx, "id", "tok")
	if err != nil || acc.License == "" || acc.AccountType != "limited" || !acc.WarpPlus || acc.Quota == 0 {
		t.Fatalf("account: %+v %v", acc, err)
	}

	c, _ = serve(t, 200, compatFixture(t, "devices-v0a4471.json"))
	devs, err := c.Devices(ctx, "id", "tok")
	if err != nil || len(devs) != 2 || devs[0].Model != "Mac16,8" || !devs[0].Active || devs[1].Name != "phone" {
		t.Fatalf("devices: %+v %v", devs, err)
	}
}

// A field changing type is a decoding error that names the problem, never a silent zero value or a panic.
func TestAPICompatTypeChangeIsAnError(t *testing.T) {
	body := strings.Replace(string(compatFixture(t, "register-v0.json")), `"ports":[2408,500,1701,4500]`, `"ports":["2408"]`, 1)
	c, _ := serve(t, 200, []byte(body))
	_, err := c.Register(context.Background(), "key", "macOS", "Mac16,8", "en_US")
	if err == nil || !strings.Contains(err.Error(), "ports") {
		t.Fatalf("want an error naming the changed field, got %v", err)
	}
}

func TestAPICompatErrorResponses(t *testing.T) {
	ctx := context.Background()

	// An HTML error page from a proxy or the edge: an APIError with the status, not a JSON error.
	c, _ := serve(t, http.StatusBadGateway, []byte("<html><body><h1>502 Bad Gateway</h1></body></html>"))
	_, err := c.Account(ctx, "id", "tok")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusBadGateway {
		t.Fatalf("502 page: %v", err)
	}

	// 200 with something that is not JSON (a captive portal): an error.
	c, _ = serve(t, 200, []byte("<html>Sign in to the Wi-Fi</html>"))
	if _, err := c.Account(ctx, "id", "tok"); err == nil {
		t.Fatal("non-JSON 200 accepted")
	}

	// Truncated JSON: an error.
	full := compatFixture(t, "register-v0.json")
	c, _ = serve(t, 200, full[:len(full)/2])
	if _, err := c.Register(ctx, "key", "macOS", "Mac16,8", "en_US"); err == nil {
		t.Fatal("truncated registration accepted")
	}

	// Rate limiting under the macOS identity is not "rejected identity": no Android retry.
	c, n := serve(t, http.StatusTooManyRequests, []byte(`{"success":false,"errors":[{"code":10000,"message":"rate limited"}]}`))
	c.Identity = MacIdentity
	if _, err := c.Devices(ctx, "id", "tok"); !errors.As(err, &ae) || ae.Status != http.StatusTooManyRequests {
		t.Fatalf("429: %v", err)
	}
	if n.Load() != 1 {
		t.Fatalf("429 retried %d times with another identity", n.Load()-1)
	}

	// Server errors are not retried with the Android identity either.
	c, n = serve(t, http.StatusInternalServerError, []byte(`{}`))
	c.Identity = MacIdentity
	c.Devices(ctx, "id", "tok")
	if n.Load() != 1 {
		t.Fatalf("5xx retried with another identity (%d requests)", n.Load())
	}

	// An unauthorised token (registration deleted on the server) surfaces as 401.
	c, _ = serve(t, http.StatusUnauthorized, []byte(`{"success":false,"errors":[{"code":10001,"message":"Unauthorized"}]}`))
	c.Identity = AndroidIdentity
	if _, err := c.Get(ctx, "id", "tok"); !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Fatalf("401: %v", err)
	}
}

func TestAPICompatHonoursTheCallerDeadline(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	c := New()
	c.BaseURL = srv.URL
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if _, err := c.Account(ctx, "id", "tok"); err == nil {
		t.Fatal("a hung API call returned no error")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("the call ignored the deadline (%v)", d)
	}
}

// The client never sends credentials anywhere but the configured API, and only over TLS by default.
func TestAPICompatDefaultsAreSafe(t *testing.T) {
	c := New()
	if c.BaseURL != "" || c.Host != DefaultHost {
		t.Fatalf("default target changed: %q %q", c.BaseURL, c.Host)
	}
	tr, ok := c.HTTP.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.InsecureSkipVerify || tr.TLSClientConfig.ServerName != DefaultHost {
		t.Fatal("API TLS verification or SNI changed")
	}
	if c.HTTP.Timeout == 0 {
		t.Fatal("API client has no overall timeout")
	}
}
