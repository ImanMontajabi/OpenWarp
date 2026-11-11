package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

// enrollHarness registers against a mock API whose key PATCH answers with patchBody.
func enrollHarness(t *testing.T, patchBody string) (*Engine, *state.Store, *atomic.Int32) {
	t.Helper()
	patches := &atomic.Int32{}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0a4471/reg", func(w http.ResponseWriter, r *http.Request) {
		var c api.Config
		c.Peers = []api.Peer{{PublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="}}
		json.NewEncoder(w).Encode(api.Registration{ID: "reg-1", Token: "tok-1", Config: c})
	})
	mux.HandleFunc("PATCH /v0a4471/reg/reg-1", func(w http.ResponseWriter, r *http.Request) {
		patches.Add(1)
		w.Write([]byte(patchBody))
	})
	ts := httptest.NewTLSServer(mux)
	t.Cleanup(ts.Close)
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	eng := NewEngineWithAPI(store, &api.Client{BaseURL: ts.URL, Identity: api.AndroidIdentity, HTTP: ts.Client()})
	t.Cleanup(eng.Shutdown)
	if _, err := eng.Register(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	return eng, store, patches
}

// Regression: a key enrollment answer without peers was cached and then indexed (cfg.Peers[0]) when an
// endpoint override skipped the candidate check, which crashed the daemon with "index out of range".
func TestKeyEnrollmentWithoutPeersIsAnErrorNotACrash(t *testing.T) {
	for name, body := range map[string]string{
		"empty peers":       `{"id":"reg-1","config":{"peers":[]}}`,
		"no config":         `{"id":"reg-1"}`,
		"peer without key":  `{"id":"reg-1","config":{"peers":[{"public_key":""}]}}`,
		"enveloped, empty":  `{"result":{"id":"reg-1","config":{"peers":[]}},"success":true,"errors":[]}`,
		"result is null":    `{"result":null,"success":true,"errors":[]}`,
		"unrelated payload": `{"message":"ok"}`,
	} {
		t.Run(name, func(t *testing.T) {
			eng, store, patches := enrollHarness(t, body)
			set := store.S.Settings
			set.Mode, set.Protocol, set.EndpointOverride = state.ModeProxy, state.ProtoMasque, "127.0.0.1:9"

			s, err := eng.startSession(context.Background(), set)
			if s != nil {
				s.close()
			}
			if err == nil || !strings.Contains(err.Error(), "no usable peer") {
				t.Fatalf("want a 'no usable peer' error, got %v", err)
			}
			// Nothing unusable is cached: the next attempt enrolls again instead of reusing it.
			if store.S.MasqueConfig != nil || store.S.ActiveKeyType == api.KeyTypeMasque {
				t.Fatalf("unusable config cached: active=%s masque=%+v", store.S.ActiveKeyType, store.S.MasqueConfig)
			}
			if _, err := eng.startSession(context.Background(), set); err == nil {
				t.Fatal("second attempt should fail the same way")
			}
			if n := patches.Load(); n != 2 {
				t.Fatalf("key PATCHed %d times, want 2 (no caching of the bad answer)", n)
			}
		})
	}
}
