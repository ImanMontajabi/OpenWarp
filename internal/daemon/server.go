package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/keys"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

// SocketPath returns the control socket path. Root daemons use /var/run so
// that unprivileged CLI/GUI processes can find them.
func SocketPath() string {
	if p := os.Getenv("OPENWARP_SOCKET"); p != "" {
		return p
	}
	if os.Geteuid() == 0 {
		return "/var/run/openwarp.sock"
	}
	if _, err := os.Stat("/var/run/openwarp.sock"); err == nil {
		return "/var/run/openwarp.sock"
	}
	return filepath.Join(state.DefaultDir(), "openwarp.sock")
}

type RegistrationView struct {
	ID          string    `json:"id"`
	AccountID   string    `json:"account_id"`
	AccountType string    `json:"account_type"`
	WarpPlus    bool      `json:"warp_plus"`
	PremiumData int64     `json:"premium_data"`
	Quota       int64     `json:"quota"`
	License     string    `json:"license"`
	PublicKey   string    `json:"public_key"`
	KeyType     string    `json:"key_type"`
	InterfaceV4 string    `json:"interface_v4"`
	InterfaceV6 string    `json:"interface_v6"`
	Created     string    `json:"created"`
	Peer        *api.Peer `json:"peer,omitempty"`
}

func (e *Engine) RegistrationView() (*RegistrationView, error) {
	e.store.Lock()
	defer e.store.Unlock()
	s := e.store.S
	if s.Registration == nil {
		return nil, errors.New("not registered: run `openwarp registration new`")
	}
	r := s.Registration
	v := &RegistrationView{
		ID: r.ID, AccountID: r.Account.ID, AccountType: r.Account.AccountType, WarpPlus: r.Account.WarpPlus,
		PremiumData: r.Account.PremiumData, Quota: r.Account.Quota, License: r.Account.License,
		KeyType: s.ActiveKeyType, Created: r.Created,
	}
	cfg := s.WireGuardConfig
	if s.ActiveKeyType == api.KeyTypeMasque {
		v.PublicKey, _ = keys.ECDSAPublicPKIX(s.ECDSAKey)
		cfg = s.MasqueConfig
	} else if s.WireGuardKey != nil {
		v.PublicKey = s.WireGuardKey.Public
	}
	if cfg != nil {
		v.InterfaceV4, v.InterfaceV6 = cfg.Interface.Addresses.V4, cfg.Interface.Addresses.V6
		if len(cfg.Peers) > 0 {
			p := cfg.Peers[0]
			v.Peer = &p
		}
	}
	return v, nil
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if v == nil {
		v = map[string]bool{"ok": true}
	}
	json.NewEncoder(w).Encode(v)
}

func (e *Engine) Handler() http.Handler {
	mux := http.NewServeMux()
	ctxT := func(r *http.Request) (context.Context, context.CancelFunc) {
		return context.WithTimeout(r.Context(), 45*time.Second)
	}
	mux.HandleFunc("GET /v1/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, e.Status(), nil) })
	mux.HandleFunc("POST /v1/connect", func(w http.ResponseWriter, r *http.Request) {
		if _, err := e.registration(); err != nil {
			writeJSON(w, nil, err)
			return
		}
		e.Connect()
		writeJSON(w, nil, nil)
	})
	mux.HandleFunc("POST /v1/disconnect", func(w http.ResponseWriter, r *http.Request) { e.Disconnect(); writeJSON(w, nil, nil) })
	// Verify the current connection; ?cloudflare=1 adds the trace request to Cloudflare through the tunnel.
	mux.HandleFunc("POST /v1/verify", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := ctxT(r)
		defer cancel()
		v, err := e.Verify(ctx, r.URL.Query().Get("cloudflare") == "1")
		writeJSON(w, v, err)
	})

	mux.HandleFunc("GET /v1/settings", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, e.Settings(), nil) })
	mux.HandleFunc("PATCH /v1/settings", func(w http.ResponseWriter, r *http.Request) {
		var patch map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&patch); err != nil {
			writeJSON(w, nil, err)
			return
		}
		s, err := e.UpdateSettings(func(s *state.Settings) error {
			cur, _ := json.Marshal(s)
			var m map[string]json.RawMessage
			json.Unmarshal(cur, &m)
			for k, v := range patch {
				if _, ok := m[k]; !ok && k != "endpoint_override" {
					return errors.New("unknown setting " + k)
				}
				m[k] = v
			}
			b, _ := json.Marshal(m)
			var n state.Settings
			if err := json.Unmarshal(b, &n); err != nil {
				return err
			}
			*s = n
			return nil
		})
		writeJSON(w, s, err)
	})
	mux.HandleFunc("POST /v1/settings/reset", func(w http.ResponseWriter, r *http.Request) {
		s, err := e.UpdateSettings(func(s *state.Settings) error {
			// Resetting never silently drops protection the user switched on.
			on, ks := s.AlwaysOn, s.KillSwitch
			*s = state.DefaultSettings()
			s.AlwaysOn, s.KillSwitch = on, ks
			return nil
		})
		writeJSON(w, s, err)
	})

	mux.HandleFunc("GET /v1/registration", func(w http.ResponseWriter, r *http.Request) {
		v, err := e.RegistrationView()
		writeJSON(w, v, err)
	})
	mux.HandleFunc("POST /v1/registration", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			AcceptToS bool `json:"accept_tos"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		ctx, cancel := ctxT(r)
		defer cancel()
		if _, err := e.Register(ctx, in.AcceptToS); err != nil {
			writeJSON(w, nil, err)
			return
		}
		v, err := e.RegistrationView()
		writeJSON(w, v, err)
	})
	mux.HandleFunc("DELETE /v1/registration", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := ctxT(r)
		defer cancel()
		writeJSON(w, nil, e.DeleteRegistration(ctx))
	})
	mux.HandleFunc("GET /v1/registration/account", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := ctxT(r)
		defer cancel()
		a, err := e.RefreshAccount(ctx)
		writeJSON(w, a, err)
	})
	mux.HandleFunc("PUT /v1/registration/license", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			License string `json:"license"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		ctx, cancel := ctxT(r)
		defer cancel()
		a, err := e.SetLicense(ctx, in.License)
		writeJSON(w, a, err)
	})
	mux.HandleFunc("GET /v1/registration/devices", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := ctxT(r)
		defer cancel()
		d, err := e.Devices(ctx)
		writeJSON(w, d, err)
	})
	mux.HandleFunc("POST /v1/tunnel/rotate-keys", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := ctxT(r)
		defer cancel()
		writeJSON(w, nil, e.RotateKeys(ctx))
	})
	return mux
}

// SetAccess sets who may use the control socket (before Serve).
func (e *Engine) SetAccess(a Access) { e.access = &a }

// Serve listens on the unix control socket until ctx is cancelled. Every request but the status needs an
// authorized peer (access.go).
func (e *Engine) Serve(ctx context.Context, path string) error {
	access := DefaultAccess()
	if e.access != nil {
		access = *e.access
	}
	os.Remove(path)
	os.MkdirAll(filepath.Dir(path), 0o755)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	// The root service's socket is open to every local user, who may read the status; anything else is
	// authorized per request from the kernel-reported peer credentials. A user daemon's socket is private.
	mode := os.FileMode(0o600)
	if os.Geteuid() == 0 {
		mode = 0o666
	}
	if err := os.Chmod(path, mode); err != nil {
		ln.Close()
		return err
	}
	srv := &http.Server{Handler: access.Wrap(e.Handler()), ConnContext: connContext, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	log.Printf("control socket: %s", path)
	err = srv.Serve(ln)
	os.Remove(path)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
