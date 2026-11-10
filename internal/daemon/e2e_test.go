package daemon

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/buildinfo"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

// mockEdge is a CONNECT-IP server whose far side is a gVisor netstack
// "internet" hosting an HTTP server at 10.9.0.1:80.
func mockEdge(t *testing.T) (netip.AddrPort, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	pemPub := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))

	inetTun, inet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := inet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 9, 0, 1), Port: 80})
	go http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from the edge")
	}))

	// One reader for internet -> client, sending to the current CONNECT-IP stream. (A reader per stream
	// would outlive its stream after a reconnect and swallow packets meant for the new one.)
	type datagramSender interface{ SendDatagram([]byte) error }
	var curMu sync.Mutex
	var cur datagramSender
	go func() {
		bufs, sizes := [][]byte{make([]byte, 65535)}, []int{0}
		for {
			n, err := inetTun.Read(bufs, sizes, 1)
			if err != nil {
				return
			}
			curMu.Lock()
			str := cur
			curMu.Unlock()
			if n == 1 && str != nil {
				b := bufs[0][:1+sizes[0]]
				b[0] = 0
				str.SendDatagram(append([]byte(nil), b...))
			}
		}
	}()

	srv := &http3.Server{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{0x276: 1},
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: k}},
			ClientAuth:   tls.RequireAnyClientCert,
		}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Proto != "cf-connect-ip" {
				w.WriteHeader(400)
				return
			}
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			str, _ := w.(http3.HTTPStreamer).HTTPStream()
			curMu.Lock()
			cur = str
			curMu.Unlock()
			for { // client -> internet
				d, err := str.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				if len(d) > 1 && d[0] == 0 {
					inetTun.Write([][]byte{append([]byte(nil), d[1:]...)}, 0)
				}
			}
		}),
	}
	pc, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Close(); pc.Close(); inetTun.Close() })
	return pc.LocalAddr().(*net.UDPAddr).AddrPort(), pemPub
}

// mockAPI imitates the WARP consumer registration API.
func mockAPI(t *testing.T, edgePEM string) (*httptest.Server, *sync.Map) {
	calls := &sync.Map{}
	cfg := func(peerKey, v4 string) api.Config {
		var c api.Config
		c.ClientID = base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
		c.Peers = []api.Peer{{PublicKey: peerKey, Endpoint: api.Endpoint{V4: v4, V6: "[2606:4700:103::1]:0"}}}
		c.Interface.Addresses.V4 = "172.16.0.2"
		c.Interface.Addresses.V6 = "2606:4700:110:8000::2"
		return c
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v0a4471/reg", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		calls.Store("register", in)
		calls.Store("register-client-version", r.Header.Get("CF-Client-Version"))
		if r.Header.Get("CF-Client-Version") == "" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(api.Registration{
			ID: "reg-1", Token: "tok-1", Account: api.Account{ID: "acc-1", AccountType: "free", License: "LIC-1"},
			Config: cfg("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "162.159.192.1:0"),
		})
	})
	mux.HandleFunc("PATCH /v0a4471/reg/reg-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-1" {
			w.WriteHeader(401)
			return
		}
		var in map[string]string
		json.NewDecoder(r.Body).Decode(&in)
		calls.Store("patch", in)
		der, err := base64.StdEncoding.DecodeString(in["key"])
		if _, perr := x509.ParsePKIXPublicKey(der); err != nil || perr != nil || in["key_type"] != "secp256r1" || in["tunnel_type"] != "masque" {
			w.WriteHeader(400)
			return
		}
		json.NewEncoder(w).Encode(api.Registration{ID: "reg-1", Config: cfg(edgePEM, "162.159.198.1:0")})
	})
	mux.HandleFunc("GET /v0a4471/reg/reg-1/account", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(api.Account{ID: "acc-1", AccountType: "free", License: "LIC-1"})
	})
	// /v0/ (macOS identity) serves the same routes wrapped in the
	// {"result": ..., "success": true} envelope, like the real API.
	root := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rest, ok := strings.CutPrefix(r.URL.Path, "/v0/")
		if !ok {
			mux.ServeHTTP(w, r)
			return
		}
		calls.Store("v0:"+r.Method+" "+rest, r.Header.Get("CF-Client-Version"))
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/v0a4471/" + rest
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, r2)
		if rec.Code/100 != 2 {
			w.WriteHeader(rec.Code)
			w.Write(rec.Body.Bytes())
			return
		}
		res := bytes.TrimSpace(rec.Body.Bytes())
		if len(res) == 0 {
			res = []byte("null")
		}
		fmt.Fprintf(w, `{"result":%s,"success":true,"errors":[],"messages":[]}`, res)
	})
	ts := httptest.NewTLSServer(root)
	t.Cleanup(ts.Close)
	return ts, calls
}

func freePort(t *testing.T) int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestEndToEndProxyModeOverMasque(t *testing.T) {
	edge, edgePEM := mockEdge(t)
	ts, calls := mockAPI(t, edgePEM)

	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client := &api.Client{BaseURL: ts.URL, Identity: api.MacIdentity, HTTP: ts.Client()}
	eng := NewEngineWithAPI(store, client)
	defer eng.Shutdown()

	// Control API over a unix socket, exactly as the CLI uses it.
	sock := t.TempDir() + "/c.sock"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go eng.Serve(ctx, sock)
	ctl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return net.Dial("unix", sock)
	}}}
	do := func(method, path, body string) (int, string) {
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest(method, "http://x"+path, strings.NewReader(body))
			resp, err := ctl.Do(req)
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return resp.StatusCode, string(b)
		}
		t.Fatal("control socket unreachable")
		return 0, ""
	}

	if code, body := do("POST", "/v1/registration", `{"accept_tos":false}`); code == 200 {
		t.Fatalf("registration without ToS should fail: %s", body)
	}
	if code, body := do("POST", "/v1/registration", `{"accept_tos":true}`); code != 200 {
		t.Fatalf("register: %d %s", code, body)
	}
	reg, _ := calls.Load("register")
	if k, _ := reg.(map[string]any)["key"].(string); len(k) != 44 {
		t.Fatalf("register did not send a WireGuard key: %v", reg)
	}

	port := freePort(t)
	patch := fmt.Sprintf(`{"mode":"proxy","protocol":"masque","endpoint_override":%q,"proxy_port":%d}`, edge.String(), port)
	if code, body := do("PATCH", "/v1/settings", patch); code != 200 {
		t.Fatalf("settings: %s", body)
	}
	if code, body := do("PATCH", "/v1/settings", `{"mode":"bogus"}`); code == 200 {
		t.Fatalf("invalid mode accepted: %s", body)
	}
	if code, body := do("POST", "/v1/connect", ""); code != 200 {
		t.Fatalf("connect: %s", body)
	}

	var st Status
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, body := do("GET", "/v1/status", "")
		json.Unmarshal([]byte(body), &st)
		if st.Status == StatusConnected {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if st.Status != StatusConnected {
		t.Fatalf("not connected: %+v", st)
	}
	if p, ok := calls.Load("patch"); !ok || p.(map[string]string)["key_type"] != "secp256r1" {
		t.Fatalf("MASQUE key was not enrolled: %v", p)
	}
	// Key enrollment uses the client's identity (macOS here) through the
	// enveloped /v0/ API, with no silent fallback to the Android paths.
	if cv, ok := calls.Load("v0:PATCH reg/reg-1"); !ok || cv != api.MacClientVersion {
		t.Fatalf("key enrollment not sent with the macOS identity (got %v)", cv)
	}
	// Registration uses the identity matching the device type: macOS on a Mac,
	// the default (Android) identity elsewhere, e.g. the Linux CI runner.
	cv, _ := calls.Load("register-client-version")
	if typ, _ := deviceIdentity(); typ == "macOS" {
		if v0, ok := calls.Load("v0:POST reg"); !ok || v0 != api.MacClientVersion || cv != api.MacClientVersion {
			t.Fatalf("registration not sent with the macOS identity (got %v)", v0)
		}
	} else if _, viaV0 := calls.Load("v0:POST reg"); viaV0 || cv != api.ClientVersion {
		t.Fatalf("%s registration should use the default identity (via v0: %v, client version %v)", typ, viaV0, cv)
	}

	for _, scheme := range []string{"socks5", "http"} {
		pu, _ := url.Parse(fmt.Sprintf("%s://127.0.0.1:%d", scheme, port))
		hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
		resp, err := hc.Get("http://10.9.0.1/")
		if err != nil {
			t.Fatalf("%s proxy: %v", scheme, err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(b) != "hello from the edge" {
			t.Fatalf("%s proxy body %q", scheme, b)
		}
	}

	_, body := do("GET", "/v1/status", "")
	json.Unmarshal([]byte(body), &st)
	if st.Tunnel == nil || st.Tunnel.RxBytes == 0 || st.Proxy == "" {
		t.Fatalf("stats missing: %s", body)
	}
	t.Logf("status: %s", body)
	if st.Version != buildinfo.Version {
		t.Fatalf("status reports version %q, want %q", st.Version, buildinfo.Version)
	}
	// Usage covers the whole connection: equal to the transport's counters so far...
	if st.Usage == nil || st.Usage.RxBytes != st.Tunnel.RxBytes || st.Usage.TxBytes != st.Tunnel.TxBytes || st.Usage.Since.IsZero() {
		t.Fatalf("usage should match the first transport: %s", body)
	}
	before := *st.Usage

	// ...and keeps counting across a reconnect, while the new transport's counters restart.
	eng.reconnect()
	waitConnected := func() {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			_, body = do("GET", "/v1/status", "")
			st = Status{}
			json.Unmarshal([]byte(body), &st)
			if st.Status == StatusConnected && st.Tunnel != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("not connected again: %s", body)
	}
	waitConnected()
	pu, _ := url.Parse(fmt.Sprintf("socks5://127.0.0.1:%d", port))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	resp, err := hc.Get("http://10.9.0.1/")
	if err != nil {
		t.Fatalf("proxy after reconnect: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	_, body = do("GET", "/v1/status", "")
	json.Unmarshal([]byte(body), &st)
	// At least: packets can still reach the old transport (TCP teardown) between the snapshot and the reconnect.
	if st.Usage == nil || st.Usage.RxBytes < before.RxBytes+st.Tunnel.RxBytes || st.Usage.TxBytes < before.TxBytes+st.Tunnel.TxBytes ||
		!st.Usage.Since.Equal(before.Since) {
		t.Fatalf("usage after reconnect = %+v, want at least %d + %d since %v", st.Usage, before.RxBytes, st.Tunnel.RxBytes, before.Since)
	}
	if st.Tunnel.RxBytes >= st.Usage.RxBytes {
		t.Fatalf("the new transport's counters should have restarted: tunnel %d, usage %d", st.Tunnel.RxBytes, st.Usage.RxBytes)
	}

	do("POST", "/v1/disconnect", "")
	_, body = do("GET", "/v1/status", "")
	st = Status{}
	json.Unmarshal([]byte(body), &st)
	if st.Status != StatusDisconnected {
		t.Fatalf("after disconnect: %s", body)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("proxy still listening after disconnect")
	}
	if st.Usage != nil {
		t.Fatalf("usage reported while disconnected: %s", body)
	}

	// A new connection starts counting from zero.
	do("POST", "/v1/connect", "")
	waitConnected()
	if st.Usage == nil || st.Usage.RxBytes > st.Tunnel.RxBytes || !st.Usage.Since.After(before.Since) {
		t.Fatalf("usage not reset for a new connection: %s", body)
	}
}
