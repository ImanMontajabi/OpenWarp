package tunnel

// Compatibility tests: how the MASQUE transport behaves when the edge answers differently from today's
// Cloudflare edge (refuses CONNECT-IP, stays silent, drops the tunnel). Offline, against local servers.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go/http3"
)

func startEdgeHandler(t *testing.T, cert tls.Certificate, h http.HandlerFunc) netip.AddrPort {
	t.Helper()
	srv := &http3.Server{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{settingH3Draft00: 1},
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
		}),
		Handler: h,
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Close(); pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func newClient(t *testing.T, peerPEM string) *Masque {
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	return NewMasque(MasqueConfig{PrivateKey: ck, PeerPublicKey: peerPEM})
}

// An edge that refuses CONNECT-IP (a changed protocol name, a revoked key) is an error naming the status.
func TestMasqueCompatRefusedConnect(t *testing.T) {
	cert, peerPEM := selfSigned(t)
	ep := startEdgeHandler(t, cert, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) })
	m := newClient(t, peerPEM)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := m.Start(ctx, newFakeTun(), ep)
	if err == nil {
		m.Close()
		t.Fatal("refused CONNECT-IP accepted")
	}
	if !strings.Contains(err.Error(), "refused") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should say the edge refused with 403: %v", err)
	}
}

// A silent edge (UDP blocked, wrong port) fails within the caller's deadline, so the engine can move on to
// the next port.
func TestMasqueCompatSilentEdgeHonoursDeadline(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0") // reads nothing, answers nothing
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	_, peerPEM := selfSigned(t)
	m := newClient(t, peerPEM)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	if err := m.Start(ctx, newFakeTun(), pc.LocalAddr().(*net.UDPAddr).AddrPort()); err == nil {
		m.Close()
		t.Fatal("handshake with a silent edge succeeded")
	}
	if d := time.Since(t0); d > 3*time.Second {
		t.Fatalf("Start ignored the deadline (%v)", d)
	}
}

// When the edge ends the tunnel after it was established, Done reports it: that is what triggers the
// engine's reconnect.
func TestMasqueCompatTunnelDeathIsReported(t *testing.T) {
	cert, peerPEM := selfSigned(t)
	ep := startEdgeHandler(t, cert, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
		if s, ok := w.(http3.HTTPStreamer); ok {
			if str, err := s.HTTPStream(); err == nil {
				str.CancelRead(0x100)
				str.Close()
			}
		}
	})
	m := newClient(t, peerPEM)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Start(ctx, newFakeTun(), ep); err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	select {
	case err := <-m.Done():
		if err == nil {
			t.Fatal("Done delivered a nil error for a dropped tunnel")
		}
	case <-time.After(8 * time.Second):
		t.Fatal("a tunnel the edge closed was not reported")
	}
}
