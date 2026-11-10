package tunnel

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeTun is an in-memory tun.Device.
type fakeTun struct {
	in     chan []byte // packets the "OS" sends into the tunnel
	out    chan []byte // packets the tunnel delivers to the "OS"
	events chan tun.Event
	once   sync.Once
	closed chan struct{}
}

func newFakeTun() *fakeTun {
	return &fakeTun{in: make(chan []byte, 16), out: make(chan []byte, 16), events: make(chan tun.Event, 1), closed: make(chan struct{})}
}
func (t *fakeTun) File() *os.File           { return nil }
func (t *fakeTun) MTU() (int, error)        { return 1280, nil }
func (t *fakeTun) Name() (string, error)    { return "fake0", nil }
func (t *fakeTun) Events() <-chan tun.Event { return t.events }
func (t *fakeTun) BatchSize() int           { return 1 }
func (t *fakeTun) Close() error             { t.once.Do(func() { close(t.closed) }); return nil }
func (t *fakeTun) Read(bufs [][]byte, sizes []int, off int) (int, error) {
	select {
	case p := <-t.in:
		sizes[0] = copy(bufs[0][off:], p)
		return 1, nil
	case <-t.closed:
		return 0, os.ErrClosed
	}
}
func (t *fakeTun) Write(bufs [][]byte, off int) (int, error) {
	for _, b := range bufs {
		t.out <- append([]byte(nil), b[off:]...)
	}
	return len(bufs), nil
}

func selfSigned(t *testing.T) (tls.Certificate, string) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k},
		string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

type seen struct {
	mu                       sync.Mutex
	proto, authority, method string
	clientCert               bool
	capsule                  string
	firstDatagram            []byte
}

// startEdge runs a minimal CONNECT-IP echo server standing in for the edge.
func startEdge(t *testing.T, cert tls.Certificate, s *seen) netip.AddrPort {
	srv := &http3.Server{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{settingH3Draft00: 1},
		TLSConfig: http3.ConfigureTLSConfig(&tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   tls.RequireAnyClientCert,
		}),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			s.proto, s.authority, s.method = r.Proto, r.Host, r.Method
			s.clientCert = r.TLS != nil && len(r.TLS.PeerCertificates) == 1
			s.capsule = r.Header.Get("Capsule-Protocol")
			s.mu.Unlock()
			if r.Method != http.MethodConnect || r.Proto != MasqueProtocol {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			str, err := w.(http3.HTTPStreamer).HTTPStream()
			if err != nil {
				return
			}
			for {
				d, err := str.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				s.mu.Lock()
				if s.firstDatagram == nil {
					s.firstDatagram = append([]byte(nil), d...)
				}
				s.mu.Unlock()
				str.SendDatagram(d) // echo, context id included
			}
		}),
	}
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(pc)
	t.Cleanup(func() { srv.Close(); pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).AddrPort()
}

func TestMasqueConnectIP(t *testing.T) {
	cert, peerPEM := selfSigned(t)
	var s seen
	ep := startEdge(t, cert, &s)

	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := NewMasque(MasqueConfig{PrivateKey: ck, PeerPublicKey: peerPEM, PostQuantum: true})
	dev := newFakeTun()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := m.Start(ctx, dev, ep); err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	pkt := []byte{0x45, 0, 0, 20, 1, 2, 3, 4, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}
	dev.in <- pkt
	select {
	case got := <-dev.out:
		if !bytes.Equal(got, pkt) {
			t.Fatalf("echo mismatch: %x != %x", got, pkt)
		}
	case <-ctx.Done():
		t.Fatal("no echo")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.method != http.MethodConnect || s.proto != "cf-connect-ip" || s.authority != "cloudflareaccess.com" {
		t.Fatalf("request = %s %s %s", s.method, s.proto, s.authority)
	}
	if !s.clientCert {
		t.Fatal("client certificate not presented")
	}
	if s.capsule != "?1" {
		t.Fatalf("capsule-protocol = %q", s.capsule)
	}
	if s.firstDatagram[0] != 0 || !bytes.Equal(s.firstDatagram[1:], pkt) {
		t.Fatalf("datagram not context-id-0 framed: %x", s.firstDatagram)
	}
	if st := m.Stats(); st.TxPackets != 1 || st.RxPackets != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestMasqueRejectsWrongEdgeKey(t *testing.T) {
	cert, _ := selfSigned(t)
	_, otherPEM := selfSigned(t)
	var s seen
	ep := startEdge(t, cert, &s)
	ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	m := NewMasque(MasqueConfig{PrivateKey: ck, PeerPublicKey: otherPEM})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := m.Start(ctx, newFakeTun(), ep)
	if err == nil {
		m.Close()
		t.Fatal("expected pinning failure")
	}
	var te *quic.TransportError
	if !errors.As(err, &te) && !bytes.Contains([]byte(err.Error()), []byte("does not match")) {
		t.Logf("error (acceptable): %v", err)
	}
}

func TestVarint(t *testing.T) {
	for _, c := range []struct {
		b []byte
		v uint64
		n int
	}{{[]byte{0}, 0, 1}, {[]byte{0x40, 0x25}, 37, 2}, {[]byte{0x80, 0, 0, 1}, 1, 4}} {
		v, n := readVarint(c.b)
		if v != c.v || n != c.n {
			t.Fatalf("%x -> %d,%d", c.b, v, n)
		}
	}
	_ = io.EOF
}
