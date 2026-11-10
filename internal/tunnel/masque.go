package tunnel

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.zx2c4.com/wireguard/tun"
)

// Values recovered from the official daemon (warp-edge h3_tun):
//
//	SNI "consumer-masque.cloudflareclient.com", request authority
//	"cloudflareaccess.com", extended CONNECT :protocol "cf-connect-ip",
//	HTTP datagrams with quarter-stream-id + context id 0 (RFC 9297/9484),
//	TLS client auth with a self-signed cert built from the registered
//	secp256r1 key ("Failed to create a self-signed client certificate").
const (
	MasqueSNI        = "consumer-masque.cloudflareclient.com"
	MasqueAuthority  = "cloudflareaccess.com"
	MasqueProtocol   = "cf-connect-ip"
	settingH3Draft00 = 0x276 // SETTINGS_H3_DATAGRAM (draft-00 code point)
)

type MasqueConfig struct {
	PrivateKey    *ecdsa.PrivateKey
	PeerPublicKey string // PEM (PKIX) public key of the edge, from the registration
	SNI           string
	PostQuantum   bool
	MTU           int
}

type Masque struct {
	cfg      MasqueConfig
	endpoint netip.AddrPort
	udp      *net.UDPConn
	qconn    *quic.Conn
	stream   *http3.RequestStream
	dev      tun.Device
	cancel   context.CancelFunc
	c        counters
	start    time.Time
	rtt      time.Duration
	tlsInfo  string
	done     chan error
	once     sync.Once
}

func NewMasque(cfg MasqueConfig) *Masque {
	if cfg.SNI == "" {
		cfg.SNI = MasqueSNI
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	return &Masque{cfg: cfg, done: make(chan error, 1)}
}

func selfSignedCert(k *ecdsa.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}, nil
}

func parsePeerKey(p string) (any, error) {
	b, _ := pem.Decode([]byte(p))
	if b == nil {
		return nil, errors.New("peer public key is not PEM")
	}
	return x509.ParsePKIXPublicKey(b.Bytes)
}

func (m *Masque) tlsConfig() (*tls.Config, error) {
	cert, err := selfSignedCert(m.cfg.PrivateKey)
	if err != nil {
		return nil, err
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   m.cfg.SNI,
		NextProtos:   []string{http3.NextProtoH3},
		MinVersion:   tls.VersionTLS13,
	}
	if !m.cfg.PostQuantum {
		conf.CurvePreferences = []tls.CurveID{tls.X25519, tls.CurveP256}
	}
	// Pin the edge key delivered in the registration when we have one.
	if pk, err := parsePeerKey(m.cfg.PeerPublicKey); err == nil {
		conf.InsecureSkipVerify = true
		conf.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("masque: server sent no certificate")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			type eq interface{ Equal(crypto.PublicKey) bool }
			if e, ok := leaf.PublicKey.(eq); ok && e.Equal(pk) {
				return nil
			}
			return errors.New("masque: server key does not match registration peer key")
		}
	}
	return conf, nil
}

func (m *Masque) Start(ctx context.Context, dev tun.Device, ep netip.AddrPort) error {
	m.endpoint, m.dev = ep, dev
	tlsConf, err := m.tlsConfig()
	if err != nil {
		return err
	}
	network := "udp4"
	if ep.Addr().Is6() {
		network = "udp6"
	}
	m.udp, err = net.ListenUDP(network, nil)
	if err != nil {
		return err
	}
	qconf := &quic.Config{
		EnableDatagrams:      true,
		InitialPacketSize:    1242,
		KeepAlivePeriod:      10 * time.Second,
		MaxIdleTimeout:       45 * time.Second,
		HandshakeIdleTimeout: 6 * time.Second,
	}
	dctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	t0 := time.Now()
	m.qconn, err = quic.Dial(dctx, m.udp, net.UDPAddrFromAddrPort(ep), tlsConf, qconf)
	if err != nil {
		m.udp.Close()
		return fmt.Errorf("masque: QUIC handshake with %s: %w", ep, err)
	}
	m.rtt = time.Since(t0)
	cs := m.qconn.ConnectionState().TLS
	m.tlsInfo = fmt.Sprintf("%s %s %s", tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite), cs.CurveID)

	tr := &http3.Transport{
		EnableDatagrams:    true,
		AdditionalSettings: map[uint64]uint64{settingH3Draft00: 1},
		DisableCompression: true,
	}
	cc := tr.NewClientConn(m.qconn)
	select {
	case <-cc.ReceivedSettings():
	case <-dctx.Done():
		m.closeConn()
		return errors.New("masque: timed out waiting for HTTP/3 SETTINGS")
	}
	rs, err := cc.OpenRequestStream(dctx)
	if err != nil {
		m.closeConn()
		return err
	}
	u := &url.URL{Scheme: "https", Host: MasqueAuthority, Path: "/"}
	req := &http.Request{
		Method: http.MethodConnect,
		Proto:  MasqueProtocol,
		Host:   MasqueAuthority,
		URL:    u,
		Header: http.Header{
			"User-Agent":       []string{""},
			"Capsule-Protocol": []string{"?1"},
		},
	}
	if err := rs.SendRequestHeader(req); err != nil {
		m.closeConn()
		return fmt.Errorf("masque: send CONNECT: %w", err)
	}
	resp, err := rs.ReadResponse()
	if err != nil {
		m.closeConn()
		return fmt.Errorf("masque: CONNECT response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		m.closeConn()
		return fmt.Errorf("masque: edge refused CONNECT-IP: %s", resp.Status)
	}
	m.stream = rs
	m.start = time.Now()

	pctx, pcancel := context.WithCancel(context.Background())
	m.cancel = pcancel
	go m.drainCapsules()
	go m.upstream(pctx)
	go m.downstream(pctx)
	return nil
}

// upstream: tun -> HTTP datagram (context id 0 prefix).
func (m *Masque) upstream(ctx context.Context) {
	batch := m.dev.BatchSize()
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, bufOffset+65535)
	}
	for ctx.Err() == nil {
		n, err := m.dev.Read(bufs, sizes, bufOffset)
		if err != nil {
			if errors.Is(err, tun.ErrTooManySegments) {
				continue
			}
			m.fail(fmt.Errorf("tun read: %w", err))
			return
		}
		for i := 0; i < n; i++ {
			// Re-use the byte just before the packet for the context ID.
			pkt := bufs[i][bufOffset-1 : bufOffset+sizes[i]]
			pkt[0] = 0
			if err := m.stream.SendDatagram(pkt); err != nil {
				var tl *quic.DatagramTooLargeError
				if errors.As(err, &tl) {
					continue // oversized packet; drop like a router would
				}
				m.fail(fmt.Errorf("masque send: %w", err))
				return
			}
			m.c.addTx(sizes[i])
		}
	}
}

// downstream: HTTP datagram -> tun.
func (m *Masque) downstream(ctx context.Context) {
	buf := make([]byte, bufOffset+65535)
	for {
		d, err := m.stream.ReceiveDatagram(ctx)
		if err != nil {
			m.fail(fmt.Errorf("masque receive: %w", err))
			return
		}
		ctxID, n := readVarint(d)
		if n == 0 || ctxID != 0 {
			continue
		}
		p := d[n:]
		if len(p) == 0 {
			continue
		}
		copy(buf[bufOffset:], p)
		if _, err := m.dev.Write([][]byte{buf[:bufOffset+len(p)]}, bufOffset); err != nil {
			continue
		}
		m.c.addRx(len(p))
	}
}

// drainCapsules reads the CONNECT stream body (capsules such as
// ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT). Addresses come from the
// registration, so they are ignored; EOF means the session ended.
func (m *Masque) drainCapsules() {
	buf := make([]byte, 4096)
	for {
		if _, err := m.stream.Read(buf); err != nil {
			m.fail(fmt.Errorf("masque stream closed: %w", err))
			return
		}
	}
}

func readVarint(b []byte) (uint64, int) {
	if len(b) == 0 {
		return 0, 0
	}
	l := 1 << (b[0] >> 6)
	if len(b) < l {
		return 0, 0
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < l; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, l
}

func (m *Masque) fail(err error) {
	m.once.Do(func() { m.done <- err; close(m.done) })
}

func (m *Masque) Done() <-chan error { return m.done }

func (m *Masque) Stats() Stats {
	s := Stats{
		Protocol: "MASQUE (HTTP/3)", Endpoint: m.endpoint.String(),
		TxBytes: m.c.tx.Load(), RxBytes: m.c.rx.Load(), TxPackets: m.c.txp.Load(), RxPackets: m.c.rxp.Load(),
		LastHandshake: m.start, TLS: m.tlsInfo,
	}
	if m.rtt > 0 {
		s.HandshakeRTT = m.rtt.Round(time.Millisecond).String()
	}
	return s
}

func (m *Masque) closeConn() {
	if m.qconn != nil {
		m.qconn.CloseWithError(0, "")
	}
	if m.udp != nil {
		m.udp.Close()
	}
}

func (m *Masque) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	if m.stream != nil {
		m.stream.CancelRead(0)
		m.stream.Close()
	}
	m.closeConn()
	m.fail(errors.New("closed"))
	return nil
}
