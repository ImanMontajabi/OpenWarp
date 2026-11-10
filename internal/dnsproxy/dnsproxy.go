// Package dnsproxy is a local stub resolver that forwards queries to
// Cloudflare over DoH or DoT (the official client's doh/dot/warp+doh/warp+dot
// modes), sends Local Domain Fallback suffixes to the network's own
// resolvers, and supports 1.1.1.1 for Families.
package dnsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Upstream string

const (
	DoH Upstream = "doh"
	DoT Upstream = "dot"
	UDP Upstream = "udp"
)

// Resolver describes one Cloudflare resolver profile.
type Resolver struct {
	DoHHost string
	DoTHost string
	IPs     []netip.Addr
}

// Families returns the resolver for 1.1.1.1 for Families: off, malware, full.
func Families(mode string) Resolver {
	switch mode {
	case "malware":
		return Resolver{"security.cloudflare-dns.com", "security.cloudflare-dns.com", addrs("1.1.1.2", "1.0.0.2", "2606:4700:4700::1112", "2606:4700:4700::1002")}
	case "full":
		return Resolver{"family.cloudflare-dns.com", "family.cloudflare-dns.com", addrs("1.1.1.3", "1.0.0.3", "2606:4700:4700::1113", "2606:4700:4700::1003")}
	}
	return Resolver{"cloudflare-dns.com", "one.one.one.one", addrs("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")}
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, len(s))
	for i, x := range s {
		out[i] = netip.MustParseAddr(x)
	}
	return out
}

type Stats struct {
	Queries  uint64 `json:"queries"`
	Fallback uint64 `json:"fallback_queries"`
	Failures uint64 `json:"failures"`
}

type Server struct {
	Listen          string // e.g. 127.0.0.1:53
	Upstream        Upstream
	Resolver        Resolver
	FallbackDomains []string
	FallbackServers []netip.Addr

	httpc   *http.Client
	udp     net.PacketConn
	tcp     net.Listener
	q, f, e atomic.Uint64
	wg      sync.WaitGroup
}

func (s *Server) Start() error {
	ip4 := s.Resolver.IPs[0].String()
	s.httpc = &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			ForceAttemptHTTP2: true,
			TLSClientConfig:   &tls.Config{ServerName: s.Resolver.DoHHost},
			// Bootstrap without DNS: connect to the resolver anycast IP.
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip4, "443"))
			},
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     60 * time.Second,
		},
	}
	var err error
	if s.udp, err = net.ListenPacket("udp", s.Listen); err != nil {
		return err
	}
	if s.tcp, err = net.Listen("tcp", s.Listen); err != nil {
		s.udp.Close()
		return err
	}
	s.wg.Add(2)
	go s.serveUDP()
	go s.serveTCP()
	return nil
}

func (s *Server) Close() {
	if s.udp != nil {
		s.udp.Close()
	}
	if s.tcp != nil {
		s.tcp.Close()
	}
	s.wg.Wait()
}

func (s *Server) Stats() Stats {
	return Stats{Queries: s.q.Load(), Fallback: s.f.Load(), Failures: s.e.Load()}
}

func (s *Server) serveUDP() {
	defer s.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, addr, err := s.udp.ReadFrom(buf)
		if err != nil {
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go func() {
			if r, err := s.Resolve(q); err == nil {
				s.udp.WriteTo(r, addr)
			}
		}()
	}
}

func (s *Server) serveTCP() {
	defer s.wg.Done()
	for {
		c, err := s.tcp.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			for {
				c.SetDeadline(time.Now().Add(20 * time.Second))
				var l uint16
				if binary.Read(c, binary.BigEndian, &l) != nil {
					return
				}
				q := make([]byte, l)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				r, err := s.Resolve(q)
				if err != nil {
					return
				}
				binary.Write(c, binary.BigEndian, uint16(len(r)))
				c.Write(r)
			}
		}()
	}
}

// QName extracts the first question name (lower-case, no trailing dot).
func QName(msg []byte) string {
	if len(msg) < 13 {
		return ""
	}
	var parts []string
	i := 12
	for i < len(msg) {
		l := int(msg[i])
		if l == 0 || l&0xc0 != 0 || i+1+l > len(msg) {
			break
		}
		parts = append(parts, strings.ToLower(string(msg[i+1:i+1+l])))
		i += 1 + l
	}
	return strings.Join(parts, ".")
}

func (s *Server) isFallback(name string) bool {
	for _, d := range s.FallbackDomains {
		d = strings.Trim(strings.ToLower(d), ".")
		if name == d || strings.HasSuffix(name, "."+d) {
			return true
		}
	}
	return false
}

func (s *Server) Resolve(q []byte) ([]byte, error) {
	s.q.Add(1)
	if len(s.FallbackServers) > 0 && s.isFallback(QName(q)) {
		s.f.Add(1)
		for _, srv := range s.FallbackServers {
			if r, err := udpExchange(netip.AddrPortFrom(srv, 53), q); err == nil {
				return r, nil
			}
		}
	}
	var r []byte
	var err error
	switch s.Upstream {
	case DoT:
		r, err = s.dot(q)
	case UDP:
		r, err = udpExchange(netip.AddrPortFrom(s.Resolver.IPs[0], 53), q)
	default:
		r, err = s.doh(q)
	}
	if err != nil {
		s.e.Add(1)
		log.Printf("dns: %s: %v", QName(q), err)
	}
	return r, err
}

func (s *Server) doh(q []byte) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodPost, "https://"+s.Resolver.DoHHost+"/dns-query", bytes.NewReader(q))
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := s.httpc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("doh: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}

func (s *Server) dot(q []byte) ([]byte, error) {
	d := &net.Dialer{Timeout: 5 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(s.Resolver.IPs[0].String(), "853"), &tls.Config{ServerName: s.Resolver.DoTHost})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(6 * time.Second))
	msg := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(msg, uint16(len(q)))
	copy(msg[2:], q)
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	var l uint16
	if err := binary.Read(c, binary.BigEndian, &l); err != nil {
		return nil, err
	}
	r := make([]byte, l)
	_, err = io.ReadFull(c, r)
	return r, err
}

func udpExchange(srv netip.AddrPort, q []byte) ([]byte, error) {
	c, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(srv))
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 2 || !bytes.Equal(buf[:2], q[:2]) {
		return nil, errors.New("dns: mismatched reply id")
	}
	return buf[:n], nil
}
