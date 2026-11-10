// Package proxy serves SOCKS5 and HTTP(S) proxy on a single local port,
// dialing out through the tunnel's userspace network stack. This mirrors the
// official client's "proxy" mode (127.0.0.1:40000 by default).
package proxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

type Server struct {
	Addr string
	Dial DialFunc
	ln   net.Listener
	wg   sync.WaitGroup
}

func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return nil
}

func (s *Server) Close() {
	if s.ln != nil {
		s.ln.Close()
		s.wg.Wait()
	}
}

func (s *Server) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 5 {
		s.socks5(c, br)
	} else {
		s.http(c, br)
	}
}

func pipe(a, b net.Conn) {
	a.SetDeadline(time.Time{})
	b.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }
func (b bufConn) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

func (s *Server) socks5(c net.Conn, br *bufio.Reader) {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	c.Write([]byte{5, 0}) // no auth
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	if req[1] != 1 { // CONNECT only
		c.Write([]byte{5, 7, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var host string
	switch req[3] {
	case 1:
		b := make([]byte, 4)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		io.ReadFull(br, b)
		host = net.IP(b).String()
	case 3:
		l, _ := br.ReadByte()
		b := make([]byte, l)
		io.ReadFull(br, b)
		host = string(b)
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	var pb [2]byte
	if _, err := io.ReadFull(br, pb[:]); err != nil {
		return
	}
	addr := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(pb[:]))))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	up, err := s.Dial(ctx, "tcp", addr)
	if err != nil {
		log.Printf("socks5: %s: %v", addr, err)
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	pipe(bufConn{c, br}, up)
}

func (s *Server) http(c net.Conn, br *bufio.Reader) {
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if req.Method == http.MethodConnect {
		up, err := s.Dial(ctx, "tcp", req.Host)
		if err != nil {
			fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		defer up.Close()
		fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		pipe(bufConn{c, br}, up)
		return
	}
	// Plain HTTP forward proxy.
	tr := &http.Transport{DialContext: s.Dial, DisableKeepAlives: true}
	for {
		if req.URL.Host == "" {
			fmt.Fprintf(c, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
			return
		}
		req.RequestURI = ""
		req.Header.Del("Proxy-Connection")
		req.Header.Del("Proxy-Authorization")
		resp, err := tr.RoundTrip(req)
		if err != nil {
			fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
			return
		}
		err = resp.Write(c)
		resp.Body.Close()
		if err != nil || req.Close || resp.Close {
			return
		}
		c.SetReadDeadline(time.Now().Add(60 * time.Second))
		if req, err = http.ReadRequest(br); err != nil {
			if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "timeout") {
				log.Printf("http proxy: %v", err)
			}
			return
		}
	}
}
