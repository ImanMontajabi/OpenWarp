package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/ImanMontajabi/OpenWarp/internal/keys"
)

func TestWireGuardWithReservedBytes(t *testing.T) {
	srvKey, _ := keys.NewWireGuard()
	cliKey, _ := keys.NewWireGuard()

	// "Edge": a plain wireguard-go peer whose bind strips reserved bytes.
	srvTun, srvNet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1280)
	if err != nil {
		t.Fatal(err)
	}
	srvDev := device.NewDevice(srvTun, &reservedBind{Bind: conn.NewDefaultBind()}, device.NewLogger(device.LogLevelError, "srv: "))
	defer srvDev.Close()
	sp, _ := keys.B64ToHex(srvKey.Private)
	cp, _ := keys.B64ToHex(cliKey.Public)
	if err := srvDev.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.9.0.2/32\n", sp, cp)); err != nil {
		t.Fatal(err)
	}
	srvDev.Up()
	var srvPort int
	cfg, _ := srvDev.IpcGet()
	fmt.Sscanf(cfg[indexOf(cfg, "listen_port="):], "listen_port=%d", &srvPort)

	// UDP relay that records the reserved bytes of client packets.
	relay, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer relay.Close()
	srvAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: srvPort}
	var mu sync.Mutex
	var reservedSeen []byte
	var client *net.UDPAddr
	up, _ := net.DialUDP("udp4", nil, srvAddr)
	defer up.Close()
	go func() {
		b := make([]byte, 2048)
		for {
			n, a, err := relay.ReadFromUDP(b)
			if err != nil {
				return
			}
			mu.Lock()
			client = a
			if reservedSeen == nil {
				reservedSeen = append([]byte(nil), b[1:4]...)
			}
			mu.Unlock()
			up.Write(b[:n])
		}
	}()
	go func() {
		b := make([]byte, 2048)
		for {
			n, err := up.Read(b)
			if err != nil {
				return
			}
			mu.Lock()
			a := client
			mu.Unlock()
			relay.WriteToUDP(b[:n], a)
		}
	}()

	// Server echoes TCP.
	ln, err := srvNet.ListenTCP(&net.TCPAddr{IP: net.IPv4(10, 9, 0, 1), Port: 7})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		c, err := ln.Accept()
		if err == nil {
			io.Copy(c, c)
		}
	}()

	cliTun, cliNet, _ := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.2")}, nil, 1280)
	wg := NewWireGuard(WireGuardConfig{PrivateKey: cliKey.Private, PeerPublicKey: srvKey.Public, Reserved: [3]byte{0xab, 0xcd, 0xef}})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := wg.Start(ctx, cliTun, relay.LocalAddr().(*net.UDPAddr).AddrPort()); err != nil {
		t.Fatal(err)
	}
	defer wg.Close()

	c, err := cliNet.DialContext(ctx, "tcp", "10.9.0.1:7")
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hello warp"))
	buf := make([]byte, 10)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "hello warp" {
		t.Fatalf("echo: %q %v", buf, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(reservedSeen) != "\xab\xcd\xef" {
		t.Fatalf("reserved bytes on wire = %x", reservedSeen)
	}
	if st := wg.Stats(); st.TxBytes == 0 || st.LastHandshake.IsZero() {
		t.Fatalf("stats %+v", st)
	}
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return 0
}
