package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/ImanMontajabi/OpenWarp/internal/keys"
)

type WireGuardConfig struct {
	PrivateKey    string // base64
	PeerPublicKey string // base64
	// Reserved is the 3-byte client_id from the registration config. The
	// edge uses it (in the reserved bytes of each WireGuard message header)
	// to route packets to the right device.
	Reserved         [3]byte
	HandshakeTimeout time.Duration
}

type WireGuard struct {
	cfg      WireGuardConfig
	dev      *device.Device
	endpoint netip.AddrPort
	done     chan error
	once     sync.Once
}

func NewWireGuard(cfg WireGuardConfig) *WireGuard {
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 6 * time.Second
	}
	return &WireGuard{cfg: cfg, done: make(chan error, 1)}
}

func (w *WireGuard) Start(ctx context.Context, td tun.Device, ep netip.AddrPort) error {
	priv, err := keys.B64ToHex(w.cfg.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	peer, err := keys.B64ToHex(w.cfg.PeerPublicKey)
	if err != nil {
		return fmt.Errorf("peer key: %w", err)
	}
	w.endpoint = ep
	bind := &reservedBind{Bind: conn.NewDefaultBind(), reserved: w.cfg.Reserved}
	w.dev = device.NewDevice(td, bind, device.NewLogger(device.LogLevelError, "wireguard: "))
	uapi := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=25\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\n",
		priv, peer, ep.String())
	if err := w.dev.IpcSet(uapi); err != nil {
		w.dev.Close()
		return err
	}
	if err := w.dev.Up(); err != nil {
		w.dev.Close()
		return err
	}
	// Wait for the first handshake so the caller can fall back to another
	// endpoint/port when this one is blocked.
	deadline := time.Now().Add(w.cfg.HandshakeTimeout)
	for time.Now().Before(deadline) {
		if !w.Stats().LastHandshake.IsZero() {
			go w.watch()
			return nil
		}
		select {
		case <-ctx.Done():
			w.dev.Close()
			return ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	w.dev.Close()
	return fmt.Errorf("wireguard: no handshake from %s within %s", ep, w.cfg.HandshakeTimeout)
}

// watch reports the tunnel dead when handshakes stop (WireGuard rekeys every
// 2 minutes; 3 minutes + keepalives without one means the path is gone).
func (w *WireGuard) watch() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-w.dev.Wait():
			w.fail(errors.New("wireguard device closed"))
			return
		case <-t.C:
			if hs := w.Stats().LastHandshake; !hs.IsZero() && time.Since(hs) > 3*time.Minute {
				w.fail(errors.New("wireguard: handshake timed out"))
				return
			}
		}
	}
}

func (w *WireGuard) fail(err error) {
	w.once.Do(func() { w.done <- err; close(w.done) })
}

func (w *WireGuard) Done() <-chan error { return w.done }

func (w *WireGuard) Stats() Stats {
	s := Stats{Protocol: "WireGuard", Endpoint: w.endpoint.String()}
	if w.dev == nil {
		return s
	}
	out, err := w.dev.IpcGet()
	if err != nil {
		return s
	}
	var sec, nsec int64
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		n, _ := strconv.ParseInt(v, 10, 64)
		switch k {
		case "tx_bytes":
			s.TxBytes = uint64(n)
		case "rx_bytes":
			s.RxBytes = uint64(n)
		case "last_handshake_time_sec":
			sec = n
		case "last_handshake_time_nsec":
			nsec = n
		}
	}
	if sec != 0 {
		s.LastHandshake = time.Unix(sec, nsec)
	}
	return s
}

func (w *WireGuard) Close() error {
	if w.dev != nil {
		w.dev.Close()
	}
	w.fail(errors.New("closed"))
	return nil
}

// reservedBind writes the client_id into bytes 1..3 of every outgoing
// WireGuard message and clears them on receive (wireguard-go reads the first
// 4 bytes as the little-endian message type).
type reservedBind struct {
	conn.Bind
	reserved [3]byte
}

func (b *reservedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, p, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		fn := fn
		wrapped[i] = func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := fn(packets, sizes, eps)
			for j := 0; j < n; j++ {
				if sizes[j] >= 4 {
					packets[j][1], packets[j][2], packets[j][3] = 0, 0, 0
				}
			}
			return n, err
		}
	}
	return wrapped, p, nil
}

func (b *reservedBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.reserved != [3]byte{} {
		for _, buf := range bufs {
			if len(buf) >= 4 {
				copy(buf[1:4], b.reserved[:])
			}
		}
	}
	return b.Bind.Send(bufs, ep)
}
