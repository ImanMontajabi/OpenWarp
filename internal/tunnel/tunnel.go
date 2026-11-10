// Package tunnel implements the two WARP data-plane protocols observed in the
// official client (warp-edge crate): WireGuard (boringtun fork) and MASQUE
// (HTTP/3 CONNECT-IP with the "cf-connect-ip" protocol token).
//
// Both transports move raw IP packets between a wireguard-go tun.Device
// (a real utun interface or a gVisor netstack) and Cloudflare's edge.
package tunnel

import (
	"context"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

type Stats struct {
	Protocol      string    `json:"protocol"`
	Endpoint      string    `json:"endpoint"`
	TxBytes       uint64    `json:"tx_bytes"`
	RxBytes       uint64    `json:"rx_bytes"`
	TxPackets     uint64    `json:"tx_packets"`
	RxPackets     uint64    `json:"rx_packets"`
	LastHandshake time.Time `json:"last_handshake,omitzero"`
	HandshakeRTT  string    `json:"handshake_rtt,omitempty"`
	TLS           string    `json:"tls,omitempty"`
}

// Transport is a running tunnel to the Cloudflare edge.
type Transport interface {
	// Start connects to endpoint and starts moving packets to/from dev.
	// It returns once the tunnel is established (or failed).
	Start(ctx context.Context, dev tun.Device, endpoint netip.AddrPort) error
	// Done is closed (after an error is sent) when the tunnel dies.
	Done() <-chan error
	Stats() Stats
	Close() error
}

type counters struct {
	tx, rx, txp, rxp atomic.Uint64
}

func (c *counters) addTx(n int) { c.tx.Add(uint64(n)); c.txp.Add(1) }
func (c *counters) addRx(n int) { c.rx.Add(uint64(n)); c.rxp.Add(1) }

// Offset reserved in front of each packet buffer; darwin utun needs 4 bytes
// of headroom and wireguard-go conventionally uses 16.
const bufOffset = 16
