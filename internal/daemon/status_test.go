package daemon

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/ImanMontajabi/OpenWarp/internal/state"
	"github.com/ImanMontajabi/OpenWarp/internal/tunnel"
)

// busyTransport is a tunnel whose counters grow between any two reads, as they do while traffic flows.
type busyTransport struct{ reads atomic.Uint64 }

func (b *busyTransport) Start(context.Context, tun.Device, netip.AddrPort) error { return nil }
func (b *busyTransport) Done() <-chan error                                      { return nil }
func (b *busyTransport) Close() error                                            { return nil }
func (b *busyTransport) Stats() tunnel.Stats {
	n := b.reads.Add(1)
	return tunnel.Stats{TxBytes: 100 * n, RxBytes: 52 * n}
}

// Regression: Status read the transport's counters twice, once for Usage and once for Tunnel, so a packet
// arriving in between made the two disagree (seen as a flaky e2e test on a slow CI runner).
func TestStatusUsesOneSnapshotOfTheCounters(t *testing.T) {
	store, err := state.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngineWithAPI(store, nil)
	t.Cleanup(e.Shutdown)
	tr := &busyTransport{}
	e.mu.Lock()
	// No poke: the loop stays idle and does not touch the session.
	e.want, e.status, e.sess = true, StatusConnected, &session{mode: state.ModeProxy, tr: tr}
	e.mu.Unlock()

	st := e.Status()
	if st.Usage == nil || st.Tunnel == nil {
		t.Fatalf("usage or tunnel missing: %+v", st)
	}
	if st.Usage.RxBytes != st.Tunnel.RxBytes || st.Usage.TxBytes != st.Tunnel.TxBytes {
		t.Fatalf("usage %d/%d does not match the tunnel's %d/%d in the same status", st.Usage.TxBytes, st.Usage.RxBytes, st.Tunnel.TxBytes, st.Tunnel.RxBytes)
	}
	e.mu.Lock()
	e.sess = nil
	e.mu.Unlock()
}
