// Package daemon is the long-running service (the equivalent of the
// official CloudflareWARP daemon): it owns the registration, runs the
// tunnel, configures the OS and serves a local control API.
package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/local/openwarp/internal/api"
	"github.com/local/openwarp/internal/dnsproxy"
	"github.com/local/openwarp/internal/keys"
	"github.com/local/openwarp/internal/proxy"
	"github.com/local/openwarp/internal/state"
	"github.com/local/openwarp/internal/sysnet"
	"github.com/local/openwarp/internal/tunnel"
)

const (
	StatusDisconnected = "Disconnected"
	StatusConnecting   = "Connecting"
	StatusConnected    = "Connected"
	StatusPaused       = "Paused"
)

// Port lists observed in the official client's logs ("Warp endpoint
// override ports ports=[443, 500, 1701, 4500, 4443, 8443, 8095]") and the
// classic WireGuard ports.
var (
	masquePorts = []uint16{443, 500, 1701, 4500, 4443, 8443, 8095}
	wgPorts     = []uint16{2408, 500, 1701, 4500}
	// Defaults if the registration lacks endpoint data.
	defaultMasqueV4 = netip.MustParseAddr("162.159.198.1")
	defaultWGV4     = netip.MustParseAddr("162.159.192.1")
)

type Status struct {
	Status      string          `json:"status"`
	Reason      string          `json:"reason,omitempty"`
	Error       string          `json:"error,omitempty"`
	Mode        state.Mode      `json:"mode"`
	ModeLabel   string          `json:"mode_label"`
	Protocol    state.Protocol  `json:"protocol"`
	Registered  bool            `json:"registered"`
	AccountType string          `json:"account_type,omitempty"`
	WarpPlus    bool            `json:"warp_plus"`
	Since       time.Time       `json:"since,omitzero"`
	Interface   string          `json:"interface,omitempty"`
	InterfaceV4 string          `json:"interface_v4,omitempty"`
	InterfaceV6 string          `json:"interface_v6,omitempty"`
	Proxy       string          `json:"proxy,omitempty"`
	DNSProtocol string          `json:"dns_protocol"`
	Tunnel      *tunnel.Stats   `json:"tunnel,omitempty"`
	DNS         *dnsproxy.Stats `json:"dns,omitempty"`
	Network     string          `json:"network,omitempty"`
}

type Engine struct {
	store *state.Store
	api   *api.Client

	mu      sync.Mutex
	want    bool
	status  string
	reason  string
	lastErr string
	since   time.Time
	sess    *session
	kick    chan struct{}
	network string
	netAt   time.Time
}

func (e *Engine) refreshNetwork() {
	e.mu.Lock()
	stale := time.Since(e.netAt) > 10*time.Second
	e.mu.Unlock()
	if !stale {
		return
	}
	kind, ssid := sysnet.NetworkKind()
	if ssid != "" {
		kind += " (" + ssid + ")"
	}
	e.mu.Lock()
	e.network, e.netAt = kind, time.Now()
	e.mu.Unlock()
}

func NewEngine(store *state.Store) *Engine {
	c := api.New()
	if t, _ := deviceIdentity(); t == "macOS" {
		// Present as the official macOS client on every call so Cloudflare
		// lists this device as macOS (falls back per request; see api.Client.do).
		c.Identity = api.MacIdentity
	}
	return NewEngineWithAPI(store, c)
}

// NewEngineWithAPI is NewEngine with a custom API client (tests, overrides).
func NewEngineWithAPI(store *state.Store, client *api.Client) *Engine {
	if u := os.Getenv("OPENWARP_API_URL"); u != "" {
		client.BaseURL = u
	}
	e := &Engine{store: store, api: client, status: StatusDisconnected, kick: make(chan struct{}, 1)}
	go e.loop()
	store.Lock()
	auto := store.S.Settings.AlwaysOn && store.S.Registration != nil
	store.Unlock()
	if auto {
		e.Connect()
	}
	return e
}

// ---------- registration ----------

func (e *Engine) Register(ctx context.Context, acceptToS bool) (*api.Registration, error) {
	if !acceptToS {
		return nil, errors.New("you must accept the Cloudflare WARP Terms of Service (https://www.cloudflare.com/application/terms/)")
	}
	wg, err := keys.NewWireGuard()
	if err != nil {
		return nil, err
	}
	ec, err := keys.NewECDSA()
	if err != nil {
		return nil, err
	}
	devType, model := deviceIdentity()
	reg, err := e.api.Register(ctx, wg.Public, devType, model, "en_US")
	if err != nil && devType != legacyDeviceType {
		// Older releases registered as Android/"PC"; fall back if the API
		// rejects this platform's identity.
		log.Printf("registration as %s/%s failed (%v); retrying as %s/%s", devType, model, err, legacyDeviceType, legacyDeviceModel)
		// Fresh key: the API rejects a public key already used by another
		// registration ("Invalid public key"), even one it just created.
		if wg, err = keys.NewWireGuard(); err != nil {
			return nil, err
		}
		reg, err = e.api.Register(ctx, wg.Public, legacyDeviceType, legacyDeviceModel, "en_US")
	}
	if err != nil {
		return nil, err
	}
	log.Printf("registered device %s as type=%q model=%q", reg.ID, reg.Type, reg.Model)
	s := e.store
	s.Lock()
	s.S.Registration = reg
	s.S.WireGuardKey = wg
	s.S.ECDSAKey = ec
	s.S.ActiveKeyType = api.KeyTypeWireGuard
	cfg := reg.Config
	s.S.WireGuardConfig = &cfg
	s.S.MasqueConfig = nil
	s.S.ToSAccepted = true
	err = s.Save()
	s.Unlock()
	return reg, err
}

func (e *Engine) registration() (*api.Registration, error) {
	e.store.Lock()
	defer e.store.Unlock()
	if e.store.S.Registration == nil {
		return nil, errors.New("not registered: run `openwarp registration new`")
	}
	r := *e.store.S.Registration
	return &r, nil
}

// ensureKey makes sure the key for proto is the one enrolled on the
// registration (the API holds a single tunnel key at a time) and returns
// the matching peer config.
func (e *Engine) ensureKey(ctx context.Context, proto state.Protocol, rotate bool) (*api.Config, error) {
	reg, err := e.registration()
	if err != nil {
		return nil, err
	}
	s := e.store
	s.Lock()
	keyType := api.KeyTypeWireGuard
	tunType := api.TunTypeWireGuard
	cached := s.S.WireGuardConfig
	if proto == state.ProtoMasque {
		keyType, tunType, cached = api.KeyTypeMasque, api.TunTypeMasque, s.S.MasqueConfig
	}
	if !rotate && s.S.ActiveKeyType == keyType && cached != nil && len(cached.Peers) > 0 {
		c := *cached
		s.Unlock()
		return &c, nil
	}
	if rotate {
		if proto == state.ProtoMasque {
			s.S.ECDSAKey, _ = keys.NewECDSA()
		} else {
			s.S.WireGuardKey, _ = keys.NewWireGuard()
		}
	}
	var pub string
	if proto == state.ProtoMasque {
		pub, err = keys.ECDSAPublicPKIX(s.S.ECDSAKey)
	} else {
		pub = s.S.WireGuardKey.Public
	}
	s.Unlock()
	if err != nil {
		return nil, err
	}
	upd, err := e.api.SetKey(ctx, reg.ID, reg.Token, pub, keyType, tunType)
	if err != nil {
		return nil, fmt.Errorf("enrolling %s key: %w", keyType, err)
	}
	s.Lock()
	defer s.Unlock()
	cfg := upd.Config
	s.S.ActiveKeyType = keyType
	if proto == state.ProtoMasque {
		s.S.MasqueConfig = &cfg
	} else {
		s.S.WireGuardConfig = &cfg
	}
	if upd.Account.ID != "" {
		s.S.Registration.Account = upd.Account
	}
	return &cfg, s.Save()
}

func (e *Engine) RotateKeys(ctx context.Context) error {
	e.store.Lock()
	proto := e.store.S.Settings.Protocol
	e.store.Unlock()
	if _, err := e.ensureKey(ctx, proto, true); err != nil {
		return err
	}
	e.reconnect()
	return nil
}

func (e *Engine) DeleteRegistration(ctx context.Context) error {
	e.Disconnect()
	reg, err := e.registration()
	if err != nil {
		return err
	}
	if err := e.api.Delete(ctx, reg.ID, reg.Token); err != nil {
		log.Printf("delete registration remotely: %v (removing locally anyway)", err)
	}
	s := e.store
	s.Lock()
	defer s.Unlock()
	s.S.Registration, s.S.WireGuardKey, s.S.ECDSAKey = nil, nil, ""
	s.S.WireGuardConfig, s.S.MasqueConfig, s.S.ActiveKeyType = nil, nil, ""
	return s.Save()
}

func (e *Engine) RefreshAccount(ctx context.Context) (*api.Account, error) {
	reg, err := e.registration()
	if err != nil {
		return nil, err
	}
	acc, err := e.api.Account(ctx, reg.ID, reg.Token)
	if err != nil {
		return nil, err
	}
	e.store.Lock()
	e.store.S.Registration.Account = *acc
	e.store.Save()
	e.store.Unlock()
	return acc, nil
}

func (e *Engine) SetLicense(ctx context.Context, license string) (*api.Account, error) {
	reg, err := e.registration()
	if err != nil {
		return nil, err
	}
	if _, err := e.api.SetLicense(ctx, reg.ID, reg.Token, strings.TrimSpace(license)); err != nil {
		return nil, err
	}
	return e.RefreshAccount(ctx)
}

func (e *Engine) Devices(ctx context.Context) ([]api.Device, error) {
	reg, err := e.registration()
	if err != nil {
		return nil, err
	}
	return e.api.Devices(ctx, reg.ID, reg.Token)
}

// ---------- connection state machine ----------

func (e *Engine) Connect() {
	e.mu.Lock()
	e.want = true
	e.mu.Unlock()
	e.setAlwaysOn(true)
	e.poke()
}

func (e *Engine) Disconnect() {
	e.mu.Lock()
	e.want = false
	sess := e.sess
	e.sess = nil
	e.status, e.reason, e.lastErr = StatusDisconnected, "Manual Disconnection", ""
	e.mu.Unlock()
	e.setAlwaysOn(false)
	if sess != nil {
		sess.close()
	}
	e.poke()
}

func (e *Engine) setAlwaysOn(v bool) {
	e.store.Lock()
	if e.store.S.Settings.AlwaysOn != v {
		e.store.S.Settings.AlwaysOn = v
		e.store.Save()
	}
	e.store.Unlock()
}

// reconnect tears down the current session so the loop rebuilds it with
// fresh settings.
func (e *Engine) reconnect() {
	e.mu.Lock()
	sess := e.sess
	e.sess = nil
	e.mu.Unlock()
	if sess != nil {
		sess.close()
	}
	e.poke()
}

func (e *Engine) poke() {
	select {
	case e.kick <- struct{}{}:
	default:
	}
}

func (e *Engine) setStatus(st, reason string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.want && st != StatusDisconnected {
		return
	}
	if st != e.status {
		e.since = time.Now()
	}
	e.status, e.reason = st, reason
	if err != nil {
		e.lastErr = err.Error()
	} else if st == StatusConnected {
		e.lastErr = ""
	}
}

func (e *Engine) trustedPause(set state.Settings) (bool, string) {
	if len(set.TrustedSSIDs) == 0 && !set.DisableWiFi && !set.DisableEthernet {
		return false, ""
	}
	kind, ssid := sysnet.NetworkKind()
	switch {
	case kind == "wifi" && set.DisableWiFi:
		return true, "Paused: disabled for Wi-Fi networks"
	case kind == "ethernet" && set.DisableEthernet:
		return true, "Paused: disabled for wired networks"
	case kind == "wifi" && ssid != "" && slices.Contains(set.TrustedSSIDs, ssid):
		return true, "Paused: trusted Wi-Fi network " + ssid
	}
	return false, ""
}

func (e *Engine) loop() {
	backoff := time.Second
	for {
		e.refreshNetwork()
		e.mu.Lock()
		want, sess := e.want, e.sess
		e.mu.Unlock()

		if !want {
			<-e.kick
			continue
		}
		e.store.Lock()
		set := e.store.S.Settings
		e.store.Unlock()

		if paused, why := e.trustedPause(set); paused {
			if sess != nil {
				e.reconnect()
			}
			e.setStatus(StatusPaused, why, nil)
			e.wait(10 * time.Second)
			continue
		}

		if sess == nil {
			e.setStatus(StatusConnecting, "Establishing connection", nil)
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			s, err := e.startSession(ctx, set)
			cancel()
			if err != nil {
				log.Printf("connect failed: %v", err)
				e.setStatus(StatusConnecting, "Retrying after error", err)
				e.wait(backoff)
				backoff = min(backoff*2, 30*time.Second)
				continue
			}
			e.mu.Lock()
			if !e.want { // disconnected while we were connecting
				e.mu.Unlock()
				s.close()
				continue
			}
			e.sess = s
			e.mu.Unlock()
			backoff = time.Second
			e.setStatus(StatusConnected, "", nil)
			log.Printf("connected (%s, %s)", set.Mode, s.describe())
			continue
		}

		// Connected: watch for tunnel death, network change, or kicks.
		select {
		case err := <-sess.done():
			e.mu.Lock()
			current := e.sess == sess
			if current {
				e.sess = nil
			}
			e.mu.Unlock()
			sess.close()
			if current { // otherwise it was closed on purpose
				log.Printf("tunnel lost: %v", err)
				e.setStatus(StatusConnecting, "Reconnecting", err)
			}
		case <-e.kick:
		case <-time.After(5 * time.Second):
			if sess.networkChanged() {
				log.Printf("network changed; reconnecting")
				e.reconnect()
			}
		}
	}
}

func (e *Engine) wait(d time.Duration) {
	select {
	case <-e.kick:
	case <-time.After(d):
	}
}

// ---------- sessions ----------

type session struct {
	mode      state.Mode
	dev       tun.Device
	tr        tunnel.Transport
	applied   *sysnet.Applied
	dns       *dnsproxy.Server
	proxy     *proxy.Server
	iface     string
	v4, v6    netip.Addr
	gateway   sysnet.Gateway
	idle      chan error // for DNS-only sessions
	proxyAddr string
	once      sync.Once
}

func (s *session) done() <-chan error {
	if s.tr != nil {
		return s.tr.Done()
	}
	return s.idle
}

func (s *session) describe() string {
	if s.tr != nil {
		st := s.tr.Stats()
		return st.Protocol + " via " + st.Endpoint
	}
	return "DNS only"
}

func (s *session) networkChanged() bool {
	if !s.gateway.Addr.IsValid() {
		return false
	}
	g, err := sysnet.DefaultGateway(false)
	return err == nil && g != s.gateway
}

func (s *session) close() {
	s.once.Do(func() {
		if s.proxy != nil {
			s.proxy.Close()
		}
		if s.dns != nil {
			s.dns.Close()
		}
		if s.applied != nil {
			s.applied.Undo()
		}
		if s.tr != nil {
			s.tr.Close()
		}
		if s.dev != nil {
			s.dev.Close()
		}
	})
}

// onceTun guards against double Close (WireGuard's device closes its tun;
// the session closes it too).
type onceTun struct {
	tun.Device
	once sync.Once
}

func (t *onceTun) Close() error {
	var err error
	t.once.Do(func() { err = t.Device.Close() })
	return err
}

func resolverFor(set state.Settings) dnsproxy.Resolver {
	return dnsproxy.Families(string(set.Families))
}

func (e *Engine) startSession(ctx context.Context, set state.Settings) (*session, error) {
	s := &session{mode: set.Mode, idle: make(chan error)}
	res := resolverFor(set)
	s.gateway, _ = sysnet.DefaultGateway(false)

	// DNS-only modes: no tunnel, local DoH/DoT stub + system DNS.
	if !set.Mode.HasTunnel() {
		up := dnsproxy.DoH
		if set.Mode == state.ModeDoT {
			up = dnsproxy.DoT
		}
		if err := e.startDNS(s, set, res, up); err != nil {
			return nil, err
		}
		a, err := sysnet.SetSystemDNS([]netip.Addr{netip.MustParseAddr("127.0.0.1")})
		if err != nil {
			s.close()
			return nil, err
		}
		s.applied = a
		return s, nil
	}

	cfg, err := e.ensureKey(ctx, set.Protocol, false)
	if err != nil {
		return nil, err
	}
	s.v4, _ = netip.ParseAddr(cfg.Interface.Addresses.V4)
	s.v6, _ = netip.ParseAddr(cfg.Interface.Addresses.V6)
	candidates, err := endpointCandidates(set, cfg)
	if err != nil {
		return nil, err
	}

	var lastErr error
	var tnet *netstack.Net
	for _, ep := range candidates {
		if ctx.Err() != nil {
			break
		}
		// Fresh device per attempt: a failed WireGuard device closes its tun.
		var raw tun.Device
		if set.Mode == state.ModeProxy {
			var local []netip.Addr
			for _, a := range []netip.Addr{s.v4, s.v6} {
				if a.IsValid() {
					local = append(local, a)
				}
			}
			raw, tnet, err = netstack.CreateNetTUN(local, res.IPs, set.MTU)
		} else {
			raw, err = tun.CreateTUN("utun", set.MTU)
		}
		if err != nil {
			return nil, fmt.Errorf("creating tunnel interface (tun modes need root; try `openwarp mode proxy`): %w", err)
		}
		dev := &onceTun{Device: raw}
		tr, err := e.newTransport(set, cfg)
		if err != nil {
			dev.Close()
			return nil, err
		}
		log.Printf("trying %s endpoint %s", set.Protocol, ep)
		if err := tr.Start(ctx, dev, ep); err != nil {
			log.Printf("  %v", err)
			lastErr = err
			tr.Close()
			dev.Close()
			continue
		}
		s.dev, s.tr = dev, tr
		s.iface, _ = raw.Name()
		break
	}
	if s.tr == nil {
		if lastErr == nil {
			lastErr = errors.New("no endpoints to try")
		}
		return nil, lastErr
	}

	switch set.Mode {
	case state.ModeProxy:
		s.proxyAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(set.ProxyPort))
		s.proxy = &proxy.Server{Addr: s.proxyAddr, Dial: tnet.DialContext}
		if err := s.proxy.Start(); err != nil {
			s.close()
			return nil, fmt.Errorf("proxy listen %s: %w", s.proxyAddr, err)
		}
	default:
		var dns []netip.Addr
		switch set.Mode {
		case state.ModeWarp:
			dns = res.IPs
		case state.ModeWarpDoH, state.ModeWarpDoT:
			up := dnsproxy.DoH
			if set.Mode == state.ModeWarpDoT {
				up = dnsproxy.DoT
			}
			if err := e.startDNS(s, set, res, up); err != nil {
				s.close()
				return nil, err
			}
			dns = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
		}
		ep, _ := netip.ParseAddrPort(s.tr.Stats().Endpoint)
		var split []netip.Prefix
		for _, p := range set.SplitIPs {
			if pf, err := parsePrefix(p); err == nil {
				split = append(split, pf)
			}
		}
		a, err := sysnet.Apply(sysnet.TunConfig{
			Iface: s.iface, V4: s.v4, V6: s.v6, MTU: set.MTU, Endpoint: ep.Addr(),
			SplitMode: string(set.SplitMode), Split: split, DNS: dns,
		})
		if err != nil {
			s.close()
			return nil, err
		}
		s.applied = a
	}
	return s, nil
}

func (e *Engine) startDNS(s *session, set state.Settings, res dnsproxy.Resolver, up dnsproxy.Upstream) error {
	s.dns = &dnsproxy.Server{
		Listen: "127.0.0.1:53", Upstream: up, Resolver: res,
		FallbackDomains: set.FallbackDomains, FallbackServers: sysnet.CurrentResolvers(),
	}
	if err := s.dns.Start(); err != nil {
		s.dns = nil
		return fmt.Errorf("dns proxy on 127.0.0.1:53 (needs root): %w", err)
	}
	return nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func (e *Engine) newTransport(set state.Settings, cfg *api.Config) (tunnel.Transport, error) {
	e.store.Lock()
	defer e.store.Unlock()
	peer := cfg.Peers[0]
	if set.Protocol == state.ProtoMasque {
		k, err := keys.ParseECDSA(e.store.S.ECDSAKey)
		if err != nil {
			return nil, err
		}
		return tunnel.NewMasque(tunnel.MasqueConfig{
			PrivateKey: k, PeerPublicKey: peer.PublicKey, PostQuantum: set.PostQuantum, MTU: set.MTU,
		}), nil
	}
	var reserved [3]byte
	if b, err := base64.StdEncoding.DecodeString(cfg.ClientID); err == nil && len(b) == 3 {
		copy(reserved[:], b)
	}
	return tunnel.NewWireGuard(tunnel.WireGuardConfig{
		PrivateKey: e.store.S.WireGuardKey.Private, PeerPublicKey: peer.PublicKey, Reserved: reserved,
	}), nil
}

func hostOf(s string) (netip.Addr, bool) {
	if s == "" {
		return netip.Addr{}, false
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a, true
	}
	return netip.Addr{}, false
}

// endpointCandidates builds the ordered list of edge addresses to try:
// override, then the registration's v4 IP across the known ports, then v6.
func endpointCandidates(set state.Settings, cfg *api.Config) ([]netip.AddrPort, error) {
	if set.EndpointOverride != "" {
		ap, err := netip.ParseAddrPort(set.EndpointOverride)
		if err != nil {
			return nil, fmt.Errorf("bad endpoint override %q (want ip:port): %w", set.EndpointOverride, err)
		}
		return []netip.AddrPort{ap}, nil
	}
	if len(cfg.Peers) == 0 {
		return nil, errors.New("registration has no peers")
	}
	ep := cfg.Peers[0].Endpoint
	ports := wgPorts
	v4 := defaultWGV4
	if set.Protocol == state.ProtoMasque {
		ports, v4 = masquePorts, defaultMasqueV4
	}
	if len(ep.Ports) > 0 && set.Protocol == state.ProtoWireGuard {
		ports = nil
		for _, p := range ep.Ports {
			ports = append(ports, uint16(p))
		}
	}
	if a, ok := hostOf(ep.V4); ok {
		v4 = a
	}
	var out []netip.AddrPort
	for _, p := range ports {
		out = append(out, netip.AddrPortFrom(v4, p))
	}
	if a, ok := hostOf(ep.V6); ok {
		if _, err := sysnet.DefaultGateway(true); err == nil {
			out = append(out, netip.AddrPortFrom(a, ports[0]))
		}
	}
	return out, nil
}

// ---------- views ----------

func (e *Engine) Status() Status {
	go e.refreshNetwork() // throttled
	e.store.Lock()
	set := e.store.S.Settings
	reg := e.store.S.Registration
	e.store.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{
		Status: e.status, Reason: e.reason, Error: e.lastErr, Mode: set.Mode, ModeLabel: set.Mode.Label(),
		Protocol: set.Protocol, Registered: reg != nil, Since: e.since, DNSProtocol: "off",
	}
	if reg != nil {
		st.AccountType = reg.Account.AccountType
		st.WarpPlus = reg.Account.WarpPlus
	}
	if s := e.sess; s != nil && e.status == StatusConnected {
		if s.tr != nil {
			ts := s.tr.Stats()
			st.Tunnel = &ts
			st.Interface = s.iface
			if s.v4.IsValid() {
				st.InterfaceV4 = s.v4.String()
			}
			if s.v6.IsValid() {
				st.InterfaceV6 = s.v6.String()
			}
		}
		if s.dns != nil {
			ds := s.dns.Stats()
			st.DNS = &ds
		}
		st.Proxy = s.proxyAddr
		switch set.Mode {
		case state.ModeWarp:
			st.DNSProtocol = "udp (via tunnel)"
		case state.ModeWarpDoH, state.ModeDoH:
			st.DNSProtocol = "doh"
		case state.ModeWarpDoT, state.ModeDoT:
			st.DNSProtocol = "dot"
		case state.ModeProxy:
			st.DNSProtocol = "udp (proxy resolver)"
		}
	}
	st.Network = e.network
	return st
}

func (e *Engine) Settings() state.Settings {
	e.store.Lock()
	defer e.store.Unlock()
	return e.store.S.Settings
}

// UpdateSettings applies a modifier and reconnects if a connection-relevant
// field changed.
func (e *Engine) UpdateSettings(fn func(*state.Settings) error) (state.Settings, error) {
	e.store.Lock()
	old := e.store.S.Settings
	next := old
	next.SplitIPs = slices.Clone(old.SplitIPs)
	next.FallbackDomains = slices.Clone(old.FallbackDomains)
	next.TrustedSSIDs = slices.Clone(old.TrustedSSIDs)
	if err := fn(&next); err != nil {
		e.store.Unlock()
		return old, err
	}
	if !next.Mode.Valid() {
		e.store.Unlock()
		return old, fmt.Errorf("invalid mode %q", next.Mode)
	}
	if next.Protocol != state.ProtoMasque && next.Protocol != state.ProtoWireGuard {
		e.store.Unlock()
		return old, fmt.Errorf("invalid protocol %q", next.Protocol)
	}
	e.store.S.Settings = next
	err := e.store.Save()
	e.store.Unlock()
	if err != nil {
		return next, err
	}
	n, o := next, old
	n.AlwaysOn, o.AlwaysOn = false, false
	n.TrustedSSIDs, o.TrustedSSIDs = nil, nil
	n.DisableWiFi, o.DisableWiFi, n.DisableEthernet, o.DisableEthernet = false, false, false, false
	if fmt.Sprint(n) != fmt.Sprint(o) {
		e.reconnect()
	} else {
		e.poke()
	}
	return next, nil
}

func (e *Engine) Shutdown() {
	e.mu.Lock()
	sess := e.sess
	e.sess = nil
	e.mu.Unlock()
	if sess != nil {
		sess.close()
	}
}
