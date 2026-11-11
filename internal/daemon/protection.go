package daemon

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/api"
	"github.com/ImanMontajabi/OpenWarp/internal/firewall"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
	"github.com/ImanMontajabi/OpenWarp/internal/sysnet"
)

// Protection is what the daemon can say about leaks right now. It never claims more than was checked:
// "verified" only follows a verification of the current connection that found no problem.
type Protection struct {
	// State: ProtUnprotected, ProtConnecting, ProtBlocking, ProtUnverified, ProtVerified, ProtFailed.
	State string `json:"state"`
	// KillSwitch: KSOff, KSStandby, KSProtecting, KSBlocking, KSUnavailable, KSError.
	KillSwitch       string `json:"kill_switch"`
	KillSwitchDetail string `json:"kill_switch_detail,omitempty"`
	// IPv6 while connected: "tunnel", "blocked" (no IPv6 in the tunnel; rejected instead of leaked),
	// "system" (include split mode), "proxy" (only proxied apps use the tunnel).
	IPv6 string `json:"ipv6,omitempty"`
	// DNS while connected: "tunnel" (Cloudflare's resolver through the tunnel), "encrypted" (DoH/DoT
	// through the local DNS proxy), "system" (not managed: Traffic only mode), "proxy" (names sent to
	// the proxy are resolved through the tunnel).
	DNS          string        `json:"dns,omitempty"`
	Verification *Verification `json:"verification,omitempty"`
}

const (
	ProtUnprotected = "unprotected" // disconnected or paused: traffic uses the normal network
	ProtConnecting  = "connecting"  // no tunnel yet and no kill switch: traffic may use the normal network
	ProtBlocking    = "blocking"    // no tunnel; the kill switch blocks traffic until it is back
	ProtUnverified  = "unverified"  // connected; not (yet) verified, or the verification was incomplete
	ProtVerified    = "verified"    // connected; the last verification of this connection passed
	ProtFailed      = "failed"      // connected; the last verification found a problem

	KSOff         = "off"
	KSStandby     = "standby"     // switched on; it takes effect when a connection is wanted
	KSProtecting  = "protecting"  // rules loaded; only the tunnel (and the exclusions) may be used
	KSBlocking    = "blocking"    // rules loaded; no tunnel, so everything but the connection attempt is blocked
	KSUnavailable = "unavailable" // switched on, but it does not apply in this mode (see the detail)
	KSError       = "error"       // switched on, but the rules could not be loaded (see the detail)
)

// Check is one verification step. Status is "pass", "fail" or "skip".
type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// Verification is the result of checking the current connection.
// Result: "verified" (nothing failed, and the routes or Cloudflare confirmed the tunnel), "failed",
// or "incomplete" (nothing failed, but nothing proved the tunnel either: run it with the Cloudflare check).
type Verification struct {
	Result string    `json:"result"`
	At     time.Time `json:"at"`
	Checks []Check   `json:"checks"`
}

// Firewall is the kill switch backend (firewall.PF in the daemon; a fake in tests).
type Firewall interface {
	Apply(firewall.Policy) error
	Verify() error
	Clear() error
}

// Probe reads the system state that verification compares against (sysnet in the daemon; a fake in tests).
type Probe interface {
	RouteTo(dst netip.Addr) (sysnet.Route, bool, error)
	Resolvers() ([]netip.Addr, error)
	// Trace fetches Cloudflare's trace page with dial and returns its key=value fields.
	Trace(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (map[string]string, error)
}

type systemProbe struct{}

func (systemProbe) RouteTo(dst netip.Addr) (sysnet.Route, bool, error) { return sysnet.RouteTo(dst) }
func (systemProbe) Resolvers() ([]netip.Addr, error)                   { return sysnet.SystemResolvers() }

// TraceURL is Cloudflare's own report of how a request reached it ("warp=on" through WARP).
const TraceURL = "https://www.cloudflare.com/cdn-cgi/trace"

func (systemProbe) Trace(ctx context.Context, dial func(ctx context.Context, network, addr string) (net.Conn, error)) (map[string]string, error) {
	tr := &http.Transport{DialContext: dial, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	c := &http.Client{Transport: tr, Timeout: 15 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", TraceURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return parseTrace(io.LimitReader(resp.Body, 8<<10)), nil
}

func parseTrace(r io.Reader) map[string]string {
	m := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if k, v, ok := strings.Cut(sc.Text(), "="); ok {
			m[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

// Addresses used to ask the routing table where ordinary traffic goes (Cloudflare's public resolver; only
// the route lookup uses them, nothing is sent).
var (
	probeV4 = netip.MustParseAddr("1.1.1.1")
	probeV6 = netip.MustParseAddr("2606:4700:4700::1111")
)

// killSwitchScope says why the kill switch does not apply to these settings ("" when it does).
func killSwitchScope(set state.Settings) string {
	switch {
	case !set.Mode.HasTunnel():
		return "DNS-only modes do not tunnel traffic, so there is nothing to block it for"
	case set.Mode == state.ModeProxy:
		return "in Local proxy mode only apps that use the proxy are tunnelled; the system network is not changed"
	case set.SplitMode == state.SplitInclude:
		return "not available with Include split tunnelling (only the listed ranges use the tunnel)"
	}
	return ""
}

// syncKillSwitch makes the pf rules match what the engine wants right now: rules for the current tunnel
// interface (or none yet) while connecting or connected with the kill switch on, nothing otherwise. sess
// is the current session, or nil while there is none. It returns an error when the kill switch should be
// active but could not be enabled; the caller must not connect without it.
func (e *Engine) syncKillSwitch(set state.Settings, sess *session, paused bool) error {
	e.ksMu.Lock()
	defer e.ksMu.Unlock()
	e.mu.Lock()
	want := e.want
	e.mu.Unlock()

	if !want || paused || !set.KillSwitch || killSwitchScope(set) != "" {
		e.clearKillSwitchLocked()
		switch {
		case !set.KillSwitch:
			e.ks, e.ksDetail = KSOff, ""
		case killSwitchScope(set) != "":
			e.ks, e.ksDetail = KSUnavailable, killSwitchScope(set)
		case paused:
			e.ks, e.ksDetail = KSStandby, "paused on a trusted network"
		default:
			e.ks, e.ksDetail = KSStandby, "takes effect when you connect"
		}
		return nil
	}
	if e.fw == nil {
		e.ks, e.ksDetail = KSError, e.fwErr.Error()
		return fmt.Errorf("the kill switch is on but cannot work here: %w", e.fwErr)
	}
	pol := e.killSwitchPolicy(set, sess)
	if err := e.fw.Apply(pol); err != nil {
		e.ks, e.ksDetail = KSError, err.Error()
		e.ksApplied = true // possibly partly loaded: clear it when the kill switch is no longer wanted
		return fmt.Errorf("the kill switch could not be enabled: %w", err)
	}
	if !e.ksApplied {
		log.Printf("kill switch: on (traffic outside the tunnel is blocked)")
	}
	e.ksApplied = true
	if pol.TunnelIface != "" {
		e.ks, e.ksDetail = KSProtecting, ""
	} else {
		e.ks, e.ksDetail = KSBlocking, "no tunnel: traffic is blocked until the connection is back"
	}
	return nil
}

func (e *Engine) clearKillSwitchLocked() {
	if !e.ksApplied || e.fw == nil {
		return
	}
	if err := e.fw.Clear(); err != nil {
		log.Printf("kill switch: removing the rules: %v", err)
	} else {
		log.Printf("kill switch: off")
	}
	e.ksApplied = false
}

// killSwitchPolicy lists what may pass outside the tunnel: the edge addresses for the selected protocol
// (from the cached peer config, or the defaults before the key is enrolled), the API fallback addresses,
// and the exclude-mode split ranges.
func (e *Engine) killSwitchPolicy(set state.Settings, sess *session) firewall.Policy {
	var p firewall.Policy
	if sess != nil && sess.tr != nil && set.Mode.UsesTun() {
		p.TunnelIface = sess.iface
	}
	e.store.Lock()
	cfg := e.store.S.WireGuardConfig
	if set.Protocol == state.ProtoMasque {
		cfg = e.store.S.MasqueConfig
	}
	if cfg == nil || len(cfg.Peers) == 0 {
		cfg = &api.Config{Peers: []api.Peer{{}}} // not enrolled yet: the default edge
	} else {
		c := *cfg
		cfg = &c
	}
	e.store.Unlock()
	p.Edges, _ = edgeCandidates(set, cfg, true)
	if sess != nil && sess.tr != nil {
		if ep, err := netip.ParseAddrPort(sess.tr.Stats().Endpoint); err == nil && !slices.Contains(p.Edges, ep) {
			p.Edges = append(p.Edges, ep)
		}
	}
	for _, s := range api.FallbackAPIIPs {
		if a, err := netip.ParseAddr(s); err == nil {
			p.API = append(p.API, a)
		}
	}
	if set.SplitMode != state.SplitInclude {
		for _, s := range set.SplitIPs {
			if pf, err := parsePrefix(s); err == nil {
				p.Bypass = append(p.Bypass, pf)
			}
		}
	}
	switch set.Mode {
	case state.ModeWarp, state.ModeWarpDoH, state.ModeWarpDoT:
		p.BlockBypassDNS = true
		if sess != nil && sess.dns != nil {
			p.DNSAllowed = sess.dns.FallbackServers
		}
	}
	return p
}

// Verify checks the current connection: that the tunnel is up, that the routing table sends IPv4 and
// IPv6 into it (or rejects IPv6), that the system DNS servers are the ones OpenWarp set, that the kill
// switch rules are loaded, and, with withTrace, that Cloudflare reports the request as coming through
// WARP. The result is kept with the connection and shown in Status until it reconnects.
func (e *Engine) Verify(ctx context.Context, withTrace bool) (*Verification, error) {
	e.mu.Lock()
	sess := e.sess
	connected := e.status == StatusConnected
	e.mu.Unlock()
	if sess == nil || !connected {
		return nil, errors.New("not connected")
	}
	e.store.Lock()
	set := e.store.S.Settings
	e.store.Unlock()

	var checks []Check
	add := func(name, status, detail string) { checks = append(checks, Check{name, status, detail}) }
	proven := false

	if sess.tr != nil {
		add("tunnel", "pass", sess.describe())
	} else {
		add("tunnel", "skip", "DNS-only mode: traffic is not tunnelled")
	}

	switch {
	case !sess.mode.UsesTun():
		why := "Local proxy mode: only apps that use the proxy are tunnelled"
		if !sess.mode.HasTunnel() {
			why = "DNS-only mode: traffic is not tunnelled"
		}
		add("ipv4_route", "skip", why)
		add("ipv6_route", "skip", why)
	case set.SplitMode == state.SplitInclude:
		add("ipv4_route", "skip", "Include split tunnelling: only the listed ranges use the tunnel")
		add("ipv6_route", "skip", "Include split tunnelling: only the listed ranges use the tunnel")
	default:
		r, ok, err := e.probe.RouteTo(probeV4)
		switch {
		case err != nil:
			add("ipv4_route", "fail", "route lookup failed: "+err.Error())
		case ok && r.Iface == sess.iface:
			add("ipv4_route", "pass", "IPv4 goes through "+sess.iface)
			proven = true
		case ok && r.Reject:
			add("ipv4_route", "fail", "IPv4 is rejected instead of tunnelled")
		case ok:
			add("ipv4_route", "fail", "IPv4 goes through "+r.Iface+", outside the tunnel")
		default:
			add("ipv4_route", "fail", "no IPv4 route")
		}
		r, ok, err = e.probe.RouteTo(probeV6)
		switch {
		case err != nil:
			add("ipv6_route", "fail", "route lookup failed: "+err.Error())
		case !ok:
			add("ipv6_route", "pass", "no IPv6 route: IPv6 cannot leave the machine")
		case r.Iface == sess.iface:
			add("ipv6_route", "pass", "IPv6 goes through "+sess.iface)
		case r.Reject:
			add("ipv6_route", "pass", "IPv6 is blocked (the tunnel has no IPv6 address)")
		default:
			add("ipv6_route", "fail", "IPv6 goes through "+r.Iface+", outside the tunnel")
		}
	}

	if want := expectedDNS(sess.mode, set); want == nil {
		why := "Traffic only mode: system DNS is not managed and may be sent outside the tunnel"
		if sess.mode == state.ModeProxy {
			why = "Local proxy mode: names sent to the proxy (socks5h) are resolved through the tunnel; system DNS is not changed"
		}
		add("dns", "skip", why)
	} else if got, err := e.probe.Resolvers(); err != nil {
		add("dns", "fail", "reading the DNS configuration failed: "+err.Error())
	} else if len(got) == 0 {
		add("dns", "fail", "no system DNS servers")
	} else if extra := notIn(got, want); len(extra) > 0 {
		add("dns", "fail", "system DNS uses "+joinAddrs(extra)+", not set by OpenWarp")
	} else {
		add("dns", "pass", "system DNS: "+joinAddrs(got))
	}

	e.ksMu.Lock()
	applied := e.ksApplied
	e.ksMu.Unlock()
	switch {
	case !set.KillSwitch:
		add("kill_switch", "skip", "off")
	case killSwitchScope(set) != "":
		add("kill_switch", "skip", killSwitchScope(set))
	case e.fw == nil || !applied:
		add("kill_switch", "fail", "switched on, but no rules are loaded")
	default:
		if err := e.fw.Verify(); err != nil {
			add("kill_switch", "fail", err.Error())
		} else {
			add("kill_switch", "pass", "pf rules loaded and pf enabled")
		}
	}

	if withTrace {
		if sess.tr == nil {
			add("cloudflare", "skip", "DNS-only mode: traffic is not tunnelled")
		} else {
			dial := (&net.Dialer{Timeout: 10 * time.Second}).DialContext
			if sess.proxy != nil {
				dial = sess.proxy.Dial
			}
			tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			m, err := e.probe.Trace(tctx, dial)
			cancel()
			switch {
			case err != nil:
				add("cloudflare", "fail", "trace request failed: "+err.Error())
			case m["warp"] == "on" || m["warp"] == "plus":
				add("cloudflare", "pass", "Cloudflare reports warp="+m["warp"]+" (data centre "+m["colo"]+")")
				proven = true
			default:
				add("cloudflare", "fail", "Cloudflare reports warp="+orDash(m["warp"])+": the request did not arrive through WARP")
			}
		}
	}

	v := &Verification{Result: "incomplete", At: time.Now().UTC(), Checks: checks}
	if slices.ContainsFunc(checks, func(c Check) bool { return c.Status == "fail" }) {
		v.Result = "failed"
	} else if proven {
		v.Result = "verified"
	}
	e.mu.Lock()
	if e.sess == sess {
		e.verif, e.verifSess = v, sess
	}
	e.mu.Unlock()
	return v, nil
}

// expectedDNS is the set of system DNS servers OpenWarp configures in a mode (nil: it does not manage DNS).
func expectedDNS(m state.Mode, set state.Settings) []netip.Addr {
	switch m {
	case state.ModeWarp:
		return resolverFor(set).IPs
	case state.ModeWarpDoH, state.ModeWarpDoT, state.ModeDoH, state.ModeDoT:
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	}
	return nil
}

func notIn(got, want []netip.Addr) []netip.Addr {
	var out []netip.Addr
	for _, a := range got {
		if !slices.Contains(want, a.Unmap()) {
			out = append(out, a)
		}
	}
	return out
}

func joinAddrs(as []netip.Addr) string {
	s := make([]string, len(as))
	for i, a := range as {
		s[i] = a.String()
	}
	return strings.Join(s, ", ")
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// killSwitchState reads the kill switch state. Never call it with e.mu held (the lock order is ksMu, then mu).
func (e *Engine) killSwitchState() (string, string) {
	e.ksMu.Lock()
	defer e.ksMu.Unlock()
	return e.ks, e.ksDetail
}

// protectionLocked summarises the protection for Status, given the kill switch state. Call with e.mu held.
func (e *Engine) protectionLocked(set state.Settings, ks, ksDetail string) Protection {
	p := Protection{KillSwitch: ks, KillSwitchDetail: ksDetail}
	if p.KillSwitch == "" {
		p.KillSwitch = KSOff
	}
	if !set.KillSwitch {
		p.KillSwitch, p.KillSwitchDetail = KSOff, ""
	} else if why := killSwitchScope(set); why != "" {
		p.KillSwitch, p.KillSwitchDetail = KSUnavailable, why
	} else if p.KillSwitch == KSOff { // switched on since the loop last looked
		p.KillSwitch, p.KillSwitchDetail = KSStandby, "takes effect when you connect"
	}
	s := e.sess
	switch {
	case !e.want || e.status == StatusPaused:
		p.State = ProtUnprotected
	case s == nil || e.status != StatusConnected:
		p.State = ProtConnecting
		if p.KillSwitch == KSBlocking {
			p.State = ProtBlocking
		}
	default:
		p.State = ProtUnverified
		if e.verifSess == s && e.verif != nil {
			p.Verification = e.verif
			switch e.verif.Result {
			case "verified":
				p.State = ProtVerified
			case "failed":
				p.State = ProtFailed
			}
		}
		switch {
		case s.mode == state.ModeProxy:
			p.IPv6, p.DNS = "proxy", "proxy"
		case !s.mode.HasTunnel():
			p.DNS = "encrypted"
		default:
			p.IPv6 = s.applied.IPv6()
			switch s.mode {
			case state.ModeWarp:
				p.DNS = "tunnel"
			case state.ModeWarpDoH, state.ModeWarpDoT:
				p.DNS = "encrypted"
			default:
				p.DNS = "system"
			}
		}
	}
	return p
}

// ResetNetwork removes the kill switch rules and undoes the routes and DNS servers recorded by a daemon
// that is no longer running (the state directory dir holds the pf reference and the journal). It needs
// root, and is used by `openwarp recover` and `openwarp service uninstall`. It returns what it did.
func ResetNetwork(dir string) []string {
	var out []string
	switch err := sysnet.Recover(filepath.Join(dir, JournalFile)); {
	case err == nil:
		out = append(out, "Restored the routes and DNS servers left by the daemon")
	case errors.Is(err, sysnet.ErrNoJournal):
	default:
		out = append(out, "Network journal not applied: "+err.Error())
	}
	fw, err := firewall.New(dir)
	if err != nil {
		return append(out, "Kill switch: "+err.Error())
	}
	if err := fw.Clear(); err != nil {
		return append(out, "Kill switch: "+err.Error())
	}
	return append(out, "Kill switch rules removed (anchor "+firewall.Anchor+")")
}
