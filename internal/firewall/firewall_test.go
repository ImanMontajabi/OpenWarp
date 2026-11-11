package firewall

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func policy() Policy {
	return Policy{
		TunnelIface: "utun7",
		Edges: []netip.AddrPort{
			netip.MustParseAddrPort("162.159.198.1:500"), netip.MustParseAddrPort("162.159.198.1:443"),
			netip.MustParseAddrPort("162.159.198.1:443"), netip.MustParseAddrPort("[2606:4700:103::1]:443"),
		},
		API:            []netip.Addr{netip.MustParseAddr("162.159.192.1"), netip.MustParseAddr("2606:4700:d0::a29f:c001")},
		Bypass:         []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("10.0.0.0/8")},
		BlockBypassDNS: true,
		DNSAllowed:     []netip.Addr{netip.MustParseAddr("192.168.1.1")},
	}
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(s), "\n") {
		if !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func index(t *testing.T, ls []string, want string) int {
	t.Helper()
	for i, l := range ls {
		if l == want {
			return i
		}
	}
	t.Fatalf("rule %q missing from:\n%s", want, strings.Join(ls, "\n"))
	return -1
}

// The ruleset blocks everything by default and lets through only the tunnel, the edge, the API fallback,
// address configuration and the configured exclusions, in an order where the final block cannot be skipped.
func TestRulesPolicy(t *testing.T) {
	out, err := Rules(policy())
	if err != nil {
		t.Fatal(err)
	}
	ls := lines(out)
	if last := ls[len(ls)-1]; last != "block drop quick all" {
		t.Fatalf("last rule = %q, want the catch-all block", last)
	}
	for _, l := range ls {
		if strings.HasPrefix(l, "pass") && !strings.Contains(l, "quick") {
			t.Errorf("pass rule without quick (a later rule could override it): %q", l)
		}
		if strings.HasPrefix(l, "pass") && strings.Contains(l, "to any") && !strings.Contains(l, "port 67") && !strings.Contains(l, "port 546") && !strings.Contains(l, "<openwarp_bypass> to any") {
			t.Errorf("unexpected open pass rule: %q", l)
		}
	}
	index(t, ls, "pass quick on lo0 all")
	index(t, ls, "pass quick on utun7 all")
	// Ports are merged and sorted per address; duplicates are dropped.
	index(t, ls, "pass out quick inet proto udp from any to 162.159.198.1 port { 443, 500 } keep state")
	index(t, ls, "pass out quick inet6 proto udp from any to 2606:4700:103::1 port { 443 } keep state")
	index(t, ls, "pass out quick inet proto tcp from any to 162.159.192.1 port 443 flags S/SA keep state")
	index(t, ls, "pass out quick inet6 proto tcp from any to 2606:4700:d0::a29f:c001 port 443 flags S/SA keep state")
	index(t, ls, "table <openwarp_bypass> const { 10.0.0.0/8, 192.168.0.0/16, fe80::/10 }")
	// DNS to the local network is blocked before the bypass pass, except to the network's own resolver
	// (Local Domain Fallback).
	dnsOK := index(t, ls, "pass out quick proto { tcp, udp } from any to <openwarp_dns> port 53 keep state")
	dnsBlock := index(t, ls, "block drop quick proto { tcp, udp } from any to <openwarp_bypass> port { 53, 853 }")
	bypass := index(t, ls, "pass out quick from any to <openwarp_bypass> keep state")
	if !(dnsOK < dnsBlock && dnsBlock < bypass) {
		t.Fatalf("DNS rules out of order: allow %d, block %d, bypass %d", dnsOK, dnsBlock, bypass)
	}
	index(t, ls, "table <openwarp_dns> const { 192.168.1.1 }")
}

// While no tunnel is up the ruleset has no interface pass: only the connection attempt can leave.
func TestRulesWithoutTunnelBlockEverythingElse(t *testing.T) {
	p := Policy{Edges: []netip.AddrPort{netip.MustParseAddrPort("162.159.198.2:443")}}
	out, err := Rules(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "utun") || strings.Contains(out, "openwarp_bypass") || strings.Contains(out, "openwarp_dns") {
		t.Fatalf("rules without tunnel or bypass mention them:\n%s", out)
	}
	ls := lines(out)
	if ls[len(ls)-1] != "block drop quick all" {
		t.Fatalf("no final block:\n%s", out)
	}
	// Without BlockBypassDNS (tunnel-only mode leaves DNS to the system) DNS to the LAN is not blocked.
	p.Bypass = []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}
	out, _ = Rules(p)
	if strings.Contains(out, "port { 53, 853 }") {
		t.Fatalf("LAN DNS blocked although the mode does not manage DNS:\n%s", out)
	}
}

func TestRulesRejectUnsafeInput(t *testing.T) {
	for _, iface := range []string{"en0", "utun1 all\npass quick all", "lo0", "utun", "utun12345"} {
		if _, err := Rules(Policy{TunnelIface: iface}); err == nil {
			t.Errorf("interface %q accepted", iface)
		}
	}
	// A bypass of everything would turn the kill switch off; it is dropped, never rendered.
	out, err := Rules(Policy{Bypass: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "0.0.0.0/0") || strings.Contains(out, "::/0") || strings.Contains(out, "openwarp_bypass") {
		t.Fatalf("catch-all bypass rendered:\n%s", out)
	}
	// Unspecified and zero-port edges are ignored.
	out, _ = Rules(Policy{Edges: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:443"), netip.MustParseAddrPort("162.159.198.1:0")}})
	if strings.Contains(out, "proto udp from any to") {
		t.Fatalf("invalid edges rendered:\n%s", out)
	}
}

func TestRulesDeterministic(t *testing.T) {
	a, _ := Rules(policy())
	p := policy()
	p.Edges[0], p.Edges[3] = p.Edges[3], p.Edges[0]
	p.Bypass[0], p.Bypass[2] = p.Bypass[2], p.Bypass[0]
	b, _ := Rules(p)
	if a != b {
		t.Fatalf("order-dependent output:\n%s\n---\n%s", a, b)
	}
}

// fakePF emulates the pfctl commands the firewall uses.
type fakePF struct {
	calls     []string
	stock     bool // the main ruleset has the com.apple anchor point
	enabled   bool
	refs      map[string]bool
	next      int
	anchor    string
	failLoad  bool
	loadCount int
}

func newFake() *fakePF { return &fakePF{stock: true, refs: map[string]bool{}, next: 100} }

func (f *fakePF) run(stdin, name string, args ...string) (string, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, cmd)
	switch cmd {
	case "pfctl -s rules":
		if f.stock {
			return "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n", nil
		}
		return "", nil
	case "pfctl -q -a com.apple/openwarp -f -":
		if f.failLoad {
			return "stdin:3: syntax error", errors.New("exit status 1")
		}
		f.loadCount++
		f.anchor = stdin
		return "", nil
	case "pfctl -a com.apple/openwarp -s rules":
		// pfctl prints only the rules (not tables or comments).
		var out []string
		for _, l := range lines(f.anchor) {
			if !strings.HasPrefix(l, "table") {
				out = append(out, l)
			}
		}
		return strings.Join(out, "\n"), nil
	case "pfctl -s info":
		if f.enabled {
			return "Status: Enabled for 0 days 00:00:01", nil
		}
		return "Status: Disabled", nil
	case "pfctl -E":
		f.next++
		tok := strconv.Itoa(f.next)
		f.refs[tok] = true
		f.enabled = true
		return "pf enabled\nToken : " + tok + "\n", nil
	case "pfctl -q -a com.apple/openwarp -F all":
		f.anchor = ""
		return "", nil
	}
	if name == "pfctl" && len(args) == 2 && args[0] == "-X" {
		if !f.refs[args[1]] {
			return "", errors.New("invalid token")
		}
		delete(f.refs, args[1])
		if len(f.refs) == 0 {
			f.enabled = false
		}
		return "", nil
	}
	return "", errors.New("unexpected command " + cmd)
}

func TestPFApplyAndClear(t *testing.T) {
	fk := newFake()
	tok := filepath.Join(t.TempDir(), "pf-token")
	f := &PF{Run: fk.run, TokenFile: tok}
	if err := f.Apply(policy()); err != nil {
		t.Fatal(err)
	}
	if !fk.enabled || len(fk.refs) != 1 || !strings.Contains(fk.anchor, "block drop quick all") {
		t.Fatalf("after Apply: enabled=%v refs=%v anchor=%q", fk.enabled, fk.refs, fk.anchor)
	}
	if b, err := os.ReadFile(tok); err != nil || strings.TrimSpace(string(b)) == "" {
		t.Fatalf("token not saved: %q %v", b, err)
	}
	// The same policy again does not reload, and does not take a second reference.
	if err := f.Apply(policy()); err != nil || fk.loadCount != 1 || len(fk.refs) != 1 {
		t.Fatalf("re-apply: err=%v loads=%d refs=%d", err, fk.loadCount, len(fk.refs))
	}
	// A changed policy (the tunnel went away) is reloaded.
	p := policy()
	p.TunnelIface = ""
	if err := f.Apply(p); err != nil || fk.loadCount != 2 || strings.Contains(fk.anchor, "utun7") {
		t.Fatalf("changed policy: err=%v loads=%d", err, fk.loadCount)
	}
	if err := f.Verify(); err != nil {
		t.Fatal(err)
	}
	// Someone flushes the anchor (or disables pf): the next Apply, which the daemon runs every few seconds
	// while connected, puts both back.
	fk.anchor, fk.enabled = "", false
	if err := f.Verify(); err == nil {
		t.Fatal("Verify passed after the anchor was flushed")
	}
	if err := f.Apply(p); err != nil || fk.loadCount != 3 || !fk.enabled {
		t.Fatalf("after an external flush: err=%v loads=%d enabled=%v", err, fk.loadCount, fk.enabled)
	}
	if err := f.Clear(); err != nil {
		t.Fatal(err)
	}
	if fk.enabled || len(fk.refs) != 0 || fk.anchor != "" {
		t.Fatalf("after Clear: enabled=%v refs=%v anchor=%q", fk.enabled, fk.refs, fk.anchor)
	}
	if _, err := os.Stat(tok); !os.IsNotExist(err) {
		t.Fatal("token file left behind")
	}
	if err := f.Verify(); err == nil {
		t.Fatal("Verify passed with the rules removed")
	}
}

// pf used by something else stays enabled when OpenWarp lets go of it.
func TestPFKeepsOtherUsersReference(t *testing.T) {
	fk := newFake()
	fk.enabled, fk.refs["99"] = true, true
	f := &PF{Run: fk.run}
	if err := f.Apply(policy()); err != nil {
		t.Fatal(err)
	}
	if len(fk.refs) != 2 {
		t.Fatalf("OpenWarp did not take its own reference: %v", fk.refs)
	}
	f.Clear()
	if !fk.enabled || !fk.refs["99"] {
		t.Fatalf("Clear released someone else's reference: enabled=%v refs=%v", fk.enabled, fk.refs)
	}
}

// After a crash, a new process finds the saved reference: it reuses it while pf is still enabled, and
// Clear releases it.
func TestPFRecoversAfterCrash(t *testing.T) {
	fk := newFake()
	tok := filepath.Join(t.TempDir(), "pf-token")
	if err := (&PF{Run: fk.run, TokenFile: tok}).Apply(policy()); err != nil {
		t.Fatal(err)
	}
	// The process dies; the rules and the reference stay (fail closed).
	g := &PF{Run: fk.run, TokenFile: tok}
	if err := g.Apply(policy()); err != nil {
		t.Fatal(err)
	}
	if len(fk.refs) != 1 {
		t.Fatalf("restart took another reference: %v", fk.refs)
	}
	h := &PF{Run: fk.run, TokenFile: tok}
	if err := h.Clear(); err != nil {
		t.Fatal(err)
	}
	if fk.enabled || len(fk.refs) != 0 || fk.anchor != "" {
		t.Fatalf("stale rules or reference after cleanup: enabled=%v refs=%v", fk.enabled, fk.refs)
	}

	// After a reboot pf is disabled and the saved token means nothing: Apply enables pf again.
	os.WriteFile(tok, []byte("42\n"), 0o600)
	fk.enabled = false
	if err := (&PF{Run: fk.run, TokenFile: tok}).Apply(policy()); err != nil || !fk.enabled {
		t.Fatalf("after reboot: err=%v enabled=%v", err, fk.enabled)
	}
}

func TestPFRefusesWithoutAnchorPoint(t *testing.T) {
	fk := newFake()
	fk.stock = false
	err := (&PF{Run: fk.run}).Apply(policy())
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if fk.loadCount != 0 || fk.enabled {
		t.Fatal("rules loaded or pf enabled although they would never be evaluated")
	}
}

func TestPFReportsLoadErrors(t *testing.T) {
	fk := newFake()
	fk.failLoad = true
	if err := (&PF{Run: fk.run}).Apply(policy()); err == nil || !strings.Contains(err.Error(), "loading") {
		t.Fatalf("err = %v", err)
	}
	if fk.enabled {
		t.Fatal("pf enabled without rules")
	}
}

func TestPFTokenFileIgnoresGarbage(t *testing.T) {
	tok := filepath.Join(t.TempDir(), "pf-token")
	os.WriteFile(tok, []byte("1; rm -rf /\n"), 0o600)
	if got := (&PF{TokenFile: tok}).readToken(); got != "" {
		t.Fatalf("token %q accepted", got)
	}
}
