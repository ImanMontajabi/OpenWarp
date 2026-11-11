//go:build darwin

package firewall

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// pfctl -n parses a ruleset without loading it (no root, nothing changes), so the generated rules are
// checked against the real pf grammar on macOS.
func TestRulesParseWithPfctl(t *testing.T) {
	if _, err := exec.LookPath("pfctl"); err != nil {
		t.Skip("pfctl not found")
	}
	check := func(name, rules string) {
		t.Helper()
		f := filepath.Join(t.TempDir(), name+".pf")
		os.WriteFile(f, []byte(rules), 0o600)
		if out, err := exec.Command("pfctl", "-n", "-a", Anchor, "-f", f).CombinedOutput(); err != nil {
			t.Fatalf("%s: pfctl rejected the rules: %v\n%s\n%s", name, err, out, rules)
		}
	}
	full, _ := Rules(policy())
	check("full", full)
	minimal, _ := Rules(Policy{})
	check("minimal", minimal)
	noDNS, _ := Rules(Policy{Bypass: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}, BlockBypassDNS: true})
	check("bypass-without-dns-allow", noDNS)
	// The check itself must catch a bad rule.
	f := filepath.Join(t.TempDir(), "bad.pf")
	os.WriteFile(f, []byte("pass quik on lo0 all\n"), 0o600)
	if err := exec.Command("pfctl", "-n", "-a", Anchor, "-f", f).Run(); err == nil {
		t.Fatal("pfctl -n accepted a syntax error; the check proves nothing here")
	}
}
