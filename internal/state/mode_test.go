package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestModesMatchTheOfficialClient(t *testing.T) {
	want := map[Mode]struct {
		label           string
		tunnel, usesTun bool
	}{
		ModeWarp:       {"Traffic and DNS (UDP)", true, true},
		ModeWarpDoH:    {"Traffic and DNS (HTTPS)", true, true},
		ModeWarpDoT:    {"Traffic and DNS (TLS)", true, true},
		ModeDoH:        {"DNS only (HTTPS)", false, false},
		ModeDoT:        {"DNS only (TLS)", false, false},
		ModeProxy:      {"Local proxy (SOCKS5/HTTP)", true, false},
		ModeTunnelOnly: {"Traffic only", true, true},
	}
	if len(AllModes) != len(want) {
		t.Fatalf("AllModes has %d modes, want %d", len(AllModes), len(want))
	}
	for _, m := range AllModes {
		w, ok := want[m]
		if !ok {
			t.Fatalf("unexpected mode %q", m)
		}
		if !m.Valid() || m.Label() != w.label || m.HasTunnel() != w.tunnel || m.UsesTun() != w.usesTun {
			t.Errorf("%s: valid=%v label=%q tunnel=%v usesTun=%v", m, m.Valid(), m.Label(), m.HasTunnel(), m.UsesTun())
		}
	}
	for _, bad := range []Mode{"", "WARP", "bogus", "warp+"} {
		if bad.Valid() {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestDefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s.Mode != ModeWarp || s.Protocol != ProtoMasque || s.ProxyPort != 40000 || s.MTU != 1280 ||
		s.SplitMode != SplitExclude || !s.PostQuantum || s.AlwaysOn || s.Families != FamiliesOff {
		t.Fatalf("defaults changed: %+v", s)
	}
	// The default lists are copies: editing them must not change the package defaults.
	s.SplitIPs[0] = "changed"
	s.FallbackDomains[0] = "changed"
	if DefaultExcludes[0] == "changed" || DefaultFallbackDomains[0] == "changed" {
		t.Fatal("DefaultSettings shares its slices with the package defaults")
	}
}

func TestOpenFillsMissingSettingsAndSavesPrivately(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"settings":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := st.S.Settings
	if s.Mode != ModeWarp || s.Protocol != ProtoMasque || s.ProxyPort != 40000 || s.MTU != 1280 {
		t.Fatalf("missing settings not defaulted: %+v", s)
	}
	st.Lock()
	st.S.Settings.MTU = 1400
	err = st.Save()
	st.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, "state.json"))
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state.json mode %v, want 0600", info.Mode().Perm())
	}
	var back State
	b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
	if json.Unmarshal(b, &back) != nil || back.Settings.MTU != 1400 {
		t.Fatalf("saved state not readable: %s", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.tmp")); err == nil {
		t.Fatal("temporary file left behind")
	}
}

func TestOpenRejectsCorruptState(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{not json`), 0o600)
	if _, err := Open(dir); err == nil {
		t.Fatal("corrupt state.json was accepted silently")
	}
}
