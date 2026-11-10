package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenMigratesLegacyState(t *testing.T) {
	root := t.TempDir()
	legacy := filepath.Join(root, legacyDirName)
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatal(err)
	}
	old := `{"active_key_type":"secp256r1","settings":{"mode":"proxy","proxy_port":41000}}`
	if err := os.WriteFile(filepath.Join(legacy, "state.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}

	st, err := Open(filepath.Join(root, "openwarp"))
	if err != nil {
		t.Fatal(err)
	}
	if st.S.Settings.Mode != "proxy" || st.S.Settings.ProxyPort != 41000 {
		t.Fatalf("legacy settings not migrated: %+v", st.S.Settings)
	}
	fi, err := os.Stat(filepath.Join(root, "openwarp", "state.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("migrated state.json missing or wrong mode: %v %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(legacy, "state.json")); err != nil {
		t.Fatalf("legacy state.json should be left in place: %v", err)
	}
}

func TestOpenDoesNotOverwriteExistingState(t *testing.T) {
	root := t.TempDir()
	for name, mode := range map[string]string{legacyDirName: "proxy", "openwarp": "doh"} {
		d := filepath.Join(root, name)
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, "state.json"), []byte(`{"settings":{"mode":"`+mode+`"}}`), 0o600)
	}
	st, err := Open(filepath.Join(root, "openwarp"))
	if err != nil {
		t.Fatal(err)
	}
	if st.S.Settings.Mode != "doh" {
		t.Fatalf("existing state was overwritten: mode %q", st.S.Settings.Mode)
	}
}
