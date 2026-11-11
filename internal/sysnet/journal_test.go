package sysnet

import (
	"os"
	"path/filepath"
	"testing"
)

func TestJournalRoundTrip(t *testing.T) {
	p := filepath.Join(t.TempDir(), "network-journal.json")
	in := &journal{
		Routes: [][]string{
			{"-n", "delete", "-inet", "-host", "162.159.198.1", "192.168.1.1"},
			{"-n", "delete", "-inet6", "-net", "::/1", "::1", "-reject"},
			{"-n", "delete", "-inet6", "-net", "fd00::/8", "fe80::1%en0"},
			{"-n", "delete", "-inet", "-net", "0.0.0.0/1", "-interface", "utun5"},
		},
		DNS: map[string][]string{"Wi-Fi": {"192.168.1.1", "fe80::1"}, "Thunderbolt Bridge": nil},
	}
	if err := writeJournal(p, in); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("journal mode %v, want 0600", fi.Mode().Perm())
	}
	out, err := readJournal(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Routes) != 4 || len(out.DNS["Wi-Fi"]) != 2 {
		t.Fatalf("read back %+v", out)
	}
}

// The journal is only ever replayed as `route -n delete …` and `networksetup -setdnsservers`; anything else
// in it is refused.
func TestJournalRejectsUnexpectedCommands(t *testing.T) {
	bad := []journal{
		{Routes: [][]string{{"-n", "add", "-inet", "-net", "0.0.0.0/1", "10.0.0.1"}}},
		{Routes: [][]string{{"-n", "flush"}}},
		{Routes: [][]string{{"-n", "delete", "-inet", "1.2.3.4; rm -rf /"}}},
		{Routes: [][]string{{"-n", "delete", "-inet", "$(id)", "x"}}},
		{DNS: map[string][]string{"Wi-Fi": {"not-an-ip"}}},
		{DNS: map[string][]string{"": {"1.1.1.1"}}},
	}
	for i, j := range bad {
		p := filepath.Join(t.TempDir(), "j.json")
		writeJournal(p, &j)
		if _, err := readJournal(p); err == nil {
			t.Errorf("case %d accepted: %+v", i, j)
		}
	}
	p := filepath.Join(t.TempDir(), "garbage.json")
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := readJournal(p); err == nil {
		t.Error("garbage accepted")
	}
}

func TestRecoverWithoutJournal(t *testing.T) {
	if err := Recover(filepath.Join(t.TempDir(), "none.json")); err != ErrNoJournal {
		t.Fatalf("err = %v, want ErrNoJournal", err)
	}
}
