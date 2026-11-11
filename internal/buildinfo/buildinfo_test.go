package buildinfo

import "testing"

func TestFullVersion(t *testing.T) {
	none := func() (string, bool) { return "", false }
	stamped := func() (string, bool) { return "1a2b3c4", true }
	for _, tc := range []struct {
		build string
		stamp func() (string, bool)
		want  string
	}{
		{"", stamped, Version},                          // release: exactly the version
		{"dev.9f8e7d6", none, Version + "+dev.9f8e7d6"}, // build.sh
		{"dev.9f8e7d6.dirty", none, Version + "+dev.9f8e7d6.dirty"},
		{"dev", stamped, Version + "+dev.1a2b3c4.dirty"}, // plain go build in a modified checkout
		{"dev", none, Version + "+dev"},                  // no VCS information (tests, tarballs)
		{"dev x;rm", none, Version + "+dev.invalid"},     // never passes odd text through
		{"dev..x", none, Version + "+dev.invalid"},
	} {
		if got := full(tc.build, tc.stamp); got != tc.want {
			t.Errorf("full(%q) = %q, want %q", tc.build, got, tc.want)
		}
	}
	if Full() == Version || IsRelease() {
		t.Fatalf("an unstamped test build reports itself as release %q", Full())
	}
}
