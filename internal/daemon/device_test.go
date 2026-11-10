package daemon

import (
	"runtime"
	"testing"
)

func TestDeviceIdentity(t *testing.T) {
	typ, model := deviceIdentity()
	if model == "" {
		t.Fatal("empty model")
	}
	if runtime.GOOS == "darwin" && (typ != "macOS" || model == legacyDeviceModel) {
		t.Fatalf("got %s/%s, want macOS and the hw.model string", typ, model)
	}
	t.Logf("registers as %s / %s", typ, model)
}
