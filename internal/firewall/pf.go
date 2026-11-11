package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

// Runner runs a command with stdin and returns its combined output.
type Runner func(stdin string, name string, args ...string) (string, error)

func execRunner(stdin string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, bytes.TrimSpace(out))
	}
	return string(out), nil
}

// PF applies policies with pfctl. Use New in the daemon; tests set Run.
type PF struct {
	// Run executes pfctl (exec by default).
	Run Runner
	// TokenFile keeps the pf enable reference across daemon restarts and crashes, so the next start can
	// release it. Empty: the reference is kept in memory only.
	TokenFile string

	mu     sync.Mutex
	token  string
	loaded string // the rules currently in the anchor, as loaded by this process
}

// New returns the macOS pf firewall when the kill switch can work here (darwin, root), keeping its enable
// reference in dir; otherwise nil and ErrUnsupported.
func New(dir string) (*PF, error) {
	if runtime.GOOS != "darwin" {
		return nil, fmt.Errorf("%w: pf is only used on macOS", ErrUnsupported)
	}
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("%w: it needs the background service (root)", ErrUnsupported)
	}
	return &PF{Run: execRunner, TokenFile: filepath.Join(dir, "pf-token")}, nil
}

var reToken = regexp.MustCompile(`(?m)^Token\s*:\s*([0-9]+)\s*$`)

// Apply loads the policy's rules into the anchor (atomically replacing the previous ones), makes sure pf is
// enabled, and reads the anchor back to verify the block rule is in place. An unchanged policy is not
// reloaded, but pf's state is still checked.
func (f *PF) Apply(p Policy) error {
	rules, err := Rules(p)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	main, err := f.Run("", "pfctl", "-s", "rules")
	if err != nil {
		return fmt.Errorf("reading the pf ruleset: %w", err)
	}
	if !strings.Contains(main, `anchor "com.apple/*"`) {
		// Without the stock anchor point our rules would load but never be evaluated: refuse rather than
		// report a kill switch that does nothing. /etc/pf.conf is deliberately not edited.
		return fmt.Errorf("%w: the active pf ruleset has no `anchor \"com.apple/*\"` (was /etc/pf.conf changed?)", ErrUnsupported)
	}
	// Reload when the policy changed, or when the rules are gone although this process loaded them (someone
	// flushed the anchor).
	if rules != f.loaded || f.verifyLocked() != nil {
		if _, err := f.Run(rules, "pfctl", "-q", "-a", Anchor, "-f", "-"); err != nil {
			return fmt.Errorf("loading the kill switch rules: %w", err)
		}
		f.loaded = rules
	}
	if f.token == "" {
		f.token = f.readToken()
	}
	info, err := f.Run("", "pfctl", "-s", "info")
	if err != nil {
		return fmt.Errorf("reading pf status: %w", err)
	}
	// Take our own reference unless the one we hold (possibly from before a restart) still counts.
	if f.token == "" || !enabled(info) {
		if f.token != "" {
			// pf was disabled behind our back (pfctl -d, a reboot): drop the old reference, if it still
			// exists, so they do not pile up.
			f.Run("", "pfctl", "-X", f.token)
			f.token = ""
		}
		out, err := f.Run("", "pfctl", "-E")
		if err != nil {
			return fmt.Errorf("enabling pf: %w", err)
		}
		m := reToken.FindStringSubmatch(out)
		if m == nil {
			return fmt.Errorf("enabling pf: no reference token in %q", strings.TrimSpace(out))
		}
		f.token = m[1]
		f.writeToken()
		if info, err = f.Run("", "pfctl", "-s", "info"); err != nil {
			return fmt.Errorf("reading pf status: %w", err)
		}
	}
	if !enabled(info) {
		return errors.New("pf is not enabled after `pfctl -E`")
	}
	return f.verifyLocked()
}

// Verify checks that the anchor holds a final block rule and that pf is enabled.
func (f *PF) Verify() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	info, err := f.Run("", "pfctl", "-s", "info")
	if err != nil {
		return fmt.Errorf("reading pf status: %w", err)
	}
	if !enabled(info) {
		return errors.New("pf is disabled")
	}
	return f.verifyLocked()
}

func (f *PF) verifyLocked() error {
	got, err := f.Run("", "pfctl", "-a", Anchor, "-s", "rules")
	if err != nil {
		return fmt.Errorf("reading the kill switch rules: %w", err)
	}
	if !strings.Contains(got, "block drop quick all") {
		return errors.New("the kill switch rules are not loaded")
	}
	return nil
}

// Clear removes OpenWarp's rules and releases its pf reference (pf stays enabled if something else holds
// one). It also cleans up after a crashed daemon, using the saved reference.
func (f *PF) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	if _, err := f.Run("", "pfctl", "-q", "-a", Anchor, "-F", "all"); err != nil {
		errs = append(errs, fmt.Errorf("removing the kill switch rules: %w", err))
	}
	f.loaded = ""
	if f.token == "" {
		f.token = f.readToken()
	}
	if f.token != "" {
		// An unknown token (pf was reset, e.g. by a reboot) is not an error worth reporting.
		f.Run("", "pfctl", "-X", f.token)
		f.token = ""
	}
	if f.TokenFile != "" {
		os.Remove(f.TokenFile)
	}
	return errors.Join(errs...)
}

func enabled(info string) bool { return strings.Contains(info, "Status: Enabled") }

func (f *PF) readToken() string {
	if f.TokenFile == "" {
		return ""
	}
	b, err := os.ReadFile(f.TokenFile)
	if err != nil {
		return ""
	}
	t := strings.TrimSpace(string(b))
	for _, c := range t {
		if c < '0' || c > '9' {
			return ""
		}
	}
	return t
}

func (f *PF) writeToken() {
	if f.TokenFile != "" {
		os.WriteFile(f.TokenFile, []byte(f.token+"\n"), 0o600)
	}
}
