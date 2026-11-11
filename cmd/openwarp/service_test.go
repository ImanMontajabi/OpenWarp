package main

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/buildinfo"
	"github.com/ImanMontajabi/OpenWarp/internal/daemon"
)

func TestLaunchdPlistRunsTheRootOwnedHelper(t *testing.T) {
	p := launchdPlist(helperPath)
	if got := plistProgram(p); got != helperPath {
		t.Fatalf("plist runs %q, want %q", got, helperPath)
	}
	if !strings.Contains(p, "<string>daemon</string>") || !strings.Contains(p, "<string>"+label+"</string>") {
		t.Fatalf("plist misses the daemon argument or label:\n%s", p)
	}
	if strings.HasPrefix(helperPath, "/usr/local/") {
		t.Fatal("the root service must not run from /usr/local, which is often user-writable")
	}
}

func TestPlistProgramOfOlderInstalls(t *testing.T) {
	if got := plistProgram(launchdPlist("/usr/local/bin/openwarp")); got != "/usr/local/bin/openwarp" {
		t.Fatalf("got %q", got)
	}
	if got := plistProgram("<plist>garbage</plist>"); got != "" {
		t.Fatalf("got %q from a plist without ProgramArguments", got)
	}
}

type fakeInfo struct {
	mode fs.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "x" }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func TestRootOnlyRejectsFilesOtherUsersCanReplace(t *testing.T) {
	tree := func(over map[string]fakeInfo) func(string) (fs.FileInfo, error) {
		return func(p string) (fs.FileInfo, error) {
			if fi, ok := over[p]; ok {
				return fi, nil
			}
			return fakeInfo{mode: fs.ModeDir | 0o755}, nil // root-owned, 755
		}
	}
	const bin = "/Library/PrivilegedHelperTools/com.local.openwarp"
	cases := []struct {
		name string
		over map[string]fakeInfo
		ok   bool
	}{
		{"root owned", map[string]fakeInfo{bin: {mode: 0o755}, "/Library/PrivilegedHelperTools": {mode: fs.ModeDir | fs.ModeSticky | 0o755}}, true},
		{"file owned by a user", map[string]fakeInfo{bin: {mode: 0o755, uid: 501}}, false},
		{"parent owned by a user (Homebrew /usr/local)", map[string]fakeInfo{"/Library/PrivilegedHelperTools": {mode: fs.ModeDir | 0o755, uid: 501}}, false},
		{"group-writable file", map[string]fakeInfo{bin: {mode: 0o775}}, false},
		{"world-writable parent", map[string]fakeInfo{"/Library": {mode: fs.ModeDir | 0o777}}, false},
		{"symlink", map[string]fakeInfo{bin: {mode: fs.ModeSymlink | 0o755}}, false},
	}
	for _, c := range cases {
		err := rootOnly(bin, tree(c.over))
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
	// A symlink's own permission bits are always 0777: it must be reported as a symlink, not as writable.
	err := rootOnly(bin, tree(map[string]fakeInfo{bin: {mode: fs.ModeSymlink | 0o777}}))
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Errorf("symlink with 0777 bits: err = %v, want \"is a symlink\"", err)
	}
	if err := rootOnly(bin, func(string) (fs.FileInfo, error) { return nil, fs.ErrNotExist }); err == nil {
		t.Error("a missing file passed")
	}
}

func TestRootOnlyOnRealPaths(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: every temp dir is root-owned")
	}
	// /usr/bin/true is a symlink on some Linux distributions (rust-coreutils); its target is a root-owned file.
	real, err := filepath.EvalSymlinks("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err := rootOnly(real, os.Lstat); err != nil {
		t.Errorf("%s: %v", real, err)
	}
	f := filepath.Join(t.TempDir(), "openwarp")
	os.WriteFile(f, nil, 0o755)
	if err := rootOnly(f, os.Lstat); err == nil {
		t.Error("a file in a user-owned temp dir passed")
	}
}

func TestWriteAtomicSetsExactMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f")
	os.WriteFile(path, []byte("old"), 0o666)
	if err := writeAtomic(path, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(path)
	b, _ := os.ReadFile(path)
	if string(b) != "new" || fi.Mode().Perm() != 0o644 {
		t.Fatalf("content %q mode %v", b, fi.Mode().Perm())
	}
	if _, err := os.Stat(path + ".new"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("temporary file left behind")
	}
}

// Probes for the service states the app distinguishes. They also produce the
// contract fixtures the Swift app decodes (testdata/contract/service-*.json).
func serviceCases() []struct {
	file  string
	probe serviceProbe
	check func(ServiceStatus) bool
} {
	missing := func() ([]byte, error) { return nil, fs.ErrNotExist }
	down := func() (daemon.Status, error) {
		return daemon.Status{}, errors.New("cannot reach the openwarp daemon at /var/run/openwarp.sock: connection refused")
	}
	running := func(v string) func() (daemon.Status, error) {
		return func() (daemon.Status, error) { return daemon.Status{Version: v}, nil }
	}
	plist := func(program string) func() ([]byte, error) {
		return func() ([]byte, error) { return []byte(launchdPlist(program)), nil }
	}
	yes, no := func() bool { return true }, func() bool { return false }
	const sock = "/var/run/openwarp.sock"
	return []struct {
		file  string
		probe serviceProbe
		check func(ServiceStatus) bool
	}{
		{"service-not-installed.json", serviceProbe{missing, no, down, sock},
			func(s ServiceStatus) bool {
				return !s.Installed && !s.Loaded && !s.Running && !s.UpToDate && s.Error != ""
			}},
		{"service-up-to-date.json", serviceProbe{plist(helperPath), yes, running(buildinfo.Version), sock},
			func(s ServiceStatus) bool {
				return s.Installed && s.Loaded && s.Running && s.UpToDate && s.Version == s.AppVersion
			}},
		// An install from before 0.1.0: runs from /usr/local/bin and reports no version.
		{"service-outdated.json", serviceProbe{plist("/usr/local/bin/openwarp"), yes, running(""), sock},
			func(s ServiceStatus) bool {
				return s.Installed && s.Running && !s.UpToDate && s.Program == "/usr/local/bin/openwarp"
			}},
		{"service-installed-not-running.json", serviceProbe{plist(helperPath), no, down, sock},
			func(s ServiceStatus) bool { return s.Installed && !s.Loaded && !s.Running && !s.UpToDate }},
	}
}

func TestServiceStatus(t *testing.T) {
	for _, c := range serviceCases() {
		if s := serviceStatus(c.probe); !c.check(s) {
			t.Errorf("%s: unexpected %+v", c.file, s)
		}
	}
	// A daemon started by hand (proxy mode without the service) is running but not installed.
	s := serviceStatus(serviceProbe{
		readPlist: func() ([]byte, error) { return nil, fs.ErrNotExist },
		loaded:    func() bool { t.Fatal("launchd queried without a plist"); return false },
		status:    func() (daemon.Status, error) { return daemon.Status{Version: buildinfo.Version}, nil },
	})
	if s.Installed || !s.Running || s.UpToDate {
		t.Fatalf("user daemon: %+v", s)
	}
}

// A development build is never "up to date" with a release service of the same version number, or with a
// development build of another commit, so the app offers to install its own CLI.
func TestServiceStatusTellsDevelopmentBuildsApart(t *testing.T) {
	defer func(b string) { buildinfo.Build = b }(buildinfo.Build)
	probe := func(daemonVersion string) serviceProbe {
		return serviceProbe{
			readPlist: func() ([]byte, error) { return []byte(launchdPlist(helperPath)), nil },
			loaded:    func() bool { return true },
			status:    func() (daemon.Status, error) { return daemon.Status{Version: daemonVersion}, nil },
			socket:    "/var/run/openwarp.sock",
		}
	}
	buildinfo.Build = "dev.1a2b3c4"
	for daemonVersion, want := range map[string]bool{
		buildinfo.Version:                  false, // the released 0.1.0 service
		buildinfo.Version + "+dev.9f8e7d6": false, // a development build of another commit
		buildinfo.Version + "+dev.1a2b3c4": true,  // this very build
	} {
		s := serviceStatus(probe(daemonVersion))
		if s.UpToDate != want || s.AppVersion != buildinfo.Version+"+dev.1a2b3c4" {
			t.Errorf("app %s, daemon %s: up_to_date=%v", s.AppVersion, daemonVersion, s.UpToDate)
		}
	}
	buildinfo.Build = ""
	if s := serviceStatus(probe(buildinfo.Version + "+dev.1a2b3c4")); s.UpToDate {
		t.Error("a release app accepts a development service as up to date")
	}
}

func TestServiceStatusContract(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "contract")
	for _, c := range serviceCases() {
		b, _ := json.MarshalIndent(serviceStatus(c.probe), "", "  ") // as printJSON writes it
		got := string(b) + "\n"
		path := filepath.Join(dir, c.file)
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run with -update to create it)", err)
		}
		if string(want) != got {
			t.Fatalf("%s changed; update the Swift models and run -update.\n--- want\n%s\n--- got\n%s", c.file, want, got)
		}
	}
}

func TestServiceStatusNeedsNoRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	f := newFakeDaemon(t)
	f.on("GET /v1/status", func(map[string]any) (int, any) { return 200, daemon.Status{Version: buildinfo.Version} })
	r := runCLI(t, f.sock, "-j", "service", "status")
	if r.code != 0 {
		t.Fatalf("service status failed without root: %+v", r)
	}
	var s ServiceStatus
	if err := json.Unmarshal([]byte(r.stdout), &s); err != nil || !s.Running || s.Version != buildinfo.Version {
		t.Fatalf("status %+v (%v) from %q", s, err, r.stdout)
	}
	if r := runCLI(t, f.sock, "service", "install"); r.code == 0 || !strings.Contains(r.stderr, "sudo") {
		t.Fatalf("install without root should ask for sudo: %+v", r)
	}
}

// The privileged leak test changes the machine's networking, so it must refuse to run in CI and without
// the explicit opt-in, before doing anything.
func TestLeakTestScriptRefusesWithoutOptIn(t *testing.T) {
	script := filepath.Join("..", "..", "scripts", "leak-test.sh")
	run := func(env ...string) (string, int) {
		cmd := exec.Command("sh", script)
		cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}, env...)
		out, err := cmd.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return string(out), code
	}
	for _, env := range [][]string{{"CI=true"}, {"GITHUB_ACTIONS=true"}, {"CI=1", "OPENWARP_LEAK_TEST=I-UNDERSTAND"}} {
		if out, code := run(env...); code != 2 || !strings.Contains(out, "refusing to run in CI") {
			t.Errorf("%v: exit %d, %q", env, code, out)
		}
	}
	// Outside CI it still needs root and the opt-in (this test never runs as root).
	if os.Geteuid() != 0 {
		if out, code := run(); code != 2 || (!strings.Contains(out, "run with sudo") && !strings.Contains(out, "macOS only")) {
			t.Errorf("no opt-in: exit %d, %q", code, out)
		}
	}
}
