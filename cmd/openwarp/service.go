package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ImanMontajabi/OpenWarp/internal/buildinfo"
	"github.com/ImanMontajabi/OpenWarp/internal/daemon"
	"github.com/ImanMontajabi/OpenWarp/internal/state"
)

const (
	label     = "com.local.openwarp"
	plistPath = "/Library/LaunchDaemons/com.local.openwarp.plist"
	// helperPath is the binary launchd runs as root. It lives in a root-owned directory: a root job must
	// never run a file that a non-root user can replace (/usr/local/bin is often user-owned, for example
	// with Homebrew on Intel Macs).
	helperPath = "/Library/PrivilegedHelperTools/com.local.openwarp"
	// linkPath is a convenience symlink so `openwarp` works in a shell. Only users run it, never launchd.
	linkPath = "/usr/local/bin/openwarp"

	// Pre-rename (cwarp) service, removed on install/uninstall.
	legacyPlistPath = "/Library/LaunchDaemons/com.local.cwarp.plist"
	legacyBinPath   = "/usr/local/bin/cwarp"
	legacyLabel     = "com.local.cwarp"
)

// removeLegacy stops and removes the old cwarp LaunchDaemon and binary, if present.
// Its state is migrated by state.Open; the old state directory is left in place.
func removeLegacy() {
	if _, err := os.Stat(legacyPlistPath); err != nil {
		return
	}
	stopService(legacyLabel)
	os.Remove(legacyPlistPath)
	os.Remove(legacyBinPath)
	os.Remove("/var/run/cwarp.sock")
	fmt.Println("Removed the old", legacyLabel, "service")
}

// loaded reports whether launchd currently knows the service. Works without root.
func loaded(l string) bool { return exec.Command("launchctl", "print", "system/"+l).Run() == nil }

// stopService boots the service out and waits until launchd has finished
// tearing it down. bootout returns before the job is gone, and bootstrapping
// the same label too early fails with "Bootstrap failed: 5: Input/output error".
func stopService(l string) {
	if !loaded(l) {
		return
	}
	exec.Command("launchctl", "bootout", "system/"+l).Run()
	for i := 0; i < 75 && loaded(l); i++ {
		time.Sleep(200 * time.Millisecond)
	}
}

// startService bootstraps the plist, retrying while launchd settles.
func startService() error {
	var last error
	for attempt := 0; attempt < 5; attempt++ {
		out, err := exec.Command("launchctl", "bootstrap", "system", plistPath).CombinedOutput()
		if err == nil {
			return nil
		}
		if loaded(label) { // already bootstrapped: restart it so the new binary runs
			return exec.Command("launchctl", "kickstart", "-k", "system/"+label).Run()
		}
		last = fmt.Errorf("launchctl bootstrap: %v: %s", err, strings.TrimSpace(string(out)))
		time.Sleep(time.Second)
	}
	return last
}

// launchdPlist is the LaunchDaemon definition for a daemon binary at program.
// launchdPlist is the LaunchDaemon definition. allow are the users (besides root and administrators) who may
// control the service: the user who installed it.
func launchdPlist(program string, allow ...uint32) string {
	args := "<string>" + program + "</string><string>daemon</string>"
	for _, uid := range allow {
		args += fmt.Sprintf("<string>--allow-uid</string><string>%d</string>", uid)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + label + `</string>
  <key>ProgramArguments</key>
  <array>` + args + `</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/openwarp.log</string>
  <key>StandardErrorPath</key><string>/var/log/openwarp.log</string>
</dict>
</plist>
`
}

// rootOnly checks that path and every directory above it are owned by root and
// not writable by group or others (the sticky /Library/PrivilegedHelperTools
// style 1755 is fine), so no other user can swap the file launchd runs as root.
func rootOnly(path string, lstat func(string) (fs.FileInfo, error)) error {
	for p := path; ; p = filepath.Dir(p) {
		fi, err := lstat(p)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot read the owner", p)
		}
		// Symlink first: a symlink's own permission bits are always 0777 and say nothing.
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink", p)
		}
		if st.Uid != 0 {
			return fmt.Errorf("%s is owned by uid %d, not root", p, st.Uid)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s is writable by non-root users (mode %v)", p, fi.Mode().Perm())
		}
		if p == "/" {
			return nil
		}
	}
}

// writeAtomic writes data to a new file next to path and renames it into place,
// so the result is a fresh root-owned file with exactly mode perm.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".new"
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil { // not subject to the umask
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// installLink points the convenience command at the helper. A regular file
// there (an older install) is replaced; anything else that is not ours is kept.
func installLink() {
	if fi, err := os.Lstat(linkPath); err == nil {
		if fi.Mode()&fs.ModeSymlink != 0 {
			if dst, _ := os.Readlink(linkPath); dst == helperPath {
				return
			}
		} else if !fi.Mode().IsRegular() {
			return
		}
		os.Remove(linkPath)
	}
	if _, err := os.Stat(filepath.Dir(linkPath)); err != nil {
		return
	}
	if err := os.Symlink(helperPath, linkPath); err != nil {
		fmt.Println("Note: could not link", linkPath, "->", helperPath+":", err)
	}
}

// service installs the daemon as a LaunchDaemon, like the official client's
// privileged CloudflareWARP service. `service status` needs no root.
func service(action string) error {
	if action == "status" {
		return printServiceStatus()
	}
	if os.Geteuid() != 0 {
		return errors.New("run with sudo")
	}
	switch action {
	case "install":
		removeLegacy()
		self, err := os.Executable()
		if err != nil {
			return err
		}
		self, _ = filepath.EvalSymlinks(self)
		if self != helperPath {
			data, err := os.ReadFile(self)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(helperPath), 0o755); err != nil {
				return err
			}
			if err := rootOnly(filepath.Dir(helperPath), os.Lstat); err != nil {
				return fmt.Errorf("refusing to install the root service: %v", err)
			}
			if err := writeAtomic(helperPath, data, 0o755); err != nil {
				return err
			}
		}
		if err := rootOnly(helperPath, os.Lstat); err != nil {
			return fmt.Errorf("refusing to install the root service: %v", err)
		}
		stopService(label)
		var allow []uint32
		if uid, ok := installingUser(os.Getenv, consoleUID); ok {
			allow = append(allow, uid)
			fmt.Printf("The service can be controlled by root, administrators and user %d.\n", uid)
		}
		if err := writeAtomic(plistPath, []byte(launchdPlist(helperPath, allow...)), 0o644); err != nil {
			return err
		}
		installLink()
		if err := startService(); err != nil {
			return err
		}
		// launchctl returns once the job is loaded, before the daemon listens on its socket: a command run
		// right after an install that returned at that point failed with "connection refused".
		if err := waitReady(daemonStatus, buildinfo.Full(), readyTimeout, time.Sleep); err != nil {
			return fmt.Errorf("installed and started %s, but %v (logs: /var/log/openwarp.log)", label, err)
		}
		fmt.Println("Installed and started", label, "(logs: /var/log/openwarp.log)")
		return nil
	case "uninstall":
		removeLegacy()
		stopService(label)
		// The stopped daemon may have kept the kill switch rules (fail closed); nothing would remove them now.
		for _, msg := range daemon.ResetNetwork(state.DefaultDir()) {
			fmt.Println(msg)
		}
		os.Remove(plistPath)
		if dst, _ := os.Readlink(linkPath); dst == helperPath {
			os.Remove(linkPath)
		}
		os.Remove(helperPath)
		fmt.Println("Removed", label, "(settings and registration are kept in /Library/Application Support/openwarp)")
		return nil
	}
	return fmt.Errorf("unknown service action %q (install, uninstall or status)", action)
}

// readyTimeout bounds how long `service install` waits for the new daemon to answer.
const readyTimeout = 15 * time.Second

const readyPoll = 250 * time.Millisecond

func daemonStatus() (daemon.Status, error) {
	var st daemon.Status
	err := call("GET", "/v1/status", nil, &st)
	return st, err
}

// waitReady polls the control socket until the daemon answers with version want (the binary just installed,
// not an old process that is still shutting down), for at most timeout.
func waitReady(status func() (daemon.Status, error), want string, timeout time.Duration, sleep func(time.Duration)) error {
	var last string
	for waited := time.Duration(0); ; waited += readyPoll {
		st, err := status()
		switch {
		case err == nil && st.Version == want:
			return nil
		case err != nil:
			last = err.Error()
		default:
			last = fmt.Sprintf("it reports version %s instead of %s", st.Version, want)
		}
		if waited >= timeout {
			return fmt.Errorf("the service did not answer on %s within %s: %s", daemon.SocketPath(), timeout, last)
		}
		sleep(readyPoll)
	}
}

// installingUser is the user on whose behalf `service install` runs: the one who ran sudo, or, for the app's
// installer (an administrator prompt, which runs as root without SUDO_UID), the user logged in at the
// console. Root itself is not recorded (it is always allowed).
func installingUser(getenv func(string) string, console func() (uint32, bool)) (uint32, bool) {
	if v := getenv("SUDO_UID"); v != "" {
		if n, err := strconv.ParseUint(v, 10, 32); err == nil && n != 0 {
			return uint32(n), true
		}
	}
	if uid, ok := console(); ok && uid != 0 {
		return uid, true
	}
	return 0, false
}

// consoleUID is the owner of /dev/console: the user logged in at the screen.
func consoleUID() (uint32, bool) {
	fi, err := os.Stat("/dev/console")
	if err != nil {
		return 0, false
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// ServiceStatus is `openwarp -j service status`: what the app checks before
// offering to install the background service and after installing it.
type ServiceStatus struct {
	Installed  bool   `json:"installed"`         // the LaunchDaemon plist exists
	Loaded     bool   `json:"loaded"`            // launchd knows the job
	Program    string `json:"program,omitempty"` // the binary the plist runs
	Running    bool   `json:"running"`           // the daemon answered on its control socket
	Version    string `json:"version,omitempty"` // the running daemon's version
	AppVersion string `json:"app_version"`       // this binary's version
	// UpToDate: the service runs this version from the root-owned helper path.
	UpToDate bool   `json:"up_to_date"`
	Socket   string `json:"socket"`
	Error    string `json:"error,omitempty"`
}

// serviceProbe is what serviceStatus reads from the system (fakes in tests).
type serviceProbe struct {
	readPlist func() ([]byte, error)
	loaded    func() bool
	status    func() (daemon.Status, error)
	socket    string
}

func serviceStatus(p serviceProbe) ServiceStatus {
	s := ServiceStatus{AppVersion: buildinfo.Full(), Socket: p.socket}
	if data, err := p.readPlist(); err == nil {
		s.Installed = true
		s.Program = plistProgram(string(data))
	}
	s.Loaded = s.Installed && p.loaded()
	if st, err := p.status(); err == nil {
		s.Running, s.Version = true, st.Version
	} else {
		s.Error = err.Error()
	}
	s.UpToDate = s.Installed && s.Loaded && s.Running && s.Version == buildinfo.Full() && s.Program == helperPath
	return s
}

// plistProgram extracts the first ProgramArguments string from our plist.
func plistProgram(plist string) string {
	_, rest, ok := strings.Cut(plist, "<key>ProgramArguments</key>")
	if !ok {
		return ""
	}
	_, rest, ok = strings.Cut(rest, "<string>")
	if !ok {
		return ""
	}
	prog, _, _ := strings.Cut(rest, "</string>")
	return strings.TrimSpace(prog)
}

func printServiceStatus() error {
	s := serviceStatus(serviceProbe{
		readPlist: func() ([]byte, error) { return os.ReadFile(plistPath) },
		loaded:    func() bool { return loaded(label) },
		status:    daemonStatus,
		socket:    daemon.SocketPath(),
	})
	if jsonOut {
		printJSON(s)
		return nil
	}
	fmt.Printf("Service:  %s\n", map[bool]string{true: "installed", false: "not installed"}[s.Installed])
	if s.Installed {
		fmt.Printf("launchd:  %s (runs %s)\n", map[bool]string{true: "loaded", false: "not loaded"}[s.Loaded], s.Program)
	}
	if s.Running {
		fmt.Printf("Daemon:   running %s on %s\n", s.Version, s.Socket)
	} else {
		fmt.Printf("Daemon:   not reachable on %s\n", s.Socket)
	}
	if s.Installed && !s.UpToDate {
		fmt.Println("Run `sudo openwarp service install` to update the service.")
	}
	return nil
}
