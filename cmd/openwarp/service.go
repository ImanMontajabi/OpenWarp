package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	plistPath = "/Library/LaunchDaemons/com.local.openwarp.plist"
	binPath   = "/usr/local/bin/openwarp"
	label     = "com.local.openwarp"

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

// loaded reports whether launchd currently knows the service.
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

const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>` + label + `</string>
  <key>ProgramArguments</key>
  <array><string>` + binPath + `</string><string>daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/openwarp.log</string>
  <key>StandardErrorPath</key><string>/var/log/openwarp.log</string>
</dict>
</plist>
`

// service installs the daemon as a LaunchDaemon, like the official client's
// privileged CloudflareWARP service.
func service(action string) error {
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
		if self != binPath {
			data, err := os.ReadFile(self)
			if err != nil {
				return err
			}
			os.MkdirAll(filepath.Dir(binPath), 0o755)
			if err := os.WriteFile(binPath+".new", data, 0o755); err != nil {
				return err
			}
			if err := os.Rename(binPath+".new", binPath); err != nil {
				return err
			}
		}
		stopService(label)
		if err := os.WriteFile(plistPath, []byte(plist), 0o644); err != nil {
			return err
		}
		if err := startService(); err != nil {
			return err
		}
		fmt.Println("Installed and started", label, "(logs: /var/log/openwarp.log)")
		return nil
	case "uninstall":
		removeLegacy()
		stopService(label)
		os.Remove(plistPath)
		fmt.Println("Removed", label, "(binary left at", binPath+")")
		return nil
	}
	return fmt.Errorf("unknown service action %q", action)
}
