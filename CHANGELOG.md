# Changelog

All notable changes to OpenWarp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed

- The daemon no longer crashes ("index out of range") when Cloudflare answers a key enrollment without a usable
  peer while an endpoint override is set. The answer is rejected with an error and not cached, so the next
  attempt enrolls again.

## [0.1.0] - 2026-11-10

First public version (MVP). Release notes: [docs/releases/v0.1.0.md](docs/releases/v0.1.0.md).

### Added

- Go daemon and `openwarp` CLI compatible with the Cloudflare WARP consumer service: device registration, WARP+
  license keys, device list, MASQUE and WireGuard tunnels, and all seven connection modes.
- SwiftUI app (OpenWarp) with Home, Connectivity, Settings, Profile and About pages.
- App icon (from `assets/icon`) in every macOS size; the menu-bar item keeps a monochrome symbol.
- Menu bar dashboard: connection status and mode, a connect/disconnect button, live upload and download rates
  with session totals (from the daemon's tunnel counters; all interfaces when not tunnelling), and the public IP,
  country and Cloudflare data centre as Cloudflare sees them (also through the proxy in proxy mode). The public IP
  lookup asks `www.cloudflare.com/cdn-cgi/trace` and can be turned off in Settings → Privacy.
- First-run setup: when the background service is missing, the app explains it and installs it after macOS's
  own administrator prompt, then verifies that it runs the app's version before continuing. It also offers to
  update an outdated service and shows the Terminal commands as an alternative.
- `openwarp service status` (no root needed): whether the service is installed, loaded, running and current.
- Status reports the daemon version and per-connection traffic totals (`version`, `usage`).
- Update checks: Settings → Updates can check GitHub once a day for a newer release (on by default, can be
  switched off) and shows a banner with a link to the release page. Updates are never downloaded or installed
  automatically. There is also a Check Now button.
- About links to the source code on GitHub.
- Registration as a macOS device (`type` macOS, `model` from `hw.model`).
- LaunchDaemon installer (`openwarp service install|uninstall`) that also removes the pre-rename `cwarp` service.
  The service runs a root-owned copy in `/Library/PrivilegedHelperTools/com.local.openwarp`; the installer
  refuses to use it unless every directory on its path is root-owned and not writable by others, and
  `/usr/local/bin/openwarp` is only a symlink for the CLI.
- Open-source publication: MIT license, contributing guide, security policy, issue and PR templates.
- Automated tests and CI: Go unit, integration and CLI tests; a JSON contract shared by the CLI and the app;
  SwiftUI unit, snapshot and XCUITest UI tests; govulncheck, gitleaks and CodeQL.
- `main`/`release` branch model: release-candidate checks on pull requests into `release`, and a manually run
  release workflow that builds, tests and drafts (never publishes) a GitHub release after manual approval.
- Distribution as a universal DMG (`OpenWarp-v<version>-macos-universal.dmg`, ad-hoc signed, not notarized) with
  an Applications shortcut, plus a zip and `SHA256SUMS.txt`; CI verifies the DMG and tests installing the app and
  the background service from it.
- `THIRD_PARTY_NOTICES.md` with the licenses of the bundled Go modules, shipped inside OpenWarp.app.
