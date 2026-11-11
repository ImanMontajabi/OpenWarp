# Changelog

All notable changes to OpenWarp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Kill switch (experimental, off by default): while a connection is wanted, a pf ruleset in the anchor
  `com.apple/openwarp` blocks all traffic outside the tunnel except the connection to Cloudflare's edge, the API
  fallback addresses, DHCP/IPv6 neighbour discovery and the split-tunnel exclusions; DNS to the local network is
  blocked in the modes that manage DNS. It fails closed (no connection without its rules), stays in place while
  the service restarts or after a crash, and is removed on disconnect, on trusted networks, by
  `sudo openwarp recover` and by `service uninstall`. `/etc/pf.conf` is never edited. Not used in Local proxy
  mode, the DNS-only modes or with Include split tunnelling (reported as such).
- Connection verification: `openwarp verify [--cloudflare]`, and Verify / Ask Cloudflare in the app, check that
  IPv4 and IPv6 are routed into the tunnel (or IPv6 is blocked), that the system DNS servers are OpenWarp's, that
  the kill switch rules are loaded, and optionally that Cloudflare reports `warp=on` for a request through the
  tunnel. Local checks run after every connection; the Cloudflare request only when asked.
- Status reports the protection state (`protection`: not protected, blocking, connected but not verified,
  verified, problem found), the kill switch state, and how IPv6 and DNS are handled. Shown in the app's new
  Leak protection card (Connectivity) and in `openwarp status` / `openwarp killswitch status`.
- `sudo openwarp recover`: removes the kill switch rules and restores routes and DNS without the daemon.
- [Privacy and leak protection](docs/privacy-and-leak-protection.md): threat model, what each mode protects,
  the kill switch, verification, and guidance for lawful peer-to-peer use. `scripts/leak-test.sh`: an opt-in,
  root-only leak test for a real Mac (refuses to run in CI or while another VPN is connected; restores the
  previous settings on any exit) with positive controls for every probe (TCP, DNS
  over UDP/TCP, NTP, IPv4/IPv6), packet captures of the physical interface, outage coverage, a crash without
  restart plus `openwarp recover`, and checks that pf, routes and DNS are restored.

### Changed

- The Home page says what a connection does ("Your traffic goes through Cloudflare.", "Your DNS queries are
  encrypted.") instead of "Your Internet is private."
- Resetting settings keeps the kill switch, like Always On.
- Kill switch rules are stateless and live in the pf anchor `com.apple/000.openwarp`, which pf evaluates before
  Apple's own anchors; loading them flushes pf's state table. Verification now also fails when other pf rules are
  evaluated before the kill switch or pf skips an interface. The old anchor `com.apple/openwarp` is cleaned up.
- Development builds identify themselves: `./build.sh` stamps the commit into the CLI, the daemon and the app
  (`openwarp --version` prints e.g. `openwarp 0.1.0+dev.1a2b3c4`, with `.dirty` for uncommitted changes; the app
  shows `0.1.0 (dev.1a2b3c4)`). Release builds (`OPENWARP_RELEASE=1`, set only by the release workflows) keep
  the plain version. A development app no longer reports a release service of the same version number, or a
  build of another commit, as up to date.

### Security

- The control socket of the root service no longer lets every local user control it. Requests are authorized
  from the connecting process's kernel-reported user: any user may read the status; only root, administrators
  and the user who installed the service (recorded by `service install`) may connect, disconnect, change settings
  (including the kill switch), verify, or read and change the registration and license. A daemon running without
  root keeps its socket private (0600) and accepts only its own user.
- Kill switch: packets of a connection opened through the tunnel could leave through the physical interface
  after the tunnel dropped, because the pass rules kept (floating) pf states. All pass rules are now stateless
  and the state table is flushed whenever the rules change.
- Kill switch: Apple's `com.apple/*` anchors were evaluated before OpenWarp's, so a `pass quick` rule there won.
- Kill switch: DNS on port 53 to the system's public resolvers (for example 8.8.8.8) was allowed around the
  tunnel for Local Domain Fallback; only resolvers on the local network are allowed now.

### Fixed

- IPv6 leaked outside the tunnel when the tunnel had no IPv6 address or assigning it failed; it is now rejected
  (apps fall back to IPv4).
- After the daemon was killed while connected, its routes and DNS servers stayed behind (in the HTTPS/TLS modes
  that meant no DNS at all). They are recorded in a journal and restored on the next start.
- The daemon no longer crashes ("index out of range") when Cloudflare answers a key enrollment without a usable
  peer while an endpoint override is set. The answer is rejected with an error and not cached, so the next
  attempt enrolls again.
- `openwarp status` reads the tunnel's counters once, so `usage` and `tunnel` always agree within one status
  (they could differ by the packets that arrived between two reads).

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
