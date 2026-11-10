# Changelog

All notable changes to OpenWarp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

First public version, not yet released.

### Added

- Go daemon and `openwarp` CLI compatible with the Cloudflare WARP consumer service: device registration, WARP+
  license keys, device list, MASQUE and WireGuard tunnels, and all seven connection modes.
- SwiftUI app (OpenWarp) with Home, Connectivity, Settings, Profile and About pages and a menu-bar item.
- Registration as a macOS device (`type` macOS, `model` from `hw.model`).
- LaunchDaemon installer (`openwarp service install|uninstall`) that also removes the pre-rename `cwarp` service.
- Open-source publication: MIT license, contributing guide, security policy, issue and PR templates.
