# OpenWarp

OpenWarp is an independent, open-source macOS client for the Cloudflare WARP consumer network. It has three
parts: a background daemon written in Go, a `warp-cli`-style command-line tool (`openwarp`), and a native
SwiftUI app.

> **OpenWarp is not affiliated with, endorsed by or supported by Cloudflare, Inc.** "Cloudflare" and "WARP" are
> trademarks of Cloudflare, Inc. and are used here only to describe compatibility. OpenWarp talks to Cloudflare's
> public WARP service, so using it means accepting the
> [Cloudflare WARP Terms of Service](https://www.cloudflare.com/application/terms/).

**Status:** early MVP (`0.1.0`, unreleased). Expect rough edges; see [Known limitations](#known-limitations).

## Why

The official WARP client is closed source. OpenWarp is a small, readable implementation of the same client
protocols that anyone can audit, build and change. Its behaviour was worked out by studying how the official
macOS client (version 2026.8.2115.0) talks to the network; no Cloudflare code is included.

## Features

| Area | What OpenWarp does |
|---|---|
| Connection modes | All seven modes of the official client: `warp` (traffic and DNS over UDP), `warp+doh`, `warp+dot`, `doh`, `dot`, `proxy` (local SOCKS5/HTTP proxy, no root) and `tunnel_only` |
| Tunnel protocols | MASQUE (HTTP/3 CONNECT-IP over QUIC, with optional post-quantum key exchange) and WireGuard |
| Registration | Register this Mac, show or delete the registration, attach a WARP+ license key, list the account's devices |
| Settings | Split tunnel (exclude or include list), local domain fallback, 1.1.1.1 for Families, trusted Wi-Fi/Ethernet, MTU, proxy port, endpoint override, key rotation |
| Reliability | Reconnect with backoff, endpoint and port fallback, restart on network change |
| App | Compact window with Home, Connectivity, Settings, Profile and About pages, a cloud-shaped connect button and a menu-bar item |

Not implemented: Zero Trust / Teams, MDM, DEX, device posture, the HTTP/2 fallback for MASQUE and
hostname-based split tunnelling.

## Requirements

- macOS 14 (Sonoma) or later. The build targets both Apple silicon (arm64) and Intel (x86_64); only Apple
  silicon has been tested so far.
- Administrator rights for the full-device VPN modes (`warp`, `warp+doh`, `warp+dot`, `doh`, `dot`,
  `tunnel_only`). `proxy` mode runs without root.
- To build from source: Go 1.27 and Xcode 27 (or its command-line tools).

## Install and use

There is no signed or notarized download yet, so OpenWarp is built from source:

```sh
git clone https://github.com/ImanMontajabi/OpenWarp.git
cd OpenWarp
./build.sh                                  # runs the Go tests, then builds build/openwarp and build/OpenWarp.app
```

Install the daemon as a LaunchDaemon (runs as root), register, and connect:

```sh
sudo ./build/openwarp service install      # installs /usr/local/bin/openwarp, logs to /var/log/openwarp.log
openwarp registration new --accept-tos
openwarp connect
openwarp status
open build/OpenWarp.app                     # the app drives the same daemon through the CLI
```

Without root, `proxy` mode exposes a local SOCKS5/HTTP proxy on `127.0.0.1:40000`:

```sh
./build/openwarp daemon &                  # user daemon; state in ~/Library/Application Support/openwarp
./build/openwarp registration new --accept-tos
./build/openwarp mode proxy && ./build/openwarp connect
curl -x socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace   # look for warp=on
```

More commands: `openwarp help`. Remove the service with `sudo openwarp service uninstall`.

The registration (including its private keys and token) is stored in `state.json` with `0600` permissions in
`/Library/Application Support/openwarp` (root daemon) or `~/Library/Application Support/openwarp` (user daemon).
Never share that file.

## How it works

```
OpenWarp.app (SwiftUI) ──runs──> openwarp -j <command> ──HTTP over a unix socket──> openwarp daemon
                                                                                      ├─ WARP device API (registration, keys, license)
                                                                                      └─ tunnel: MASQUE or WireGuard ─> Cloudflare edge
```

The app never talks to the network itself: it runs the CLI with JSON output, and the CLI talks to the daemon
over `/var/run/openwarp.sock` (or a per-user socket). The daemon owns the registration, the tunnel, routes and
DNS. [CLAUDE.md](CLAUDE.md) documents the architecture and protocol details in depth.

```
cmd/openwarp/       CLI and daemon entry point, LaunchDaemon installer
internal/api        WARP device API client
internal/daemon     connection state machine, sessions, unix-socket control API
internal/tunnel     MASQUE (quic-go HTTP/3) and WireGuard (wireguard-go) transports
internal/sysnet     macOS utun, route and DNS integration
internal/dnsproxy   DoH/DoT stub resolver with local domain fallback
internal/proxy      SOCKS5 and HTTP proxy over the userspace network stack
internal/state      persisted registration and settings
internal/keys       Curve25519 and P-256 key generation
ui/macos            SwiftUI app
```

## Development

```sh
go test ./... -race -count=1     # Go unit and integration tests (offline: mock API and mock edge)
go vet ./... && gofmt -l .       # must be clean
./build.sh                       # full build
```

Tests never touch real Cloudflare registrations, the network configuration or root-only paths. See
[CONTRIBUTING.md](CONTRIBUTING.md) for the full workflow, including the macOS app tests.

## Contributing

Contributions are welcome. Every change goes through a pull request with tests and passing CI; `main` is
protected. Read [CONTRIBUTING.md](CONTRIBUTING.md) first, and report security problems privately as described
in [SECURITY.md](SECURITY.md).

## Known limitations

- Early MVP: verified live in `proxy` mode (registration, MASQUE and WireGuard) and by the author in `warp`
  mode on one Apple silicon Mac. Other root modes, Intel Macs and older macOS versions are untested.
- Full-device modes change routes and DNS with `route` and `networksetup` instead of Apple's Network Extension
  framework. If the daemon is killed while connected, the DNS settings may need to be restored by hand.
- Trusted-network detection by SSID needs Location permission, which OpenWarp does not request yet; the
  Wi-Fi and Ethernet switches work without it.
- The builds are ad-hoc signed, not signed with a Developer ID or notarized, so Gatekeeper warns on first launch.
- OpenWarp depends on Cloudflare's undocumented client API. Cloudflare can change it at any time, and whether
  WARP works on a given network depends on that network.

## License

[MIT](LICENSE). Third-party Go modules keep their own licenses (MIT, BSD-3-Clause and Apache-2.0); see
`go.mod` for the list.
