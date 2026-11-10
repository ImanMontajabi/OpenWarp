# OpenWarp

An independent client for the Cloudflare WARP consumer network, built from a
reverse-engineering pass over the official macOS client (Cloudflare WARP
2026.8.2115.0). It has a privileged daemon, a `warp-cli`-style CLI and a
SwiftUI app with the same pages as the official UI.

Not affiliated with Cloudflare. Using it means accepting the
[WARP Terms of Service](https://www.cloudflare.com/application/terms/).

## How the official app works (findings)

| Component | What it is |
|---|---|
| `Contents/MacOS/Cloudflare WARP` | Flutter UI (`App.framework`, `FlutterMacOS`, `rust_bridge.framework`, `tray_manager`, Sparkle updates) |
| `Contents/Resources/CloudflareWARP` | Rust daemon (tokio actors: `actor-configuration`, `actor-ipc`, `warp-api-client`, `warp-edge`, `warp-storage`) |
| `com.cloudflare.warp.PacketTunnel.systemextension` | NetworkExtension packet tunnel (utun) |
| `warp-cli`, `warp-diag`, `warp-dex`, `warp-updater` | CLI, diagnostics, DEX tests, updater |

**Registration API.** The daemon calls `api.cloudflareclient.com`, sending a
`cf-client-version` header. If DNS fails it falls back to the anycast API IPs
`162.159.192.1` and `2606:4700:d0::a29f:c001`; both are in its logs as
`ConsumerEndpointConfig`. A device registers once, then a single tunnel key
is enrolled (`TunnelKeyType`): `curve25519` for WireGuard or `secp256r1` for
MASQUE (`RegistrationTunnelKeys{key_type, tunnel_type}`). The response's
`config` holds `peers[].public_key`, `peers[].endpoint.{v4,v6}`,
`interface.addresses` and `client_id`.

**Tunnel protocols** (`warp_edge::{wireguard_tun, h3_tun}`):
* **MASQUE** (the default): QUIC to `162.159.198.x`. Ports seen in the logs
  are 443, 500, 1701, 4500, 4443, 8443 and 8095, with an HTTP/2 fallback.
  * SNI is `consumer-masque.cloudflareclient.com`.
  * TLS client auth uses a self-signed certificate made from the registered
    P-256 key (`rcgen`; "Failed to create a self-signed client certificate").
  * An extended CONNECT is sent to `cloudflareaccess.com` with
    `:protocol = cf-connect-ip`.
  * IP packets travel in HTTP datagrams: `quarter_stream_id` plus
    "context id should be 0".
  * Post-quantum is supported ("downgrades allowed").
* **WireGuard**: a Cloudflare fork of `boringtun`. The endpoint is
  `162.159.192.x:2408`, and the 3-byte `client_id` goes in the reserved
  header bytes.

**Features / options** (from `warp-cli --help`, `settings list` and the UI):
* modes `warp`, `doh`, `warp+doh`, `dot`, `warp+dot`, `proxy` (127.0.0.1:40000), `tunnel_only`
* tunnel protocol, endpoint override, rotate-keys, MASQUE options
* split tunnel (default exclude list), Local Domain Fallback
* 1.1.1.1 for Families (off/malware/full)
* trusted SSIDs, disable on Wi-Fi/ethernet
* license key and device list
* stats, Zero Trust / MDM / DEX / posture (enterprise only)

## What openwarp implements

| | |
|---|---|
| Registration | new / show / delete / license / devices / account, ToS prompt, DNS-failure API fallback |
| Protocols | MASQUE (HTTP/3 CONNECT-IP, client cert, key pinning, PQ) and WireGuard (with reserved bytes) |
| Endpoint selection | registration IP across known ports, then IPv6, or a manual override |
| Modes | all seven of the official client's modes |
| System | utun + routes + DNS on macOS (root), local DoH/DoT stub resolver |
| Settings | split tunnel (exclude/include), Local Domain Fallback, Families, trusted networks, MTU, proxy port, always-on |
| Reliability | reconnect with backoff, restart on network change, auto-connect at daemon start |
| UI | "OpenWarp" SwiftUI window: compact portrait panel, bottom navigation (Home / Connectivity / Settings / Profile / About), interactive cloud, all seven modes as tiles, menu-bar item |

Not implemented: Zero Trust/Teams, MDM, DEX, posture, the HTTP/2 MASQUE
fallback, and hostname-based split tunnel.

## Build & use

```sh
./build.sh                      # tests, then build/openwarp and build/OpenWarp.app
```

Full-device VPN (modes `warp*`, `doh`, `dot`, `tunnel_only` need root):

```sh
sudo ./build/openwarp service install      # LaunchDaemon com.local.openwarp, logs in /var/log/openwarp.log
openwarp registration new --accept-tos
openwarp connect
openwarp status
open build/OpenWarp.app
```

No root (SOCKS5/HTTP proxy on 127.0.0.1:40000):

```sh
./build/openwarp daemon &          # user daemon, state in ~/Library/Application Support/openwarp
openwarp mode proxy && openwarp connect
curl -x socks5h://127.0.0.1:40000 https://www.cloudflare.com/cdn-cgi/trace   # warp=on
```

Other commands: `openwarp tunnel protocol set wireguard|masque`, `openwarp dns families malware`,
`openwarp tunnel ip add 203.0.113.0/24`, `openwarp trusted ssid add MyWiFi`, `openwarp registration license KEY`,
`openwarp stats`, `openwarp settings`.

## Layout

```
cmd/openwarp/          CLI + daemon entry, LaunchDaemon installer
internal/api        WARP device API client
internal/keys       curve25519 / P-256 key generation
internal/tunnel     MASQUE (quic-go http3) and WireGuard (wireguard-go) transports
internal/daemon     connection state machine, sessions, unix-socket control API
internal/sysnet     macOS ifconfig/route/networksetup integration
internal/dnsproxy   DoH/DoT stub resolver with Local Domain Fallback
internal/proxy      SOCKS5 + HTTP proxy over the userspace netstack
internal/state      persisted registration and settings
ui/macos            SwiftUI app (OpenWarp UI: theme, components, cloud, pages)
```
