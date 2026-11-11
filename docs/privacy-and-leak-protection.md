# Privacy and leak protection

What OpenWarp protects, what it does not, and how its leak protection works. It is written for people who use
OpenWarp every day on ordinary, unrestricted networks (home, office, café, hotel Wi-Fi). It is not legal advice.

**In short:** with OpenWarp connected in a full-device mode, the local network and your Internet provider see
encrypted traffic to Cloudflare instead of the sites you visit, and those sites see a Cloudflare address instead
of yours. That is privacy *from the network you are on*, not anonymity. Cloudflare sees your real IP address and
where your traffic goes. OpenWarp does not make you anonymous, does not hide you from Cloudflare, and does not
protect you from legal identification.

## What each party can see

| Party | Disconnected | Connected (Traffic and DNS modes) | DNS-only modes (`doh`, `dot`) | Local proxy mode |
|---|---|---|---|---|
| Local network (Wi-Fi operator, others on it) | Destinations, DNS queries, unencrypted content | That you use Cloudflare WARP (edge address, timing, volume) | Destinations (IP addresses, TLS SNI); not DNS | Same as disconnected, except for apps that use the proxy |
| Internet provider | Same as the local network | Same as the local network | Same as the local network | Same as disconnected, except proxied apps |
| Sites and peers you connect to | Your IP address | A Cloudflare address shared with other WARP users | Your IP address | Your IP address for apps not using the proxy |
| Cloudflare | Nothing (unless you use its services) | Your IP address, the device registration, the destinations of your traffic and its volume | Your DNS queries | Destinations of proxied traffic |
| Apps and malware on this Mac | Everything they have access to | Unchanged: a VPN does not protect against software on the device | Unchanged | Unchanged |

Things WARP never changes: what you reveal by logging in to an account, browser fingerprinting and cookies,
content you send to a site, and what software on your Mac can see. Cloudflare's privacy policy and terms of
service govern what Cloudflare records and when it discloses it; OpenWarp has no influence on them.

## Threat model

**Protected (when the features below are on and verified):**

- An observer on the local network or at the Internet provider learning which sites you visit, or reading DNS
  queries, while OpenWarp is connected.
- Traffic leaving outside the tunnel when the tunnel drops, while the daemon reconnects, while it restarts, or
  after it crashes, with the kill switch on.
- IPv6 traffic bypassing an IPv4-only tunnel.
- DNS queries going to the local network's resolver instead of through the tunnel, in the modes that manage DNS.

**Not protected:**

- Identification by Cloudflare, or by anyone who can compel Cloudflare to disclose information.
- Correlation by timing and volume between your connection and Cloudflare's edge.
- Anything an app does on purpose: binding to a specific interface or address, using its own DNS-over-HTTPS
  resolver (that is encrypted and goes through the tunnel like other traffic), or connecting to excluded ranges.
- Software on the Mac. Any local user can control the daemon through its socket (`/var/run/openwarp.sock`, mode
  0666, like the official client's), including switching the kill switch off.
- Traffic to the split-tunnel exclusions (by default private, link-local and multicast ranges, and a few Apple
  push ranges), which uses the local network by design.
- Leaks when the kill switch is off: then a dropped tunnel means traffic uses the normal network until it is back.

## Leak paths audited

| Path | Before | Now |
|---|---|---|
| Tunnel drops or reconnects | Routes and DNS were removed before reconnecting: traffic used the normal network until the new tunnel was up | With the kill switch on, pf blocks everything but the reconnection attempt until the new tunnel is up |
| Daemon crash or `kill -9` | The utun interface vanished with its routes; traffic went direct. DNS stayed pointed at the tunnel's resolver, or at the dead local proxy (no DNS at all) | The kill switch rules are kernel state and survive the process. A journal records route and DNS changes; the next start (launchd restarts the service) undoes them, then reconnects with the kill switch still blocking |
| Service stopped or upgraded | Same as a crash | Rules are kept while a connection is wanted; `service uninstall` and `openwarp recover` remove them |
| Tunnel without an IPv6 address | IPv6 kept using the physical network (only IPv4 was routed into the tunnel) | IPv6 outside the exclusions is rejected (`::/1` and `8000::/1` reject routes); apps fall back to IPv4 at once. The kill switch also blocks it |
| Assigning the tunnel's IPv6 address fails | Only logged; IPv6 leaked | Treated like a tunnel without IPv6: rejected |
| DNS to the router or other local resolvers | Possible for apps that ask it directly | Blocked by the kill switch in the modes that manage DNS (ports 53 and 853 to the excluded ranges), except to the network's own resolver for the Local Domain Fallback domains in the HTTPS/TLS modes |
| Trusted networks | Pause removes the tunnel | Unchanged, by design: the kill switch is lifted too while paused |
| Status claims | Status said "Connected" and a DNS protocol label without checking anything | Status reports what was checked: the kill switch state, IPv6 and DNS handling, and the last verification of the current connection |

## The kill switch (experimental)

Off by default. Turn it on in the app (Connectivity → Leak protection, which asks for confirmation) or with
`openwarp killswitch on`.

**What it does.** While a connection is wanted (connecting, connected, reconnecting, restarting), OpenWarp keeps a
pf ruleset loaded that drops every packet, in and out, IPv4 and IPv6, except:

- the loopback interface;
- the tunnel interface of the current connection (`utunN`), once it is up;
- UDP to the Cloudflare edge addresses and ports of the selected protocol (MASQUE or WireGuard), so the tunnel
  can come up;
- TCP 443 to the WARP API's fallback addresses (`162.159.192.1`, `2606:4700:d0::a29f:c001`), used when DNS is
  blocked;
- DHCP, DHCPv6 and IPv6 neighbour discovery, so the Mac keeps its address on the local network;
- the split-tunnel exclusions (Exclude mode), with DNS to them blocked in the modes that manage DNS.

When you disconnect, the rules are removed. On a trusted network (pause) they are removed too.

**Where it applies.** The full-device modes with Exclude split tunnelling: Traffic and DNS (UDP, HTTPS, TLS) and
Traffic only. It is reported as *not used* in Local proxy mode (only apps that use the proxy are tunnelled), in
the DNS-only modes (no tunnel), and with Include split tunnelling. It needs the background service (root).

**Fail closed.** If the kill switch is on but its rules cannot be loaded (pf unavailable, an error from `pfctl`),
OpenWarp does not connect, and the status says why. Switch the kill switch off to connect without it.

**How it is installed.** The rules live in the pf anchor `com.apple/openwarp`, which macOS's stock `/etc/pf.conf`
already evaluates through its `anchor "com.apple/*"` line; OpenWarp never edits `/etc/pf.conf`. If that anchor
point is missing (a customised pf configuration), the kill switch reports that it cannot work instead of loading
rules that would never be evaluated. pf is enabled with a reference (`pfctl -E`), released when the rules are
removed (`pfctl -X`), so pf stays enabled for anything else that uses it. While connected the daemon re-checks
the rules every few seconds and re-enables pf if something disabled it.

**Recovering.** If you ever lose your connection and OpenWarp cannot fix it:

```sh
openwarp disconnect          # removes the rules (the daemon must be running)
sudo openwarp recover        # works without the daemon: removes the rules, restores routes and DNS
sudo pfctl -a com.apple/openwarp -F all    # the rules alone, by hand
```

Uninstalling the service (`sudo openwarp service uninstall`) runs the same cleanup.

**Limitations.** pf evaluates other `com.apple/*` anchors (Internet Sharing, AirDrop, the application firewall)
before OpenWarp's; a `pass quick` rule in one of them is not blocked by the kill switch. Connections that pf was
already tracking before the rules were loaded (only possible if something else had pf enabled) can continue.
Local users and malware with access to the control socket can switch it off.

**Status: experimental.** The rule generation, the pfctl sequence, the fail-closed logic and the recovery are
tested offline (the rules are also parsed by the real `pfctl -n` on macOS). The kill switch has not yet been run
against a live connection on a real Mac. Run `scripts/leak-test.sh` (below) before relying on it.

## IPv6

Cloudflare normally gives the tunnel an IPv6 address, and then IPv6 goes through the tunnel like IPv4. If the
registration has no IPv6 address, or assigning it fails, OpenWarp adds reject routes for `::/1` and `8000::/1`
instead: IPv6 to anything outside the exclusions fails immediately and apps use IPv4. The Connectivity page and
`openwarp killswitch status` show which of the two is in effect (`tunnel` or `blocked`). With Include split
tunnelling IPv6 is not touched (only the listed ranges are tunnelled).

## DNS

| Mode | System DNS | Where queries go |
|---|---|---|
| Traffic and DNS (UDP) | Cloudflare's resolver (1.1.1.1, or 1.1.1.2/1.1.1.3 with Families) | Through the tunnel |
| Traffic and DNS (HTTPS/TLS) | 127.0.0.1 (OpenWarp's local DNS proxy) | DNS over HTTPS/TLS to Cloudflare, through the tunnel; Local Domain Fallback suffixes to the network's resolvers |
| DNS only (HTTPS/TLS) | 127.0.0.1 | DNS over HTTPS/TLS to Cloudflare over the normal network (traffic is not tunnelled) |
| Traffic only | Unchanged | Wherever the system sends them, through the tunnel if the resolver is not in an excluded range |
| Local proxy | Unchanged | Names sent to the proxy (`socks5h://`) are resolved through the tunnel; everything else as usual |

Verification compares the system's resolvers with the expected ones and fails if any other server is configured.

## Verification

`openwarp verify`, or Verify on the Connectivity page, checks the current connection on this Mac:

| Check | Pass means |
|---|---|
| `tunnel` | A transport is up (protocol and edge) |
| `ipv4_route` | The routing table sends IPv4 (1.1.1.1 as the probe address) into the tunnel interface |
| `ipv6_route` | IPv6 goes into the tunnel, is rejected, or has no route at all |
| `dns` | Every system DNS server is one OpenWarp set for the mode |
| `kill_switch` | The rules are loaded and pf is enabled (skipped when the kill switch is off or not used) |
| `cloudflare` | Only with `--cloudflare` / Ask Cloudflare: a request to `https://www.cloudflare.com/cdn-cgi/trace` sent through the tunnel comes back with `warp=on` |

The result is `verified` when nothing failed and either the routes or Cloudflare confirmed the tunnel, `failed`
when any check failed, and `incomplete` otherwise (for example in Local proxy mode without the Cloudflare check).
The local checks run automatically after every connection; the Cloudflare check only when you ask for it. A
result belongs to one connection: after a reconnect the state is "not verified" again until the next check.

The protection state shown in the app and in `openwarp status`:

| State | Meaning |
|---|---|
| Not protected | Disconnected or paused: traffic uses the normal network |
| Not protected yet | Connecting without the kill switch: traffic may use the normal network |
| Blocking until connected | No tunnel, and the kill switch blocks traffic until it is back |
| Connected, not verified | Connected; not checked yet, or the check was incomplete |
| Verified | The last check of this connection passed |
| Problem found | The last check of this connection failed (the check says what) |

## Peer-to-peer file sharing

OpenWarp works with BitTorrent and other peer-to-peer software for lawful sharing, for example downloading and
seeding official Linux distribution images. To keep a client's traffic in the tunnel:

1. Use **Traffic and DNS** mode (or Traffic only) and turn on the **kill switch**.
2. In the client, bind to the tunnel's IPv4 address (Connectivity → Tunnel, or `openwarp stats`; usually
   `172.16.0.2`). qBittorrent: Settings → Advanced → *Optional IP address to bind to*. The address only exists
   while the tunnel is up, so the client cannot fall back to your normal address even if the kill switch is off.
   It stays the same until you create a new registration.
3. Do not use Local proxy mode for BitTorrent: OpenWarp's proxy carries TCP only, so DHT, uTP and UDP trackers
   would bypass it unless the client refuses connections the proxy cannot carry.

Expect these limits:

- **No incoming connections.** WARP has no port forwarding, so other peers cannot connect to you. You download
  and upload only over connections your client opens, which usually means fewer peers and slower seeding.
- **Your IP address to peers is Cloudflare's**, shared with other WARP users. Cloudflare still knows which device
  and IP address used it.
- **Cloudflare's terms of service apply** to what you send over WARP.
- **The law where you are applies.** In Germany, for example, rights holders monitor public swarms and send
  warning letters (Abmahnungen) for copyright infringement. OpenWarp does not change your legal obligations and
  is not a way around them. Share only what you are allowed to share.

## Testing on a real Mac

The automated tests never change a machine's networking. `scripts/leak-test.sh` is for an authorised Mac with
the service installed: it connects with the kill switch, verifies through Cloudflare, tries to send traffic around
the tunnel, kills the daemon and checks that nothing leaks while launchd restarts it, disconnects, and checks that
the rules, routes and DNS servers are back to how they were. It refuses to run in CI, without root, or without
`OPENWARP_LEAK_TEST=I-UNDERSTAND`:

```sh
sudo OPENWARP_LEAK_TEST=I-UNDERSTAND scripts/leak-test.sh
```

## Code

| Part | Code | Tests |
|---|---|---|
| pf rules, apply/verify/clear | `internal/firewall` | `internal/firewall/*_test.go` (fake pfctl; real `pfctl -n` parse on macOS) |
| Routes, IPv6 reject, DNS, crash journal | `internal/sysnet` | `internal/sysnet/*_test.go` |
| Kill switch lifecycle, verification, status | `internal/daemon/protection.go`, `engine.go` | `internal/daemon/protection_test.go`, `e2e_test.go`, `control_test.go` |
| CLI (`killswitch`, `verify`, `recover`) | `cmd/openwarp/main.go` | `cmd/openwarp/cli_test.go`, contract fixtures |
| App | `ui/macos/Protection.swift` | `ui/macos/Tests/ProtectionTests.swift`, snapshots, UI test |
