// Connectivity: live DNS and tunnel details from the daemon, and key rotation.

import SwiftUI

struct ConnectivityView: View {
    @EnvironmentObject var store: Store
    @State private var confirmReset = false

    var body: some View {
        let st = store.status
        Page(title: "Connectivity") {
            CardSection(title: "DNS connection") {
                ValueRow(icon: "globe", title: "DNS protocol", value: st?.dns_protocol)
                if let d = st?.dns {
                    ValueRow(icon: "number", title: "DNS queries",
                             value: "\(d.queries) · fallback \(d.fallback_queries) · failed \(d.failures)")
                }
            }

            CardSection(title: "Tunnel connection") {
                Row(icon: "waveform.path.ecg", title: "Connection status") {
                    StatusBadge(state: store.connState, label: st?.status ?? "—")
                }
                ValueRow(icon: "lock", title: "WARP tunnel protocol", value: st?.tunnel?.protocol ?? "N/A")
                if let t = st?.tunnel {
                    ValueRow(icon: "server.rack", title: "Edge endpoint", value: t.endpoint, mono: true, copyable: true)
                    if let tls = t.tls { ValueRow(icon: "key.horizontal", title: "TLS", value: tls) }
                    if let rtt = t.handshake_rtt { ValueRow(icon: "timer", title: "Handshake time", value: rtt) }
                    ValueRow(icon: "arrow.up.arrow.down", title: "Sent / received",
                             value: "\(human(t.tx_bytes)) / \(human(t.rx_bytes))")
                }
                if let n = st?.network, !n.isEmpty { ValueRow(icon: "wifi", title: "Network", value: n) }
            }

            CardSection(title: "Encryption keys") {
                Row(icon: "key", title: "Reset keys",
                    subtitle: "Generate a new key pair, keeping the current registration.") {
                    Button("Reset") { confirmReset = true }
                        .buttonStyle(.flat(.secondary))
                        .disabled(store.busy || !store.registered)
                }
            }
        }
        .confirmationDialog("Reset encryption keys?", isPresented: $confirmReset) {
            Button("Reset keys") {
                store.act(["tunnel", "rotate-keys"], success: "A new key pair was generated.")
            }
        } message: {
            Text("A new key pair is generated and enrolled with Cloudflare. Your registration is kept. An active connection will reconnect.")
        }
    }
}
