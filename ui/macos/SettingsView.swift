// Settings: tunnel protocol, post-quantum, trusted networks, Families,
// Split Tunnel, Local Domain Fallback, and the advanced options.

import SwiftUI

private enum Sheet: String, Identifiable {
    case ssid, split, fallback
    var id: String { rawValue }
}

struct SettingsView: View {
    @EnvironmentObject var store: Store
    @State private var sheet: Sheet?
    @State private var port = ""
    @State private var endpoint = ""
    @State private var confirmReset = false

    var body: some View {
        let s = store.settings
        Page(title: "Settings") {
            CardSection(title: "Tunnel") {
                VStack(alignment: .leading, spacing: Space.sm) {
                    Row(icon: "square.stack.3d.up", title: "WARP tunnel protocol",
                        subtitle: "MASQUE (HTTP/3, QUIC) is the default; WireGuard is the classic protocol.")
                        .padding(.bottom, -Space.sm)
                    Segmented(options: [("masque", "MASQUE"), ("wireguard", "WireGuard")],
                              selection: value("protocol", s?.protocol ?? "masque")) {
                        store.set("protocol", $0, ["tunnel", "protocol", "set", $0])
                    }
                    .padding(.horizontal, Space.md).padding(.bottom, Space.sm)
                    .padding(.leading, 32)
                    .accessibilityLabel("WARP tunnel protocol")
                }
                toggleRow(icon: "key.viewfinder", title: "Post-quantum key agreement",
                          subtitle: "X25519MLKEM768 for MASQUE", key: "post_quantum",
                          current: s?.post_quantum ?? true) { ["tunnel", "pq", $0 ? "on" : "off"] }
            }

            CardSection(title: "Trusted networks") {
                Row(icon: "wifi", title: "Pause for Wi-Fi networks",
                    subtitle: "OpenWarp pauses on the configured Wi-Fi networks.\(countSuffix(s?.trusted_ssids))") {
                    Button("Configure") { sheet = .ssid }.buttonStyle(.flat())
                }
                toggleRow(icon: "wifi.slash", title: "Disable for all Wi-Fi networks", key: "disable_wifi",
                          current: s?.disable_wifi ?? false) { ["trusted", "wifi", $0 ? "enable" : "disable"] }
                toggleRow(icon: "cable.connector", title: "Disable for all wired networks", key: "disable_ethernet",
                          current: s?.disable_ethernet ?? false) { ["trusted", "ethernet", $0 ? "enable" : "disable"] }
            }

            CardSection(title: "DNS") {
                ChoiceRow(icon: "figure.and.child.holdinghands", title: "1.1.1.1 for Families",
                          options: [("off", "None"), ("malware", "Block malware"),
                                    ("full", "Block malware and adult content")],
                          selection: value("families", s?.families ?? "off")) {
                    store.set("families", $0, ["dns", "families", $0])
                }
                Row(icon: "list.bullet.indent", title: "Local Domain Fallback",
                    subtitle: "Send queries for these suffixes to local network DNS servers.") {
                    Button("Configure") { sheet = .fallback }.buttonStyle(.flat())
                }
            }

            CardSection(title: "Routing") {
                Row(icon: "arrow.triangle.branch", title: "Split Tunnel",
                    subtitle: "Choose which traffic bypasses Cloudflare's network (\(s?.split_mode ?? "exclude") mode).") {
                    Button("Configure") { sheet = .split }.buttonStyle(.flat())
                }
            }

            DisclosureSection(title: "Advanced") {
                Row(icon: "point.3.connected.trianglepath.dotted", title: "Proxy port",
                    subtitle: "Used in Local proxy mode (127.0.0.1:port).") {
                    field("\(s?.proxy_port ?? 40000)", text: $port, width: 80) {
                        guard !port.isEmpty else { return }
                        store.act(["proxy", "port", port]); port = ""
                    }
                }
                Row(icon: "scope", title: "Endpoint override",
                    subtitle: "Force an edge IP:PORT. Submit empty for automatic.") {
                    field(s?.endpoint_override?.isEmpty == false ? s!.endpoint_override! : "automatic",
                          text: $endpoint, width: 130) {
                        store.act(endpoint.isEmpty ? ["tunnel", "endpoint", "reset"] : ["tunnel", "endpoint", "set", endpoint])
                        endpoint = ""
                    }
                }
                Row(icon: "arrow.counterclockwise", title: "Reset all settings") {
                    Button("Reset") { confirmReset = true }.buttonStyle(.flat(.destructive))
                }
            }
        }
        .disabled(s == nil)
        .confirmationDialog("Reset all settings to their defaults?", isPresented: $confirmReset) {
            Button("Reset all settings", role: .destructive) { store.act(["settings", "reset"], success: "Settings were reset.") }
        } message: {
            Text("Your registration and keys are kept.")
        }
        .sheet(item: $sheet) { which in
            editor(which).environmentObject(store)
        }
    }

    // MARK: helpers

    private func value(_ key: String, _ current: String) -> String { store.pendingValue(key) ?? current }

    private func countSuffix(_ list: [String]?) -> String {
        guard let n = list?.count, n > 0 else { return "" }
        return " \(n) configured."
    }

    private func toggleRow(icon: String, title: String, subtitle: String? = nil, key: String,
                           current: Bool, args: @escaping (Bool) -> [String]) -> some View {
        let on = store.pendingValue(key).map { $0 == "true" } ?? current
        return Row(icon: icon, title: title, subtitle: subtitle) {
            Toggle("", isOn: Binding(get: { on }, set: { store.set(key, $0 ? "true" : "false", args($0)) }))
                .toggleStyle(PillToggleStyle())
                .labelsHidden()
                .accessibilityLabel(title)
        }
    }

    private func field(_ placeholder: String, text: Binding<String>, width: CGFloat, submit: @escaping () -> Void) -> some View {
        TextField(placeholder, text: text)
            .textFieldStyle(.plain).font(Typo.mono)
            .multilineTextAlignment(.trailing)
            .padding(.horizontal, Space.xs).frame(width: width, height: 26)
            .background(Palette.raised.color, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
            .onSubmit(submit)
    }

    @ViewBuilder private func editor(_ which: Sheet) -> some View {
        let s = store.settings
        switch which {
        case .ssid:
            ListEditorSheet(title: "Trusted Wi-Fi networks",
                            help: "Pause when connected to these SSIDs. macOS needs Location access to read SSIDs.",
                            placeholder: "Network name", items: s?.trusted_ssids ?? [],
                            add: { store.act(["trusted", "ssid", "add", $0]) },
                            remove: { store.act(["trusted", "ssid", "remove", $0]) },
                            reset: { store.act(["trusted", "ssid", "reset"]) })
        case .split:
            let include = s?.split_mode == "include"
            ListEditorSheet(title: "Split Tunnel",
                            help: "IPs and CIDR ranges that \(include ? "go through" : "bypass") the tunnel.",
                            placeholder: "203.0.113.0/24", items: s?.split_ips ?? [],
                            add: { store.act(["tunnel", "ip", "add", $0]) },
                            remove: { store.act(["tunnel", "ip", "remove", $0]) },
                            reset: { store.act(["tunnel", "ip", "reset"]) }) {
                Segmented(options: [("exclude", "Exclude listed"), ("include", "Include only listed")],
                          selection: value("split_mode", s?.split_mode ?? "exclude")) {
                    store.set("split_mode", $0, ["tunnel", "split-mode", $0])
                }
                .accessibilityLabel("Split tunnel mode")
            }
        case .fallback:
            ListEditorSheet(title: "Local Domain Fallback",
                            help: "Domain suffixes resolved by your local network's DNS servers.",
                            placeholder: "example.local", items: s?.fallback_domains ?? [],
                            add: { store.act(["dns", "fallback", "add", $0]) },
                            remove: { store.act(["dns", "fallback", "remove", $0]) },
                            reset: { store.act(["dns", "fallback", "reset"]) })
        }
    }
}
