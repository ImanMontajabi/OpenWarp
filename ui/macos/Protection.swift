// Leak protection: the kill switch, IPv6/DNS handling and connection verification, as the daemon reports
// them (Status.protection). Wording never claims more than the daemon checked: "verified" only appears
// after a verification of the current connection passed.

import SwiftUI

/// Display text for the daemon's protection values (protection.go). Unknown values are shown as they come.
enum ProtectionText {
    enum Tone { case good, caution, bad, neutral }

    static func state(_ s: String?) -> (label: String, tone: Tone) {
        switch s {
        case "verified": ("Verified", .good)
        case "unverified": ("Connected, not verified", .caution)
        case "failed": ("Problem found", .bad)
        case "blocking": ("Blocking until connected", .caution)
        case "connecting": ("Not protected yet", .bad)
        case "unprotected": ("Not protected", .neutral)
        case nil: ("—", .neutral)
        case let other?: (other, .neutral)
        }
    }

    static func killSwitch(_ p: Protection?) -> String {
        guard let p else { return "—" }
        switch p.kill_switch {
        case "off": return "Off"
        case "standby": return "On. It takes effect when you connect."
        case "protecting": return "On. Traffic outside the tunnel is blocked."
        case "blocking": return "On. All traffic is blocked until the tunnel is back."
        case "unavailable": return "Not used: \(p.kill_switch_detail ?? "not available in this mode")."
        case "error": return "Not working: \(p.kill_switch_detail ?? "unknown error")"
        default: return p.kill_switch
        }
    }

    static func ipv6(_ v: String?) -> String {
        switch v {
        case "tunnel": "Through the tunnel"
        case "blocked": "Blocked (no IPv6 in the tunnel)"
        case "system": "Not tunnelled (Include split mode)"
        case "proxy": "Only apps that use the proxy"
        case nil, "": "—"
        case let other?: other
        }
    }

    static func dns(_ v: String?) -> String {
        switch v {
        case "tunnel": "Cloudflare, through the tunnel"
        case "encrypted": "Encrypted (local DNS proxy)"
        case "system": "System DNS, not managed"
        case "proxy": "Resolved through the tunnel by the proxy"
        case nil, "": "—"
        case let other?: other
        }
    }

    static func checkTitle(_ name: String) -> String {
        switch name {
        case "tunnel": "Tunnel"
        case "ipv4_route": "IPv4 route"
        case "ipv6_route": "IPv6 route"
        case "dns": "DNS servers"
        case "kill_switch": "Kill switch"
        case "cloudflare": "Cloudflare check"
        default: name
        }
    }

    static func checkIcon(_ status: String) -> (String, Tone) {
        switch status {
        case "pass": ("checkmark.circle.fill", .good)
        case "fail": ("xmark.octagon.fill", .bad)
        default: ("minus.circle", .neutral)
        }
    }

    static func color(_ t: Tone) -> Color {
        switch t {
        case .good: Palette.success.color
        case .caution: Palette.warning.color
        case .bad: Palette.danger.color
        case .neutral: Palette.textTertiary
        }
    }
}

struct ProtectionBadge: View {
    var state: String?
    var body: some View {
        let (label, tone) = ProtectionText.state(state)
        let color = ProtectionText.color(tone)
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text(label).font(.system(size: 11.5, weight: .semibold))
        }
        .foregroundStyle(color)
        .padding(.horizontal, Space.xs).padding(.vertical, 4)
        .background(color.opacity(0.14), in: Capsule())
        .accessibilityElement(children: .ignore)
        .accessibilityAddTraits(.isStaticText)   // a plain group exposes no value on macOS
        .accessibilityLabel("Protection")
        .accessibilityValue(label)
        .accessibilityIdentifier("protection.state")
    }
}

/// One verification step: icon, name, and what was found.
struct CheckRow: View {
    var check: Check
    var body: some View {
        let (icon, tone) = ProtectionText.checkIcon(check.status)
        HStack(alignment: .firstTextBaseline, spacing: Space.sm) {
            Image(systemName: icon).font(.system(size: 13, weight: .semibold))
                .foregroundStyle(ProtectionText.color(tone)).frame(width: 20)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(ProtectionText.checkTitle(check.name)).font(Typo.rowTitle).foregroundStyle(Palette.text)
                if let d = check.detail, !d.isEmpty {
                    Text(d).font(Typo.caption).foregroundStyle(Palette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, Space.md)
        .padding(.vertical, Space.xs)
        .accessibilityElement(children: .ignore)
        .accessibilityAddTraits(.isStaticText)
        .accessibilityLabel(ProtectionText.checkTitle(check.name))
        .accessibilityValue("\(check.status): \(check.detail ?? "")")
        .accessibilityIdentifier("check.\(check.name)")
    }
}

/// The Connectivity page's leak protection card.
struct LeakProtectionSection: View {
    @EnvironmentObject var store: Store
    @State private var confirmKillSwitch = false

    var body: some View {
        let p = store.status?.protection
        let connected = store.connected
        CardSection(title: "Leak protection") {
            Row(icon: "shield.lefthalf.filled", title: "Protection") { ProtectionBadge(state: p?.state) }
            killSwitchRow(p)
            if connected {
                ValueRow(icon: "6.circle", title: "IPv6", value: ProtectionText.ipv6(p?.ipv6))
                ValueRow(icon: "text.magnifyingglass", title: "DNS", value: ProtectionText.dns(p?.dns))
            }
            if connected, let v = p?.verification {
                ForEach(v.checks, id: \.name) { CheckRow(check: $0) }
            }
            Row(icon: "checkmark.shield", title: "Verify connection",
                subtitle: "Checks the routes, DNS servers and kill switch on this Mac. Nothing is sent anywhere.") {
                Button("Verify") { store.verify(cloudflare: false) }
                    .buttonStyle(.flat())
                    .disabled(!connected || store.verifying)
                    .accessibilityIdentifier("protection.verify")
            }
            Row(icon: "cloud", title: "Ask Cloudflare",
                subtitle: "Sends one request to cloudflare.com/cdn-cgi/trace through the tunnel and checks that Cloudflare reports it as WARP traffic.") {
                Button("Check") { store.verify(cloudflare: true) }
                    .buttonStyle(.flat())
                    .disabled(!connected || store.verifying)
                    .accessibilityIdentifier("protection.cloudflare")
            }
        }
        .confirmationDialog("Turn on the kill switch?", isPresented: $confirmKillSwitch) {
            Button("Turn On Kill Switch") { store.set("kill_switch", "true", ["killswitch", "on"]) }
        } message: {
            Text("""
            While OpenWarp is connected or reconnecting, traffic that does not go through the tunnel is blocked, \
            except the excluded local ranges. If the tunnel stays down, nothing gets through until you disconnect. \
            Experimental: it uses the macOS packet filter (pf) and needs the background service. If you ever lose \
            your connection, disconnect in OpenWarp or run `sudo openwarp recover` in Terminal.
            """)
        }
    }

    private func killSwitchRow(_ p: Protection?) -> some View {
        let current = store.settings?.kill_switch ?? false
        let on = store.pendingValue("kill_switch").map { $0 == "true" } ?? current
        return Row(icon: "hand.raised", title: "Kill switch (experimental)", subtitle: ProtectionText.killSwitch(p)) {
            Toggle("", isOn: Binding(get: { on }, set: { new in
                if new { confirmKillSwitch = true } else { store.set("kill_switch", "false", ["killswitch", "off"]) }
            }))
            .toggleStyle(PillToggleStyle())
            .labelsHidden()
            .disabled(store.settings?.kill_switch == nil)   // a daemon without leak protection
            .accessibilityLabel("Kill switch")
            .accessibilityIdentifier("toggle.kill_switch")
        }
    }
}
