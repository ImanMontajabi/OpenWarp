// The menu bar dashboard (MenuBarExtra, window style): status, a large
// connect/disconnect button, live throughput, session totals, public IP and
// location, and quick actions. It reads the same Store as the main window, so
// both always show the same state and share one daemon poller.

import SwiftUI
import AppKit

struct DashboardView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var location: LocationModel
    @EnvironmentObject var setup: SetupModel
    /// Opens (or brings forward) the main window.
    var openMain: () -> Void = {}
    var quit: () -> Void = { NSApp.terminate(nil) }

    static let width: CGFloat = 320

    private var tint: Tint { Tint(accent: ModeInfo.find(store.mode).accent, engaged: store.connected) }
    private var source: TrafficSource { TrafficSource(state: store.connState, mode: store.status?.mode ?? store.mode) }

    var body: some View {
        VStack(alignment: .leading, spacing: Space.md) {
            header
            DashboardButton(state: store.buttonState, openMain: openMain) {
                store.toggle()
            }
            feedback
            hairline
            activity
            locationSection
            hairline
            footer
        }
        .padding(Space.md)
        .frame(width: Self.width)
        .foregroundStyle(Palette.text)
        .background(tint.background)
        .environment(\.owTint, tint)
        .motion(Motion.accent, value: tint)
        .motion(Motion.standard, value: store.buttonState)
        .preferredColorScheme(.dark)
        .onAppear { refreshLocation() }
        .onDisappear { location.cancel() }
        .onChange(of: routeKey) { refreshLocation() }
    }

    // MARK: header

    private var header: some View {
        VStack(alignment: .leading, spacing: Space.xxs) {
            HStack(spacing: Space.xs) {
                Image(systemName: "cloud.fill").font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(store.connected ? tint.accentColor : Palette.textSecondary)
                    .accessibilityHidden(true)
                Text("OpenWarp").font(.system(size: 15, weight: .semibold))
                Spacer(minLength: Space.xs)
                Circle().fill(statusColor).frame(width: 7, height: 7).accessibilityHidden(true)
                Text(statusText).font(.system(size: 12.5, weight: .semibold)).foregroundStyle(statusColor)
                    .accessibilityIdentifier("dash.status")
            }
            Text(store.daemonError == nil ? ModeInfo.find(store.mode).fullName : "Background service not running")
                .font(Typo.caption).foregroundStyle(Palette.textSecondary)
                .accessibilityIdentifier("dash.mode")
        }
        .accessibilityElement(children: .contain)
    }

    private var statusText: String {
        switch store.buttonState {
        case .unavailable: "Not set up"
        case .loading: "…"
        case .unregistered: "Not registered"
        case .disconnected: "Disconnected"
        case .connecting: "Connecting"
        case .connected: "Connected"
        case .disconnecting: "Disconnecting"
        case .retrying: "Reconnecting"
        case .paused: "Paused"
        }
    }

    private var statusColor: Color {
        switch store.buttonState {
        case .connected: Palette.success.color
        case .retrying, .unavailable: Palette.danger.color
        case .paused, .connecting, .disconnecting: Palette.warning.color
        default: Palette.textSecondary
        }
    }

    /// Errors and reasons under the button: the retry error, the pause reason,
    /// or the last failed action.
    @ViewBuilder private var feedback: some View {
        let text: (String, Color)? = {
            if case .failed(let m) = setup.phase, store.daemonError != nil { return (m, Palette.danger.color) }
            if let t = store.toast, t.kind == .error { return (t.text, Palette.danger.color) }
            switch store.buttonState {
            case .retrying: return (store.status?.error ?? "Retrying…", Palette.danger.color)
            case .paused: return (store.status?.reason ?? "Paused on a trusted network", Palette.warning.color)
            case .unavailable: return ("OpenWarp needs its background service to connect.", Palette.textSecondary)
            default: return nil
            }
        }()
        if let (message, color) = text {
            Text(message).font(Typo.caption).foregroundStyle(color)
                .lineLimit(3).fixedSize(horizontal: false, vertical: true)
                .accessibilityIdentifier("dash.feedback")
                .transition(.opacity)
        }
    }

    private var hairline: some View { Rectangle().fill(Palette.hairline).frame(height: 1) }

    // MARK: network activity

    private var activity: some View {
        let rates = source == .system ? store.systemRates : store.tunnelRates
        let usage = source == .system ? nil : store.status?.usage
        return VStack(alignment: .leading, spacing: Space.xs) {
            sectionTitle("Network Activity", caption: source.caption, id: "dash.source")
            HStack(spacing: Space.xs) {
                StatCard(title: "Upload", icon: "arrow.up", color: RGB(0xF4AD86).color,
                         rate: rates.map { ByteFormat.rate($0.up) },
                         total: usage.map { "Total " + ByteFormat.bytes(Double($0.tx_bytes)) } ?? totalPlaceholder,
                         id: "dash.upload")
                StatCard(title: "Download", icon: "arrow.down", color: RGB(0x8DB2EE).color,
                         rate: rates.map { ByteFormat.rate($0.down) },
                         total: usage.map { "Total " + ByteFormat.bytes(Double($0.rx_bytes)) } ?? totalPlaceholder,
                         id: "dash.download")
            }
            if source != .system, let sys = store.systemRates {
                Text("All interfaces  ↑ \(ByteFormat.rate(sys.up))  ↓ \(ByteFormat.rate(sys.down))")
                    .font(Typo.caption).foregroundStyle(Palette.textTertiary)
                    .accessibilityLabel("All network interfaces: upload \(ByteFormat.rate(sys.up)), download \(ByteFormat.rate(sys.down))")
                    .accessibilityIdentifier("dash.system")
            }
        }
    }

    private var totalPlaceholder: String { source == .system ? "No WARP session" : "Total —" }

    // MARK: network location

    /// Changes when the route a lookup measures may have changed.
    private var routeKey: String {
        LocationModel.routes(for: store.status, network: store.status?.network)?
            .map { "\($0.path)|\($0.context)" }.joined(separator: ",") ?? "pending"
    }

    private func refreshLocation(force: Bool = false) {
        location.refresh(status: store.status, network: store.status?.network, force: force)
    }

    private var locationSection: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            HStack(alignment: .firstTextBaseline) {
                sectionTitle("Network Location", caption: locationCaption, id: "dash.location.caption")
                Spacer()
                if location.enabled {
                    Button { refreshLocation(force: true) } label: {
                        Image(systemName: "arrow.clockwise").font(.system(size: 11, weight: .semibold))
                            .frame(width: 22, height: 22)
                    }
                    .buttonStyle(.flat(.quiet)).foregroundStyle(Palette.textSecondary)
                    .help("Look up again").accessibilityLabel("Look up the public IP again")
                    .accessibilityIdentifier("dash.location.refresh")
                }
            }
            if !location.enabled {
                Card {
                    Row(icon: "eye.slash", title: "Public IP lookup is off",
                        subtitle: "Turn it on to ask Cloudflare which address it sees.") {
                        Button("Turn On") { location.enabled = true; refreshLocation() }.buttonStyle(.flat())
                            .accessibilityIdentifier("dash.location.enable")
                    }
                }
            } else {
                LocationCard(state: location.system, label: location.proxy == nil ? nil : "This Mac", id: "dash.location.system")
                if let proxy = location.proxy {
                    LocationCard(state: proxy, label: "Through the proxy", id: "dash.location.proxy")
                }
            }
        }
    }

    private var locationCaption: String {
        switch store.connState {
        case .connected where source == .tunnel: "As seen by Cloudflare, through WARP"
        case .connected where source == .proxy: "Only proxied apps use WARP"
        case .connected: "DNS only: your traffic is not tunnelled"
        case .connecting, .retrying: "Updates once connected"
        default: "As seen by Cloudflare, without WARP"
        }
    }

    private func sectionTitle(_ title: String, caption: String, id: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundStyle(tint.accentColor.opacity(0.95))
                .accessibilityAddTraits(.isHeader)
            Text(caption).font(Typo.caption).foregroundStyle(Palette.textTertiary)
                .accessibilityIdentifier(id)
        }
    }

    // MARK: footer

    private var footer: some View {
        HStack {
            Button(action: quit) {
                Label("Quit", systemImage: "rectangle.portrait.and.arrow.right")
            }
            .buttonStyle(.flat(.quiet))
            .keyboardShortcut("q")
            .accessibilityIdentifier("dash.quit")
            Spacer()
            Button(action: openMain) {
                Label("Open OpenWarp", systemImage: "macwindow")
            }
            .buttonStyle(.flat(.quiet))
            .accessibilityIdentifier("dash.open")
        }
        .foregroundStyle(Palette.textSecondary)
    }
}

// MARK: - Connect button

struct DashboardButton: View {
    var state: ButtonState
    var openMain: () -> Void
    var toggle: () -> Void
    @Environment(\.owTint) private var tint
    @State private var hovering = false

    var body: some View {
        Button(action: { state == .unavailable || state == .unregistered ? openMain() : toggle() }) {
            HStack(spacing: Space.xs) {
                if [.connecting, .disconnecting, .loading].contains(state) {
                    ProgressView().controlSize(.small).tint(foreground)
                }
                Text(title).font(.system(size: 16, weight: .semibold))
                if let icon { Image(systemName: icon).font(.system(size: 15, weight: .semibold)) }
            }
            .foregroundStyle(foreground)
            .frame(maxWidth: .infinity, minHeight: 52)
            .background(background, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: Radius.md))
        }
        .buttonStyle(PressStyle())
        .disabled(!enabledForClick)
        .onHover { hovering = $0 }
        .motion(Motion.quick, value: hovering)
        .accessibilityLabel(title)
        .accessibilityHint(hint)
        .accessibilityIdentifier("dash.connect")
    }

    private var enabledForClick: Bool { state.enabled || state == .unregistered }

    var title: String {
        switch state {
        case .loading: "Checking…"
        case .unavailable: "Set Up OpenWarp"
        case .unregistered: "Register in OpenWarp"
        case .disconnected: "Connect"
        case .connecting: "Connecting…"
        case .disconnecting: "Disconnecting…"
        case .connected, .retrying, .paused: "Disconnect"
        }
    }

    private var icon: String? {
        switch state {
        case .disconnected, .connected, .retrying, .paused: "power"
        case .unavailable: "wrench.and.screwdriver"
        case .unregistered: "macwindow"
        default: nil
        }
    }

    private var hint: String {
        switch state {
        case .connecting: "Stops the connection attempt"
        case .unavailable: "Opens OpenWarp to install its background service"
        case .unregistered: "Opens OpenWarp to register this Mac"
        default: ""
        }
    }

    /// Off: the mode's pastel accent with dark text. On: a matte, darker version of
    /// the accent with light text, so the state reads at a glance without glow.
    private var background: Color {
        let lift = hovering && enabledForClick ? 0.06 : 0
        switch state {
        case .disconnected: return tint.accent.mix(RGB(0xFFFFFF), lift).color
        case .connected, .connecting, .retrying, .paused, .disconnecting:
            return Palette.surface.mix(tint.accent, 0.32 + lift).color
        default: return Palette.raised.mix(RGB(0xFFFFFF), lift).color
        }
    }

    private var foreground: Color {
        switch state {
        case .disconnected: Palette.onAccent
        case .connected, .connecting, .retrying, .paused, .disconnecting: Palette.text
        default: Palette.text
        }
    }
}

private struct PressStyle: ButtonStyle {
    @Environment(\.owReduceMotion) private var reduce
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(enabled ? 1 : 0.6)
            .scaleEffect(configuration.isPressed && !reduce ? 0.98 : 1)
            .animation(Motion.quick, value: configuration.isPressed)
    }
}

// MARK: - Cards

private struct StatCard: View {
    var title: String
    var icon: String
    var color: Color
    var rate: String?
    var total: String
    var id: String
    @Environment(\.owTint) private var tint

    var body: some View {
        VStack(alignment: .leading, spacing: Space.xxs) {
            HStack(spacing: 4) {
                Text(title).font(Typo.caption).foregroundStyle(Palette.textSecondary)
                Image(systemName: icon).font(.system(size: 10, weight: .bold)).foregroundStyle(color)
            }
            Text(rate ?? "—")
                .font(.system(size: 20, weight: .semibold).monospacedDigit())
                .lineLimit(1).minimumScaleFactor(0.7)
                .contentTransition(.numericText())
                .accessibilityIdentifier("\(id).rate")
            Text(total).font(Typo.caption).foregroundStyle(Palette.textTertiary).lineLimit(1)
                .accessibilityIdentifier("\(id).total")
        }
        .padding(Space.sm)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(tint.surface, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
        .accessibilityElement(children: .contain)
    }
}

private struct LocationCard: View {
    var state: LookupState
    var label: String?
    var id: String

    var body: some View {
        CardSection(title: label) {
            switch state {
            case .idle:
                ValueRow(icon: "globe", title: "Public IP", value: nil)
            case .loading:
                Row(icon: "globe", title: "Public IP") {
                    ProgressView().controlSize(.small).accessibilityLabel("Looking up")
                }
            case .failed(let message):
                Row(icon: "exclamationmark.triangle", title: "Public IP", subtitle: message)
            case .done(let info):
                // No copy button: it would squeeze the address in a 320 pt panel. Right-click copies.
                ValueRow(icon: "globe", title: "Public IP", value: info.ip, mono: true)
                    .contextMenu { Button("Copy IP Address") { Clipboard.copy(info.ip) } }
                ValueRow(icon: "mappin.and.ellipse", title: "Location", value: info.countryName)
                ValueRow(icon: "server.rack", title: "Cloudflare",
                         value: [info.colo, info.throughWARP ? "WARP on" : "WARP off"].compactMap { $0 }.joined(separator: " · "))
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(id)
    }
}
