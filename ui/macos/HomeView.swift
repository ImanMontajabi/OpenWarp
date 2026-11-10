// Home: the cloud (connect/disconnect), the live status, and the seven modes.

import SwiftUI

struct HomeView: View {
    @EnvironmentObject var store: Store
    @Environment(\.owTint) private var tint

    var body: some View {
        let st = store.status
        let state = store.connState
        let look = CloudLook(state, registered: store.registered)

        Page {
            VStack(spacing: Space.sm) {
                CloudButton(look: look, accent: tint.accent,
                            enabled: store.registered && !store.busy && st != nil,
                            label: store.wantsOn ? "Disconnect" : "Connect",
                            action: { store.toggle() })
                    .padding(.top, Space.md)

                VStack(spacing: Space.xxs) {
                    Text(title(state)).font(Typo.statusTitle)
                        .foregroundStyle(Palette.text)
                        .contentTransition(.opacity)
                        .accessibilityAddTraits(.updatesFrequently)
                        .accessibilityIdentifier("home.status")
                    Text(subtitle(state, st)).font(Typo.body)
                        .foregroundStyle(state == .retrying ? Palette.danger.color : Palette.textSecondary)
                        .multilineTextAlignment(.center).lineLimit(3)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("home.detail")
                }
                .motion(Motion.standard, value: state)

                if store.registered {
                    Text(hint(state)).font(Typo.caption).foregroundStyle(Palette.textTertiary)
                } else if st != nil {
                    RegisterCard()
                }
            }
            .frame(maxWidth: .infinity)

            Spacer(minLength: Space.xs)

            ModeGrid()
        }
    }

    private func title(_ s: ConnState) -> String {
        switch s {
        case .connected: "Connected"
        case .connecting: "Connecting"
        case .retrying: "Reconnecting"
        case .paused: "Paused"
        case .disconnected: "Disconnected"
        case .unknown: "…"
        }
    }

    private func subtitle(_ s: ConnState, _ st: Status?) -> String {
        switch s {
        case .connected:
            if let p = st?.proxy { return "Proxy listening on \(p)" }
            return st?.mode.hasPrefix("do") == true ? "Your DNS queries are private." : "Your Internet is private."
        case .connecting: return st?.reason ?? "Connecting…"
        case .retrying: return st?.error ?? "Retrying…"
        case .paused: return st?.reason ?? "Paused on a trusted network."
        case .disconnected: return "Your Internet is not private."
        case .unknown: return "Waiting for the OpenWarp service…"
        }
    }

    private func hint(_ s: ConnState) -> String {
        switch s {
        case .disconnected, .unknown: "Click the cloud to connect"
        default: "Click the cloud to disconnect"
        }
    }
}

/// Shown when the device has no WARP registration yet.
private struct RegisterCard: View {
    @EnvironmentObject var store: Store
    var body: some View {
        VStack(spacing: Space.sm) {
            Text("This device is not registered yet.").font(Typo.body).foregroundStyle(Palette.textSecondary)
            Button("Accept Terms of Service & Register") { store.act(["registration", "new", "--accept-tos"]) }
                .buttonStyle(.flat(.primary, fullWidth: true))
                .disabled(store.busy)
            Link("Cloudflare WARP Terms", destination: URL(string: "https://www.cloudflare.com/application/terms/")!)
                .font(Typo.caption)
        }
        .padding(Space.md)
        .background(Palette.surface.color, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
    }
}

// MARK: - Mode tiles

struct ModeGrid: View {
    @EnvironmentObject var store: Store
    private let columns = [GridItem(.flexible(), spacing: Space.xs), GridItem(.flexible(), spacing: Space.xs)]

    var body: some View {
        let modes = ModeInfo.all
        VStack(alignment: .leading, spacing: Space.xs) {
            Text("MODE").font(Typo.sectionHeader).tracking(0.6)
                .foregroundStyle(Palette.textTertiary).padding(.leading, Space.xxs)
                .accessibilityAddTraits(.isHeader)
            LazyVGrid(columns: columns, spacing: Space.xs) {
                ForEach(modes.dropLast()) { m in tile(m, wide: false) }
            }
            tile(modes.last!, wide: true)
        }
    }

    private func tile(_ m: ModeInfo, wide: Bool) -> some View {
        ModeTile(mode: m, selected: store.mode == m.id, wide: wide) {
            if store.mode != m.id { store.set("mode", m.id, ["mode", m.id]) }
        }
    }
}

struct ModeTile: View {
    var mode: ModeInfo
    var selected: Bool
    var wide: Bool
    var action: () -> Void
    @Environment(\.owTint) private var tint
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            Group {
                if wide {
                    HStack(spacing: Space.sm) {
                        icon
                        labels(alignment: .leading)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, Space.md)
                } else {
                    VStack(spacing: 6) {
                        icon
                        labels(alignment: .center)
                    }
                    .padding(.horizontal, Space.xs)
                }
            }
            .frame(maxWidth: .infinity, minHeight: wide ? 52 : Metrics.tileHeight)
            .foregroundStyle(selected ? Palette.onAccent : Palette.text)
            .background(background, in: RoundedRectangle(cornerRadius: Radius.md, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: Radius.md))
        }
        .buttonStyle(TilePressStyle())
        .onHover { hovering = $0 }
        .motion(Motion.standard, value: selected)
        .motion(Motion.quick, value: hovering)
        .accessibilityLabel(mode.fullName)
        .accessibilityIdentifier("mode.\(mode.id)")
        .accessibilityAddTraits(selected ? .isSelected : [])
        .help(mode.fullName)
    }

    private var icon: some View {
        Image(systemName: mode.icon).font(.system(size: 16, weight: .semibold))
            .foregroundStyle(selected ? Palette.onAccent : mode.accent.color)
            .frame(height: 18)
    }

    private func labels(alignment: HorizontalAlignment) -> some View {
        VStack(alignment: alignment, spacing: 1) {
            Text(mode.title).font(.system(size: 12.5, weight: .semibold))
            Text(mode.detail).font(.system(size: 11, weight: .medium))
                .opacity(selected ? 0.7 : 0.6)
        }
        .multilineTextAlignment(alignment == .center ? .center : .leading)
        .lineLimit(1).minimumScaleFactor(0.9)
    }

    private var background: Color {
        if selected { return mode.accent.color }
        return hovering ? Palette.hover.color : tint.raised
    }
}

private struct TilePressStyle: ButtonStyle {
    @Environment(\.owReduceMotion) private var reduce
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed && !reduce ? 0.97 : 1)
            .animation(Motion.quick, value: configuration.isPressed)
    }
}
