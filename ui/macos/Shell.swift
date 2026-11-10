// Window shell: unified title area, page container, bottom navigation,
// toast overlay, and the NSWindow configuration that removes the title-bar strip.

import SwiftUI
import AppKit

enum Tab: String, CaseIterable, Identifiable {
    case home = "Home", connectivity = "Connectivity", settings = "Settings", profile = "Profile", about = "About"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .home: "house"
        case .connectivity: "chart.bar"
        case .settings: "gearshape"
        case .profile: "person"
        case .about: "info.circle"
        }
    }
}

struct RootView: View {
    @EnvironmentObject var store: Store
    @State private var tab: Tab
    @Environment(\.owReduceMotion) private var reduce

    init(initialTab: Tab = .home) { _tab = State(initialValue: initialTab) }

    private var tint: Tint { Tint(accent: ModeInfo.find(store.mode).accent, engaged: store.connected) }

    var body: some View {
        VStack(spacing: 0) {
            TitleArea()
            ZStack {
                Group {
                    if let err = store.daemonError, tab != .about {
                        DaemonDownView(error: err)
                    } else {
                        switch tab {
                        case .home: HomeView()
                        case .connectivity: ConnectivityView()
                        case .settings: SettingsView()
                        case .profile: ProfileView()
                        case .about: AboutView()
                        }
                    }
                }
                .id(tab)
                .transition(reduce ? .opacity : .opacity.combined(with: .offset(y: 6)))
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .clipped()   // keep scrolled content out of the title strip
            .overlay(alignment: .bottom) {
                if let t = store.toast {
                    ToastBanner(toast: t) { store.toast = nil }
                        .padding(.horizontal, Space.md).padding(.bottom, Space.xs)
                        .transition(.move(edge: .bottom).combined(with: .opacity))
                        .task(id: t.id) {
                            try? await Task.sleep(nanoseconds: t.kind == .error ? 8_000_000_000 : 3_000_000_000)
                            if store.toast?.id == t.id { store.toast = nil }
                        }
                }
            }
            .motion(Motion.standard, value: store.toast)
            BottomNav(selection: $tab)
        }
        .ignoresSafeArea(.container, edges: .top)   // title area shares the title-bar strip
        .foregroundStyle(Palette.text)
        .background(tint.background.ignoresSafeArea())
        .environment(\.owTint, tint)
        .motion(Motion.accent, value: tint)
        .background(WindowConfigurator())
        .frame(minWidth: Metrics.minWidth, maxWidth: Metrics.maxWidth, minHeight: Metrics.minHeight)
        .preferredColorScheme(.dark)
    }
}

// MARK: - Title area

/// Shares the window background; the native traffic lights sit on its left.
struct TitleArea: View {
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "cloud.fill").font(.system(size: 11, weight: .semibold))
            Text("OpenWarp").font(.system(size: 12, weight: .semibold))
            Spacer()
        }
        .foregroundStyle(Palette.textSecondary)
        .padding(.leading, Metrics.trafficLightInset)
        .frame(height: Metrics.titleBarHeight)
        .background(WindowDragArea())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("OpenWarp")
    }
}

/// An NSView that lets the user drag the window from the title area.
private struct WindowDragArea: NSViewRepresentable {
    final class DragView: NSView {
        override var mouseDownCanMoveWindow: Bool { true }
        override func mouseDown(with event: NSEvent) { window?.performDrag(with: event) }
    }
    func makeNSView(context: Context) -> NSView { DragView() }
    func updateNSView(_ nsView: NSView, context: Context) {}
}

/// Makes the title bar transparent and the window background match the content.
private struct WindowConfigurator: NSViewRepresentable {
    final class Probe: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard let w = window else { return }
            w.titlebarAppearsTransparent = true
            w.titleVisibility = .hidden
            w.styleMask.insert(.fullSizeContentView)
            w.titlebarSeparatorStyle = .none
            w.toolbar = nil
            w.backgroundColor = Palette.base.nsColor
            w.appearance = NSAppearance(named: .darkAqua)
            w.title = "OpenWarp"
        }
    }
    func makeNSView(context: Context) -> NSView { Probe() }
    func updateNSView(_ nsView: NSView, context: Context) {}
}

// MARK: - Bottom navigation

struct BottomNav: View {
    @Binding var selection: Tab
    @Environment(\.owTint) private var tint
    @Environment(\.owReduceMotion) private var reduce
    @Namespace private var ns

    var body: some View {
        HStack(spacing: Space.xxs) {
            ForEach(Tab.allCases) { t in
                let on = t == selection
                Button {
                    withAnimation(reduce ? nil : Motion.standard) { selection = t }
                } label: {
                    VStack(spacing: 3) {
                        Image(systemName: on ? t.icon + ".fill" : t.icon)
                            .font(.system(size: 15, weight: .semibold))
                            .frame(height: 18)
                        Text(t.rawValue).font(Typo.navLabel).lineLimit(1).minimumScaleFactor(0.85)
                    }
                    .foregroundStyle(on ? tint.accentColor : Palette.textSecondary)
                    .frame(maxWidth: .infinity, minHeight: 44)
                    .background {
                        if on {
                            RoundedRectangle(cornerRadius: Radius.md, style: .continuous)
                                .fill(tint.soft)
                                .matchedGeometryEffect(id: "navpill", in: ns)
                        }
                    }
                    .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityLabel(t.rawValue)
                .accessibilityIdentifier("tab.\(t.id.lowercased())")
                .accessibilityAddTraits(on ? .isSelected : [])
                .keyboardShortcut(KeyEquivalent(Character("\(Tab.allCases.firstIndex(of: t)! + 1)")), modifiers: .command)
            }
        }
        .padding(.horizontal, Space.sm)
        .padding(.vertical, Space.xs)
        .frame(height: Metrics.navHeight + Space.xs)
        .overlay(alignment: .top) { Rectangle().fill(Palette.hairline).frame(height: 1) }
    }
}

// MARK: - Daemon not reachable

struct DaemonDownView: View {
    var error: String
    var body: some View {
        Page(centered: true) {
            VStack(spacing: Space.md) {
                Image(systemName: "bolt.horizontal.circle").font(.system(size: 40, weight: .regular))
                    .foregroundStyle(Palette.warning.color)
                Text("The OpenWarp service is not running").font(.system(size: 17, weight: .semibold))
                    .multilineTextAlignment(.center)
                    .accessibilityIdentifier("daemon.down")
                Text("Install it once with:").font(Typo.caption).foregroundStyle(Palette.textSecondary)
                HStack(spacing: Space.xs) {
                    Text("sudo \(CLI.path) service install").font(Typo.mono).textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                    CopyButton(value: "sudo \(CLI.path) service install", label: "command")
                }
                .padding(Space.sm)
                .background(Palette.raised.color, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
                Text(error).font(Typo.caption).foregroundStyle(Palette.textTertiary).multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
        }
    }
}
