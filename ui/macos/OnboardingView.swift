// First-run setup screen, shown when the background service is missing or not
// running (the main window and the menu bar's "Set Up OpenWarp" lead here), and
// the slim banner shown when the running service is older than the app.

import SwiftUI
import AppKit

struct OnboardingView: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var setup: SetupModel
    @Environment(\.owTint) private var tint
    @State private var showManual = false
    @Environment(\.owReduceMotion) private var reduce

    var body: some View {
        Page(centered: true) {
            VStack(spacing: Space.lg) {
                VStack(spacing: Space.sm) {
                    CloudShape().fill(tint.accentColor)
                        .frame(width: 96, height: 96 * CloudShape.aspect)
                        .accessibilityHidden(true)
                    Text("Welcome to OpenWarp").font(Typo.pageTitle)
                        .accessibilityAddTraits(.isHeader)
                        .accessibilityIdentifier("onboarding.title")
                    Text(intro).font(Typo.body).foregroundStyle(Palette.textSecondary)
                        .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                        .accessibilityIdentifier("onboarding.intro")
                }

                Card {
                    Row(icon: "gearshape.2", title: "Runs as a system service",
                        subtitle: "Starts with your Mac and manages the tunnel, routes and DNS.")
                    Row(icon: "lock.shield", title: "Asks macOS for approval",
                        subtitle: "macOS shows its own administrator prompt. OpenWarp never sees your password.")
                    Row(icon: "tray.full", title: "Keeps your setup",
                        subtitle: "Your registration and settings are preserved when installing or updating.")
                }

                VStack(spacing: Space.xs) {
                    Button(action: { setup.install(onReady: { await store.refreshAll() }) }) {
                        HStack(spacing: Space.xs) {
                            if setup.phase.busy { ProgressView().controlSize(.small) }
                            Text(buttonTitle)
                        }
                    }
                    .buttonStyle(.flat(.primary, fullWidth: true))
                    .controlSize(.large)
                    .disabled(setup.phase.busy)
                    .accessibilityIdentifier("onboarding.install")

                    status
                }

                if Self.runningFromDiskImage {
                    Text("Move OpenWarp to your Applications folder before installing, so the app is still there after you eject the disk image.")
                        .font(Typo.caption).foregroundStyle(Palette.warning.color)
                        .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                }

                manual
            }
            .frame(maxWidth: .infinity)
        }
        .task { if setup.phase == .checking { setup.check() } }
    }

    private var intro: String {
        if case .needed(.notRunning) = setup.phase {
            return "The OpenWarp background service is installed but not running. Reinstalling it restarts it."
        }
        return "OpenWarp needs a background service to manage full-device VPN connections and system networking."
    }

    private var buttonTitle: String {
        switch setup.phase {
        case .checking: "Checking…"
        case .installing: "Waiting for approval…"
        case .verifying: "Starting the service…"
        case .needed(.notRunning): "Restart Background Service"
        case .needed(.outdated): "Update Background Service"
        case .failed: "Try Again"
        default: "Install Background Service"
        }
    }

    @ViewBuilder private var status: some View {
        switch setup.phase {
        case .failed(let message):
            VStack(spacing: Space.xxs) {
                Text(message).font(Typo.caption).foregroundStyle(Palette.danger.color)
                    .multilineTextAlignment(.center).fixedSize(horizontal: false, vertical: true)
                    .accessibilityIdentifier("onboarding.error")
                Button("Check Again") { setup.check() }.buttonStyle(.flat(.quiet))
                    .accessibilityIdentifier("onboarding.recheck")
            }
        case .ready:
            Label("Service is running", systemImage: "checkmark.circle.fill")
                .font(Typo.caption).foregroundStyle(Palette.success.color)
                .accessibilityIdentifier("onboarding.ready")
        default:
            if let note = setup.note {
                Text(note).font(Typo.caption).foregroundStyle(Palette.textSecondary)
                    .accessibilityIdentifier("onboarding.note")
            }
        }
    }

    private var manual: some View {
        VStack(alignment: .leading, spacing: Space.xs) {
            Button { Accordion.toggle($showManual, reduceMotion: reduce) } label: {
                HStack {
                    Text("Set up from Terminal instead").font(Typo.caption.weight(.semibold))
                    Image(systemName: "chevron.down").font(.system(size: 9, weight: .bold))
                        .rotationEffect(.degrees(showManual ? 180 : 0))
                }
                .foregroundStyle(Palette.textSecondary)
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("onboarding.manual")
            Reveal(open: showManual) {
                VStack(alignment: .leading, spacing: Space.xs) {
                    command("sudo \(Self.quoted(CLI.path)) service install")
                    Text("Without administrator rights only the Local proxy mode works. Run the service yourself, then choose Local proxy:")
                        .font(Typo.caption).foregroundStyle(Palette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    command("\(Self.quoted(CLI.path)) daemon")
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func command(_ text: String) -> some View {
        HStack(spacing: Space.xs) {
            Text(text).font(Typo.mono).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
            CopyButton(value: text, label: "command")
        }
        .padding(Space.sm)
        .background(Palette.raised.color, in: RoundedRectangle(cornerRadius: Radius.sm, style: .continuous))
    }

    /// Shell-quotes a path for display in a command the user copies.
    static func quoted(_ path: String) -> String {
        path.contains(where: { " '\"$`\\".contains($0) }) ? "'" + path.replacingOccurrences(of: "'", with: "'\\''") + "'" : path
    }

    /// Launched from a mounted disk image or a quarantined, translocated copy.
    static var runningFromDiskImage: Bool {
        let p = Bundle.main.bundlePath
        return p.hasPrefix("/Volumes/") || p.contains("/AppTranslocation/")
    }
}

/// Shown above the pages when the running service is older than the app.
struct ServiceUpdateBanner: View {
    @EnvironmentObject var store: Store
    @EnvironmentObject var setup: SetupModel

    var body: some View {
        if case .needed(.outdated(let version)) = setup.phase, store.daemonError == nil {
            banner(text: "The background service is outdated (\(version ?? "older than 0.1.0")).")
        } else if setup.phase.busy, setup.phase != .checking, store.daemonError == nil {
            banner(text: "Updating the background service…")
        } else if case .failed(let m) = setup.phase, store.daemonError == nil {
            banner(text: m)
        }
    }

    private func banner(text: String) -> some View {
        HStack(spacing: Space.xs) {
            Image(systemName: "arrow.triangle.2.circlepath").foregroundStyle(Palette.warning.color)
                .accessibilityHidden(true)
            Text(text).font(Typo.caption).foregroundStyle(Palette.text)
                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: Space.xs)
            Button("Update") { setup.install(onReady: { await store.refreshAll() }) }
                .buttonStyle(.flat(.secondary))
                .disabled(setup.phase.busy)
                .accessibilityIdentifier("banner.update")
        }
        .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
        .background(Palette.warning.color.opacity(0.10))
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("banner.outdated")
    }
}
