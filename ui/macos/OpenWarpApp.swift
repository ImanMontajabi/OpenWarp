// OpenWarp — SwiftUI front end for the openwarp daemon.
// It talks to the daemon through the bundled `openwarp` CLI with JSON output
// (see Models.swift). Pages: Home / Connectivity / Settings / Profile / About,
// plus the menu bar dashboard (DashboardView) on the same Store.

import SwiftUI
import AppKit

@main
struct OpenWarpApp: App {
    @StateObject private var store: Store
    @StateObject private var setup: SetupModel
    @StateObject private var location: LocationModel
    @StateObject private var updates: UpdateChecker

    init() {
        let m = AppModels.forLaunch()
        _store = StateObject(wrappedValue: m.store)
        _setup = StateObject(wrappedValue: m.setup)
        _location = StateObject(wrappedValue: m.location)
        _updates = StateObject(wrappedValue: m.updates)
    }

    var body: some Scene {
        Window("OpenWarp", id: "main") {
            RootView()
                .environmentObject(store)
                .environmentObject(setup)
                .environmentObject(location)
                .environmentObject(updates)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultSize(width: Metrics.windowWidth, height: Metrics.windowHeight)

        MenuBarExtra {
            MenuBarDashboard()
                .environmentObject(store)
                .environmentObject(setup)
                .environmentObject(location)
        } label: {
            Image(systemName: store.connected ? "cloud.fill" : "cloud")
                .accessibilityLabel("OpenWarp")
        }
        .menuBarExtraStyle(.window)
    }
}

/// The dashboard with its window actions bound to this scene.
private struct MenuBarDashboard: View {
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        DashboardView(openMain: {
            openWindow(id: "main")
            NSApp.activate(ignoringOtherApps: true)
        })
    }
}
