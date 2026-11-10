// OpenWarp — SwiftUI front end for the openwarp daemon.
// It talks to the daemon through the bundled `openwarp` CLI with JSON output
// (see Models.swift). Pages: Home / Connectivity / Settings / Profile / About.

import SwiftUI
import AppKit

struct MenuContent: View {
    @EnvironmentObject var store: Store
    @Environment(\.openWindow) var openWindow
    var body: some View {
        Text("OpenWarp: \(store.status?.status ?? (store.daemonError != nil ? "service not running" : "…"))")
        if let t = store.status?.tunnel { Text("\(t.protocol) · \(t.endpoint)") }
        Text("Mode: \(ModeInfo.find(store.mode).fullName)")
        Divider()
        Button(store.wantsOn ? "Disconnect" : "Connect") { store.toggle() }.disabled(store.status?.registered != true)
        Button("Open OpenWarp…") { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
        Divider()
        Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut("q")
    }
}

@main
struct OpenWarpApp: App {
    @StateObject private var store = Store()
    var body: some Scene {
        Window("OpenWarp", id: "main") {
            RootView().environmentObject(store)
        }
        .windowStyle(.hiddenTitleBar)
        .windowResizability(.contentSize)
        .defaultSize(width: Metrics.windowWidth, height: Metrics.windowHeight)
        MenuBarExtra {
            MenuContent().environmentObject(store)
        } label: {
            Image(systemName: store.connected ? "cloud.fill" : "cloud")
        }
    }
}
