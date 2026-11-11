import AppKit
import SwiftUI
import XCTest

/// Visual regression tests: the real window content (RootView) rendered for the
/// key screens from the contract fixtures, compared with PNG goldens in
/// __Snapshots__/. Reduce Motion is forced so continuous animations cannot make
/// frames differ, and rendering is at a fixed 2x scale in sRGB.
///
/// Text metrics change even between macOS point releases (a label that fits on
/// 27.2 wraps on 27.0.1), so goldens live in one folder per exact OS version
/// (__Snapshots__/macOS-27.0.1/ for the CI image, others for maintainers' Macs).
/// Without goldens for the running version the tests are skipped, and the CI
/// workflow turns that skip into a warning. Record with `scripts/test-app.sh
/// record` (or the macOS workflow's record_snapshots input for the CI image),
/// then review the PNG diff before committing.
@MainActor
final class SnapshotTests: XCTestCase {
    static let size = CGSize(width: Metrics.windowWidth, height: Metrics.windowHeight)
    static let scale: CGFloat = 2
    /// A pixel differs when any channel moves by more than this (0–255).
    static let channelTolerance = 10
    /// The test fails when more than this fraction of pixels differ.
    static let maxDifferingFraction = 0.002

    static var osVersion: String {
        let v = ProcessInfo.processInfo.operatingSystemVersion
        return "macOS-\(v.majorVersion).\(v.minorVersion).\(v.patchVersion)"
    }
    static let goldens = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("__Snapshots__").appendingPathComponent(osVersion)
    static var recording: Bool { ProcessInfo.processInfo.environment["OPENWARP_RECORD_SNAPSHOTS"] == "1" }

    override func setUp() async throws {
        Motion.forceReduced = true
        // Overlay scroll bars, as with a trackpad. With a mouse attached macOS uses legacy scroll bars that
        // take 15 pt from every scrolling page, so goldens would depend on the input devices. Volatile: the
        // argument domain lives only in this test process.
        var args = UserDefaults.standard.volatileDomain(forName: UserDefaults.argumentDomain)
        args["AppleShowScrollBars"] = "WhenScrolling"
        UserDefaults.standard.setVolatileDomain(args, forName: UserDefaults.argumentDomain)
        if Self.recording {
            try FileManager.default.createDirectory(at: Self.goldens, withIntermediateDirectories: true)
            return
        }
        guard FileManager.default.fileExists(atPath: Self.goldens.path) else {
            throw XCTSkip("no snapshot goldens for \(Self.osVersion); record them with scripts/test-app.sh record")
        }
    }

    override func tearDown() async throws { Motion.forceReduced = false }

    // MARK: screens

    func testHomeConnected() throws {
        try assertSnapshot("home-connected", tab: .home, status: "status-connected.json")
    }

    func testHomeRetrying() throws {
        try assertSnapshot("home-retrying", tab: .home, status: "status-connecting-error.json")
    }

    func testHomeUnregistered() throws {
        try assertSnapshot("home-unregistered", tab: .home, status: "status-unregistered.json", registered: false)
    }

    func testConnectivityConnected() throws {
        // The connected fixture reports the kill switch protecting, so the setting is on too.
        try assertSnapshot("connectivity-connected", tab: .connectivity, status: "status-connected.json", killSwitch: true)
    }

    func testSettingsDefaults() throws {
        try assertSnapshot("settings-default", tab: .settings, status: "status-unregistered.json")
    }

    func testProfile() throws {
        try assertSnapshot("profile", tab: .profile, status: "status-connected.json")
    }

    func testAbout() throws {
        try assertSnapshot("about", tab: .about, status: "status-unregistered.json")
    }

    /// First run: the service is not installed, so the main window shows setup.
    func testDaemonDown() throws {
        let store = Store(backend: MockBackend(), polling: false)
        store.daemonError = "cannot reach the openwarp daemon at /var/run/openwarp.sock"
        try compare("daemon-down", render(window(RootView(initialTab: .home), store: store, setup: setup(.needed(.notInstalled)))))
    }

    func testOnboardingInstallFailed() throws {
        let store = Store(backend: MockBackend(), polling: false)
        store.daemonError = "cannot reach the openwarp daemon at /var/run/openwarp.sock"
        let s = setup(.failed("The service is installed but did not start. See /var/log/openwarp.log."))
        try compare("onboarding-failed", render(window(RootView(initialTab: .home), store: store, setup: s)))
    }

    // MARK: menu bar dashboard

    func testDashboardConnected() throws {
        let store = try connectedStore(mode: "warp+doh")
        let loc = location(direct: "ip=198.51.100.7\nloc=DE\ncolo=FRA\nwarp=on\n")
        try compare("dashboard-connected", render(dashboard(store, loc), fit: true))
    }

    func testDashboardProxyMode() throws {
        let store = try connectedStore(mode: "proxy") { $0["proxy"] = "127.0.0.1:40000"; $0["interface"] = nil }
        let loc = location(proxied: "ip=198.51.100.7\nloc=DE\ncolo=FRA\nwarp=on\n")
        try compare("dashboard-proxy", render(dashboard(store, loc), fit: true))
    }

    func testDashboardDisconnected() throws {
        let store = Store(backend: MockBackend(), polling: false, interfaceCounters: { [] })
        store.status = try Contract.decode(Status.self, "status-unregistered.json")
        store.status?.registered = true
        store.settings = try Contract.decode(Settings.self, "settings-default.json")
        try compare("dashboard-disconnected", render(dashboard(store, location()), fit: true))
    }

    func testDashboardServiceNotSetUp() throws {
        let store = Store(backend: MockBackend(), polling: false, interfaceCounters: { [] })
        store.daemonError = "cannot reach the openwarp daemon at /var/run/openwarp.sock"
        let loc = location()
        loc.enabled = false
        try compare("dashboard-not-set-up", render(dashboard(store, loc), fit: true))
    }

    // MARK: helpers

    private func assertSnapshot(_ name: String, tab: Tab, status: String, registered: Bool = true,
                                killSwitch: Bool = false) throws {
        let store = Store(backend: MockBackend(), polling: false)
        store.status = try Contract.decode(Status.self, status)
        store.settings = try Contract.decode(Settings.self, "settings-default.json")
        store.settings?.kill_switch = killSwitch
        if registered {
            store.registration = try Contract.decode(Registration.self, "registration.json")
            store.devices = try Contract.decode([Device].self, "devices.json")
            store.devicesLoaded = true
        }
        try compare(name, render(window(RootView(initialTab: tab), store: store, setup: setup(.ready))))
    }

    private func window<V: View>(_ view: V, store: Store, setup: SetupModel) -> some View {
        view.environmentObject(store).environmentObject(setup).environmentObject(location())
            .environmentObject(UpdateChecker(fetcher: UpdatesTests.ScriptedReleases(.success(nil)),
                                             defaults: UserDefaults(suiteName: "openwarp.snapshots.\(UUID())")!,
                                             currentVersion: "0.1.0", build: nil))
    }

    private func setup(_ phase: SetupPhase) -> SetupModel {
        let backend = MockBackend()
        let m = SetupModel(backend: backend, installer: SetupTests.ScriptedInstaller(result: .cancelled))
        m.phaseForTesting = phase
        return m
    }

    /// A location model whose lookups (made by the dashboard when it appears) get these answers.
    /// The default direct answer is 203.0.113.10 in the Netherlands, without WARP.
    private func location(direct: String? = nil, proxied: String? = nil) -> LocationModel {
        let trace = NetworkLocationTests.ScriptedTrace()
        Task {
            if let direct { await trace.set(nil, direct) }
            if let proxied { await trace.set("127.0.0.1:40000", proxied) }
        }
        RunLoop.main.run(until: Date().addingTimeInterval(0.05))
        return LocationModel(fetcher: trace, defaults: UserDefaults(suiteName: "openwarp.snapshots.\(UUID())")!)
    }

    /// A store that has seen two status polls 1.5 s apart, so it has real rates.
    private func connectedStore(mode: String, edit: (inout [String: Any]) -> Void = { _ in }) throws -> Store {
        let backend = MockBackend()
        var now = Date(timeIntervalSince1970: 5000)
        var rx: UInt32 = 1_000_000
        let store = Store(backend: backend, polling: false,
                          interfaceCounters: { [InterfaceCounters(name: "en0", rx: rx, tx: rx / 9)] }, clock: { now })
        func poll(_ tx: Int, _ rxBytes: Int) throws {
            var obj = try Contract.object("status-connected.json") as! [String: Any]
            obj["mode"] = mode
            obj["mode_label"] = ModeInfo.find(mode).fullName
            obj["usage"] = ["tx_bytes": tx, "rx_bytes": rxBytes, "since": "2026-01-02T03:04:05Z"]
            edit(&obj)
            store.status = try JSONDecoder().decode(Status.self, from: JSONSerialization.data(withJSONObject: obj))
            store.recordSampleForTesting()
        }
        try poll(127_000_000, 1_195_000_000)
        now.addTimeInterval(1.5); rx += 3_900_000
        try poll(127_510_000, 1_198_600_000)   // 340 KB/s up, 2.4 MB/s down
        store.settings = try Contract.decode(Settings.self, "settings-default.json")
        store.registration = try Contract.decode(Registration.self, "registration.json")
        return store
    }

    private func dashboard(_ store: Store, _ loc: LocationModel) -> some View {
        DashboardView().environmentObject(store).environmentObject(loc).environmentObject(setup(.ready))
    }

    /// Renders at the window size, or with `fit` at the view's own height once it has settled
    /// (the menu bar panel sizes itself to its content).
    private func render<V: View>(_ view: V, fit: Bool = false) -> NSBitmapImageRep {
        var size = fit ? CGSize(width: DashboardView.width, height: 1200) : Self.size
        let host = NSHostingView(rootView: fit ? AnyView(view.frame(width: size.width)) : AnyView(view.frame(width: size.width, height: size.height)))
        host.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false   // ARC owns it; close() must not release it again
        window.colorSpace = .sRGB
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        // Let SwiftUI finish layout, lookups and any (reduced, 0.12s) transitions.
        for _ in 0..<5 {
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
        }
        if fit {
            size.height = ceil(host.fittingSize.height)
            window.setContentSize(size)
            host.frame = CGRect(origin: .zero, size: size)
            for _ in 0..<2 {
                host.layoutSubtreeIfNeeded()
                RunLoop.main.run(until: Date().addingTimeInterval(0.1))
            }
        }
        let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size.width * Self.scale),
                                   pixelsHigh: Int(size.height * Self.scale), bitsPerSample: 8, samplesPerPixel: 4,
                                   hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                   bytesPerRow: 0, bitsPerPixel: 32)!
        rep.size = size
        host.cacheDisplay(in: host.bounds, to: rep)
        window.close()
        return rep.converting(to: .sRGB, renderingIntent: .default) ?? rep
    }

    private func compare(_ name: String, _ actual: NSBitmapImageRep) throws {
        let url = Self.goldens.appendingPathComponent("\(name).png")
        let png = try XCTUnwrap(actual.representation(using: .png, properties: [:]))
        if Self.recording {
            try png.write(to: url)
            save(png, "\(name).png")
            return
        }
        guard let goldenData = try? Data(contentsOf: url), let golden = NSBitmapImageRep(data: goldenData) else {
            attach(png, "\(name)-actual")
            save(png, "\(name).png")
            return XCTFail("no golden for \(name); record it with OPENWARP_RECORD_SNAPSHOTS=1")
        }
        let (differing, total) = Self.diff(golden, actual)
        let fraction = Double(differing) / Double(max(total, 1))
        if fraction > Self.maxDifferingFraction {
            attach(png, "\(name)-actual")
            attach(goldenData, "\(name)-golden")
            save(png, "\(name).png")
            XCTFail("\(name): \(differing) of \(total) pixels differ (\(String(format: "%.3f", fraction * 100))%)")
        }
    }

    /// Counts pixels whose channels differ by more than the tolerance. Both
    /// images are first drawn into the same RGBA8 sRGB layout. Different sizes
    /// count as entirely different.
    static func diff(_ a: NSBitmapImageRep, _ b: NSBitmapImageRep) -> (Int, Int) {
        let w = a.pixelsWide, h = a.pixelsHigh
        guard w == b.pixelsWide, h == b.pixelsHigh, let pa = rgba(a), let pb = rgba(b) else {
            return (max(w * h, 1), max(w * h, 1))
        }
        var differing = 0
        for i in stride(from: 0, to: pa.count, by: 4) {
            for c in 0..<4 where abs(Int(pa[i + c]) - Int(pb[i + c])) > channelTolerance {
                differing += 1
                break
            }
        }
        return (differing, w * h)
    }

    static func rgba(_ rep: NSBitmapImageRep) -> [UInt8]? {
        guard let image = rep.cgImage, let space = CGColorSpace(name: CGColorSpace.sRGB) else { return nil }
        let w = rep.pixelsWide, h = rep.pixelsHigh
        var bytes = [UInt8](repeating: 0, count: w * h * 4)
        let ok = bytes.withUnsafeMutableBytes { buf -> Bool in
            guard let ctx = CGContext(data: buf.baseAddress, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                                      space: space, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return false }
            ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
            return true
        }
        return ok ? bytes : nil
    }

    private func attach(_ png: Data, _ name: String) {
        let a = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
        a.name = name
        a.lifetime = .keepAlways
        add(a)
    }

    /// Failed snapshots are also written where CI uploads them from.
    private func save(_ png: Data, _ file: String) {
        guard let dir = ProcessInfo.processInfo.environment["OPENWARP_SNAPSHOT_ARTIFACTS"] else { return }
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try? png.write(to: URL(fileURLWithPath: dir).appendingPathComponent(file))
    }
}
