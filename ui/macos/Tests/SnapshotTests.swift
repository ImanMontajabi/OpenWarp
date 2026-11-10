import AppKit
import SwiftUI
import XCTest

/// Visual regression tests: the real window content (RootView) rendered for the
/// key screens from the contract fixtures, compared with PNG goldens in
/// __Snapshots__/. Reduce Motion is forced so continuous animations cannot make
/// frames differ, and rendering is at a fixed 2x scale in sRGB.
///
/// Font rasterisation changes between macOS releases, so goldens are only
/// compared on the macOS major version they were recorded on (RECORDED_ON);
/// elsewhere the test is skipped, visibly. Record or update goldens with
///   OPENWARP_RECORD_SNAPSHOTS=1 xcodebuild test -scheme OpenWarp -only-testing:OpenWarpTests/SnapshotTests
/// (in Xcode: set the variable in the scheme), then review the PNG diff before committing.
@MainActor
final class SnapshotTests: XCTestCase {
    static let size = CGSize(width: Metrics.windowWidth, height: Metrics.windowHeight)
    static let scale: CGFloat = 2
    /// A pixel differs when any channel moves by more than this (0–255).
    static let channelTolerance = 10
    /// The test fails when more than this fraction of pixels differ.
    static let maxDifferingFraction = 0.002

    static let goldens = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("__Snapshots__")
    static var recording: Bool { ProcessInfo.processInfo.environment["OPENWARP_RECORD_SNAPSHOTS"] == "1" }
    static var osMajor: String { "macOS \(ProcessInfo.processInfo.operatingSystemVersion.majorVersion)" }

    override func setUp() async throws {
        Motion.forceReduced = true
        if Self.recording {
            try FileManager.default.createDirectory(at: Self.goldens, withIntermediateDirectories: true)
            try Self.osMajor.write(to: Self.goldens.appendingPathComponent("RECORDED_ON"), atomically: true, encoding: .utf8)
            return
        }
        let recordedOn = (try? String(contentsOf: Self.goldens.appendingPathComponent("RECORDED_ON"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard recordedOn == Self.osMajor else {
            throw XCTSkip("goldens were recorded on \(recordedOn ?? "nothing"), this is \(Self.osMajor)")
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
        try assertSnapshot("connectivity-connected", tab: .connectivity, status: "status-connected.json")
    }

    func testSettingsDefaults() throws {
        try assertSnapshot("settings-default", tab: .settings, status: "status-unregistered.json")
    }

    func testProfile() throws {
        try assertSnapshot("profile", tab: .profile, status: "status-connected.json")
    }

    func testDaemonDown() throws {
        let store = Store(backend: MockBackend(), polling: false)
        store.daemonError = "cannot reach the openwarp daemon at /var/run/openwarp.sock"
        try compare("daemon-down", render(RootView(initialTab: .home).environmentObject(store)))
    }

    // MARK: helpers

    private func assertSnapshot(_ name: String, tab: Tab, status: String, registered: Bool = true) throws {
        let store = Store(backend: MockBackend(), polling: false)
        store.status = try Contract.decode(Status.self, status)
        store.settings = try Contract.decode(Settings.self, "settings-default.json")
        if registered {
            store.registration = try Contract.decode(Registration.self, "registration.json")
            store.devices = try Contract.decode([Device].self, "devices.json")
            store.devicesLoaded = true
        }
        try compare(name, render(RootView(initialTab: tab).environmentObject(store)))
    }

    private func render<V: View>(_ view: V) -> NSBitmapImageRep {
        let size = Self.size
        let host = NSHostingView(rootView: view.frame(width: size.width, height: size.height))
        host.frame = CGRect(origin: .zero, size: size)
        let window = NSWindow(contentRect: host.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false   // ARC owns it; close() must not release it again
        window.colorSpace = .sRGB
        window.appearance = NSAppearance(named: .darkAqua)
        window.contentView = host
        // Let SwiftUI finish layout and any (reduced, 0.12s) transitions.
        for _ in 0..<5 {
            host.layoutSubtreeIfNeeded()
            RunLoop.main.run(until: Date().addingTimeInterval(0.1))
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
            return
        }
        guard let goldenData = try? Data(contentsOf: url), let golden = NSBitmapImageRep(data: goldenData) else {
            attach(png, "\(name)-actual")
            return XCTFail("no golden for \(name); record it with OPENWARP_RECORD_SNAPSHOTS=1")
        }
        let (differing, total) = Self.diff(golden, actual)
        let fraction = Double(differing) / Double(max(total, 1))
        if fraction > Self.maxDifferingFraction {
            attach(png, "\(name)-actual")
            attach(goldenData, "\(name)-golden")
            save(png, "\(name)-actual.png")
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
