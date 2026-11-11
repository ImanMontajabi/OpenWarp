// Backend bridge: models decoded from the daemon's JSON (via `openwarp -j`),
// the CLI runner, and the observable Store the views read from.
// The structs mirror the Go json tags; keep them in sync with the daemon.

import SwiftUI
import AppKit

// MARK: - Models (match the daemon's JSON)

struct TunnelStats: Decodable {
    var `protocol`: String
    var endpoint: String
    var tx_bytes: UInt64
    var rx_bytes: UInt64
    var handshake_rtt: String?
    var tls: String?
}

struct DNSStats: Decodable { var queries: UInt64; var fallback_queries: UInt64; var failures: UInt64 }

/// Traffic of the current connection, summed over reconnects (engine.go Usage).
struct Usage: Decodable, Equatable {
    var tx_bytes: UInt64
    var rx_bytes: UInt64
    var since: String
}

/// One verification step (protection.go Check). status: "pass", "fail" or "skip".
struct Check: Decodable, Equatable {
    var name: String
    var status: String
    var detail: String?
}

/// The last verification of the current connection. result: "verified", "failed" or "incomplete".
struct Verification: Decodable, Equatable {
    var result: String
    var at: String
    var checks: [Check]
}

/// Leak protection as the daemon reports it (protection.go Protection).
struct Protection: Decodable, Equatable {
    /// unprotected, connecting, blocking, unverified, verified, failed
    var state: String
    /// off, standby, protecting, blocking, unavailable, error
    var kill_switch: String
    var kill_switch_detail: String?
    var ipv6: String?
    var dns: String?
    var verification: Verification?
}

struct Status: Decodable {
    var status: String
    var reason: String?
    var error: String?
    var mode: String
    var mode_label: String
    var `protocol`: String
    var registered: Bool
    var account_type: String?
    var warp_plus: Bool
    var interface: String?
    var interface_v4: String?
    var interface_v6: String?
    var proxy: String?
    var dns_protocol: String
    var tunnel: TunnelStats?
    var dns: DNSStats?
    var network: String?
    var version: String?   // absent from daemons older than 0.1.0
    var usage: Usage?
    var protection: Protection?   // absent from daemons without leak protection (0.1.0)
}

struct Settings: Decodable {
    var mode: String
    var `protocol`: String
    var always_on: Bool
    var families: String
    var proxy_port: Int
    var endpoint_override: String?
    var mtu: Int
    var split_mode: String
    var split_ips: [String]?
    var fallback_domains: [String]?
    var trusted_ssids: [String]?
    var disable_wifi: Bool
    var disable_ethernet: Bool
    var post_quantum: Bool
    var kill_switch: Bool?   // absent from daemons without leak protection (0.1.0)
}

struct Registration: Decodable {
    var id: String
    var account_type: String
    var warp_plus: Bool
    var license: String
    var public_key: String
    var key_type: String
    var interface_v4: String
    var interface_v6: String
    var premium_data: Int64
    var quota: Int64
}

struct Device: Decodable, Identifiable {
    var id: String
    var type: String
    var model: String
    var name: String
    var active: Bool
}

/// Daemon connection states (engine.go StatusDisconnected/Connecting/Connected/Paused).
enum ConnState: Equatable {
    case disconnected, connecting, connected, paused, retrying, unknown

    init(_ status: Status?) {
        switch status?.status {
        case "Connected": self = .connected
        case "Connecting": self = (status?.error?.isEmpty == false) ? .retrying : .connecting
        case "Paused": self = .paused
        case "Disconnected": self = .disconnected
        default: self = .unknown
        }
    }
}

// MARK: - CLI bridge

/// Runs `openwarp -j <args>` and returns (stdout, error message or nil).
/// The app uses `CLIBackend`; tests and UI-test launches inject a fake.
protocol Backend: Sendable {
    func run(_ args: [String]) async -> (Data, String?)
}

struct CLIBackend: Backend {
    func run(_ args: [String]) async -> (Data, String?) { await CLI.run(args) }
}

enum CLI {
    static var path: String = {
        if let p = Bundle.main.path(forResource: "openwarp", ofType: nil) { return p }
        return "/usr/local/bin/openwarp"
    }()

    /// Runs `openwarp -j args…` off the main thread.
    static func run(_ args: [String]) async -> (Data, String?) { await run(args, executable: path) }

    /// Runs `executable -j args…` off the main thread. A non-zero exit becomes an
    /// error message taken from stderr, without the CLI's "Error: " prefix.
    static func run(_ args: [String], executable: String) async -> (Data, String?) {
        await withCheckedContinuation { cont in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: executable)
                p.arguments = ["-j"] + args
                let out = Pipe(), err = Pipe()
                p.standardOutput = out
                p.standardError = err
                do { try p.run() } catch {
                    cont.resume(returning: (Data(), "cannot run \(executable): \(error.localizedDescription)"))
                    return
                }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                let e = err.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                cont.resume(returning: (data, p.terminationStatus == 0 ? nil : errorMessage(e)))
            }
        }
    }

    static func errorMessage(_ stderr: Data) -> String {
        let msg = String(data: stderr, encoding: .utf8)?
            .replacingOccurrences(of: "Error: ", with: "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return msg?.isEmpty == false ? msg! : "failed"
    }
}

// MARK: - Store

enum PendingAction: String { case connect, disconnect }

/// What a connect/disconnect control shows.
enum ButtonState: Equatable {
    case loading, unavailable, unregistered, disconnected, connecting, connected, disconnecting, retrying, paused

    /// Clicking disconnects (or stops the attempt) in these states.
    var stops: Bool { [.connecting, .connected, .retrying, .paused].contains(self) }
    var enabled: Bool { ![.loading, .disconnecting, .unregistered].contains(self) }
}

struct Toast: Equatable, Identifiable {
    enum Kind { case error, success }
    let id = UUID()
    var kind: Kind
    var text: String
}

@MainActor
final class Store: ObservableObject {
    @Published var status: Status?
    @Published var settings: Settings?
    @Published var registration: Registration?
    @Published var devices: [Device] = []
    @Published var devicesLoaded = false
    @Published var daemonError: String?
    @Published var toast: Toast?
    @Published var busy = false
    @Published private(set) var verifying = false
    /// The connect or disconnect the user just asked for, until the daemon has answered.
    @Published private(set) var pendingAction: PendingAction?
    /// Live throughput: through the tunnel (daemon counters) and over all interfaces.
    @Published private(set) var tunnelRates: Rates?
    @Published private(set) var systemRates: Rates?
    private var tunnelMeter = CounterMeter()
    private var systemMeter = SystemMeter()
    private let interfaceCounters: () -> [InterfaceCounters]
    private let clock: () -> Date
    /// Values the user just chose, shown until the daemon confirms them, so
    /// controls don't snap back while the CLI round-trip is in flight.
    @Published private(set) var pending: [String: String] = [:]
    private let backend: Backend
    private var timer: Timer?
    private var tick = 0

    /// `polling: false` (tests) skips the timer and the initial refresh.
    init(backend: Backend = CLIBackend(), polling: Bool = true,
         interfaceCounters: @escaping () -> [InterfaceCounters] = SystemMeter.read, clock: @escaping () -> Date = Date.init) {
        self.backend = backend
        self.interfaceCounters = interfaceCounters
        self.clock = clock
        guard polling else { return }
        // Status every 1.5s; settings/registration every ~6s so changes made
        // from the CLI show up too.
        timer = Timer.scheduledTimer(withTimeInterval: 1.5, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.tick += 1
                if self.tick % 4 == 0 { await self.refreshAll() } else { await self.refreshStatus() }
            }
        }
        Task { await refreshAll() }
    }

    var connState: ConnState { ConnState(status) }
    var connected: Bool { status?.status == "Connected" }
    var registered: Bool { status?.registered ?? (registration != nil) }
    var wantsOn: Bool {
        if let s = status?.status, ["Connected", "Connecting", "Paused"].contains(s) { return true }
        return settings?.always_on ?? false
    }
    var mode: String { pending["mode"] ?? status?.mode ?? settings?.mode ?? "warp" }

    func pendingValue(_ key: String) -> String? { pending[key] }

    func refreshStatus() async {
        let (d, err) = await backend.run(["status"])
        let now = clock()
        systemRates = systemMeter.update(interfaceCounters(), at: now)
        if let err { daemonError = err; status = nil; tunnelRates = nil; tunnelMeter.reset(); return }
        daemonError = nil
        status = try? JSONDecoder().decode(Status.self, from: d)
        updateTunnelRates(at: now)
    }

    /// Feeds the meters from the current `status` (snapshot tests set the status directly).
    func recordSampleForTesting() {
        let now = clock()
        systemRates = systemMeter.update(interfaceCounters(), at: now)
        updateTunnelRates(at: now)
    }

    /// The tunnel rate follows the connection's usage counters. A new connection
    /// (different `since`) or a daemon restart (counters going down) starts over.
    private func updateTunnelRates(at now: Date) {
        guard let u = status?.usage, status?.status == "Connected" else {
            tunnelRates = nil
            tunnelMeter.reset()
            return
        }
        tunnelRates = tunnelMeter.update(tx: u.tx_bytes, rx: u.rx_bytes, at: now, epoch: u.since)
    }

    func refreshAll() async {
        await refreshStatus()
        guard daemonError == nil else { return }
        let (s, _) = await backend.run(["settings"])
        settings = try? JSONDecoder().decode(Settings.self, from: s)
        let (r, rerr) = await backend.run(["registration", "show"])
        registration = rerr == nil ? try? JSONDecoder().decode(Registration.self, from: r) : nil
    }

    func loadDevices() async {
        let (d, err) = await backend.run(["registration", "devices"])
        if let err { show(.error, err); return }
        devices = (try? JSONDecoder().decode([Device].self, from: d)) ?? []
        devicesLoaded = true
    }

    /// Runs a command, surfaces errors, then refreshes everything.
    /// The returned task lets tests wait for completion; views ignore it.
    @discardableResult
    func act(_ args: [String], success: String? = nil) -> Task<Void, Never> {
        Task {
            busy = true
            let (_, err) = await backend.run(args)
            busy = false
            if let err { show(.error, err) } else if let success { show(.success, success) }
            await refreshAll()
        }
    }

    /// Like `act`, but shows `value` for `key` immediately until the daemon confirms.
    @discardableResult
    func set(_ key: String, _ value: String, _ args: [String]) -> Task<Void, Never> {
        pending[key] = value
        return Task {
            let (_, err) = await backend.run(args)
            if let err { show(.error, err) }
            await refreshAll()
            pending[key] = nil
        }
    }

    @discardableResult
    func toggle() -> Task<Void, Never> {
        let action: PendingAction = wantsOn ? .disconnect : .connect
        pendingAction = action
        let task = act([action.rawValue])
        return Task {
            await task.value
            if pendingAction == action { pendingAction = nil }
        }
    }

    /// The state both connect controls (the cloud and the menu bar button) show.
    var buttonState: ButtonState {
        if daemonError != nil { return .unavailable }
        if status == nil { return .loading }
        if !registered { return .unregistered }
        switch pendingAction {
        case .disconnect: return .disconnecting
        case .connect where connState == .disconnected || connState == .unknown: return .connecting
        default: break
        }
        switch connState {
        case .connected: return .connected
        case .connecting: return .connecting
        case .retrying: return .retrying
        case .paused: return .paused
        case .disconnected: return wantsOn ? .connecting : .disconnected
        case .unknown: return .loading
        }
    }


    /// Verifies the current connection (`openwarp verify`, plus the Cloudflare check when asked) and shows
    /// the outcome. The result itself arrives with the next status (Status.protection.verification).
    @discardableResult
    func verify(cloudflare: Bool) -> Task<Void, Never> {
        Task {
            verifying = true
            let (d, err) = await backend.run(cloudflare ? ["verify", "--cloudflare"] : ["verify"])
            verifying = false
            // A failed verification exits non-zero but still prints the result.
            if let v = try? JSONDecoder().decode(Verification.self, from: d) {
                switch v.result {
                case "verified": show(.success, "Connection verified.")
                case "failed":
                    let fail = v.checks.first { $0.status == "fail" }
                    show(.error, fail.map { "\(ProtectionText.checkTitle($0.name)): \($0.detail ?? "failed")" } ?? "Verification failed.")
                default: show(.success, "Nothing failed, but nothing proved the tunnel yet. Ask Cloudflare to confirm it.")
                }
            } else if let err {
                show(.error, err)
            }
            await refreshStatus()
        }
    }

    func show(_ kind: Toast.Kind, _ text: String) { toast = Toast(kind: kind, text: text) }
}

// MARK: - Launch

/// The app's shared models: one Store (and one daemon poller) for the main
/// window and the menu bar.
@MainActor
struct AppModels {
    var store: Store
    var setup: SetupModel
    var location: LocationModel
    var updates: UpdateChecker

    static func forLaunch() -> AppModels {
        #if DEBUG
        if let models = UITestLaunch.models() { return models }
        #endif
        return AppModels(store: Store(), setup: SetupModel(), location: LocationModel(), updates: UpdateChecker())
    }
}
