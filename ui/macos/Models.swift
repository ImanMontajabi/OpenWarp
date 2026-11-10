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

enum CLI {
    static var path: String = {
        if let p = Bundle.main.path(forResource: "openwarp", ofType: nil) { return p }
        return "/usr/local/bin/openwarp"
    }()

    /// Runs `openwarp -j args…` off the main thread.
    static func run(_ args: [String]) async -> (Data, String?) {
        await withCheckedContinuation { cont in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: path)
                p.arguments = ["-j"] + args
                let out = Pipe(), err = Pipe()
                p.standardOutput = out
                p.standardError = err
                do { try p.run() } catch {
                    cont.resume(returning: (Data(), "cannot run \(path): \(error.localizedDescription)"))
                    return
                }
                let data = out.fileHandleForReading.readDataToEndOfFile()
                let e = err.fileHandleForReading.readDataToEndOfFile()
                p.waitUntilExit()
                let msg = String(data: e, encoding: .utf8)?
                    .replacingOccurrences(of: "Error: ", with: "")
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                cont.resume(returning: (data, p.terminationStatus == 0 ? nil : (msg?.isEmpty == false ? msg : "failed")))
            }
        }
    }
}

// MARK: - Store

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
    /// Values the user just chose, shown until the daemon confirms them, so
    /// controls don't snap back while the CLI round-trip is in flight.
    @Published private(set) var pending: [String: String] = [:]
    private var timer: Timer?
    private var tick = 0

    init() {
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
        let (d, err) = await CLI.run(["status"])
        if let err { daemonError = err; status = nil; return }
        daemonError = nil
        status = try? JSONDecoder().decode(Status.self, from: d)
    }

    func refreshAll() async {
        await refreshStatus()
        guard daemonError == nil else { return }
        let (s, _) = await CLI.run(["settings"])
        settings = try? JSONDecoder().decode(Settings.self, from: s)
        let (r, rerr) = await CLI.run(["registration", "show"])
        registration = rerr == nil ? try? JSONDecoder().decode(Registration.self, from: r) : nil
    }

    func loadDevices() async {
        let (d, err) = await CLI.run(["registration", "devices"])
        if let err { show(.error, err); return }
        devices = (try? JSONDecoder().decode([Device].self, from: d)) ?? []
        devicesLoaded = true
    }

    /// Runs a command, surfaces errors, then refreshes everything.
    func act(_ args: [String], success: String? = nil) {
        Task {
            busy = true
            let (_, err) = await CLI.run(args)
            busy = false
            if let err { show(.error, err) } else if let success { show(.success, success) }
            await refreshAll()
        }
    }

    /// Like `act`, but shows `value` for `key` immediately until the daemon confirms.
    func set(_ key: String, _ value: String, _ args: [String]) {
        pending[key] = value
        Task {
            let (_, err) = await CLI.run(args)
            if let err { show(.error, err) }
            await refreshAll()
            pending[key] = nil
        }
    }

    func toggle() { act([wantsOn ? "disconnect" : "connect"]) }

    func show(_ kind: Toast.Kind, _ text: String) { toast = Toast(kind: kind, text: text) }
}
