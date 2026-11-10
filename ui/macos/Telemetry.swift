// Live traffic for the menu bar dashboard: throughput through the tunnel (from
// the daemon's counters) and system-wide throughput (from the interface
// counters), plus the byte formatting both use. Nothing here measures speed by
// sending traffic; rates are what is actually flowing.

import Foundation
import Darwin

/// Bytes per second in each direction.
struct Rates: Equatable {
    var up: Double
    var down: Double
}

// MARK: - Formatting

enum ByteFormat {
    /// Decimal units (1 KB = 1000 bytes), like Finder and Activity Monitor's network tab.
    private static let units = ["B", "KB", "MB", "GB", "TB"]

    /// "0 B", "512 B", "9.8 KB", "340 KB", "2.4 MB", "1.2 GB".
    static func bytes(_ value: Double) -> String {
        guard value.isFinite, value >= 0 else { return "—" }
        var v = value, unit = 0
        while v >= 999.95, unit < units.count - 1 { v /= 1000; unit += 1 }
        if unit == 0 { return "\(Int(v.rounded())) B" }
        // Rounding 99.95 up to "100.0" would add a digit: switch to no decimals there.
        let text = v >= 99.95 ? String(format: "%.0f", v) : String(format: "%.1f", v)
        return "\(text) \(units[unit])"
    }

    /// "340 KB/s", "2.4 MB/s".
    static func rate(_ bytesPerSecond: Double) -> String { bytes(bytesPerSecond) + "/s" }
}

// MARK: - Tunnel throughput

/// Turns successive cumulative counters into rates. A counter that goes
/// backwards (the daemon restarted, or a new connection started counting from
/// zero) or a change of `epoch` starts over instead of producing a negative or
/// absurd rate; the first sample after that has no rate yet.
struct CounterMeter {
    private var last: (tx: UInt64, rx: UInt64, at: Date, epoch: String)?

    /// Feeds a sample; returns the rate since the previous one, or nil when
    /// there is none to compare with yet.
    mutating func update(tx: UInt64, rx: UInt64, at: Date, epoch: String) -> Rates? {
        defer { last = (tx, rx, at, epoch) }
        guard let last, last.epoch == epoch, tx >= last.tx, rx >= last.rx else { return nil }
        let dt = at.timeIntervalSince(last.at)
        guard dt >= 0.2 else { return nil }   // too close together to be meaningful
        return Rates(up: Double(tx - last.tx) / dt, down: Double(rx - last.rx) / dt)
    }

    mutating func reset() { last = nil }
}

// MARK: - System-wide throughput

/// One network interface's byte counters as the kernel reports them in
/// `if_data`: 32-bit, so they wrap after 4 GiB.
struct InterfaceCounters: Equatable {
    var name: String
    var rx: UInt32
    var tx: UInt32
}

/// Rates over all physical interfaces. Loopback and point-to-point interfaces
/// (utun tunnels, VPNs) are left out: tunnelled traffic also crosses the
/// physical interface, so counting both would count it twice.
struct SystemMeter {
    private var last: (byName: [String: InterfaceCounters], at: Date)?

    mutating func update(_ samples: [InterfaceCounters], at: Date) -> Rates? {
        let byName = Dictionary(samples.map { ($0.name, $0) }, uniquingKeysWith: { a, _ in a })
        defer { last = (byName, at) }
        guard let last else { return nil }
        let dt = at.timeIntervalSince(last.at)
        guard dt >= 0.2 else { return nil }
        var up: UInt64 = 0, down: UInt64 = 0
        for (name, now) in byName {
            guard let before = last.byName[name] else { continue }   // appeared: no baseline yet
            // Wrapping subtraction handles the 32-bit counter rolling over between samples.
            up += UInt64(now.tx &- before.tx)
            down += UInt64(now.rx &- before.rx)
        }
        return Rates(up: Double(up) / dt, down: Double(down) / dt)
    }

    /// Reads the counters of the interfaces that are up, excluding loopback and
    /// point-to-point ones. Needs no privileges.
    static func read() -> [InterfaceCounters] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }
        var out: [InterfaceCounters] = []
        for p in sequence(first: first, next: { $0.pointee.ifa_next }) {
            let ifa = p.pointee
            guard let addr = ifa.ifa_addr, addr.pointee.sa_family == UInt8(AF_LINK), let data = ifa.ifa_data else { continue }
            let flags = Int32(ifa.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0, flags & IFF_POINTOPOINT == 0 else { continue }
            let d = data.assumingMemoryBound(to: if_data.self).pointee
            out.append(InterfaceCounters(name: String(cString: ifa.ifa_name), rx: d.ifi_ibytes, tx: d.ifi_obytes))
        }
        return out
    }
}

// MARK: - What the dashboard shows

/// Where the traffic numbers come from, which depends on the mode and state.
enum TrafficSource: Equatable {
    /// Connected in a mode that routes traffic through WARP: the daemon's tunnel counters.
    case tunnel
    /// Connected in proxy mode: only apps using the local proxy go through WARP.
    case proxy
    /// Not tunnelling traffic (disconnected, paused, DNS-only modes): all interfaces.
    case system

    init(state: ConnState, mode: String) {
        guard state == .connected else { self = .system; return }
        switch mode {
        case "proxy": self = .proxy
        case "doh", "dot": self = .system   // DNS only: the tunnel carries no traffic
        default: self = .tunnel
        }
    }

    var caption: String {
        switch self {
        case .tunnel: "Through the WARP tunnel"
        case .proxy: "Through the local proxy"
        case .system: "All network interfaces · not through WARP"
        }
    }
}
