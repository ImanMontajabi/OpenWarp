// Public IP and approximate location for the menu bar dashboard.
//
// Source: Cloudflare's trace endpoint (https://www.cloudflare.com/cdn-cgi/trace),
// the same service OpenWarp already talks to, so no other third party learns the
// user's address. It reports the IP Cloudflare sees, a country code derived from
// it, the Cloudflare data centre that answered and whether the request arrived
// through WARP. It has no city: the dashboard shows the country and the data
// centre instead of guessing. Lookups are user-controllable (Settings), cached
// per route, and only made while the dashboard is open.

import Foundation
import SwiftUI

/// The fields of a Cloudflare trace response that the dashboard uses.
struct TraceInfo: Equatable {
    var ip: String
    var country: String?    // ISO 3166 code, e.g. "DE"; "XX"/"T1" (unknown, Tor) are dropped
    var colo: String?       // IATA code of the Cloudflare data centre, e.g. "FRA"
    var warp: String?       // "on", "plus" or "off"

    /// Parses the `key=value` lines of /cdn-cgi/trace. Nil without an IP.
    init?(trace: String) {
        var fields: [String: String] = [:]
        for line in trace.split(whereSeparator: \.isNewline) {
            guard let eq = line.firstIndex(of: "=") else { continue }
            fields[String(line[..<eq])] = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
        }
        guard let ip = fields["ip"], !ip.isEmpty else { return nil }
        self.ip = ip
        let loc = fields["loc"]?.uppercased()
        country = (loc?.count == 2 && loc != "XX" && loc != "T1") ? loc : nil
        colo = fields["colo"].flatMap { $0.isEmpty ? nil : $0.uppercased() }
        warp = fields["warp"]
    }

    init(ip: String, country: String?, colo: String?, warp: String?) {
        self.ip = ip; self.country = country; self.colo = colo; self.warp = warp
    }

    /// "Germany" (in the user's language), or the code when it has no name.
    var countryName: String? {
        guard let country else { return nil }
        return Locale.current.localizedString(forRegionCode: country) ?? country
    }

    var throughWARP: Bool { warp == "on" || warp == "plus" }
}

// MARK: - Fetching

protocol TraceFetcher: Sendable {
    /// Fetches the trace directly, or through the SOCKS5 proxy at `socks` ("127.0.0.1:40000").
    func trace(socks: String?) async throws -> String
}

struct CloudflareTrace: TraceFetcher {
    static let url = URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!

    func trace(socks: String?) async throws -> String {
        // Ephemeral: no cookies, no cache, nothing written to disk.
        let config = URLSessionConfiguration.ephemeral
        config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        config.urlCache = nil
        config.httpCookieStorage = nil
        config.timeoutIntervalForRequest = 8
        config.timeoutIntervalForResource = 10
        if let socks, let colon = socks.lastIndex(of: ":"), let port = Int(socks[socks.index(after: colon)...]) {
            config.connectionProxyDictionary = [
                kCFNetworkProxiesSOCKSEnable as String: 1,
                kCFNetworkProxiesSOCKSProxy as String: String(socks[..<colon]),
                kCFNetworkProxiesSOCKSPort as String: port,
            ]
        }
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }
        var request = URLRequest(url: Self.url)
        request.setValue("OpenWarp", forHTTPHeaderField: "User-Agent")
        let (data, response) = try await session.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.badServerResponse) }
        return String(decoding: data, as: UTF8.self)
    }
}

// MARK: - Model

/// Which path a lookup measures. Requests from the app follow the system's
/// routes, so they go through the tunnel exactly when the user's traffic does.
struct LocationRoute: Hashable {
    enum Path: Hashable {
        case system          // the app's own connection: tunnelled in warp modes, direct otherwise
        case proxy(String)   // through the local SOCKS5 proxy at this address
    }
    var path: Path
    /// Changes whenever the effective route may have changed (state, mode, network).
    var context: String
}

enum LookupState: Equatable {
    case idle
    case loading
    case done(TraceInfo)
    case failed(String)
}

@MainActor
final class LocationModel: ObservableObject {
    static let enabledKey = "lookupPublicIP"
    /// How long a result stays valid for an unchanged route.
    static let ttl: TimeInterval = 300

    @Published var system: LookupState = .idle
    @Published var proxy: LookupState?
    @Published var enabled: Bool {
        didSet {
            defaults.set(enabled, forKey: Self.enabledKey)
            if !enabled { cancel(); system = .idle; proxy = nil; cache = [:] }
        }
    }

    private let fetcher: TraceFetcher
    private let defaults: UserDefaults
    private let now: () -> Date
    private var cache: [LocationRoute: (TraceInfo, Date)] = [:]
    private var tasks: [LocationRoute.Path: Task<Void, Never>] = [:]
    private var current: [LocationRoute.Path: LocationRoute] = [:]
    /// Number of network requests made (tests check that caching works).
    private(set) var requests = 0

    init(fetcher: TraceFetcher = CloudflareTrace(), defaults: UserDefaults = .standard, now: @escaping () -> Date = Date.init) {
        self.fetcher = fetcher
        self.defaults = defaults
        self.now = now
        enabled = defaults.object(forKey: Self.enabledKey) as? Bool ?? true
    }

    /// The routes to look up for a status: the system path, plus the proxy
    /// when proxy mode is connected. Nil while connecting, when the route is
    /// about to change anyway.
    nonisolated static func routes(for status: Status?, network: String?) -> [LocationRoute]? {
        let state = ConnState(status)
        guard state != .connecting, state != .retrying else { return nil }
        let mode = status?.mode ?? "-"
        let context = "\(state == .connected ? "on" : "off")|\(state == .connected ? mode : "-")|\(network ?? "-")"
        var routes = [LocationRoute(path: .system, context: context)]
        if state == .connected, let p = status?.proxy { routes.append(LocationRoute(path: .proxy(p), context: context)) }
        return routes
    }

    /// Looks up each route unless a fresh cached result exists. `force` skips the cache.
    func refresh(status: Status?, network: String?, force: Bool = false) {
        guard enabled else { return }
        guard let routes = Self.routes(for: status, network: network) else { return }
        if !routes.contains(where: { if case .proxy = $0.path { return true } else { return false } }) {
            tasks.keys.filter { $0 != .system }.forEach { tasks[$0]?.cancel(); tasks[$0] = nil }
            proxy = nil
        }
        for route in routes {
            let changed = current[route.path] != route
            current[route.path] = route
            if !force, let (info, at) = cache[route], now().timeIntervalSince(at) < Self.ttl {
                set(route.path, .done(info))
                continue
            }
            if !changed, !force, tasks[route.path] != nil { continue }   // already in flight
            tasks[route.path]?.cancel()
            set(route.path, .loading)
            requests += 1
            let fetcher = self.fetcher
            let socks: String? = { if case .proxy(let a) = route.path { return a } else { return nil } }()
            tasks[route.path] = Task { [weak self] in
                let result: LookupState
                do {
                    let text = try await fetcher.trace(socks: socks)
                    result = TraceInfo(trace: text).map(LookupState.done) ?? .failed("Unexpected response")
                } catch is CancellationError {
                    return
                } catch {
                    result = .failed((error as? URLError)?.code == .notConnectedToInternet ? "No internet connection" : "Lookup failed")
                }
                guard !Task.isCancelled, let self, self.current[route.path] == route else { return }
                if case .done(let info) = result { self.cache[route] = (info, self.now()) }
                self.tasks[route.path] = nil
                self.set(route.path, result)
            }
        }
    }

    func cancel() {
        tasks.values.forEach { $0.cancel() }
        tasks = [:]
    }

    private func set(_ path: LocationRoute.Path, _ state: LookupState) {
        if case .proxy = path { proxy = state } else { system = state }
    }
}
