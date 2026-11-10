import XCTest

/// Public IP / location: parsing Cloudflare's trace, which route is looked up,
/// caching, and the user's switch. No network: a scripted fetcher.
@MainActor
final class NetworkLocationTests: XCTestCase {
    actor ScriptedTrace: TraceFetcher {
        var answers: [String?: String] = [:]   // by SOCKS address (nil: direct)
        var fail = false
        private(set) var calls: [String?] = []
        func set(_ socks: String?, _ text: String) { answers[socks] = text }
        func setFail(_ f: Bool) { fail = f }
        func trace(socks: String?) async throws -> String {
            calls.append(socks)
            if fail { throw URLError(.timedOut) }
            return answers[socks] ?? "ip=203.0.113.10\nloc=NL\ncolo=AMS\nwarp=off\n"
        }
    }

    private var defaults: UserDefaults!
    private var clock = Date(timeIntervalSince1970: 1_000_000)

    override func setUp() {
        defaults = UserDefaults(suiteName: "openwarp.tests.\(UUID().uuidString)")
    }

    private func model(_ fetcher: TraceFetcher) -> LocationModel {
        LocationModel(fetcher: fetcher, defaults: defaults, now: { [unowned self] in self.clock })
    }

    private func status(_ file: String, edit: (inout [String: Any]) -> Void = { _ in }) throws -> Status {
        var obj = try Contract.object(file) as! [String: Any]
        edit(&obj)
        return try JSONDecoder().decode(Status.self, from: JSONSerialization.data(withJSONObject: obj))
    }

    private func settle(_ m: LocationModel) async {
        for _ in 0..<50 where m.system == .loading || m.proxy == .loading { await Task.yield(); try? await Task.sleep(nanoseconds: 2_000_000) }
    }

    func testParsesTheTrace() {
        let t = TraceInfo(trace: "fl=1\nh=www.cloudflare.com\nip=2001:db8::7\nts=1\ncolo=fra\nloc=DE\nwarp=plus\ngateway=off\n")
        XCTAssertEqual(t, TraceInfo(ip: "2001:db8::7", country: "DE", colo: "FRA", warp: "plus"))
        XCTAssertTrue(t!.throughWARP)
        XCTAssertNotNil(t?.countryName)
        XCTAssertNil(TraceInfo(trace: "loc=DE\nwarp=on"), "no IP, no result")
        XCTAssertNil(TraceInfo(trace: "<html>error</html>"))
        XCTAssertNil(TraceInfo(trace: "ip=192.0.2.1\nloc=XX")?.country, "unknown country is not shown")
        XCTAssertFalse(TraceInfo(trace: "ip=192.0.2.1\nwarp=off")!.throughWARP)
    }

    func testRoutesFollowTheConnection() throws {
        let off = try status("status-unregistered.json")
        XCTAssertEqual(LocationModel.routes(for: off, network: "Wi-Fi")?.map(\.path), [.system])
        let on = try status("status-connected.json")
        XCTAssertEqual(LocationModel.routes(for: on, network: "Wi-Fi")?.map(\.path), [.system])
        XCTAssertNotEqual(LocationModel.routes(for: on, network: "Wi-Fi"), LocationModel.routes(for: off, network: "Wi-Fi"),
                          "connecting changes the route, so cached results are not reused")
        let proxy = try status("status-connected.json") { $0["mode"] = "proxy"; $0["proxy"] = "127.0.0.1:40000" }
        XCTAssertEqual(LocationModel.routes(for: proxy, network: nil)?.map(\.path), [.system, .proxy("127.0.0.1:40000")],
                       "proxy mode looks up both the Mac's own route and the proxied one")
        XCTAssertNil(LocationModel.routes(for: try status("status-connecting-error.json"), network: nil),
                     "no lookup while the route is changing")
    }

    func testLooksUpOnceAndCachesPerRoute() async throws {
        let f = ScriptedTrace()
        let m = model(f)
        let off = try status("status-unregistered.json")
        m.refresh(status: off, network: "Wi-Fi")
        XCTAssertEqual(m.system, .loading)
        await settle(m)
        XCTAssertEqual(m.system, .done(TraceInfo(ip: "203.0.113.10", country: "NL", colo: "AMS", warp: "off")))
        m.refresh(status: off, network: "Wi-Fi")
        m.refresh(status: off, network: "Wi-Fi")
        await settle(m)
        XCTAssertEqual(m.requests, 1, "a fresh result is reused")

        clock.addTimeInterval(LocationModel.ttl + 1)
        m.refresh(status: off, network: "Wi-Fi")
        await settle(m)
        XCTAssertEqual(m.requests, 2, "an expired result is looked up again")
        m.refresh(status: off, network: "Wi-Fi", force: true)
        await settle(m)
        XCTAssertEqual(m.requests, 3, "the refresh button bypasses the cache")
    }

    func testProxyModeLooksUpThroughTheProxy() async throws {
        let f = ScriptedTrace()
        await f.set("127.0.0.1:40000", "ip=198.51.100.7\nloc=DE\ncolo=FRA\nwarp=on\n")
        let m = model(f)
        let proxy = try status("status-connected.json") { $0["mode"] = "proxy"; $0["proxy"] = "127.0.0.1:40000" }
        m.refresh(status: proxy, network: nil)
        await settle(m)
        XCTAssertEqual(m.system, .done(TraceInfo(ip: "203.0.113.10", country: "NL", colo: "AMS", warp: "off")))
        XCTAssertEqual(m.proxy, .done(TraceInfo(ip: "198.51.100.7", country: "DE", colo: "FRA", warp: "on")))
        let calls = await f.calls
        XCTAssertEqual(Set(calls.map { $0 ?? "direct" }), ["direct", "127.0.0.1:40000"])

        m.refresh(status: try status("status-unregistered.json"), network: nil)
        XCTAssertNil(m.proxy, "the proxy result goes away when the proxy does")
    }

    func testFailureIsShownNotInvented() async throws {
        let f = ScriptedTrace()
        await f.setFail(true)
        let m = model(f)
        m.refresh(status: try status("status-unregistered.json"), network: nil)
        await settle(m)
        XCTAssertEqual(m.system, .failed("Lookup failed"))
    }

    func testTheSwitchStopsLookupsAndIsRemembered() async throws {
        let f = ScriptedTrace()
        let m = model(f)
        XCTAssertTrue(m.enabled, "on by default; the request only goes to Cloudflare")
        m.enabled = false
        m.refresh(status: try status("status-unregistered.json"), network: nil)
        await settle(m)
        XCTAssertEqual(m.system, .idle)
        XCTAssertEqual(m.requests, 0)
        XCTAssertFalse(model(f).enabled, "the choice persists")
    }
}
