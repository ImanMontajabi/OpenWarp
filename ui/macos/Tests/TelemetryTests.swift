import XCTest

/// Throughput, totals and their formatting for the menu bar dashboard.
final class TelemetryTests: XCTestCase {
    func testByteFormatting() {
        XCTAssertEqual(ByteFormat.bytes(0), "0 B")
        XCTAssertEqual(ByteFormat.bytes(999), "999 B")
        XCTAssertEqual(ByteFormat.bytes(1000), "1.0 KB")
        XCTAssertEqual(ByteFormat.bytes(9_840), "9.8 KB")
        XCTAssertEqual(ByteFormat.bytes(340_000), "340 KB")
        XCTAssertEqual(ByteFormat.bytes(99_960), "100 KB", "no \"100.0\"")
        XCTAssertEqual(ByteFormat.bytes(999_960), "1.0 MB", "rolls over to the next unit")
        XCTAssertEqual(ByteFormat.bytes(2_400_000), "2.4 MB")
        XCTAssertEqual(ByteFormat.bytes(1_234_000_000), "1.2 GB")
        XCTAssertEqual(ByteFormat.bytes(-1), "—")
        XCTAssertEqual(ByteFormat.bytes(.nan), "—")
        XCTAssertEqual(ByteFormat.rate(340_000), "340 KB/s")
        XCTAssertEqual(ByteFormat.rate(2_400_000), "2.4 MB/s")
    }

    func testCounterMeterRates() {
        var m = CounterMeter()
        let t0 = Date(timeIntervalSince1970: 1000)
        XCTAssertNil(m.update(tx: 1000, rx: 5000, at: t0, epoch: "a"), "no rate from a single sample")
        let r = m.update(tx: 4000, rx: 20000, at: t0.addingTimeInterval(1.5), epoch: "a")
        XCTAssertEqual(r?.up, 2000)
        XCTAssertEqual(r?.down, 10000)
    }

    func testCounterMeterStartsOverOnResetOrNewConnection() {
        var m = CounterMeter()
        let t0 = Date(timeIntervalSince1970: 1000)
        _ = m.update(tx: 9000, rx: 9000, at: t0, epoch: "a")
        XCTAssertNil(m.update(tx: 100, rx: 100, at: t0.addingTimeInterval(1), epoch: "a"), "counters went down (daemon restart)")
        XCTAssertEqual(m.update(tx: 300, rx: 600, at: t0.addingTimeInterval(2), epoch: "a"), Rates(up: 200, down: 500))
        XCTAssertNil(m.update(tx: 400, rx: 700, at: t0.addingTimeInterval(3), epoch: "b"), "a new connection")
        XCTAssertNil(m.update(tx: 500, rx: 800, at: t0.addingTimeInterval(3.05), epoch: "b"), "samples too close together")
    }

    func testSystemMeterHandlesWrapAndInterfaceChanges() {
        var m = SystemMeter()
        let t0 = Date(timeIntervalSince1970: 1000)
        _ = m.update([InterfaceCounters(name: "en0", rx: UInt32.max - 999, tx: 10)], at: t0)
        let r = m.update([InterfaceCounters(name: "en0", rx: 1000, tx: 2010),
                          InterfaceCounters(name: "en1", rx: 7_000_000, tx: 7_000_000)], at: t0.addingTimeInterval(2))
        // en0 rx wrapped past 2^32 (UInt32.max - 999 is 2^32 - 1000): 1000 bytes before the wrap + 1000 after.
        XCTAssertEqual(r?.down, 2000.0 / 2)
        XCTAssertEqual(r?.up, 1000, "a newly appeared interface has no baseline yet")
        let r2 = m.update([InterfaceCounters(name: "en1", rx: 7_000_100, tx: 7_000_000)], at: t0.addingTimeInterval(3))
        XCTAssertEqual(r2, Rates(up: 0, down: 100), "a vanished interface is ignored")
    }

    func testSystemCountersReadRealInterfaces() {
        let counters = SystemMeter.read()
        XCTAssertFalse(counters.contains { $0.name == "lo0" }, "loopback is excluded")
        XCTAssertFalse(counters.contains { $0.name.hasPrefix("utun") }, "tunnels are excluded (counted twice otherwise)")
    }

    func testTrafficSourceFollowsModeAndState() {
        XCTAssertEqual(TrafficSource(state: .connected, mode: "warp"), .tunnel)
        XCTAssertEqual(TrafficSource(state: .connected, mode: "warp+doh"), .tunnel)
        XCTAssertEqual(TrafficSource(state: .connected, mode: "tunnel_only"), .tunnel)
        XCTAssertEqual(TrafficSource(state: .connected, mode: "proxy"), .proxy)
        XCTAssertEqual(TrafficSource(state: .connected, mode: "doh"), .system, "DNS only tunnels no traffic")
        XCTAssertEqual(TrafficSource(state: .connected, mode: "dot"), .system)
        XCTAssertEqual(TrafficSource(state: .disconnected, mode: "warp"), .system)
        XCTAssertEqual(TrafficSource(state: .paused, mode: "warp"), .system)
        XCTAssertEqual(TrafficSource(state: .connecting, mode: "warp"), .system)
    }
}
