import XCTest

/// The app decodes exactly what `openwarp -j` prints. These fixtures are written
/// by the Go CLI tests, so a Go-side json change that breaks the app fails here.
final class ContractTests: XCTestCase {
    func testConnectedStatusDecodes() throws {
        let s = try Contract.decode(Status.self, "status-connected.json")
        XCTAssertEqual(s.status, "Connected")
        XCTAssertEqual(s.mode, "warp")
        XCTAssertEqual(s.mode_label, "Traffic and DNS (UDP)")
        XCTAssertEqual(s.protocol, "masque")
        XCTAssertTrue(s.registered)
        XCTAssertEqual(s.interface, "utun9")
        XCTAssertEqual(s.tunnel?.endpoint, "192.0.2.10:443")
        XCTAssertEqual(s.tunnel?.tx_bytes, 123456)
        XCTAssertEqual(s.tunnel?.rx_bytes, 654321)
        XCTAssertEqual(s.tunnel?.handshake_rtt, "42ms")
        XCTAssertEqual(s.dns?.fallback_queries, 2)
        XCTAssertEqual(s.network, "Wi-Fi")
        XCTAssertEqual(ConnState(s), .connected)
    }

    func testConnectingWithErrorIsRetrying() throws {
        let s = try Contract.decode(Status.self, "status-connecting-error.json")
        XCTAssertEqual(s.status, "Connecting")
        XCTAssertEqual(s.error, "dial 192.0.2.10:443: timeout")
        XCTAssertNil(s.tunnel)
        XCTAssertTrue(s.warp_plus)
        XCTAssertEqual(ConnState(s), .retrying)
    }

    func testUnregisteredStatusDecodesWithOptionalFieldsMissing() throws {
        let s = try Contract.decode(Status.self, "status-unregistered.json")
        XCTAssertFalse(s.registered)
        XCTAssertNil(s.account_type)
        XCTAssertNil(s.tunnel)
        XCTAssertNil(s.dns)
        XCTAssertEqual(ConnState(s), .disconnected)
    }

    func testDefaultSettingsDecode() throws {
        let s = try Contract.decode(Settings.self, "settings-default.json")
        XCTAssertEqual(s.mode, "warp")
        XCTAssertEqual(s.protocol, "masque")
        XCTAssertEqual(s.proxy_port, 40000)
        XCTAssertEqual(s.mtu, 1280)
        XCTAssertEqual(s.split_mode, "exclude")
        XCTAssertEqual(s.split_ips?.count, 27)
        XCTAssertEqual(s.fallback_domains?.first, "corp")
        XCTAssertTrue(s.post_quantum)
        XCTAssertFalse(s.always_on)
        XCTAssertNil(s.endpoint_override, "omitted when empty")
    }

    func testRegistrationDecodes() throws {
        let r = try Contract.decode(Registration.self, "registration.json")
        XCTAssertEqual(r.id, "00000000-0000-4000-8000-000000000001")
        XCTAssertEqual(r.account_type, "free")
        XCTAssertEqual(r.key_type, "curve25519")
        XCTAssertEqual(r.interface_v4, "172.16.0.2")
    }

    func testDevicesDecode() throws {
        let d = try Contract.decode([Device].self, "devices.json")
        XCTAssertEqual(d.map(\.type), ["macOS", "Android"])
        XCTAssertEqual(d.map(\.model), ["Mac16,8", "PC"])
        XCTAssertEqual(d.map(\.active), [true, false])
    }

    func testEveryAppModeIsADaemonMode() throws {
        // The Go side enumerates the seven modes; the app shows one tile per mode.
        XCTAssertEqual(ModeInfo.all.count, 7)
        XCTAssertEqual(Set(ModeInfo.all.map(\.id)), Set(FakeDaemon.modeLabels.keys))
        for m in ModeInfo.all {
            XCTAssertEqual(m.fullName, FakeDaemon.modeLabels[m.id], "label for \(m.id) differs from the daemon's")
        }
        XCTAssertEqual(ModeInfo.find("bogus").id, "warp", "unknown modes fall back to the default")
    }
}

/// The UI tests run against FakeDaemon, so it must speak the same JSON as the CLI.
final class FakeDaemonFidelityTests: XCTestCase {
    func testDefaultSettingsMatchTheCLI() async throws {
        let fake = FakeDaemon(scenario: .registered)
        let (data, err) = await fake.run(["settings"])
        XCTAssertNil(err)
        let got = try JSONSerialization.jsonObject(with: data) as? NSDictionary
        let want = try Contract.object("settings-default.json") as? NSDictionary
        XCTAssertEqual(got, want)
    }

    func testResponsesDecodeAndUseOnlyContractKeys() async throws {
        let fake = FakeDaemon(scenario: .registered)
        _ = await fake.run(["connect"])
        _ = await fake.run(["status"])                 // Connecting
        let (s, _) = await fake.run(["status"])        // Connected
        let status = try JSONDecoder().decode(Status.self, from: s)
        XCTAssertEqual(status.status, "Connected")
        let contractKeys = Set((try Contract.object("status-connected.json") as! [String: Any]).keys)
            .union(["reason", "error", "proxy"])
        let keys = Set((try JSONSerialization.jsonObject(with: s) as! [String: Any]).keys)
        XCTAssertTrue(keys.isSubset(of: contractKeys), "unknown keys: \(keys.subtracting(contractKeys))")

        let (r, _) = await fake.run(["registration", "show"])
        XCTAssertNoThrow(try JSONDecoder().decode(Registration.self, from: r))
        let (d, _) = await fake.run(["registration", "devices"])
        XCTAssertEqual(try JSONDecoder().decode([Device].self, from: d).count, 2)
    }

    func testValidatesLikeTheCLI() async {
        let fake = FakeDaemon(scenario: .registered)
        let (_, modeErr) = await fake.run(["mode", "bogus"])
        XCTAssertEqual(modeErr, "invalid mode \"bogus\"")
        let (_, portErr) = await fake.run(["proxy", "port", "0"])
        XCTAssertEqual(portErr, "usage: openwarp proxy port <1-65535>")
        let unregistered = FakeDaemon(scenario: .unregistered)
        let (_, connectErr) = await unregistered.run(["connect"])
        XCTAssertEqual(connectErr, "not registered: run `openwarp registration new`")
    }
}
