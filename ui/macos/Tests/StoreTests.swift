import XCTest

/// Store: how the app turns daemon responses into state and user actions into
/// CLI commands. Runs against a scripted backend; no daemon or network.
@MainActor
final class StoreTests: XCTestCase {
    private var backend: MockBackend!
    private var store: Store!

    override func setUp() async throws {
        backend = MockBackend()
        try await backend.respond(["status"], fixture: "status-unregistered.json")
        try await backend.respond(["settings"], fixture: "settings-default.json")
        try await backend.respond(["registration", "show"], fixture: "registration.json")
        try await backend.respond(["registration", "devices"], fixture: "devices.json")
        store = Store(backend: backend, polling: false)
    }

    func testRefreshAllLoadsStatusSettingsAndRegistration() async throws {
        try await backend.respond(["status"], fixture: "status-connected.json")
        await store.refreshAll()
        XCTAssertEqual(store.status?.status, "Connected")
        XCTAssertEqual(store.settings?.proxy_port, 40000)
        XCTAssertEqual(store.registration?.id, "00000000-0000-4000-8000-000000000001")
        XCTAssertNil(store.daemonError)
        XCTAssertEqual(store.connState, .connected)
        XCTAssertTrue(store.connected)
        XCTAssertTrue(store.wantsOn)
        XCTAssertEqual(store.mode, "warp")
    }

    func testDaemonUnreachableClearsStatusAndSkipsOtherReads() async {
        await backend.fail(["status"], "cannot reach the openwarp daemon at /var/run/openwarp.sock")
        await store.refreshAll()
        XCTAssertEqual(store.daemonError, "cannot reach the openwarp daemon at /var/run/openwarp.sock")
        XCTAssertNil(store.status)
        XCTAssertEqual(store.connState, .unknown)
        let calls = await backend.calls
        XCTAssertEqual(calls, [["status"]], "settings and registration are not read while the daemon is down")
    }

    func testMissingRegistrationIsNil() async {
        await backend.fail(["registration", "show"], "not registered: run `openwarp registration new`")
        await store.refreshAll()
        XCTAssertNil(store.registration)
        XCTAssertFalse(store.registered)
        XCTAssertNil(store.toast, "an unregistered device is a state, not an error")
    }

    func testToggleConnectsWhenOffAndDisconnectsWhenOn() async throws {
        await store.refreshAll()
        XCTAssertFalse(store.wantsOn)
        await store.toggle().value
        try await backend.respond(["status"], fixture: "status-connected.json")
        await store.refreshAll()
        await store.toggle().value
        let commands = await backend.commands
        XCTAssertEqual(commands, [["connect"], ["disconnect"]])
    }

    func testWantsOnFollowsAlwaysOnWhileDisconnected() async throws {
        var settings = try JSONSerialization.jsonObject(with: Contract.data("settings-default.json")) as! [String: Any]
        settings["always_on"] = true
        await backend.respond(["settings"], json: try JSONSerialization.data(withJSONObject: settings))
        await store.refreshAll()
        XCTAssertEqual(store.connState, .disconnected)
        XCTAssertTrue(store.wantsOn, "the daemon will reconnect, so the cloud offers Disconnect")
    }

    func testActShowsErrorAndSuccessToasts() async {
        await backend.fail(["registration", "license", "BAD"], "Invalid license key")
        await store.act(["registration", "license", "BAD"], success: "License key updated.").value
        XCTAssertEqual(store.toast?.kind, .error)
        XCTAssertEqual(store.toast?.text, "Invalid license key")
        XCTAssertFalse(store.busy)

        await store.act(["tunnel", "rotate-keys"], success: "A new key pair was generated.").value
        XCTAssertEqual(store.toast?.kind, .success)
        XCTAssertEqual(store.toast?.text, "A new key pair was generated.")
    }

    func testSetShowsThePendingValueUntilTheDaemonConfirms() async {
        await store.refreshAll()
        XCTAssertEqual(store.mode, "warp")
        let task = store.set("mode", "proxy", ["mode", "proxy"])
        XCTAssertEqual(store.mode, "proxy", "the new mode shows immediately")
        XCTAssertEqual(store.pendingValue("mode"), "proxy")
        await task.value
        XCTAssertNil(store.pendingValue("mode"))
        // The mock daemon still reports warp, so the confirmed value wins.
        XCTAssertEqual(store.mode, "warp")
        let commands = await backend.commands
        XCTAssertEqual(commands, [["mode", "proxy"]])
    }

    func testSelectingEachModeSendsTheModeCommand() async {
        for m in ModeInfo.all { await store.set("mode", m.id, ["mode", m.id]).value }
        let commands = await backend.commands
        XCTAssertEqual(commands, ModeInfo.all.map { ["mode", $0.id] })
    }

    func testFailedSetShowsAnErrorAndRevertsToTheDaemonValue() async {
        await store.refreshAll()
        await backend.fail(["tunnel", "protocol", "set", "wireguard"], "connection refused")
        await store.set("protocol", "wireguard", ["tunnel", "protocol", "set", "wireguard"]).value
        XCTAssertEqual(store.toast?.text, "connection refused")
        XCTAssertNil(store.pendingValue("protocol"))
        XCTAssertEqual(store.settings?.protocol, "masque")
    }

    func testLoadDevices() async {
        await store.loadDevices()
        XCTAssertTrue(store.devicesLoaded)
        XCTAssertEqual(store.devices.map(\.model), ["Mac16,8", "PC"])

        let failing = Store(backend: backend, polling: false)
        await backend.fail(["registration", "devices"], "not registered: run `openwarp registration new`")
        await failing.loadDevices()
        XCTAssertFalse(failing.devicesLoaded)
        XCTAssertEqual(failing.toast?.kind, .error)
    }
}

/// UI-facing state mappings.
final class StateMappingTests: XCTestCase {
    func testCloudLookFollowsConnectionState() {
        XCTAssertEqual(CloudLook(.connected, registered: true), .connected)
        XCTAssertEqual(CloudLook(.connecting, registered: true), .connecting)
        XCTAssertEqual(CloudLook(.retrying, registered: true), .error)
        XCTAssertEqual(CloudLook(.paused, registered: true), .paused)
        XCTAssertEqual(CloudLook(.disconnected, registered: true), .idle)
        XCTAssertEqual(CloudLook(.unknown, registered: true), .idle)
        XCTAssertEqual(CloudLook(.connected, registered: false), .disabled, "no registration, no connect")
    }

    func testConnStateFromStatusStrings() throws {
        func state(_ s: String, error: String? = nil) throws -> ConnState {
            var obj = try JSONSerialization.jsonObject(with: Contract.data("status-unregistered.json")) as! [String: Any]
            obj["status"] = s
            obj["error"] = error
            return ConnState(try JSONDecoder().decode(Status.self, from: JSONSerialization.data(withJSONObject: obj)))
        }
        XCTAssertEqual(try state("Paused"), .paused)
        XCTAssertEqual(try state("Connecting"), .connecting)
        XCTAssertEqual(try state("Connecting", error: ""), .connecting, "an empty error is not a retry")
        XCTAssertEqual(try state("Connecting", error: "timeout"), .retrying)
        XCTAssertEqual(try state("Something new"), .unknown)
        XCTAssertEqual(ConnState(nil), .unknown)
    }

    func testOnlyARealConnectionTintsTheWindow() {
        let accent = ModeInfo.find("proxy").accent
        XCTAssertNotEqual(Tint(accent: accent, engaged: true).background, Tint(accent: accent, engaged: false).background)
    }
}

/// The state the menu bar dashboard and the main window share.
extension StoreTests {
    // MARK: dashboard state

    private func status(_ file: String, edit: (inout [String: Any]) -> Void) throws -> Data {
        var obj = try JSONSerialization.jsonObject(with: Contract.data(file)) as! [String: Any]
        edit(&obj)
        return try JSONSerialization.data(withJSONObject: obj)
    }

    func testTunnelRateComesFromUsageAndStartsOverForANewConnection() async throws {
        var now = Date(timeIntervalSince1970: 5000)
        let store = Store(backend: backend, polling: false, interfaceCounters: { [] }, clock: { now })
        func poll(tx: Int, rx: Int, since: String = "2026-01-02T03:04:05Z") async throws {
            await backend.respond(["status"], json: try status("status-connected.json") {
                $0["usage"] = ["tx_bytes": tx, "rx_bytes": rx, "since": since]
            })
            await store.refreshStatus()
        }
        try await poll(tx: 1_000, rx: 10_000)
        XCTAssertNil(store.tunnelRates, "one sample is not a rate")
        now.addTimeInterval(2)
        try await poll(tx: 5_000, rx: 2_010_000)
        XCTAssertEqual(store.tunnelRates, Rates(up: 2_000, down: 1_000_000))
        now.addTimeInterval(2)
        try await poll(tx: 100, rx: 100, since: "2026-01-02T04:00:00Z")
        XCTAssertNil(store.tunnelRates, "a reconnect by the user starts a new count, never a negative rate")

        try await backend.respond(["status"], fixture: "status-unregistered.json")
        await store.refreshStatus()
        XCTAssertNil(store.tunnelRates, "no tunnel rate while disconnected")
    }

    func testSystemRateIsMeasuredEvenWhenTheDaemonIsDown() async {
        var now = Date(timeIntervalSince1970: 5000)
        var rx: UInt32 = 0
        let store = Store(backend: backend, polling: false,
                          interfaceCounters: { [InterfaceCounters(name: "en0", rx: rx, tx: 0)] }, clock: { now })
        await backend.fail(["status"], "cannot reach the openwarp daemon")
        await store.refreshStatus()
        now.addTimeInterval(1); rx = 3_000_000
        await store.refreshStatus()
        XCTAssertEqual(store.systemRates, Rates(up: 0, down: 3_000_000))
        XCTAssertNil(store.tunnelRates)
    }

    func testButtonStatesCoverEveryDaemonState() async throws {
        await backend.fail(["status"], "cannot reach the openwarp daemon")
        await store.refreshStatus()
        XCTAssertEqual(store.buttonState, .unavailable)

        try await backend.respond(["status"], fixture: "status-unregistered.json")
        await backend.fail(["registration", "show"], "not registered")
        await store.refreshAll()
        XCTAssertEqual(store.buttonState, .unregistered)
        XCTAssertFalse(store.buttonState.stops)

        let states: [(String, String?, ButtonState)] = [
            ("Disconnected", nil, .disconnected), ("Connecting", nil, .connecting), ("Connecting", "timeout", .retrying),
            ("Connected", nil, .connected), ("Paused", nil, .paused),
        ]
        for (st, err, want) in states {
            await backend.respond(["status"], json: try status("status-connected.json") { $0["status"] = st; $0["error"] = err })
            await store.refreshStatus()
            XCTAssertEqual(store.buttonState, want, st)
        }
        XCTAssertTrue(ButtonState.connected.stops && ButtonState.connecting.stops && ButtonState.retrying.stops)
    }

    func testDisconnectShowsDisconnectingUntilTheDaemonAnswers() async throws {
        try await backend.respond(["status"], fixture: "status-connected.json")
        await store.refreshAll()
        XCTAssertEqual(store.buttonState, .connected)
        let task = store.toggle()
        XCTAssertEqual(store.buttonState, .disconnecting, "immediate feedback while the CLI runs")
        XCTAssertFalse(store.buttonState.enabled, "no double clicks")
        try await backend.respond(["status"], fixture: "status-unregistered.json")
        await task.value
        XCTAssertNil(store.pendingAction)
        XCTAssertEqual(store.connState, .disconnected)
    }

    func testFailedConnectEndsTheConnectingStateWithAnError() async throws {
        await backend.respond(["status"], json: try status("status-connected.json") { $0["status"] = "Disconnected" })
        await store.refreshAll()
        XCTAssertEqual(store.buttonState, .disconnected)
        await backend.fail(["connect"], "not registered: run `openwarp registration new`")
        let task = store.toggle()
        XCTAssertEqual(store.buttonState, .connecting)
        await task.value
        XCTAssertNil(store.pendingAction)
        XCTAssertEqual(store.toast?.kind, .error)
        XCTAssertNotEqual(store.buttonState, .connecting)
    }

    /// The menu bar dashboard and the main window's cloud read one Store, so an
    /// action in either shows up in both, with no second poller.
    func testMenuBarAndMainWindowShareOneState() async throws {
        await store.refreshAll()
        let dashboardToggle = { self.store.toggle() }   // what DashboardButton calls
        try await backend.respond(["status"], fixture: "status-connected.json")
        await dashboardToggle().value
        XCTAssertEqual(store.buttonState, .connected)
        XCTAssertEqual(CloudLook(store.connState, registered: store.registered), .connected, "the cloud shows it too")
        let commands = await backend.commands
        XCTAssertEqual(commands, [["connect"]])
    }
}
