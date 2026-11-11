import XCTest

/// Leak protection in the app: the daemon's protection fields decode, are worded without overclaiming,
/// and "Verify" runs the right command and reports its outcome.
@MainActor
final class ProtectionTests: XCTestCase {
    func testProtectionDecodesFromTheContract() throws {
        let connected = try Contract.decode(Status.self, "status-connected.json").protection
        XCTAssertEqual(connected?.state, "verified")
        XCTAssertEqual(connected?.kill_switch, "protecting")
        XCTAssertEqual(connected?.ipv6, "blocked")
        XCTAssertEqual(connected?.dns, "tunnel")
        XCTAssertEqual(connected?.verification?.result, "verified")
        XCTAssertEqual(connected?.verification?.checks.map(\.name),
                       ["tunnel", "ipv4_route", "ipv6_route", "dns", "kill_switch", "cloudflare"])

        let retrying = try Contract.decode(Status.self, "status-connecting-error.json").protection
        XCTAssertEqual(retrying?.state, "connecting")
        XCTAssertEqual(retrying?.kill_switch, "unavailable")
        XCTAssertNotNil(retrying?.kill_switch_detail)
        XCTAssertNil(retrying?.verification)

        let idle = try Contract.decode(Status.self, "status-unregistered.json").protection
        XCTAssertEqual(idle?.state, "unprotected")
        XCTAssertNil(idle?.ipv6, "nothing is claimed about IPv6 while disconnected")

        XCTAssertEqual(try Contract.decode(Settings.self, "settings-default.json").kill_switch, false,
                       "the kill switch is off by default")
        let v = try Contract.decode(Verification.self, "verify-verified.json")
        XCTAssertEqual(v.result, "verified")
        XCTAssertTrue(v.checks.allSatisfy { $0.status == "pass" })
    }

    func testOlderDaemonWithoutProtectionStillDecodes() throws {
        var obj = try Contract.object("status-connected.json") as! [String: Any]
        obj.removeValue(forKey: "protection")
        let s = try JSONDecoder().decode(Status.self, from: JSONSerialization.data(withJSONObject: obj))
        XCTAssertNil(s.protection)
        XCTAssertEqual(ProtectionText.state(s.protection?.state).label, "—")
        var set = try Contract.object("settings-default.json") as! [String: Any]
        set.removeValue(forKey: "kill_switch")
        XCTAssertNil(try JSONDecoder().decode(Settings.self, from: JSONSerialization.data(withJSONObject: set)).kill_switch)
    }

    func testWordingNeverClaimsMoreThanWasChecked() {
        XCTAssertEqual(ProtectionText.state("verified").label, "Verified")
        for s in ["unverified", "failed", "blocking", "connecting", "unprotected", "something-new"] {
            XCTAssertFalse(ProtectionText.state(s).label.contains("Verified"), s)
        }
        XCTAssertEqual(ProtectionText.state("connecting").tone, .bad, "connecting without a kill switch can leak")
        XCTAssertEqual(ProtectionText.state("something-new").label, "something-new", "unknown values are shown as they are")
        XCTAssertEqual(ProtectionText.ipv6(nil), "—")
        XCTAssertEqual(ProtectionText.dns("system"), "System DNS, not managed")
        let err = Protection(state: "connecting", kill_switch: "error", kill_switch_detail: "pf is disabled")
        XCTAssertTrue(ProtectionText.killSwitch(err).contains("pf is disabled"))
        XCTAssertEqual(ProtectionText.killSwitch(nil), "—")
    }

    func testVerifyRunsTheCommandAndReportsTheOutcome() async throws {
        let backend = MockBackend()
        try await backend.respond(["status"], fixture: "status-connected.json")
        try await backend.respond(["verify"], fixture: "verify-verified.json")
        try await backend.respond(["verify", "--cloudflare"], fixture: "verify-verified.json")
        let store = Store(backend: backend, polling: false)

        await store.verify(cloudflare: false).value
        XCTAssertEqual(store.toast?.kind, .success)
        XCTAssertFalse(store.verifying)
        await store.verify(cloudflare: true).value
        let commands = await backend.commands
        XCTAssertEqual(commands, [["verify"], ["verify", "--cloudflare"]], "the Cloudflare check only runs when asked")

        // A failed verification exits non-zero but prints the result: the failing check is shown.
        let failed = #"{"result":"failed","at":"2026-01-02T03:04:05Z","checks":[{"name":"tunnel","status":"pass"},{"name":"dns","status":"fail","detail":"system DNS uses 192.0.2.1, not set by OpenWarp"}]}"#
        await backend.respond(["verify"], json: Data(failed.utf8), error: "verification failed")
        await store.verify(cloudflare: false).value
        XCTAssertEqual(store.toast?.kind, .error)
        XCTAssertEqual(store.toast?.text, "DNS servers: system DNS uses 192.0.2.1, not set by OpenWarp")

        await backend.fail(["verify"], "not connected")
        await store.verify(cloudflare: false).value
        XCTAssertEqual(store.toast?.text, "not connected")

        let incomplete = #"{"result":"incomplete","at":"2026-01-02T03:04:05Z","checks":[{"name":"tunnel","status":"pass"}]}"#
        await backend.respond(["verify"], json: Data(incomplete.utf8))
        await store.verify(cloudflare: false).value
        XCTAssertEqual(store.toast?.kind, .success)
        XCTAssertFalse(store.toast?.text.contains("verified") ?? true, "an incomplete check is not reported as verified")
    }

    func testFakeDaemonProtectionMatchesTheContract() async throws {
        let protectionKeys = try ["status-connected.json", "status-connecting-error.json", "status-unregistered.json"]
            .reduce(into: Set<String>()) { keys, file in
                keys.formUnion(((try Contract.object(file) as! [String: Any])["protection"] as! [String: Any]).keys)
            }
        let verifyKeys = Set((try Contract.object("verify-verified.json") as! [String: Any]).keys)
        let fake = FakeDaemon(scenario: .registered)
        _ = await fake.run(["killswitch", "on"])
        let (settings, _) = await fake.run(["settings"])
        XCTAssertEqual(try JSONDecoder().decode(Settings.self, from: settings).kill_switch, true)

        let (idle, _) = await fake.run(["status"])
        XCTAssertEqual(try JSONDecoder().decode(Status.self, from: idle).protection?.kill_switch, "standby")
        let (_, notConnected) = await fake.run(["verify"])
        XCTAssertEqual(notConnected, "not connected")

        _ = await fake.run(["connect"])
        let (connecting, _) = await fake.run(["status"])
        XCTAssertEqual(try JSONDecoder().decode(Status.self, from: connecting).protection?.state, "blocking")
        _ = await fake.run(["status"])
        let (v, err) = await fake.run(["verify"])
        XCTAssertNil(err)
        XCTAssertTrue(Set((try JSONSerialization.jsonObject(with: v) as! [String: Any]).keys).isSubset(of: verifyKeys))
        let (s, _) = await fake.run(["status"])
        let p = (try JSONSerialization.jsonObject(with: s) as! [String: Any])["protection"] as! [String: Any]
        XCTAssertTrue(Set(p.keys).isSubset(of: protectionKeys), "unknown keys: \(Set(p.keys).subtracting(protectionKeys))")
        let status = try JSONDecoder().decode(Status.self, from: s)
        XCTAssertEqual(status.protection?.state, "verified")
        XCTAssertEqual(status.protection?.kill_switch, "protecting")

        // In proxy mode the kill switch does not apply, as in the daemon.
        _ = await fake.run(["mode", "proxy"])
        _ = await fake.run(["status"])
        let (proxy, _) = await fake.run(["status"])
        XCTAssertEqual(try JSONDecoder().decode(Status.self, from: proxy).protection?.kill_switch, "unavailable")
    }
}
