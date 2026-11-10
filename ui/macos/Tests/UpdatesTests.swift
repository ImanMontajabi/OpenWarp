import XCTest

/// Update checks: version comparison, GitHub's answer, scheduling and the user's choices.
@MainActor
final class UpdatesTests: XCTestCase {
    /// Answers `latest()` from a script and counts the requests.
    final class ScriptedReleases: ReleaseFetcher, @unchecked Sendable {
        var result: Result<ReleaseInfo?, Error>
        private(set) var requests = 0
        init(_ result: Result<ReleaseInfo?, Error>) { self.result = result }
        func latest() async throws -> ReleaseInfo? {
            requests += 1
            return try result.get()
        }
    }

    static func release(_ tag: String, draft: Bool = false, prerelease: Bool = false) -> ReleaseInfo {
        ReleaseInfo(tag_name: tag, html_url: "https://github.com/ImanMontajabi/OpenWarp/releases/tag/\(tag)",
                    draft: draft, prerelease: prerelease)
    }

    private func defaults() -> UserDefaults { UserDefaults(suiteName: "openwarp.updates.\(UUID())")! }

    func testVersionParsingAndOrdering() {
        XCTAssertEqual(AppVersion("v0.1.0")?.parts, [0, 1, 0])
        XCTAssertEqual(AppVersion("1.2")?.parts, [1, 2])
        XCTAssertEqual(AppVersion("0.2.0-beta.1")?.parts, [0, 2, 0], "pre-release suffixes are ignored")
        XCTAssertNil(AppVersion("latest"))
        XCTAssertNil(AppVersion("1..2"))
        XCTAssertNil(AppVersion(""))
        XCTAssertLessThan(AppVersion("0.1.0")!, AppVersion("0.1.1")!)
        XCTAssertLessThan(AppVersion("0.9.9")!, AppVersion("0.10.0")!, "numeric, not lexical")
        XCTAssertEqual(AppVersion("1.0")!, AppVersion("1.0.0")!)
        XCTAssertFalse(AppVersion("1.0.0")! < AppVersion("1.0")!)
    }

    func testEvaluateGitHubAnswers() {
        XCTAssertEqual(UpdateChecker.evaluate(nil, current: "0.1.0"), .upToDate, "no release published yet")
        XCTAssertEqual(UpdateChecker.evaluate(Self.release("v0.1.0"), current: "0.1.0"), .upToDate)
        XCTAssertEqual(UpdateChecker.evaluate(Self.release("v0.0.9"), current: "0.1.0"), .upToDate, "older is not an update")
        XCTAssertEqual(UpdateChecker.evaluate(Self.release("v0.2.0"), current: "0.1.0"),
                       .available(version: "0.2.0", url: URL(string: "https://github.com/ImanMontajabi/OpenWarp/releases/tag/v0.2.0")!))
        XCTAssertEqual(UpdateChecker.evaluate(Self.release("v0.2.0", draft: true), current: "0.1.0"), .upToDate)
        XCTAssertEqual(UpdateChecker.evaluate(Self.release("v0.2.0", prerelease: true), current: "0.1.0"), .upToDate)
        XCTAssertEqual(UpdateChecker.evaluate(Self.release("nightly"), current: "0.1.0"), .upToDate, "unparseable tags are ignored")
        // The link only ever opens github.com.
        let odd = ReleaseInfo(tag_name: "v0.2.0", html_url: "https://example.com/evil", draft: false, prerelease: false)
        XCTAssertEqual(UpdateChecker.evaluate(odd, current: "0.1.0"), .available(version: "0.2.0", url: AppInfo.releases))
    }

    func testCheckReportsAnAvailableVersionAndRemembersWhen() async {
        let d = defaults()
        let now = Date(timeIntervalSince1970: 2_000_000)
        let c = UpdateChecker(fetcher: ScriptedReleases(.success(Self.release("v0.3.0"))), defaults: d,
                              currentVersion: "0.1.0", clock: { now })
        await c.check().value
        XCTAssertEqual(c.bannerVersion?.version, "0.3.0")
        XCTAssertEqual(c.lastChecked, now)
        XCTAssertEqual(d.object(forKey: UpdateChecker.lastCheckKey) as? Date, now)
    }

    func testFailureIsReportedAndNotRecordedAsACheck() async {
        let d = defaults()
        let c = UpdateChecker(fetcher: ScriptedReleases(.failure(URLError(.notConnectedToInternet))), defaults: d,
                              currentVersion: "0.1.0")
        await c.check().value
        guard case .failed = c.state else { return XCTFail("state is \(c.state)") }
        XCTAssertNil(c.lastChecked)
        XCTAssertNil(c.bannerVersion)
    }

    func testAutomaticChecksOncePerLaunchThenDaily() async {
        var now = Date(timeIntervalSince1970: 2_000_000)
        let d = defaults()
        d.set(now.addingTimeInterval(-60), forKey: UpdateChecker.lastCheckKey)   // an earlier launch checked a minute ago
        let gh = ScriptedReleases(.success(Self.release("v0.1.0")))
        let c = UpdateChecker(fetcher: gh, defaults: d, currentVersion: "0.1.0", clock: { now })
        await c.checkIfDue()?.value
        XCTAssertEqual(gh.requests, 1, "a new launch checks once")
        XCTAssertNil(c.checkIfDue(), "not again within a day")
        now.addTimeInterval(UpdateChecker.interval + 1)
        await c.checkIfDue()?.value
        XCTAssertEqual(gh.requests, 2, "again after a day")
    }

    func testTurningAutomaticChecksOffStopsThemAndPersists() async {
        let d = defaults()
        let gh = ScriptedReleases(.success(Self.release("v0.2.0")))
        let c = UpdateChecker(fetcher: gh, defaults: d, currentVersion: "0.1.0")
        XCTAssertTrue(c.automatic, "on by default")
        c.automatic = false
        XCTAssertNil(c.checkIfDue())
        XCTAssertEqual(gh.requests, 0, "no request while switched off")
        XCTAssertEqual(d.object(forKey: UpdateChecker.automaticKey) as? Bool, false)
        let again = UpdateChecker(fetcher: gh, defaults: d, currentVersion: "0.1.0")
        XCTAssertFalse(again.automatic, "the choice survives a relaunch")
        // A manual check still works while automatic checks are off.
        await again.check().value
        XCTAssertEqual(gh.requests, 1)
    }

    func testDismissedVersionStaysHiddenUntilANewerOne() async {
        let d = defaults()
        let gh = ScriptedReleases(.success(Self.release("v0.2.0")))
        let c = UpdateChecker(fetcher: gh, defaults: d, currentVersion: "0.1.0")
        await c.check().value
        c.dismissBanner()
        XCTAssertNil(c.bannerVersion)
        let relaunched = UpdateChecker(fetcher: gh, defaults: d, currentVersion: "0.1.0")
        await relaunched.check().value
        XCTAssertNil(relaunched.bannerVersion, "dismissed across launches")
        gh.result = .success(Self.release("v0.3.0"))
        await relaunched.check().value
        XCTAssertEqual(relaunched.bannerVersion?.version, "0.3.0", "a newer version shows again")
    }
}
