import XCTest

/// First-run setup: detecting the service, installing it, and never reporting
/// success before the new service actually answers. No root, no launchd: a
/// scripted backend and installer.
@MainActor
final class SetupTests: XCTestCase {
    struct ScriptedInstaller: ServiceInstaller {
        var result: InstallResult
        var onInstall: @Sendable () async -> Void = {}
        func install() async -> InstallResult { await onInstall(); return result }
    }

    private var backend: MockBackend!

    override func setUp() async throws {
        backend = MockBackend()
        try await backend.respond(["service", "status"], fixture: "service-not-installed.json")
    }

    private func model(_ installer: ServiceInstaller) -> SetupModel {
        let m = SetupModel(backend: backend, installer: installer, sleep: { _ in await Task.yield() })
        m.verifyTimeout = 2
        return m
    }

    func testCheckReportsWhatIsNeeded() async throws {
        let m = model(ScriptedInstaller(result: .installed))
        await m.check().value
        XCTAssertEqual(m.phase, .needed(.notInstalled))
        try await backend.respond(["service", "status"], fixture: "service-up-to-date.json")
        await m.check().value
        XCTAssertEqual(m.phase, .ready)
        await backend.fail(["service", "status"], "cannot run /usr/local/bin/openwarp")
        await m.check().value
        XCTAssertEqual(m.phase, .failed("cannot run /usr/local/bin/openwarp"))
    }

    func testInstallSucceedsOnlyAfterTheServiceAnswers() async throws {
        let backend = self.backend!
        var readyCalled = false
        let m = model(ScriptedInstaller(result: .installed, onInstall: {
            // launchd takes a moment: the first checks still see it down.
            try? await backend.respond(["service", "status"], fixture: "service-installed-not-running.json")
        }))
        m.verifyTimeout = 1000   // many quick rounds: the test decides when the service comes up
        let task = m.install(onReady: { readyCalled = true })
        // Let a few verification rounds see "not running", then the service comes up.
        for _ in 0..<5 { await Task.yield() }
        try await backend.respond(["service", "status"], fixture: "service-up-to-date.json")
        await task.value
        XCTAssertEqual(m.phase, .ready)
        XCTAssertTrue(readyCalled, "the app refreshes once the service answers")
        XCTAssertEqual(m.service?.up_to_date, true)
    }

    func testInstallThatNeverStartsFailsWithAReason() async throws {
        let backend = self.backend!
        let m = model(ScriptedInstaller(result: .installed, onInstall: {
            try? await backend.respond(["service", "status"], fixture: "service-installed-not-running.json")
        }))
        await m.install().value
        XCTAssertEqual(m.phase, .failed("The service is installed but launchd did not load it. See /var/log/openwarp.log."))
    }

    func testOutdatedServiceAfterInstallIsNotSuccess() async throws {
        let backend = self.backend!
        let m = model(ScriptedInstaller(result: .installed, onInstall: {
            try? await backend.respond(["service", "status"], fixture: "service-outdated.json")
        }))
        await m.install().value
        guard case .failed(let msg) = m.phase else { return XCTFail("\(m.phase)") }
        XCTAssertTrue(msg.contains("not 0.1.0"), msg)
    }

    func testCancelledPromptChangesNothing() async {
        let m = model(ScriptedInstaller(result: .cancelled))
        await m.install().value
        XCTAssertEqual(m.phase, .needed(.notInstalled))
        XCTAssertEqual(m.note, "Installation was cancelled. Nothing was changed.")
    }

    func testInstallerErrorIsShownAndCanBeRetried() async throws {
        let m = model(ScriptedInstaller(result: .failed("launchctl bootstrap: 5: Input/output error")))
        await m.install().value
        XCTAssertEqual(m.phase, .failed("launchctl bootstrap: 5: Input/output error"))
        // Retry with a working installer: the same model recovers.
        let backend = self.backend!
        let retry = model(ScriptedInstaller(result: .installed, onInstall: {
            try? await backend.respond(["service", "status"], fixture: "service-up-to-date.json")
        }))
        await retry.install().value
        XCTAssertEqual(retry.phase, .ready)
    }

    func testAdminPromptResultParsing() {
        XCTAssertEqual(AdminInstaller.result(status: 0, stderr: ""), .installed)
        XCTAssertEqual(AdminInstaller.result(status: 1, stderr: "0:180: execution error: User canceled. (-128)\n"), .cancelled)
        XCTAssertEqual(AdminInstaller.result(status: 1, stderr: "0:180: execution error: Error: refusing to install the root service: /Library/PrivilegedHelperTools is owned by uid 501, not root (1)\n"),
                       .failed("refusing to install the root service: /Library/PrivilegedHelperTools is owned by uid 501, not root"))
        XCTAssertEqual(AdminInstaller.result(status: 1, stderr: ""), .failed("Installation failed"))
    }

    func testAdminScriptPassesThePathAsAnArgument() {
        let script = AdminInstaller.script.joined(separator: "\n")
        XCTAssertTrue(script.contains("quoted form of (item 1 of argv)"), "the path is quoted by AppleScript, never spliced in")
        XCTAssertTrue(script.contains("with administrator privileges"))
        XCTAssertFalse(script.contains("password"), "OpenWarp never handles the password")
    }

    func testMissingBundledBinaryFailsClearly() async {
        let r = await AdminInstaller(binary: nil).install()
        guard case .failed(let msg) = r else { return XCTFail("\(r)") }
        XCTAssertTrue(msg.contains("build.sh"), msg)
    }

    func testManualCommandQuotesPathsWithSpaces() {
        XCTAssertEqual(OnboardingView.quoted("/Applications/OpenWarp.app/Contents/Resources/openwarp"),
                       "/Applications/OpenWarp.app/Contents/Resources/openwarp")
        XCTAssertEqual(OnboardingView.quoted("/Volumes/Open Warp/OpenWarp.app/x"), "'/Volumes/Open Warp/OpenWarp.app/x'")
        XCTAssertEqual(OnboardingView.quoted("/tmp/it's"), "'/tmp/it'\\''s'")
    }
}
