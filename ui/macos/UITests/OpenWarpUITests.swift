import XCTest

/// End-to-end UI tests. Each test launches the UITest build of OpenWarp (bundle
/// id local.openwarp.app.uitest) with OPENWARP_UITEST_SCENARIO set, so the app
/// talks to its in-process fake daemon: no real daemon, network, root or
/// Cloudflare account, and the user's own OpenWarp is never touched. Reduce
/// Motion is forced in that mode, so animations cannot make the tests flaky.
final class OpenWarpUITests: XCTestCase {
    private var app: XCUIApplication!
    private let timeout: TimeInterval = 10

    override func setUp() {
        continueAfterFailure = false
    }

    override func tearDown() {
        app?.terminate()
    }

    private func launch(_ scenario: String = "registered") {
        app = XCUIApplication()
        app.launchEnvironment["OPENWARP_UITEST_SCENARIO"] = scenario
        app.launch()
        XCTAssertTrue(app.windows.firstMatch.waitForExistence(timeout: timeout), "the main window did not appear")
    }

    private func element(_ id: String) -> XCUIElement { app.descendants(matching: .any)[id] }
    private var statusTitle: XCUIElement { app.staticTexts["home.status"] }
    private var cloud: XCUIElement { app.buttons["cloud"] }

    /// The text of a static text. On macOS SwiftUI puts it in the accessibility
    /// value; the label is only set when the view overrides it.
    private func text(_ e: XCUIElement) -> String {
        if let v = e.value as? String, !v.isEmpty { return v }
        return e.label
    }

    /// A SwiftUI Toggle is a checkbox whose value is 1 (on) or 0 (off).
    private func isOn(_ e: XCUIElement) -> Bool? {
        switch e.value {
        case let n as NSNumber: return n.boolValue
        case let s as String: return s == "1" || s == "On"
        default: return nil
        }
    }

    private func wait(_ format: String, _ args: [Any] = [], on e: XCUIElement) -> Bool {
        let done = expectation(for: NSPredicate(format: format, argumentArray: args), evaluatedWith: e)
        return XCTWaiter().wait(for: [done], timeout: timeout) == .completed
    }

    /// macOS UI tests do not scroll for you: bring an element inside the page's
    /// scroll view (clear of the bottom navigation) before clicking it.
    private func scrollIntoView(_ e: XCUIElement) {
        let scroll = app.scrollViews["page.scroll"].firstMatch
        for _ in 0..<15 where e.exists && !scroll.frame.contains(e.frame) {
            scroll.scroll(byDeltaX: 0, deltaY: e.frame.minY < scroll.frame.minY ? 120 : -120)
        }
    }

    private func waitForStatus(_ text: String, file: StaticString = #filePath, line: UInt = #line) {
        let match = NSPredicate(format: "label == %@ OR value == %@", text, text)
        let found = expectation(for: match, evaluatedWith: statusTitle)
        XCTAssertEqual(XCTWaiter().wait(for: [found], timeout: timeout), .completed,
                       "status never became \(text) (is \(self.text(statusTitle)))", file: file, line: line)
    }

    private func open(_ tab: String) {
        let button = app.buttons["tab.\(tab.lowercased())"]
        XCTAssertTrue(button.waitForExistence(timeout: timeout), "tab \(tab) missing")
        button.click()
    }

    private func assertPageTitle(_ title: String, file: StaticString = #filePath, line: UInt = #line) {
        // About has no page title, only the app name as its heading.
        let header = title == "About" ? element("about.title") : element("page.title")
        XCTAssertTrue(header.waitForExistence(timeout: timeout), "no title on \(title)", file: file, line: line)
        XCTAssertEqual(text(header), title == "About" ? "OpenWarp" : title, file: file, line: line)
    }

    // MARK: launch and Home

    func testLaunchShowsHomeWithCloudAndAllSevenModes() {
        launch()
        XCTAssertTrue(statusTitle.waitForExistence(timeout: timeout))
        waitForStatus("Disconnected")
        XCTAssertTrue(cloud.isEnabled, "a registered device can connect")
        XCTAssertEqual(cloud.label, "Connect")
        for id in ["warp", "warp+doh", "warp+dot", "doh", "dot", "tunnel_only", "proxy"] {
            XCTAssertTrue(app.buttons["mode.\(id)"].exists, "mode tile \(id) missing")
        }
        XCTAssertTrue(app.buttons["mode.warp"].isSelected, "the default mode is selected")
    }

    func testCloudConnectsAndDisconnects() {
        launch()
        waitForStatus("Disconnected")
        cloud.click()
        waitForStatus("Connected")
        XCTAssertEqual(cloud.label, "Disconnect")
        XCTAssertEqual(text(app.staticTexts["home.detail"]), "Your Internet is private.")
        cloud.click()
        waitForStatus("Disconnected")
        XCTAssertEqual(cloud.label, "Connect")
    }

    func testSelectingEachModeMarksOnlyThatMode() {
        launch()
        waitForStatus("Disconnected")
        let ids = ["warp+doh", "warp+dot", "doh", "dot", "tunnel_only", "proxy", "warp"]
        for id in ids {
            let tile = app.buttons["mode.\(id)"]
            tile.click()
            let selected = expectation(for: NSPredicate(format: "isSelected == true"), evaluatedWith: tile)
            XCTAssertEqual(XCTWaiter().wait(for: [selected], timeout: timeout), .completed, "\(id) not selected")
            for other in ids where other != id {
                XCTAssertFalse(app.buttons["mode.\(other)"].isSelected, "\(other) still selected after choosing \(id)")
            }
        }
    }

    func testProxyModeConnectedShowsTheProxyAddress() {
        launch()
        app.buttons["mode.proxy"].click()
        cloud.click()
        waitForStatus("Connected")
        XCTAssertEqual(text(app.staticTexts["home.detail"]), "Proxy listening on 127.0.0.1:40000")
    }

    func testConnectionFailureShowsReconnectingWithTheError() {
        launch("connect-fails")
        waitForStatus("Disconnected")
        cloud.click()
        waitForStatus("Reconnecting")
        XCTAssertEqual(text(app.staticTexts["home.detail"]), "dial 192.0.2.10:443: i/o timeout")
        XCTAssertEqual(cloud.label, "Disconnect", "the user can stop retrying")
    }

    func testUnregisteredDeviceCanRegister() {
        launch("unregistered")
        let register = app.buttons["Accept Terms of Service & Register"]
        XCTAssertTrue(register.waitForExistence(timeout: timeout))
        XCTAssertFalse(cloud.isEnabled, "cannot connect before registering")
        register.click()
        let gone = expectation(for: NSPredicate(format: "exists == false"), evaluatedWith: register)
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: timeout), .completed)
        let enabled = expectation(for: NSPredicate(format: "isEnabled == true"), evaluatedWith: cloud)
        XCTAssertEqual(XCTWaiter().wait(for: [enabled], timeout: timeout), .completed)
    }

    // MARK: first-run setup

    func testMissingServiceShowsOnboardingAndInstallMakesTheAppUsable() {
        launch("daemon-down")
        let install = app.buttons["onboarding.install"]
        XCTAssertTrue(install.waitForExistence(timeout: timeout), "onboarding is shown when the service is missing")
        XCTAssertTrue(element("onboarding.title").exists)
        XCTAssertFalse(cloud.exists, "Home's connect button is not offered without the service")
        install.click()
        // The fake installer "installs" the service; the app then verifies it and shows Home.
        XCTAssertTrue(cloud.waitForExistence(timeout: timeout), "Home appears once the service is verified")
        waitForStatus("Disconnected")
        cloud.click()
        waitForStatus("Connected")
    }

    func testFailedInstallShowsTheErrorAndStaysOnOnboarding() {
        launch("install-fails")
        let install = app.buttons["onboarding.install"]
        XCTAssertTrue(install.waitForExistence(timeout: timeout))
        install.click()
        let error = element("onboarding.error")
        XCTAssertTrue(error.waitForExistence(timeout: timeout), "the installer's error is shown")
        XCTAssertTrue(text(error).contains("Input/output error"), "is \(text(error))")
        XCTAssertEqual(text(install), "Try Again")
        XCTAssertFalse(cloud.exists, "no success state after a failed install")
        XCTAssertFalse(element("onboarding.ready").exists)
    }

    func testManualSetupShowsTheTerminalCommand() {
        launch("daemon-down")
        let manual = app.buttons["onboarding.manual"]
        XCTAssertTrue(manual.waitForExistence(timeout: timeout))
        manual.click()
        let command = app.staticTexts.matching(NSPredicate(format: "label CONTAINS 'service install' OR value CONTAINS 'service install'")).firstMatch
        XCTAssertTrue(command.waitForExistence(timeout: timeout), "the sudo command is shown")
        open("About")   // About stays available without the service
        assertPageTitle("About")
    }

    func testOutdatedServiceShowsTheUpdateBanner() {
        launch("outdated")
        waitForStatus("Disconnected")
        let update = app.buttons["banner.update"]
        XCTAssertTrue(update.waitForExistence(timeout: timeout), "the update banner is shown")
        update.click()
        let gone = expectation(for: NSPredicate(format: "exists == false"), evaluatedWith: element("banner.outdated"))
        XCTAssertEqual(XCTWaiter().wait(for: [gone], timeout: timeout), .completed, "the banner goes away once updated")
    }

    // MARK: menu bar dashboard

    /// Opens the menu bar panel, or skips when the status item cannot be reached
    /// (for example when the menu bar is hidden on a CI runner).
    private func openDashboard() throws -> XCUIElement {
        let item = app.statusItems.firstMatch
        guard item.waitForExistence(timeout: timeout) else { throw XCTSkip("the menu bar item is not reachable here") }
        item.click()
        let button = element("dash.connect")
        guard button.waitForExistence(timeout: timeout) else { throw XCTSkip("the menu bar panel did not open") }
        return button
    }

    func testMenuBarDashboardConnectsAndShowsLiveTraffic() throws {
        launch()
        waitForStatus("Disconnected")
        let connect = try openDashboard()
        XCTAssertEqual(text(element("dash.status")), "Disconnected")
        connect.click()
        let status = element("dash.status")
        XCTAssertTrue(wait("label == 'Connected' OR value == 'Connected'", on: status), "is \(text(status))")
        // Rates need two polls; totals come straight from the daemon's usage counters.
        let rate = element("dash.download.rate")
        XCTAssertTrue(wait("value ENDSWITH '/s' OR label ENDSWITH '/s'", on: rate), "download rate is \(text(rate))")
        let total = element("dash.download.total")
        XCTAssertTrue(wait("value CONTAINS 'B' OR label CONTAINS 'B'", on: total), "download total is \(text(total))")
        let ip = element("dash.location.system").descendants(matching: .any)["value.Public IP"]
        XCTAssertTrue(wait("value == '198.51.100.7'", on: ip), "the public IP through WARP is shown")
    }

    func testPublicIPLookupCanBeTurnedOff() throws {
        launch()
        open("Settings")
        let toggle = app.checkBoxes["toggle.lookup_public_ip"]
        XCTAssertTrue(toggle.waitForExistence(timeout: timeout))
        scrollIntoView(toggle)
        XCTAssertEqual(isOn(toggle), true, "on by default")
        toggle.click()
        XCTAssertTrue(wait("value == 0", on: toggle))
        _ = try openDashboard()
        XCTAssertTrue(element("dash.location.enable").waitForExistence(timeout: timeout), "the dashboard offers to turn it back on")
    }

    // MARK: navigation

    func testAllFiveTabsAreReachable() {
        launch()
        waitForStatus("Disconnected")
        for (tab, title) in [("Connectivity", "Connectivity"), ("Settings", "Settings"), ("Profile", "Profile"), ("About", "About")] {
            open(tab)
            assertPageTitle(title)
            XCTAssertTrue(app.buttons["tab.\(tab.lowercased())"].isSelected)
        }
        open("Home")
        XCTAssertTrue(cloud.waitForExistence(timeout: timeout))
    }

    func testKeyboardShortcutsSwitchTabs() {
        launch()
        waitForStatus("Disconnected")
        app.typeKey("3", modifierFlags: .command)
        assertPageTitle("Settings")
        app.typeKey("5", modifierFlags: .command)
        assertPageTitle("About")
        app.typeKey("1", modifierFlags: .command)
        XCTAssertTrue(cloud.waitForExistence(timeout: timeout))
    }

    func testScrolledPagesKeepTheBottomNavigationUsable() {
        launch()
        open("Settings")
        let scroll = app.scrollViews["page.scroll"].firstMatch
        XCTAssertTrue(scroll.waitForExistence(timeout: timeout))
        scroll.scroll(byDeltaX: 0, deltaY: -2000)
        let advanced = app.buttons.matching(NSPredicate(format: "label CONTAINS[c] 'Advanced'")).firstMatch
        XCTAssertTrue(advanced.waitForExistence(timeout: timeout), "the end of Settings is reachable by scrolling")
        for tab in ["home", "connectivity", "settings", "profile", "about"] {
            XCTAssertTrue(app.buttons["tab.\(tab)"].isHittable, "tab \(tab) is covered after scrolling")
        }
        open("Profile")
        assertPageTitle("Profile")
    }

    // MARK: settings

    func testTunnelProtocolSegmentSwitches() {
        launch()
        open("Settings")
        let wireguard = app.buttons["segment.wireguard"]
        XCTAssertTrue(wireguard.waitForExistence(timeout: timeout))
        XCTAssertTrue(app.buttons["segment.masque"].isSelected)
        wireguard.click()
        let selected = expectation(for: NSPredicate(format: "isSelected == true"), evaluatedWith: wireguard)
        XCTAssertEqual(XCTWaiter().wait(for: [selected], timeout: timeout), .completed)
        XCTAssertFalse(app.buttons["segment.masque"].isSelected)
    }

    func testTogglesFlipAndStayFlipped() {
        launch()
        open("Settings")
        let pq = app.checkBoxes["toggle.post_quantum"]
        XCTAssertTrue(pq.waitForExistence(timeout: timeout))
        XCTAssertEqual(isOn(pq), true)
        pq.click()
        XCTAssertTrue(wait("value == 0", on: pq), "post-quantum did not switch off")
        // Survives the next settings refresh from the daemon (about every 6 seconds).
        sleep(7)
        XCTAssertEqual(isOn(pq), false)

        let wifi = app.checkBoxes["toggle.disable_wifi"]
        XCTAssertEqual(isOn(wifi), false)
        wifi.click()
        XCTAssertTrue(wait("value == 1", on: wifi), "Wi-Fi toggle did not switch on")
    }

    func testFamiliesChoiceUpdatesTheRow() {
        launch()
        open("Settings")
        let row = app.buttons["choice.1.1.1.1 for Families"]
        XCTAssertTrue(row.waitForExistence(timeout: timeout))
        row.click()
        let malware = app.buttons["choice.option.malware"]
        XCTAssertTrue(malware.waitForExistence(timeout: timeout))
        scrollIntoView(malware)
        malware.click()
        // The row is one button whose label combines its title and current value.
        XCTAssertTrue(wait("label == %@", ["1.1.1.1 for Families, Block malware"], on: row),
                      "the row shows the new choice (is \(row.label))")
    }

    // MARK: profile

    /// Regression: reading the Profile page's accessibility tree (as VoiceOver
    /// and XCUITest do) used to crash the app with endless label recursion.
    func testProfilePageIsReadable() {
        launch()
        open("Profile")
        assertPageTitle("Profile")
        XCTAssertTrue(app.buttons["Change"].waitForExistence(timeout: timeout))
        XCTAssertTrue(app.staticTexts.matching(NSPredicate(format: "label == 'Hidden' OR value == 'Hidden'")).firstMatch.exists,
                      "the license key is hidden from assistive technology until revealed")
        XCTAssertGreaterThan(app.descendants(matching: .any).count, 10)
        // Value rows read as "title, value", not just their copy button.
        let deviceID = element("value.Device ID")
        XCTAssertTrue(deviceID.exists, "Device ID row")
        let spoken = deviceID.label + " " + (deviceID.value as? String ?? "")
        XCTAssertTrue(spoken.contains("00000000-0000-4000-8000-000000000001"), "the Device ID row exposes the ID: \(spoken)")
        XCTAssertEqual(app.state, .runningForeground, "the app is still running")
    }

    // MARK: errors

    func testInvalidLicenseShowsAnErrorToast() {
        launch()
        open("Profile")
        let change = app.buttons["Change"]
        XCTAssertTrue(change.waitForExistence(timeout: timeout))
        change.click()
        let field = app.sheets.textFields.firstMatch.exists ? app.sheets.textFields.firstMatch : app.textFields["xxxxxxxx-xxxxxxxx-xxxxxxxx"]
        XCTAssertTrue(field.waitForExistence(timeout: timeout))
        field.click()
        field.typeText("NOT-A-KEY-AT-ALL\r")
        let toast = element("toast.error")
        XCTAssertTrue(toast.waitForExistence(timeout: timeout), "no error toast")
        let message = toast.descendants(matching: .any)["toast.text"]
        XCTAssertTrue(message.exists, "the toast exposes its message")
        XCTAssertTrue(text(message).contains("Invalid license key"), "toast says \(text(message))")
    }
}
