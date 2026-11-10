// First-run setup: detects whether the background service (the root
// LaunchDaemon that runs `openwarp daemon`) is installed, running and current,
// and installs or updates it with the administrator's approval.
//
// How the service is installed: the bundled `openwarp` binary runs
// `openwarp service install` as root, after macOS's own administrator prompt
// (AppleScript `do shell script … with administrator privileges`). The password
// goes to the system dialog, never to OpenWarp. `service install` copies the
// binary to /Library/PrivilegedHelperTools (root-owned), writes the LaunchDaemon
// plist and starts it, so the service keeps working after the disk image is
// ejected or the app is moved. SMAppService was not used: it needs the daemon to
// stay inside a Developer ID–signed app in /Applications, which v0.1.0 is not.

import Foundation
import SwiftUI

/// `openwarp -j service status` (cmd/openwarp/service.go ServiceStatus).
struct ServiceStatus: Decodable, Equatable {
    var installed: Bool
    var loaded: Bool
    var program: String?
    var running: Bool
    var version: String?
    var app_version: String
    var up_to_date: Bool
    var socket: String
    var error: String?
}

enum SetupNeed: Equatable {
    case notInstalled
    case notRunning            // installed, but launchd has not got it running
    case outdated(String?)     // running an older version (nil: older than version reporting)
}

enum SetupPhase: Equatable {
    case checking
    case ready
    case needed(SetupNeed)
    case installing
    case verifying
    case failed(String)

    var busy: Bool { self == .checking || self == .installing || self == .verifying }
}

enum InstallResult: Equatable {
    case installed
    case cancelled
    case failed(String)
}

protocol ServiceInstaller: Sendable {
    func install() async -> InstallResult
}

/// Runs the bundled CLI's `service install` as root after the macOS administrator prompt.
struct AdminInstaller: ServiceInstaller {
    var binary: String?

    init(binary: String? = Bundle.main.path(forResource: "openwarp", ofType: nil)) { self.binary = binary }

    /// The AppleScript. The binary path arrives as an argument and is quoted by
    /// AppleScript itself, so a path cannot inject shell syntax.
    static let script = [
        "on run argv",
        "do shell script (quoted form of (item 1 of argv)) & \" service install\" with prompt \"OpenWarp wants to install its background service.\" with administrator privileges",
        "end run",
    ]

    func install() async -> InstallResult {
        guard let binary, FileManager.default.isExecutableFile(atPath: binary) else {
            return .failed("This copy of OpenWarp has no bundled openwarp binary. Build it with ./build.sh.")
        }
        return await withCheckedContinuation { cont in
            DispatchQueue.global().async {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                p.arguments = Self.script.flatMap { ["-e", $0] } + [binary]
                let err = Pipe()
                p.standardOutput = FileHandle.nullDevice
                p.standardError = err
                do { try p.run() } catch {
                    cont.resume(returning: .failed("Cannot ask for administrator approval: \(error.localizedDescription)"))
                    return
                }
                let e = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
                p.waitUntilExit()
                cont.resume(returning: Self.result(status: p.terminationStatus, stderr: e))
            }
        }
    }

    /// Maps osascript's exit status and message to a result. -128 is "User canceled".
    static func result(status: Int32, stderr: String) -> InstallResult {
        if status == 0 { return .installed }
        if stderr.contains("(-128)") { return .cancelled }
        // "…: execution error: Error: launchctl bootstrap: … (1)" → the part after the last "Error: ".
        var msg = stderr.trimmingCharacters(in: .whitespacesAndNewlines)
        if let r = msg.range(of: "execution error: ") { msg = String(msg[r.upperBound...]) }
        if let r = msg.range(of: "Error: ", options: .backwards) { msg = String(msg[r.upperBound...]) }
        if let r = msg.range(of: #" \(-?\d+\)$"#, options: .regularExpression) { msg.removeSubrange(r) }
        return .failed(msg.isEmpty ? "Installation failed" : msg)
    }
}

@MainActor
final class SetupModel: ObservableObject {
    @Published private(set) var phase: SetupPhase = .checking

    /// Tests and snapshots set a phase directly.
    var phaseForTesting: SetupPhase {
        get { phase }
        set { phase = newValue }
    }
    @Published private(set) var service: ServiceStatus?
    /// Shown under the install button (a cancelled prompt, for example).
    @Published private(set) var note: String?

    private let backend: Backend
    private let installer: ServiceInstaller
    private let sleep: @Sendable (Double) async -> Void
    /// How long to wait for the new service to answer after installing.
    var verifyTimeout: Double = 20

    init(backend: Backend = CLIBackend(), installer: ServiceInstaller = AdminInstaller(),
         sleep: @escaping @Sendable (Double) async -> Void = { try? await Task.sleep(nanoseconds: UInt64($0 * 1e9)) }) {
        self.backend = backend
        self.installer = installer
        self.sleep = sleep
    }

    /// What the service needs, from `service status`. A daemon started by hand
    /// (proxy mode without the service) counts as ready.
    nonisolated static func phase(for s: ServiceStatus) -> SetupPhase {
        if s.running { return (s.up_to_date || !s.installed) ? .ready : .needed(.outdated(s.version)) }
        return .needed(s.installed ? .notRunning : .notInstalled)
    }

    @discardableResult
    func check() -> Task<Void, Never> {
        Task {
            if !phase.busy || phase == .checking { phase = .checking }
            let s = await readStatus()
            guard phase == .checking else { return }   // an install started meanwhile
            if let s { service = s; phase = Self.phase(for: s) } else { phase = .failed(lastError ?? "Cannot check the service") }
        }
    }

    /// Installs (or updates) the service, then verifies that launchd runs it and
    /// that it answers with this version. Never reports success without that.
    @discardableResult
    func install(onReady: @escaping @MainActor () async -> Void = {}) -> Task<Void, Never> {
        Task {
            guard !phase.busy || phase == .checking else { return }
            note = nil
            phase = .installing
            switch await installer.install() {
            case .cancelled:
                note = "Installation was cancelled. Nothing was changed."
                let s = await readStatus()
                service = s ?? service
                phase = s.map(Self.phase(for:)) ?? .needed(.notInstalled)
                return
            case .failed(let msg):
                phase = .failed(msg)
                return
            case .installed:
                phase = .verifying
            }
            var waited = 0.0
            var last: ServiceStatus?
            while waited <= verifyTimeout {
                if let s = await readStatus() {
                    last = s
                    if s.installed && s.loaded && s.running && s.up_to_date {
                        service = s
                        phase = .ready
                        await onReady()
                        return
                    }
                }
                await sleep(0.5)
                waited += 0.5
            }
            service = last ?? service
            phase = .failed(Self.verifyFailure(last))
        }
    }

    nonisolated static func verifyFailure(_ s: ServiceStatus?) -> String {
        guard let s else { return "The service could not be checked after installing." }
        if !s.installed { return "The service was not installed." }
        if !s.loaded { return "The service is installed but launchd did not load it. See /var/log/openwarp.log." }
        if !s.running { return "The service is installed but did not start. See /var/log/openwarp.log." }
        return "The service runs version \(s.version ?? "unknown"), not \(s.app_version)."
    }

    private var lastError: String?

    private func readStatus() async -> ServiceStatus? {
        let (data, err) = await backend.run(["service", "status"])
        if let err { lastError = err; return nil }
        return try? JSONDecoder().decode(ServiceStatus.self, from: data)
    }
}
