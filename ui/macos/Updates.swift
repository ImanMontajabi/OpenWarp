// Update checks: asks GitHub for the latest published OpenWarp release and tells
// the user when a newer version exists. Nothing is downloaded or installed
// automatically: OpenWarp is not signed with a Developer ID, so a new version is
// installed by hand from the release page (and the background service is then
// updated from the app, after the macOS administrator prompt).

import Foundation
import SwiftUI
import AppKit

enum AppInfo {
    static let repository = URL(string: "https://github.com/ImanMontajabi/OpenWarp")!
    static let releases = URL(string: "https://github.com/ImanMontajabi/OpenWarp/releases")!
    /// GitHub's REST endpoint for the latest published (not draft, not pre-release) release.
    static let latestReleaseAPI = URL(string: "https://api.github.com/repos/ImanMontajabi/OpenWarp/releases/latest")!

    static var version: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0.0"
    }

    /// The development build identifier ("dev.1a2b3c4") build.sh writes into Info.plist (OpenWarpBuild);
    /// nil for a release build.
    static var build: String? {
        (Bundle.main.object(forInfoDictionaryKey: "OpenWarpBuild") as? String).flatMap { $0.isEmpty ? nil : $0 }
    }

    /// "0.1.0" for a release, "0.1.0 (dev.1a2b3c4)" for a development build.
    static func displayVersion(_ version: String, build: String?) -> String {
        guard let build, !build.isEmpty else { return version }
        return "\(version) (\(build))"
    }
}

/// A dotted numeric version ("0.1.0", "v1.2"). Pre-release suffixes ("-beta.1") are ignored.
struct AppVersion: Comparable, Equatable, CustomStringConvertible {
    var parts: [Int]

    init?(_ string: String) {
        var s = string.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("v") || s.hasPrefix("V") { s.removeFirst() }
        if let dash = s.firstIndex(where: { $0 == "-" || $0 == "+" }) { s = String(s[..<dash]) }
        let nums = s.split(separator: ".", omittingEmptySubsequences: false).map { Int($0) }
        guard !nums.isEmpty, nums.count <= 4, nums.allSatisfy({ $0 != nil && $0! >= 0 }) else { return nil }
        parts = nums.map { $0! }
    }

    var description: String { parts.map(String.init).joined(separator: ".") }

    static func < (a: AppVersion, b: AppVersion) -> Bool {
        for i in 0..<max(a.parts.count, b.parts.count) {
            let x = i < a.parts.count ? a.parts[i] : 0, y = i < b.parts.count ? b.parts[i] : 0
            if x != y { return x < y }
        }
        return false
    }
    static func == (a: AppVersion, b: AppVersion) -> Bool { !(a < b) && !(b < a) }
}

/// The parts of GitHub's release JSON that matter here.
struct ReleaseInfo: Decodable, Equatable {
    var tag_name: String
    var html_url: String
    var draft: Bool?
    var prerelease: Bool?
}

protocol ReleaseFetcher: Sendable {
    /// The latest published release, or nil when the repository has none yet.
    func latest() async throws -> ReleaseInfo?
}

struct GitHubReleases: ReleaseFetcher {
    var url = AppInfo.latestReleaseAPI

    func latest() async throws -> ReleaseInfo? {
        var req = URLRequest(url: url, timeoutInterval: 15)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.setValue("OpenWarp/\(AppInfo.version)", forHTTPHeaderField: "User-Agent")
        let session = URLSession(configuration: .ephemeral)
        defer { session.finishTasksAndInvalidate() }
        let (data, response) = try await session.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 404 { return nil }   // no published release yet
        guard status == 200 else { throw URLError(.badServerResponse, userInfo: [NSLocalizedDescriptionKey: "GitHub answered \(status)"]) }
        return try JSONDecoder().decode(ReleaseInfo.self, from: data)
    }
}

enum UpdateState: Equatable {
    case idle
    case checking
    case upToDate
    case available(version: String, url: URL)
    case failed(String)
}

@MainActor
final class UpdateChecker: ObservableObject {
    @Published private(set) var state: UpdateState = .idle
    @Published private(set) var lastChecked: Date?
    /// "Check for updates automatically" (Settings). On by default.
    @Published var automatic: Bool {
        didSet {
            defaults.set(automatic, forKey: Self.automaticKey)
            if automatic { checkIfDue() }
        }
    }
    /// A newer version the user dismissed in the banner; shown again only for an even newer one.
    @Published private(set) var dismissedVersion: String?

    static let automaticKey = "checkForUpdates"
    static let lastCheckKey = "lastUpdateCheck"
    static let dismissedKey = "dismissedUpdateVersion"
    /// Automatic checks run at most this often.
    static let interval: TimeInterval = 24 * 60 * 60

    private let fetcher: ReleaseFetcher
    private let defaults: UserDefaults
    private let current: String
    private let build: String?
    private let clock: () -> Date
    private var task: Task<Void, Never>?

    init(fetcher: ReleaseFetcher = GitHubReleases(), defaults: UserDefaults = .standard,
         currentVersion: String = AppInfo.version, build: String? = AppInfo.build,
         clock: @escaping () -> Date = Date.init) {
        self.fetcher = fetcher
        self.defaults = defaults
        self.current = currentVersion
        self.build = build
        self.clock = clock
        automatic = defaults.object(forKey: Self.automaticKey) as? Bool ?? true
        lastChecked = defaults.object(forKey: Self.lastCheckKey) as? Date
        dismissedVersion = defaults.string(forKey: Self.dismissedKey)
    }

    var currentVersion: String { current }
    /// The version as shown to the user, with the development build identifier when there is one. Update
    /// checks compare only `currentVersion`.
    var displayVersion: String { AppInfo.displayVersion(current, build: build) }

    /// The banner shows an available version unless the user dismissed exactly that one.
    var bannerVersion: (version: String, url: URL)? {
        guard case .available(let v, let url) = state, v != dismissedVersion else { return nil }
        return (v, url)
    }

    /// The automatic check: once per launch (so this launch knows the answer), then whenever the last
    /// check is older than `interval`. Does nothing while switched off.
    @discardableResult
    func checkIfDue() -> Task<Void, Never>? {
        guard automatic, state != .checking else { return nil }
        if state != .idle, let lastChecked, clock().timeIntervalSince(lastChecked) < Self.interval { return nil }
        return check()
    }

    /// Keeps checking while the app runs (the caller's task is cancelled when the app quits).
    func runAutomaticChecks() async {
        while !Task.isCancelled {
            checkIfDue()
            try? await Task.sleep(nanoseconds: 60 * 60 * 1_000_000_000)   // look again in an hour
        }
    }

    /// Asks GitHub now (the "Check Now" button, or an automatic check).
    @discardableResult
    func check() -> Task<Void, Never> {
        task?.cancel()
        state = .checking
        let t = Task {
            do {
                let latest = try await fetcher.latest()
                guard !Task.isCancelled else { return }
                state = Self.evaluate(latest, current: current)
                lastChecked = clock()
                defaults.set(lastChecked, forKey: Self.lastCheckKey)
            } catch {
                guard !Task.isCancelled else { return }
                state = .failed((error as? URLError)?.localizedDescription ?? error.localizedDescription)
            }
        }
        task = t
        return t
    }

    func dismissBanner() {
        guard case .available(let v, _) = state else { return }
        dismissedVersion = v
        defaults.set(v, forKey: Self.dismissedKey)
    }

    func openReleasePage() {
        if case .available(_, let url) = state { NSWorkspace.shared.open(url) } else { NSWorkspace.shared.open(AppInfo.releases) }
    }

    /// Compares GitHub's answer with the running version. Drafts and pre-releases never count.
    nonisolated static func evaluate(_ latest: ReleaseInfo?, current: String) -> UpdateState {
        guard let latest, latest.draft != true, latest.prerelease != true,
              let theirs = AppVersion(latest.tag_name) else { return .upToDate }
        guard let ours = AppVersion(current), ours < theirs else { return .upToDate }
        let url = URL(string: latest.html_url).flatMap { $0.host == "github.com" ? $0 : nil } ?? AppInfo.releases
        return .available(version: theirs.description, url: url)
    }
}

/// Shown above the pages when a newer release exists.
struct AppUpdateBanner: View {
    @EnvironmentObject var updates: UpdateChecker

    var body: some View {
        if let version = updates.bannerVersion?.version {
            HStack(spacing: Space.xs) {
                Image(systemName: "arrow.down.circle").foregroundStyle(Palette.success.color)
                    .accessibilityHidden(true)
                Text("OpenWarp \(version) is available.").font(Typo.caption).foregroundStyle(Palette.text)
                    .accessibilityIdentifier("update.banner.text")
                Spacer(minLength: Space.xs)
                Button("Download") { updates.openReleasePage() }
                    .buttonStyle(.flat(.secondary))
                    .accessibilityIdentifier("update.banner.download")
                Button { updates.dismissBanner() } label: {
                    Image(systemName: "xmark").font(.system(size: 9, weight: .bold)).frame(width: 18, height: 18)
                }
                .buttonStyle(.flat(.quiet))
                .accessibilityLabel("Dismiss")
                .accessibilityIdentifier("update.banner.dismiss")
            }
            .padding(.horizontal, Space.md).padding(.vertical, Space.xs)
            .background(Palette.success.color.opacity(0.08))
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier("update.banner")
        }
    }
}
