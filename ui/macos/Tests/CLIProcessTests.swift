import XCTest

/// CLI.run: the real Process-based bridge, exercised with tiny stand-in
/// executables instead of the openwarp binary.
final class CLIProcessTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent("owcli-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: dir)
    }

    private func script(_ body: String) throws -> String {
        let url = dir.appendingPathComponent("openwarp-\(UUID().uuidString)")
        try ("#!/bin/sh\n" + body + "\n").write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        return url.path
    }

    func testPassesJSONFlagAndArgumentsAndReturnsStdout() async throws {
        let exe = try script(#"printf '%s|' "$@""#)
        let (data, err) = await CLI.run(["mode", "warp+doh"], executable: exe)
        XCTAssertNil(err)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "-j|mode|warp+doh|")
    }

    func testNonZeroExitReturnsStderrWithoutPrefix() async throws {
        let exe = try script(#"echo 'Error: not registered: run `openwarp registration new`' >&2; exit 1"#)
        let (data, err) = await CLI.run(["connect"], executable: exe)
        XCTAssertEqual(err, "not registered: run `openwarp registration new`")
        XCTAssertTrue(data.isEmpty)
    }

    func testNonZeroExitWithoutMessage() async throws {
        let exe = try script("exit 3")
        let (_, err) = await CLI.run(["status"], executable: exe)
        XCTAssertEqual(err, "failed")
    }

    func testMissingExecutable() async {
        let missing = dir.appendingPathComponent("does-not-exist").path
        let (_, err) = await CLI.run(["status"], executable: missing)
        XCTAssertTrue(err?.hasPrefix("cannot run \(missing)") == true, err ?? "nil")
    }

    func testLargeOutputIsReadCompletely() async throws {
        // More than a pipe buffer (64 KiB): the reader must drain stdout before waiting for exit.
        let exe = try script("head -c 300000 /dev/zero | tr '\\0' 'a'")
        let (data, err) = await CLI.run(["status"], executable: exe)
        XCTAssertNil(err)
        XCTAssertEqual(data.count, 300000)
    }

    func testStoreSurfacesCLIErrors() async throws {
        let exe = try script(#"echo 'Error: cannot reach the openwarp daemon' >&2; exit 1"#)
        struct ScriptBackend: Backend {
            let exe: String
            func run(_ args: [String]) async -> (Data, String?) { await CLI.run(args, executable: exe) }
        }
        let store = await Store(backend: ScriptBackend(exe: exe), polling: false)
        await store.refreshAll()
        let err = await store.daemonError
        XCTAssertEqual(err, "cannot reach the openwarp daemon")
    }
}
