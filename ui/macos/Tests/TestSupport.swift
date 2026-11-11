import Foundation
import XCTest

/// The JSON contract fixtures written by the Go CLI tests
/// (`go test ./cmd/openwarp -run TestCLIJSONContract -update`).
enum Contract {
    static let directory = URL(fileURLWithPath: #filePath)   // ui/macos/Tests/TestSupport.swift
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("testdata/contract")

    static func data(_ name: String) throws -> Data {
        try Data(contentsOf: directory.appendingPathComponent(name))
    }

    static func decode<T: Decodable>(_ type: T.Type, _ name: String) throws -> T {
        try JSONDecoder().decode(type, from: data(name))
    }

    static func object(_ name: String) throws -> Any {
        try JSONSerialization.jsonObject(with: data(name))
    }
}

/// A scripted backend: canned responses per command, and a log of every call.
actor MockBackend: Backend {
    private var responses: [[String]: (Data, String?)] = [:]
    private(set) var calls: [[String]] = []

    func respond(_ args: [String], json: Data) { responses[args] = (json, nil) }
    func respond(_ args: [String], fixture: String) throws { responses[args] = (try Contract.data(fixture), nil) }
    func fail(_ args: [String], _ message: String) { responses[args] = (Data(), message) }
    /// Output and a failing exit status together (e.g. `verify` prints the result and exits 1 when it failed).
    func respond(_ args: [String], json: Data, error: String) { responses[args] = (json, error) }

    func run(_ args: [String]) async -> (Data, String?) {
        calls.append(args)
        return responses[args] ?? (Data(#"{"ok":true}"#.utf8), nil)
    }

    /// Calls other than the periodic refresh reads.
    var commands: [[String]] {
        calls.filter { !Self.reads.contains($0) }
    }

    static let reads: Set<[String]> = [["status"], ["settings"], ["registration", "show"], ["registration", "devices"]]
}
