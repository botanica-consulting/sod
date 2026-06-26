import Foundation
import SSHWire

/// Tiny assertion harness shared by the test suites.
final class Harness {
    var checks = 0
    var failures = 0

    func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

    func fail(_ msg: String, line: UInt = #line) {
        failures += 1
        FileHandle.standardError.write(Data("FAIL [\(line)] \(msg)\n".utf8))
    }
    func ok(_ cond: Bool, _ label: String, line: UInt = #line) {
        checks += 1
        if !cond { fail(label, line: line) }
    }
    func eq<T: Equatable>(_ a: T, _ b: T, _ label: String, line: UInt = #line) {
        checks += 1
        if a != b { fail("\(label): \(a) != \(b)", line: line) }
    }
    func eqData(_ a: Data, _ b: Data, _ label: String, line: UInt = #line) {
        checks += 1
        if a != b { fail("\(label): \(hex(a)) != \(hex(b))", line: line) }
    }
    func throwsErr(_ label: String, line: UInt = #line, _ body: () throws -> Void) {
        checks += 1
        do {
            try body()
            fail("\(label): expected throw", line: line)
        } catch {
            // expected: throwing is the success case here
        }
    }

    /// Assert a fully-framed agent message has the expected type byte.
    func eqFramed(_ framed: Data, type: UInt8, _ label: String, line: UInt = #line) {
        checks += 1
        do {
            let (t, _) = try SSHWire.splitFramed(framed)
            if t != type { fail("\(label): type \(t) != \(type)", line: line) }
        } catch { fail("\(label): splitFramed threw \(error)", line: line) }
    }

    /// Emit a non-failing informational line (e.g. a skipped suite).
    func note(_ msg: String) { FileHandle.standardError.write(Data("note: \(msg)\n".utf8)) }

    /// A fresh unique temp directory for filesystem-touching suites.
    func tempDir() -> String {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("sod-tests-" + UUID().uuidString)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url.path
    }

    func finishAndExit() -> Never {
        if failures == 0 {
            print("ok — \(checks) checks passed")
            exit(0)
        } else {
            FileHandle.standardError.write(Data("FAILED — \(failures) of \(checks) checks failed\n".utf8))
            exit(1)
        }
    }
}
