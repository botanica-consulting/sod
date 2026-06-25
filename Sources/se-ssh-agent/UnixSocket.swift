import Foundation
#if canImport(Darwin)
import Darwin
#endif

enum AgentError: Error, CustomStringConvertible {
    case socket(String)
    var description: String { switch self { case .socket(let m): return m } }
}

func errnoString() -> String { String(cString: strerror(errno)) }

/// Minimal blocking Unix-domain stream socket server.
final class UnixSocketServer {
    let path: String
    private var fd: Int32 = -1

    init(path: String) { self.path = path }

    /// macOS `sockaddr_un.sun_path` is 104 bytes incl. NUL → 103 usable.
    static var maxPathLength: Int { MemoryLayout.size(ofValue: sockaddr_un().sun_path) }

    func bindAndListen() throws {
        let pathBytes = Array(path.utf8)
        guard pathBytes.count < Self.maxPathLength else {
            throw AgentError.socket("socket path too long: \(pathBytes.count) bytes, max \(Self.maxPathLength - 1): \(path)")
        }
        unlink(path)   // clear any stale socket

        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw AgentError.socket("socket(): \(errnoString())") }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutablePointer(to: &addr.sun_path) {
            $0.withMemoryRebound(to: CChar.self, capacity: Self.maxPathLength) { dst in
                for (i, b) in pathBytes.enumerated() { dst[i] = CChar(bitPattern: b) }
                dst[pathBytes.count] = 0
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, len) }
        }
        guard bound == 0 else { let e = errnoString(); close(fd); throw AgentError.socket("bind(\(path)): \(e)") }
        guard chmod(path, 0o600) == 0 else { let e = errnoString(); close(fd); throw AgentError.socket("chmod: \(e)") }
        guard listen(fd, 16) == 0 else { let e = errnoString(); close(fd); throw AgentError.socket("listen(): \(e)") }
    }

    /// Accept connections forever, serving each to completion (serial — Touch ID
    /// naturally serializes, and this is single-user interactive use).
    func acceptLoop(_ serve: (Int32) -> Void) {
        while true {
            let conn = accept(fd, nil, nil)
            if conn < 0 {
                if errno == EINTR { continue }
                break
            }
            serve(conn)
            close(conn)
        }
    }
}

/// Probe whether something is accepting connections at `path` (a live agent).
func isSocketLive(_ path: String) -> Bool {
    let pathBytes = Array(path.utf8)
    guard pathBytes.count < UnixSocketServer.maxPathLength else { return false }
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    var addr = sockaddr_un()
    addr.sun_family = sa_family_t(AF_UNIX)
    addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutablePointer(to: &addr.sun_path) {
        $0.withMemoryRebound(to: CChar.self, capacity: UnixSocketServer.maxPathLength) { dst in
            for (i, b) in pathBytes.enumerated() { dst[i] = CChar(bitPattern: b) }
            dst[pathBytes.count] = 0
        }
    }
    let len = socklen_t(MemoryLayout<sockaddr_un>.size)
    let r = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, len) }
    }
    return r == 0
}

/// Read exactly `n` bytes (handling short reads); nil on EOF/error.
func readExactly(_ fd: Int32, _ n: Int) -> Data? {
    guard n > 0 else { return Data() }
    var buf = [UInt8](repeating: 0, count: n)
    var got = 0
    while got < n {
        let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress!.advanced(by: got), n - got) }
        if r <= 0 { return nil }
        got += r
    }
    return Data(buf)
}

/// Write all of `data` (handling short writes); false on error.
func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    let bytes = [UInt8](data)
    var off = 0
    while off < bytes.count {
        let w = bytes.withUnsafeBytes { write(fd, $0.baseAddress!.advanced(by: off), bytes.count - off) }
        if w <= 0 { return false }
        off += w
    }
    return true
}
