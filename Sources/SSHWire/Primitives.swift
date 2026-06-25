import Foundation

/// Errors from decoding SSH wire bytes.
public enum WireError: Error, Equatable {
    case truncated
    case malformed(String)
}

/// Pure SSH wire-format primitives and helpers. No SE / Security / CryptoKit —
/// this is the CI-able, vector-checkable core. All functions are byte-in/byte-out.
public enum SSHWire {
    /// 4-byte big-endian unsigned integer.
    public static func uint32(_ v: UInt32) -> Data {
        Data([
            UInt8(truncatingIfNeeded: v >> 24),
            UInt8(truncatingIfNeeded: v >> 16),
            UInt8(truncatingIfNeeded: v >> 8),
            UInt8(truncatingIfNeeded: v),
        ])
    }

    /// SSH `string` (RFC 4251 §5): uint32 length prefix followed by the raw bytes.
    public static func string(_ bytes: Data) -> Data {
        uint32(UInt32(bytes.count)) + bytes
    }

    /// SSH `string` from UTF-8 text.
    public static func string(_ s: String) -> Data {
        string(Data(s.utf8))
    }

    /// SSH `mpint` (RFC 4251 §5): minimal big-endian two's-complement, length-prefixed.
    /// A leading `0x00` is prepended iff the top bit of the first byte is set, so a
    /// positive value never reads as negative. Zero encodes as an empty string.
    ///
    /// Input is the raw big-endian magnitude (e.g. a 32-byte ECDSA `r` or `s`).
    /// NOTE: we must strip leading zeros and conditionally prepend — *never* just
    /// emit a fixed-width 32-byte field (that is a malformed mpint ~half the time).
    public static func mpint(_ raw: Data) -> Data {
        var bytes = [UInt8](raw)
        while let first = bytes.first, first == 0x00 { bytes.removeFirst() }
        if bytes.isEmpty { return string(Data()) }              // zero -> empty string
        if bytes[0] & 0x80 != 0 { bytes.insert(0x00, at: 0) }    // would look negative -> pad
        return string(Data(bytes))
    }
}

/// Sequential reader over a byte buffer with bounds-checked SSH accessors.
public struct ByteReader {
    private let bytes: [UInt8]
    private var pos: Int = 0

    public init(_ data: Data) { self.bytes = [UInt8](data) }
    public init(_ bytes: [UInt8]) { self.bytes = bytes }

    public var remaining: Int { bytes.count - pos }
    public var isAtEnd: Bool { pos >= bytes.count }

    public mutating func readUInt32() throws -> UInt32 {
        guard remaining >= 4 else { throw WireError.truncated }
        let v = (UInt32(bytes[pos]) << 24)
              | (UInt32(bytes[pos + 1]) << 16)
              | (UInt32(bytes[pos + 2]) << 8)
              |  UInt32(bytes[pos + 3])
        pos += 4
        return v
    }

    public mutating func readBytes(_ n: Int) throws -> Data {
        guard n >= 0, remaining >= n else { throw WireError.truncated }
        let slice = bytes[pos ..< pos + n]
        pos += n
        return Data(slice)
    }

    /// Read an SSH `string` (uint32 length + bytes).
    public mutating func readString() throws -> Data {
        let n = Int(try readUInt32())
        return try readBytes(n)
    }
}
