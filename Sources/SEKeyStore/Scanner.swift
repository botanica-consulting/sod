import Foundation

/// A handle file discovered in a directory scan.
public struct DiscoveredHandle {
    public let path: String
    public let handle: Data
    public let comment: String
    public init(path: String, handle: Data, comment: String) {
        self.path = path
        self.handle = handle
        self.comment = comment
    }
}

/// Stateless discovery of handle files. The agent calls this on each request and
/// holds nothing between calls.
public enum HandleScanner {
    /// Scan `directory` for handle files whose stored kind matches `kind`. Each
    /// file's comment is the 3rd field of the adjacent `.pub`, else the filename.
    public static func scan(directory: String, kind: UInt8) -> [DiscoveredHandle] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: directory) else { return [] }
        var result: [DiscoveredHandle] = []
        for name in names.sorted() {
            if name.hasSuffix(".pub") { continue }
            let path = directory + "/" + name
            guard let data = fm.contents(atPath: path),
                let decoded = HandleFile.decode(data),
                decoded.kind == kind
            else { continue }
            let comment = pubComment(path + ".pub") ?? name
            result.append(DiscoveredHandle(path: path, handle: decoded.handle, comment: comment))
        }
        return result
    }

    /// Resolve a provider — a single handle file OR a directory of handles — to
    /// the handles it yields (matching `kind`). Used for `ssh-add -s <provider>`.
    public static func resolve(provider: String, kind: UInt8) -> [DiscoveredHandle] {
        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: provider, isDirectory: &isDir) else { return [] }
        if isDir.boolValue { return scan(directory: provider, kind: kind) }
        guard let data = fm.contents(atPath: provider),
            let decoded = HandleFile.decode(data),
            decoded.kind == kind
        else { return [] }
        let comment = pubComment(provider + ".pub") ?? (provider as NSString).lastPathComponent
        return [DiscoveredHandle(path: provider, handle: decoded.handle, comment: comment)]
    }

    private static func pubComment(_ pubPath: String) -> String? {
        guard let data = FileManager.default.contents(atPath: pubPath),
            let firstLine = String(data: data, encoding: .utf8)?.split(separator: "\n").first
        else {
            return nil
        }
        let fields = firstLine.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: true)
        return fields.count >= 3 ? String(fields[2]) : nil
    }
}
