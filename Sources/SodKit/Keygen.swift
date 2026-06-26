import ArgumentParser
import CryptoKit  // SHA256 for the fingerprint line only
import Foundation
import SEKeyStore
import SSHWire

private let tool = "sod ssh-keygen"
private func elog(_ msg: String) { FileHandle.standardError.write(Data("\(tool): \(msg)\n".utf8)) }
private func errExit(_ msg: String) -> Never { elog(msg); exit(1) }

private func shortHostname() -> String {
    var name = ProcessInfo.processInfo.hostName
    if name.hasSuffix(".local") { name = String(name.dropLast(6)) }
    return name
}

private func writeFile(_ path: String, _ data: Data, mode: Int) throws {
    let fm = FileManager.default
    let parent = (path as NSString).deletingLastPathComponent
    if !parent.isEmpty {
        try fm.createDirectory(
            atPath: parent, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
    }
    guard
        fm.createFile(
            atPath: path, contents: data,
            attributes: [.posixPermissions: NSNumber(value: mode)])
    else {
        throw KeyBackendError.create("could not write \(path)")
    }
}

private func fingerprint(_ blob: Data) -> String {
    "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
}

public struct Keygen: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "ssh-keygen",
        abstract: "Create a Secure-Enclave P-256 SSH key.",
        discussion: """
            Writes two files:
              <keyfile>       opaque Secure-Enclave handle (consumed only by sod; no usable secret)
              <keyfile>.pub   standard "ecdsa-sha2-nistp256 ..." public-key line

            The private key is generated inside the Secure Enclave and never leaves it;
            Touch ID is required for every signature. Only -t ecdsa is supported (the
            Secure Enclave is P-256 only); -b and -N are rejected.
            """
    )

    @Option(
        name: .customShort("f"), help: ArgumentHelp("Output keyfile (default ~/.ssh/id_sod).", valueName: "keyfile"))
    var file: String?

    @Option(name: .customShort("C"), help: ArgumentHelp("Comment for the public-key line.", valueName: "comment"))
    var comment: String?

    @Option(
        name: .customShort("t"),
        help: ArgumentHelp("Key type — only 'ecdsa' (the Secure Enclave is P-256).", valueName: "type"))
    var type: String?

    @Flag(name: .customShort("y"), help: "Read a handle file (-f) and print its public-key line.")
    var extractPublic = false

    @Option(
        name: .customShort("b"),
        help: ArgumentHelp("Unsupported (Secure Enclave is fixed at P-256).", visibility: .private))
    var bits: String?

    @Option(
        name: .customShort("N"),
        help: ArgumentHelp("Unsupported (Touch ID replaces the passphrase).", visibility: .private))
    var passphrase: String?

    public init() {}

    public func validate() throws {
        if let t = type, t.lowercased() != "ecdsa" {
            throw ValidationError("only '-t ecdsa' is supported (Secure Enclave is P-256 only); got '\(t)'")
        }
        if bits != nil {
            throw ValidationError("-b is not supported (Secure Enclave keys are fixed at P-256)")
        }
        if passphrase != nil {
            throw ValidationError("-N is not supported (Touch ID presence replaces the passphrase)")
        }
    }

    public func run() throws {
        let path = expandTilde(file ?? "~/.ssh/id_sod")

        if extractPublic { extractPub(path: path); return }

        if Backends.isMock { elog(Backends.mockWarning) }
        let cmt = comment ?? "\(NSUserName())@\(shortHostname())"

        // Refuse to clobber a file that isn't one of our handles (e.g. a real private key).
        let fm = FileManager.default
        if fm.fileExists(atPath: path) {
            let existing = fm.contents(atPath: path) ?? Data()
            guard HandleFile.isHandleFile(existing) else {
                errExit(
                    "refusing to overwrite '\(path)': not a sod handle file "
                        + "(looks like a real key or other file). Remove it first to replace it.")
            }
            // Existing handle: confirm overwrite, like ssh-keygen.
            FileHandle.standardOutput.write(Data("\(path) already exists.\nOverwrite (y/n)? ".utf8))
            let answer = readLine() ?? ""
            guard answer.lowercased().hasPrefix("y") else { return }  // declined: exit 0, change nothing
        }

        let backend = Backends.active()
        let created: (handle: Data, publicKeyX963: Data)
        do { created = try backend.createKey() } catch { errExit("\(error)") }

        do {
            try writeFile(path, HandleFile.encode(kind: backend.kind, handle: created.handle), mode: 0o600)
        } catch { errExit("\(error)") }
        let pubLine = SSHWire.ecdsaP256PublicKeyLine(x963: created.publicKeyX963, comment: cmt)
        do {
            try writeFile(path + ".pub", Data((pubLine + "\n").utf8), mode: 0o644)
        } catch {
            try? FileManager.default.removeItem(atPath: path)  // don't leave a handle with no .pub
            errExit("\(error)")
        }

        let blob = SSHWire.ecdsaP256PublicKeyBlob(x963: created.publicKeyX963)
        print("Your identification has been saved in \(path)")
        print("Your public key has been saved in \(path).pub")
        print("The key fingerprint is:")
        print("\(fingerprint(blob)) \(cmt)")
        if backend.isMock { print("(backend: MOCK — development only, not the Secure Enclave)") }
    }

    /// `-y`: reconstruct the public key from a stored handle and print its `.pub` line.
    /// Never prompts (reading the public key does not require Touch ID).
    private func extractPub(path: String) {
        let fm = FileManager.default
        guard let data = fm.contents(atPath: path), let decoded = HandleFile.decode(data) else {
            errExit("not a sod handle file: \(path)")
        }
        let backend = Backends.active()
        guard backend.kind == decoded.kind else {
            errExit(
                "handle is for a different backend (kind \(decoded.kind)); this build uses "
                    + "\(backend.isMock ? "the mock backend" : "the Secure Enclave")")
        }
        let x963: Data
        do { x963 = try backend.publicKey(forHandle: decoded.handle) } catch { errExit("\(error)") }
        print(SSHWire.ecdsaP256PublicKeyLine(x963: x963, comment: comment ?? ""))
    }
}
