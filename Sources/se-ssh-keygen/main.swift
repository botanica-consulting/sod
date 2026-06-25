import Foundation
import SSHWire
import SEKeyStore

private let tool = "se-ssh-keygen"

private func errExit(_ msg: String) -> Never {
    FileHandle.standardError.write(Data("\(tool): \(msg)\n".utf8))
    exit(1)
}

private func usage() {
    print("""
    usage: \(tool) [-f keyfile] [-C comment] [-t ecdsa]

    Creates a Secure-Enclave P-256 SSH key. Writes two files:
      <keyfile>       opaque handle (consumed only by se-ssh-agent; no usable secret)
      <keyfile>.pub   standard "ecdsa-sha2-nistp256 ..." line

    Default keyfile: ~/.ssh/id_ecdsa_se
    Only -t ecdsa is supported (the Secure Enclave is P-256 only). -b and -N are
    rejected: key size is fixed, and Touch ID presence replaces the passphrase.
    """)
}

private func shortHostname() -> String {
    var name = ProcessInfo.processInfo.hostName
    if name.hasSuffix(".local") { name = String(name.dropLast(6)) }
    return name
}

private func writeFile(_ path: String, _ data: Data, mode: Int) throws {
    let fm = FileManager.default
    let parent = (path as NSString).deletingLastPathComponent
    if !parent.isEmpty {
        try fm.createDirectory(atPath: parent, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
    }
    guard fm.createFile(atPath: path, contents: data,
                        attributes: [.posixPermissions: NSNumber(value: mode)]) else {
        throw KeyBackendError.create("could not write \(path)")
    }
}

private func runKeygen() {
    if Backends.isMock {
        FileHandle.standardError.write(Data("\(tool): \(Backends.mockWarning)\n".utf8))
    }

    var path = expandTilde("~/.ssh/id_ecdsa_se")
    var comment = "\(NSUserName())@\(shortHostname())"

    let argv = CommandLine.arguments
    var i = 1
    while i < argv.count {
        switch argv[i] {
        case "-f":
            i += 1; guard i < argv.count else { errExit("-f requires a path") }
            path = expandTilde(argv[i])
        case "-C":
            i += 1; guard i < argv.count else { errExit("-C requires a comment") }
            comment = argv[i]
        case "-t":
            i += 1; guard i < argv.count else { errExit("-t requires a type") }
            if argv[i].lowercased() != "ecdsa" {
                errExit("only '-t ecdsa' is supported (Secure Enclave is P-256 only); got '\(argv[i])'")
            }
        case "-b":
            errExit("-b is not supported (Secure Enclave keys are fixed at P-256)")
        case "-N":
            errExit("-N is not supported (Touch ID presence replaces the passphrase)")
        case "-h", "--help":
            usage(); exit(0)
        default:
            errExit("unknown argument '\(argv[i])'")
        }
        i += 1
    }

    // Refuse to clobber a file that isn't one of our handles (e.g. a real private key).
    let fm = FileManager.default
    if fm.fileExists(atPath: path) {
        let existing = fm.contents(atPath: path) ?? Data()
        if !HandleFile.isHandleFile(existing) {
            errExit("refusing to overwrite '\(path)': not an se-ssh handle file " +
                    "(looks like a real key or other file). Remove it first to replace it.")
        }
    }

    let backend = Backends.active()
    let created: (handle: Data, publicKeyX963: Data)
    do { created = try backend.createKey() } catch { errExit("\(error)") }

    do {
        try writeFile(path, HandleFile.encode(kind: backend.kind, handle: created.handle), mode: 0o600)
    } catch { errExit("\(error)") }
    do {
        let line = SSHWire.ecdsaP256PublicKeyLine(x963: created.publicKeyX963, comment: comment) + "\n"
        try writeFile(path + ".pub", Data(line.utf8), mode: 0o644)
    } catch {
        try? FileManager.default.removeItem(atPath: path)   // don't leave a handle with no .pub
        errExit("\(error)")
    }

    print("Your Secure-Enclave SSH key has been created.")
    print("  handle file:  \(path)")
    print("  public key:   \(path).pub")
    print("  comment:      \(comment)")
    if backend.isMock { print("  backend:      MOCK (development only — not the Secure Enclave)") }
}

runKeygen()
