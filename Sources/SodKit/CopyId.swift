import ArgumentParser
import Foundation
import SEKeyStore

/// Whether the forwarded arguments already name an identity file (`-i file` or `-i<file>`),
/// in which case the wrapper must NOT inject the default sod key. Pure for unit testing.
public func sshCopyIdHasIdentity(_ args: [String]) -> Bool {
    args.contains("-i") || args.contains { $0.hasPrefix("-i") && $0.count > 2 }
}

/// The full ssh-copy-id argument vector: `-i <defaultPub>` prepended unless the caller
/// already passed their own identity. Pure for unit testing.
public func sshCopyIdArgs(_ passthrough: [String], defaultPub: String) -> [String] {
    sshCopyIdHasIdentity(passthrough) ? passthrough : ["-i", defaultPub] + passthrough
}

/// `sd ssh-copy-id` — a thin wrapper over the system `ssh-copy-id(1)` that defaults the
/// identity to your sod public key, so authorizing the Secure-Enclave key on a server is
/// one step. Everything else is forwarded untouched.
public struct CopyId: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "ssh-copy-id",
        abstract: "Authorize your sod key on a server (wraps ssh-copy-id).",
        discussion: """
            A thin wrapper over the system ssh-copy-id(1): it defaults the identity to your
            sod public key (~/.ssh/id_sod.pub) and forwards every other argument untouched. So

              sd ssh-copy-id user@host

            is shorthand for `ssh-copy-id -i ~/.ssh/id_sod.pub user@host` — it appends the
            Secure-Enclave public key to the server's authorized_keys. Pass any ssh-copy-id
            option (-f, -p port, -o ssh_option, …), or your own -i to override the default.
            """
    )

    @Argument(
        parsing: .captureForPassthrough,
        help: ArgumentHelp(
            "Arguments forwarded to ssh-copy-id, e.g. [user@]host (plus -p, -o, -f …).",
            valueName: "ssh-copy-id-args"))
    var passthrough: [String] = []

    public init() {}

    public func run() throws {
        let tool = "/usr/bin/ssh-copy-id"
        guard FileManager.default.isExecutableFile(atPath: tool) else {
            FileHandle.standardError.write(Data("sd ssh-copy-id: \(tool) not found\n".utf8))
            throw ExitCode.failure
        }

        // Default -i to the sod public key unless the caller named their own identity.
        var args = passthrough
        if !sshCopyIdHasIdentity(args) {
            let pub = expandTilde("~/.ssh/id_sod.pub")
            guard FileManager.default.fileExists(atPath: pub) else {
                FileHandle.standardError.write(
                    Data("sd ssh-copy-id: \(pub) not found — create your key first:  sd ssh-keygen\n".utf8))
                throw ExitCode.failure
            }
            args = sshCopyIdArgs(passthrough, defaultPub: pub)
        }

        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        // Inherit this terminal (stdin/out/err) so ssh-copy-id can prompt for the password.
        do {
            try p.run()
        } catch {
            FileHandle.standardError.write(Data("sd ssh-copy-id: could not run \(tool): \(error)\n".utf8))
            throw ExitCode.failure
        }
        p.waitUntilExit()
        if p.terminationStatus != 0 { throw ExitCode(p.terminationStatus) }
    }
}
