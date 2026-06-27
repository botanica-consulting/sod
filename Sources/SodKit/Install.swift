import ArgumentParser
import Foundation
import SEKeyStore

#if canImport(Darwin)
import Darwin
#endif

private let tool = "sd install"
private func elog(_ s: String) { FileHandle.standardError.write(Data("\(tool): \(s)\n".utf8)) }
private func errExit(_ s: String) -> Never { elog(s); exit(1) }

/// Ask a yes/no question (default yes) on the terminal. Only prompts when stdin is a
/// TTY; in a non-interactive context it returns `false` so nothing is created silently.
private func askYesDefault(_ question: String) -> Bool {
    guard isatty(0) != 0 else { return false }
    FileHandle.standardOutput.write(Data("\(question) [Y/n] ".utf8))
    guard let line = readLine() else { return true }  // EOF → take the default
    let a = line.trimmingCharacters(in: .whitespaces).lowercased()
    return a.isEmpty || a.hasPrefix("y")
}

/// `sd install` — one-step setup: make sure ~/.ssh/id_sod exists, run the agent at
/// login with that key preloaded, and print the single command to point this shell at
/// it. Deliberately a plain top-level command (not a flag on `ssh-agent`, which mirrors
/// OpenSSH's flagless tool).
public struct Install: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "install",
        abstract: "Run the agent at login with id_sod loaded, and print the shell line to use it.",
        discussion: """
            Installs a per-user LaunchAgent so `sd ssh-agent` runs on a fixed socket at
            login (restarting if it exits). The agent serves your default key ~/.ssh/id_sod
            automatically — no separate `sd ssh-add` — so if you have no key yet, it offers
            to create one. It edits no shell files: it prints an `echo … >> <rc>` command
            for you to run. Reverse it with `sd uninstall`.
            """
    )

    @Option(
        name: .customShort("a"),
        help: ArgumentHelp("Agent socket path (default ~/.ssh/sod-agent.sock).", valueName: "socket"))
    var socket: String?

    public init() {}

    public func run() throws {
        let sock = expandTilde(socket ?? "~/.ssh/sod-agent.sock")
        let keyPath = expandTilde("~/.ssh/id_sod")

        // The agent serves ~/.ssh/id_sod on its own, so just make sure the key exists:
        // offer to create it if missing (declining is fine — the agent picks it up as soon
        // as the file appears).
        if !FileManager.default.fileExists(atPath: keyPath) {
            if askYesDefault("No key at ~/.ssh/id_sod yet. Create one now?") {
                try Keygen.parse([]).run()  // writes ~/.ssh/id_sod (+ .pub) with the defaults
                print("")
            }
        }

        let r = LaunchAgentManager.install(sodPath: executablePath(), socketPath: sock)
        guard r.ok else { errExit(r.message) }

        let snip = shellSnippet(
            shellPath: ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/sh", socketPath: sock)
        let served = FileManager.default.fileExists(atPath: keyPath) ? " (serving id_sod)" : ""

        print("The sod agent is running and will start at every login\(served).")
        print("")
        print("Point your shell at it:")
        print("")
        print("    echo '\(snip.line)' >> \(snip.rcFile)")
        print("    exec $SHELL")
    }
}

/// `sd uninstall` — remove the LaunchAgent installed by `sd install`.
public struct Uninstall: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "uninstall",
        abstract: "Remove the login agent installed by `sd install`."
    )

    public init() {}

    public func run() throws {
        let r = LaunchAgentManager.uninstall()
        print(r.message)
        print("If you added an SSH_AUTH_SOCK line to a shell startup file, remove it too.")
    }
}
