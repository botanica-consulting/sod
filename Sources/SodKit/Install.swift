import ArgumentParser
import Foundation
import SEKeyStore

private let tool = "sd install"
private func elog(_ s: String) { FileHandle.standardError.write(Data("\(tool): \(s)\n".utf8)) }
private func errExit(_ s: String) -> Never { elog(s); exit(1) }

/// `sd install` — the one-step setup after `brew install`: it runs the agent at login
/// and prints the single line to add to your shell startup file. Deliberately a plain
/// top-level command (not a flag on `ssh-agent`, which mirrors OpenSSH's flagless tool).
public struct Install: ParsableCommand {
    public static let configuration = CommandConfiguration(
        commandName: "install",
        abstract: "Run the agent at login and print the line to add to your shell startup file.",
        discussion: """
            Installs a per-user LaunchAgent so `sd ssh-agent` runs on a fixed socket at
            login (and restarts if it exits), then prints the one line to add to your
            shell startup file so every shell finds it. It edits nothing on your behalf —
            you paste the printed line yourself. Reverse it with `sd uninstall`.
            """
    )

    @Option(
        name: .customShort("a"),
        help: ArgumentHelp("Agent socket path (default ~/.ssh/sod-agent.sock).", valueName: "socket"))
    var socket: String?

    public init() {}

    public func run() throws {
        let sock = expandTilde(socket ?? "~/.ssh/sod-agent.sock")

        let r = LaunchAgentManager.install(sodPath: executablePath(), socketPath: sock)
        guard r.ok else { errExit(r.message) }

        let snip = shellSnippet(
            shellPath: ProcessInfo.processInfo.environment["SHELL"] ?? "/bin/sh", socketPath: sock)
        let hasKey = FileManager.default.fileExists(atPath: expandTilde("~/.ssh/id_sod"))

        print("The sod agent is running now and will start at every login (socket: \(tildeSocket(sock))).")
        print("")
        if !hasKey {
            print("You don't have a key yet. Create one first:")
            print("")
            print("    sd ssh-keygen")
            print("")
        }
        print("Add this line to \(snip.rcFile), then open a new shell:")
        print("")
        print("    \(snip.line)")
        print("")
        print("Then load your key into the agent:")
        print("")
        print("    sd ssh-add")
        print("")
        print("Prefer to keep your current agent (1Password, Secretive, …) for most hosts?")
        print("Skip the line above and route only chosen hosts to sod in ~/.ssh/config:")
        print("")
        print("    Host github.com")
        print("        IdentityAgent \(tildeSocket(sock))")
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
