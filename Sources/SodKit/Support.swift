import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Absolute path to the running `sod` binary — embedded in the LaunchAgent plist and
/// used by the agent's lazy self-spawn. Falls back to argv[0].
func executablePath() -> String {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var buf = [CChar](repeating: 0, count: Int(size) + 1)
    guard _NSGetExecutablePath(&buf, &size) == 0 else { return CommandLine.arguments[0] }
    return String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
}

/// Render a home-relative socket path as `$HOME/...` — for a double-quoted shell
/// assignment, where `~` would NOT expand but `$HOME` does.
func displaySocket(_ socketPath: String) -> String {
    let home = NSHomeDirectory()
    if socketPath == home { return "$HOME" }
    if socketPath.hasPrefix(home + "/") { return "$HOME" + String(socketPath.dropFirst(home.count)) }
    return socketPath
}

/// Render a home-relative socket path as `~/...` — for `~/.ssh/config`, where the
/// tilde is supported but `$HOME` is not.
func tildeSocket(_ socketPath: String) -> String {
    let home = NSHomeDirectory()
    if socketPath == home { return "~" }
    if socketPath.hasPrefix(home + "/") { return "~" + String(socketPath.dropFirst(home.count)) }
    return socketPath
}

/// The one line a user adds to their shell startup file to point `SSH_AUTH_SOCK` at
/// the sod agent. Pure (no I/O) so it can be unit-tested; `shellPath` is typically
/// `$SHELL`. Covers the common macOS shells and falls back to a POSIX `export`.
public struct ShellSnippet: Equatable {
    public let shell: String  // "zsh", "bash", "fish", "csh", "sh"
    public let rcFile: String  // startup file to edit, e.g. "~/.zshrc"
    public let line: String  // the export/set/setenv line to add
}

public func shellSnippet(shellPath: String, socketPath: String) -> ShellSnippet {
    let sock = displaySocket(socketPath)
    switch (shellPath as NSString).lastPathComponent {
    case "zsh":
        return ShellSnippet(shell: "zsh", rcFile: "~/.zshrc", line: "export SSH_AUTH_SOCK=\"\(sock)\"")
    case "bash":
        return ShellSnippet(shell: "bash", rcFile: "~/.bash_profile", line: "export SSH_AUTH_SOCK=\"\(sock)\"")
    case "fish":
        return ShellSnippet(
            shell: "fish", rcFile: "~/.config/fish/config.fish", line: "set -gx SSH_AUTH_SOCK \"\(sock)\"")
    case "csh", "tcsh":
        return ShellSnippet(shell: "csh", rcFile: "~/.cshrc", line: "setenv SSH_AUTH_SOCK \"\(sock)\"")
    default:
        return ShellSnippet(shell: "sh", rcFile: "~/.profile", line: "export SSH_AUTH_SOCK=\"\(sock)\"")
    }
}
