import Foundation
import SodKit

/// Pure (no SE, no launchd) checks of the shell-startup snippet that `sod install`
/// prints. Always runs — not gated on SE_SSH_MOCK.
func runInstallSuite(_ h: Harness) {
    let home = NSHomeDirectory()
    let sock = home + "/.ssh/sod-agent.sock"

    let z = shellSnippet(shellPath: "/bin/zsh", socketPath: sock)
    h.eq(z.rcFile, "~/.zshrc", "zsh -> ~/.zshrc")
    // $HOME (not ~) because the path sits inside double quotes, where ~ would not expand.
    h.eq(z.line, "export SSH_AUTH_SOCK=\"$HOME/.ssh/sod-agent.sock\"", "zsh export uses $HOME")

    let b = shellSnippet(shellPath: "/bin/bash", socketPath: sock)
    h.eq(b.rcFile, "~/.bash_profile", "bash -> ~/.bash_profile")
    h.eq(b.line, "export SSH_AUTH_SOCK=\"$HOME/.ssh/sod-agent.sock\"", "bash export line")

    let f = shellSnippet(shellPath: "/opt/homebrew/bin/fish", socketPath: sock)
    h.eq(f.rcFile, "~/.config/fish/config.fish", "fish -> config.fish")
    h.eq(f.line, "set -gx SSH_AUTH_SOCK \"$HOME/.ssh/sod-agent.sock\"", "fish uses set -gx")

    let c = shellSnippet(shellPath: "/bin/tcsh", socketPath: sock)
    h.eq(c.line, "setenv SSH_AUTH_SOCK \"$HOME/.ssh/sod-agent.sock\"", "tcsh uses setenv")

    // Unknown shell falls back to a POSIX export against ~/.profile.
    let s = shellSnippet(shellPath: "/usr/bin/somesh", socketPath: sock)
    h.eq(s.shell, "sh", "unknown shell -> sh")
    h.eq(s.rcFile, "~/.profile", "sh -> ~/.profile")

    // A socket outside $HOME is left literal (no $HOME rewrite).
    let outside = shellSnippet(shellPath: "/bin/zsh", socketPath: "/tmp/sod.sock")
    h.eq(outside.line, "export SSH_AUTH_SOCK=\"/tmp/sod.sock\"", "non-home socket stays literal")
}
