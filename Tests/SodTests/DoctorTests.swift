import Foundation
import SodKit

/// Pure (no SE, no launchd, no sockets) checks of the two helpers behind `sd doctor`:
/// the LaunchAgent plist parser and the shell-rc detector. Always runs.
func runDoctorSuite(_ h: Harness) {
    // --- parsePlistProgram: shape mirrors LaunchAgentManager.plist exactly. ---
    let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>consulting.botanica.sod.agent</string>
            <key>ProgramArguments</key>
            <array>
                <string>/usr/local/bin/sd</string>
                <string>ssh-agent</string>
                <string>-d</string>
                <string>-a</string>
                <string>/Users/me/.ssh/sod-agent.sock</string>
            </array>
            <key>RunAtLoad</key><true/>
        </dict>
        </plist>
        """
    if let p = parsePlistProgram(plist) {
        h.eq(p.binary, "/usr/local/bin/sd", "plist binary is ProgramArguments[0]")
        h.eq(p.socket ?? "<nil>", "/Users/me/.ssh/sod-agent.sock", "plist socket is the -a value")
    } else {
        h.fail("parsePlistProgram returned nil for a valid plist")
    }

    // No -a flag → socket is nil but the binary is still found.
    let noSocket = """
        <key>ProgramArguments</key>
        <array>
            <string>/usr/local/bin/sd</string>
            <string>ssh-agent</string>
            <string>-d</string>
        </array>
        """
    if let p = parsePlistProgram(noSocket) {
        h.eq(p.binary, "/usr/local/bin/sd", "binary parsed without -a")
        h.ok(p.socket == nil, "socket is nil when -a is absent")
    } else {
        h.fail("parsePlistProgram returned nil when only -a was missing")
    }

    h.ok(parsePlistProgram("<plist><dict></dict></plist>") == nil, "no ProgramArguments -> nil")

    // --- rcConfigured ---
    let sock = "/Users/me/.ssh/sod-agent.sock"
    h.ok(
        rcConfigured(contents: "export SSH_AUTH_SOCK=\"\(sock)\"\n", socketPath: sock),
        "literal export of our socket -> configured")
    h.ok(
        !rcConfigured(contents: "# export SSH_AUTH_SOCK=\"\(sock)\"\n", socketPath: sock),
        "commented-out line -> not configured")
    h.ok(
        !rcConfigured(contents: "export PATH=/usr/bin\n", socketPath: sock),
        "unrelated rc contents -> not configured")
    h.ok(
        !rcConfigured(contents: "export SSH_AUTH_SOCK=\"/other/agent.sock\"\n", socketPath: sock),
        "points at a different agent -> not configured")

    // $HOME / ~ forms (built relative to the real home so the test is deterministic).
    let homeSock = NSHomeDirectory() + "/.ssh/sod-agent.sock"
    h.ok(
        rcConfigured(contents: "export SSH_AUTH_SOCK=\"$HOME/.ssh/sod-agent.sock\"\n", socketPath: homeSock),
        "$HOME form -> configured")
    h.ok(
        rcConfigured(contents: "set -gx SSH_AUTH_SOCK ~/.ssh/sod-agent.sock\n", socketPath: homeSock),
        "~ form (fish) -> configured")
}
