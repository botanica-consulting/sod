import Foundation

#if canImport(Darwin)
import Darwin
#endif

/// Optional per-user LaunchAgent that keeps `sd ssh-agent` running on a fixed
/// socket across logins. Installed only on explicit request (`sd install`); the .pkg
/// never writes it. It must be a LaunchAgent (GUI session), never a LaunchDaemon, or
/// Touch ID cannot present.
enum LaunchAgentManager {
    static let label = "consulting.botanica.sod.agent"

    static func plistPath() -> String {
        NSHomeDirectory() + "/Library/LaunchAgents/" + label + ".plist"
    }

    /// launchd runs the agent in the FOREGROUND (`-d`) and owns its lifecycle; the
    /// self-detaching `--daemon` path is NOT used here.
    static func plist(sodPath: String, socketPath: String) -> String {
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>\(label)</string>
            <key>ProgramArguments</key>
            <array>
                <string>\(sodPath)</string>
                <string>ssh-agent</string>
                <string>-d</string>
                <string>-a</string>
                <string>\(socketPath)</string>
            </array>
            <key>RunAtLoad</key><true/>
            <key>KeepAlive</key><true/>
            <key>ProcessType</key><string>Interactive</string>
            <key>StandardOutPath</key><string>\(socketPath).log</string>
            <key>StandardErrorPath</key><string>\(socketPath).log</string>
        </dict>
        </plist>
        """
    }

    static func install(sodPath: String, socketPath: String) -> (ok: Bool, message: String) {
        let dir = NSHomeDirectory() + "/Library/LaunchAgents"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let path = plistPath()
        do {
            try plist(sodPath: sodPath, socketPath: socketPath)
                .write(toFile: path, atomically: true, encoding: .utf8)
        } catch {
            return (false, "could not write \(path): \(error)")
        }
        // (Re)load: bootout first in case it is already loaded, then bootstrap.
        let uid = getuid()
        _ = runLaunchctl(["bootout", "gui/\(uid)/\(label)"])  // ignore "not loaded"
        let rc = runLaunchctl(["bootstrap", "gui/\(uid)", path])
        guard rc == 0 else {
            return (false, "wrote \(path) but `launchctl bootstrap` failed (exit \(rc))")
        }
        return (true, "installed \(label)")
    }

    /// Whether launchd currently has the agent loaded (used by `sd doctor`).
    static func isLoaded() -> Bool {
        runLaunchctl(["print", "gui/\(getuid())/\(label)"]) == 0
    }

    static func uninstall() -> (ok: Bool, message: String) {
        let uid = getuid()
        _ = runLaunchctl(["bootout", "gui/\(uid)/\(label)"])
        let path = plistPath()
        try? FileManager.default.removeItem(atPath: path)
        return (true, "uninstalled \(label) (removed \(path))")
    }

    private static func runLaunchctl(_ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        p.arguments = args
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do {
            try p.run()
            p.waitUntilExit()
            return p.terminationStatus
        } catch {
            return -1
        }
    }
}
