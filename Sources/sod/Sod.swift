import ArgumentParser
import SodKit

/// `sod` dispatches to subcommands that intentionally mirror the OpenSSH tools they
/// imitate (ssh-keygen, ssh-agent, ssh-add). This file is only the entry point and
/// routing; each subcommand lives in SodKit.
/// Entry point. We wrap the ArgumentParser command so the generated build version
/// (which lives in this executable target, not SodKit) can be handed to SodKit for
/// `sd doctor` to report.
@main
enum Main {
    static func main() {
        SodRuntime.version = Build.version
        Sod.main()
    }
}

struct Sod: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sd",
        abstract: "Secure-Enclave-backed SSH — your key never leaves the Secure Enclave; Touch ID signs.",
        version: Build.version,
        subcommands: [Keygen.self, Agent.self, Add.self, Install.self, Uninstall.self, Doctor.self]
    )
}
