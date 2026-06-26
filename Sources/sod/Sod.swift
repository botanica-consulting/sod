import ArgumentParser
import SodKit

/// `sod` dispatches to subcommands that intentionally mirror the OpenSSH tools they
/// imitate (ssh-keygen, ssh-agent, ssh-add). This file is only the entry point and
/// routing; each subcommand lives in SodKit.
@main
struct Sod: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sod",
        abstract: "Secure-Enclave-backed SSH — your key never leaves the Secure Enclave; Touch ID signs.",
        version: Build.version,
        subcommands: [Keygen.self, Agent.self, Add.self]
    )
}
