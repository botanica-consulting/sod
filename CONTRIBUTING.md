# Contributing

sod is a Secure-Enclave-backed SSH key, served to stock OpenSSH over the ssh-agent
protocol. The principles below describe the project; they're what to keep in mind when
changing it.

## Design principles

- **Lean.** One binary, no third-party dependencies beyond Apple's frameworks and
  swift-argument-parser. No config files, no telemetry, no root daemons. New surface needs
  a reason; the default answer is "don't add it."

- **Composes; doesn't replace.** sod is the key and the agent. It stacks with OpenSSH and
  its ecosystem — `ssh`, `ssh-add`, `ssh-keygen -Y`, git — and uses their features instead
  of re-implementing them. Where `sd` shadows a stock tool it mirrors that tool's flags and
  output; where a wrapper exists (e.g. `sd ssh-copy-id`) it's a thin pass-through that fills
  in a default, not new behavior.

- **No homegrown crypto.** Signing, key handling, and the SSH / agent / SSHSIG wire formats
  come from CryptoKit, Security.framework, and the documented protocols. Verification is
  whatever stock tooling already does (`ssh-keygen -Y verify`). sod defines no formats and
  implements no ciphers.

- **A thin path to the finger.** The agent is a minimal bridge between a request and the
  Secure Enclave. Every signature is one Touch ID. Nothing goes between intent and presence
  that would dilute it — no presence cache by default, no silent reuse.

- **An oracle for presence.** sod's value is the proof that a person was physically there
  and approved a specific thing. Changes preserve or sharpen that. When sod can't honor a
  guarantee it refuses rather than pretending — it rejects key constraints it won't enforce,
  and refuses a forwarded agent instead of silently signing for one.

## Working on it

```sh
make                                              # build the binary (writes Version.swift, release build)
SE_SSH_MOCK=1 swift run sod-tests                 # unit suites — no Secure Enclave, no Touch ID
SE_SSH_MOCK=1 bash scripts/selftest.sh /tmp/k     # mock end-to-end
swift format lint --strict --recursive Sources Tests   # format / lint gate
mandoc -Tlint man/sd.1                            # man-page lint
```

A Swift 6 toolchain from the Command Line Tools is enough; Xcode isn't required.

Secure Enclave access sits behind `KeyBackend`. `SE_SSH_MOCK=1` swaps in an in-process
P-256 key, so everything except the real SE runs without a finger; the mock is compiled in
only when that variable is set. The real-SE path has no automated coverage — it's exercised
by running on a Mac with Touch ID.

## Layout

- `Sources/SSHWire` — SSH / agent wire formats. Pure; no Secure Enclave.
- `Sources/SEKeyStore` — `KeyBackend`, the Secure-Enclave and mock backends, handle files.
- `Sources/SodKit` — command logic (keygen, agent, add, install, doctor).
- `Sources/sod` — entry point.

## Pull requests

Keep the diff focused. The lint gate and `SE_SSH_MOCK=1 swift run sod-tests` should pass.
Changes under `SEKeyStore` or `SSHWire` touch crypto and the wire protocol — note the
reasoning.
