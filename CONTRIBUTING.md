# Contributing

sod is a Secure-Enclave-backed SSH key, served to stock OpenSSH over the ssh-agent
protocol. The principles below describe the project; they're what to keep in mind when
changing it.

## Design principles

- **Lean.** 

- **Compose with, don't replace.** 

- **Don't roll your own crypto.** 


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

You are welcome to submit pull requests.
