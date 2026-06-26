<div align="center">

<!-- Branding: drop the banner at docs/assets/sod-banner.png and replace this block with
     <picture><source ... media="(prefers-color-scheme: dark)"><img src="docs/assets/sod-banner.png" ...></picture> -->

# sod

**SSH native keys, sealed in the Secure Enclave. Use Touch ID to login.**

[![CI](https://github.com/botanica-consulting/sod/actions/workflows/ci.yml/badge.svg)](https://github.com/botanica-consulting/sod/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![macOS 13+](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)](#requirements)
[![Swift 6](https://img.shields.io/badge/Swift-6-orange?logo=swift)](Package.swift)

</div>

`sod` keeps an SSH authentication key **inside the Secure Enclave** — the private key
is generated there and never leaves it — and serves it to stock OpenSSH over the
ssh-agent protocol. **Touch ID gates every signature.** The key is a plain
`ecdsa-sha2-nistp256`, accepted by any SSH server; no FIDO/`sk-`
support required on the other end.

`sod` has the same usage as the bog-standard OpenSSH tooling - just prefix with `sod` and the rest takes care of itself.
| Command | Like | Does |
|---|---|---|
| `sod ssh-keygen` | `ssh-keygen` | create a Secure-Enclave P-256 key (an opaque handle + a standard `.pub`) |
| `sod ssh-agent` | `ssh-agent` | run the agent on a unix socket; print `SSH_AUTH_SOCK` to use it |
| `sod ssh-add` | `ssh-add` | load / unload / list keys in the agent — no PIN prompt |

## Why sod

- **Non-exportable.** The handle file is an opaque, device-bound blob with no usable
  secret. Only this Mac's Secure Enclave can use the key, and only through the agent.
- **Presence on every signature.** Touch ID with
  passcode fallback, durable across fingerprint re-enrollment.
- **Stock OpenSSH.** Speaks the ssh-agent protocol; no patched `ssh`, no kernel
  extensions, no daemons running as root.
- **Zero conf.** Runs as an independant ssh agent, does not meddle with your other SSH key flows.
- **Lean.** A single notarized binary, linked solely with Apple code - zero third-party dependencies.

## Requirements

- A Mac with a Secure Enclave (Apple Silicon, or Intel with a T2 chip) and Touch ID, macOS 13+.
- OpenSSH (`ssh`, `ssh-add`) — macOS ships it.
- To build from source: a Swift 6 toolchain (Command Line Tools is enough — no Xcode app required).

## Install

### Homebrew

```sh
brew install botanica-consulting/tap/sod
```

### Packaged installer

Download `sod-<version>.pkg` from [Releases](https://github.com/botanica-consulting/sod/releases)
and open it. It installs `sod` to `/usr/local/bin` and its man page — nothing else.

### From source

```sh
git clone https://github.com/botanica-consulting/sod && cd sod
make install      # builds a universal binary, installs to /usr/local (sudo)
# or just: swift build -c release   (binary at .build/release/sod)
```

## Quickstart

```sh
sod ssh-keygen                 # creates ~/.ssh/id_sod (+ .pub); no Touch ID at creation
eval "$(sod ssh-agent)"        # starts/reuses the agent, exports SSH_AUTH_SOCK
sod ssh-add                    # loads ~/.ssh/id_sod into the agent
ssh -i ~/.ssh/id_sod user@host # Touch ID prompts on connect
```

## Advanced usage

**Generate a key.** The default `~/.ssh/id_sod` never collides with your normal
`id_ecdsa`/`id_ed25519`. Or put it anywhere:

```sh
sod ssh-keygen                              # -> ~/.ssh/id_sod (+ id_sod.pub)
sod ssh-keygen -f ~/keys/work -C "me@work"  # -> ~/keys/work  (+ work.pub)
sod ssh-keygen -y -f ~/keys/work            # reprint the .pub line from a handle
```

**Run the agent.** With no options it starts an agent (or reuses a running one) on the
fixed socket `~/.ssh/sod-agent.sock` and prints the env to use it:

```sh
eval "$(sod ssh-agent)"        # sh/zsh/csh/fish auto-detected (-s / -c to force)
sod ssh-agent -k               # stop it
```

To start it automatically at every login (optional):

```sh
sod ssh-agent --install-launch-agent
# then add to your shell profile so every shell finds it:
echo 'export SSH_AUTH_SOCK="$HOME/.ssh/sod-agent.sock"' >> ~/.zshrc
```

**Load / list / unload keys** (no PIN prompt, unlike stock `ssh-add -s`):

```sh
sod ssh-add                    # load the default ~/.ssh/id_sod
sod ssh-add ~/keys/work        # load a specific handle
sod ssh-add -l                 # list fingerprints   (-L for full public keys)
sod ssh-add -d ~/keys/work     # unload one          (-D to unload all)
```

**Authorize and connect.** Put the `.pub` on the server, then connect:

```sh
ssh-copy-id -i ~/.ssh/id_sod.pub user@host
ssh user@host                  # Touch ID on connect
```

**Interop with stock tooling.** `sod ssh-add` is just a convenience client;
the agent also speaks to stock `ssh-add`, which loads Secure-Enclave handles via its
smartcard messages:

```sh
ssh-add -s ~/.ssh/id_sod       # press Enter at the PKCS#11 PIN prompt — the SE ignores it
ssh-add -e ~/.ssh/id_sod       # unload      (ssh-add -l / -L to list)
```

## How it works

```
sod ssh-keygen ──► Secure Enclave generates a P-256 key
                   └─► ~/.ssh/id_sod      (opaque handle, no usable secret)
                       ~/.ssh/id_sod.pub  (ecdsa-sha2-nistp256 ...)

ssh ──unix socket──► sod ssh-agent ──► Secure Enclave signs  ──► Touch ID
   (ssh-agent proto)  (holds handles)    (private key never leaves the SE)
```

The agent reconstructs the public key and lists identities without prompting; only a
**signature** triggers Touch ID. Deleting the handle file orphans the key — there is
no keychain item to clean up, because the blob is the only reference to it.

## Security model

- The private key is generated in and never leaves the Secure Enclave. The handle is
  the CryptoKit `dataRepresentation` — a device-bound, SEP-wrapped blob with no usable
  secret; only this Mac's SE can use it.
- `.userPresence` = Touch ID with passcode fallback, durable across re-enrollment.
- Listing identities / reading the public key never prompts; only signing does.
- No keychain item, no keychain access group, no entitlements — which is also why a
  plain Developer-ID signature notarizes cleanly. See [`SECURITY.md`](SECURITY.md) to
  report a vulnerability.

## Development & testing (no Touch ID)

All SE operations sit behind a `KeyBackend` seam. A build-time mock (a plain in-process
P-256 key — real signatures, no SE, no Touch ID) runs the whole flow without a finger:

```sh
SE_SSH_MOCK=1 swift run sod-tests              # wire + keystore + agent unit suites
SE_SSH_MOCK=1 bash scripts/selftest.sh /tmp/k  # full generate → agent → ssh-add → ssh, no taps
```

The mock is compiled **only** when `SE_SSH_MOCK` is set, so it is physically absent
from any release build (which prints a loud warning if you somehow build one). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for the lint and coverage commands.

## Project layout

- `Sources/SSHWire/` — pure SSH wire format (uint32/string/mpint, ecdsa blobs,
  ssh-agent framing). No SE imports; fully unit-tested.
- `Sources/SEKeyStore/` — `KeyBackend`, `SecureEnclaveBackend`, gated `MockP256Backend`,
  the handle-file format, and provider resolution.
- `Sources/SodKit/` — the keygen/agent/add command logic + argument parsing.
- `Sources/sod/` — the thin `@main` entry point.
- `Tests/SodTests/`, `scripts/`, `packaging/`, `man/`, `docs/` — tests, build &
  packaging, the man page, and design notes (`docs/PLAN.md`, `docs/M0-RESULT.md`).

## License

[MIT](LICENSE) © Botanica Software Labs. A Botanica Software Labs product.
