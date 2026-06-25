# se-ssh — Secure-Enclave-backed SSH agent + keygen

A minimal, no-GUI macOS tool that keeps an SSH authentication key **in the Secure
Enclave** (the private key never leaves the SE) and serves it to stock OpenSSH over
the ssh-agent protocol. Touch ID gates every signature. The key is served as a
plain `ecdsa-sha2-nistp256` — any server accepts it; no FIDO/`sk-` support needed.

Executables:
- **`se-ssh-keygen`** — creates a P-256 key in the Secure Enclave; writes an opaque
  handle file + a standard `.pub`.
- **`se-ssh-agent`** — an ssh-agent on a unix socket. It holds no keys until you load
  one with **`se-ssh-add`** / `ssh-add -s` (or preload by passing handle paths as
  args). Lists keys without a prompt; signs behind Touch ID.
- **`se-ssh-add`** *(disposable convenience)* — loads/removes/lists keys like
  `ssh-add`, but without `ssh-add -s`'s pointless PKCS#11 PIN prompt. Safe to delete
  if that prompt ever goes away; nothing depends on it.

Status: **working (M0–M4, plus `ssh-add -s` key-loading and the `-E`/lazy-daemon —
the M5 ergonomics).** Auto-start at login (a proper LaunchAgent) and CI/packaging
(M6) are not built yet.

## Requirements
- Apple Silicon Mac with Touch ID, macOS 13+.
- Swift toolchain (Command Line Tools is enough — no Xcode.app required).
- OpenSSH (`ssh`, `ssh-add`); macOS ships it, or use Homebrew's.

## Build
```sh
swift build -c release
# binaries: .build/release/se-ssh-keygen, .build/release/se-ssh-agent
```
Binaries are ad-hoc signed (no Apple Developer account needed) and, being built
locally, are not quarantined. Run them by full path, or copy them somewhere on your
`PATH` yourself.

## Use

1. **Generate a key** (no Touch ID at creation) — put it wherever you like:
   ```sh
   se-ssh-keygen -f ~/keys/se/id -C "me@laptop"   # -> ~/keys/se/id (+ id.pub)
   # bare `se-ssh-keygen` defaults to ~/.ssh/id_ecdsa_se
   ```
2. **Authorize it on the server** — append `~/keys/se/id.pub` to the remote
   `~/.ssh/authorized_keys` (e.g. `ssh-copy-id -i ~/keys/se/id.pub user@host`).
3. **Start the agent into your shell** (empty; starts a background one if needed):
   ```sh
   eval "$(se-ssh-agent -E)"
   ```
4. **Load the key into the agent** with `se-ssh-add` (no prompt):
   ```sh
   se-ssh-add ~/keys/se/id        # -d <key> to unload, -l / -L to list
   ```
   `se-ssh-add` is a small disposable wrapper that avoids `ssh-add -s`'s pointless
   PKCS#11 PIN prompt (see `Sources/se-ssh-add/main.swift`). Stock tooling works too:
   `ssh-add -s ~/keys/se/id` (press Enter at the PIN prompt — the SE ignores it),
   `ssh-add -e` to unload, `ssh-add -l`/`-L` to list.
5. **Connect as usual** — Touch ID prompts once per connection:
   ```sh
   ssh -i ~/keys/se/id user@host
   ```
   You can point `-i` at the handle or the `.pub`, or omit `-i` — the agent offers
   the loaded key either way. (Presence on every connect is the point — N
   connections = N taps.)

Notes:
- **Preload instead of `ssh-add -s`** by naming handles/dirs at startup:
  `se-ssh-agent ~/keys/se/id` (or `eval "$(se-ssh-agent -E ~/keys/se/id)"`).
- The agent is a plain process (not yet a login LaunchAgent), so after a reboot run
  `eval "$(se-ssh-agent -E)"` again. Default socket: `~/.ssh/se-agent.sock` (`-a` to
  change). Stop it with `pkill -f se-ssh-agent`.
- It never touches your default `SSH_AUTH_SOCK` unless you `eval` it, so it coexists
  with 1Password/Secretive. To scope it per-host without `eval`, point a `~/.ssh/config`
  `Host` block at `IdentityAgent ~/.ssh/se-agent.sock` + `IdentityFile <key>.pub`.

**Quick self-test** against a local throwaway sshd (no sudo, no other machine; you
tap Touch ID once):
```sh
bash scripts/selftest.sh ~/keys/se/id      # creates the key if missing
```

## Security model
- The private key is generated in and never leaves the Secure Enclave. The handle
  file is an opaque, device-bound `dataRepresentation` blob with **no usable
  secret** — only this Mac's SE can use it, only via this agent.
- Access policy is `.userPresence`: Touch ID **with passcode fallback**, durable
  across fingerprint re-enrollment.
- Reconstructing the key / listing identities never prompts; only **signing** does.
- `ssh-add -s` sends a PIN field we ignore; presence is enforced by the SE at sign
  time, not by a PIN.

## Development & testing (no Touch ID)
All SE operations sit behind a `KeyBackend` seam. A build-time mock (a plain
in-process P-256 key — real signatures, **no SE, no Touch ID**) runs the whole
flow without a fingerprint:
```sh
swift run wire-tests                       # pure wire-format unit tests (no SE)
SE_SSH_MOCK=1 swift build                  # build keygen+agent with the mock backend
SE_SSH_MOCK=1 bash scripts/selftest.sh /tmp/k   # full eval → ssh-add -s → ssh, no taps
```
The mock is compiled **only** when `SE_SSH_MOCK` is set, so it is physically absent
from a normal/release build. Mock builds print a loud warning on stderr.

## Layout
- `Sources/SSHWire/` — pure SSH wire format (uint32/string/mpint, ecdsa pub/sig
  blobs, ssh-agent framing incl. smartcard add/remove). No SE imports.
- `Sources/SEKeyStore/` — `KeyBackend` protocol, `SecureEnclaveBackend`,
  `MockP256Backend` (gated), handle-file format, provider resolution (file or dir).
- `Sources/se-ssh-keygen/`, `Sources/se-ssh-agent/` — the keygen + agent CLIs.
- `Sources/se-ssh-add/` — disposable, PIN-free key loader (see its file header).
- `Sources/spike/` — M0 feasibility throwaway (see `M0-RESULT.md`).
- `Tests/SSHWireTests/` — the `wire-tests` runner.
