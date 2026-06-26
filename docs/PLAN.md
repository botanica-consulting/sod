# Plan: Secure-Enclave-backed SSH agent + keygen (working name `se-ssh-*`)

## Context

We want a minimal OSS macOS tool that lets the Secure Enclave hold an SSH
authentication key — private key never leaves the SE, Touch ID on every
connect — with **no GUI, no per-connection config edits, and no global env
clobber**. The design was settled over a long discussion; this plan is the
construction/testing roadmap only.

Why the chosen shape (recap of decisions already made):

- **Agent, not an in-process provider.** OpenSSH has exactly two extension
  points: an in-process middleware dylib (`ssh-keygen -w` / `SecurityKeyProvider`
  / PKCS#11) or an out-of-process **agent** over `SSH_AUTH_SOCK`. We chose the
  agent because (a) it injects nothing into Apple's `ssh`, sidestepping
  hardened-runtime/library-validation entirely (Apple's own
  `/usr/lib/ssh-keychain.dylib` only loads because it's Apple-signed; a
  third-party provider would not), (b) it works with stock system `ssh`,
  (c) it lets us serve the key as a **plain `ecdsa-sha2-nistp256`** key — any
  server accepts it, no `sk-`/FIDO support required — and (d) signing in our own
  process removes all the FIDO `sk_enroll`/`sk_sign` authData/flags/counter
  formatting complexity.
- **Selection is explicit, never ambient.** Primary usage is
  `ssh -o IdentityAgent=~/.ssh/se-agent.sock host` (per-command, no env, no
  `~/.ssh/config` edit). A convenience `eval $(se-ssh-agent -E)` sets
  `SSH_AUTH_SOCK` **for one shell session only** (opt-in, not a destructive
  global clobber like `SSH_SK_PROVIDER`).
- **keygen keeps `ssh-keygen` semantics** in our own binary (`-f`, `-C`,
  `-t ecdsa`), but the real `ssh-keygen` is never invoked. It cannot create our
  key anyway (it only makes on-disk or sk keys); generation must be our code.
- **No merge/proxy logic in our agent.** One agent = one socket; coexistence
  with 1Password/system agents is handled by external multiplexers
  (ssh-agent-mux / ssh-union-agent), not by us. We stay "one thing well."
- **No app state.** Keys are plain files in `~/.ssh` — a handle + a `.pub`, just
  like `ssh-keygen` output. No registry, no `~/.se-ssh` folder, no listing
  feature, no `doctor`. The agent is **stateless**: it derives the identities it
  serves from the `~/.ssh` handle files on demand and holds nothing. (`ssh-add
  -L` still works incidentally — that's just the protocol's identities request,
  which the agent must answer — but it's not a feature we build state around.)

## Locked architecture

Two executables (likely one multicall Swift binary dispatching on `argv[0]`, or
two thin products in one SwiftPM package):

1. **keygen** — emulates `ssh-keygen`. Creates a P-256 key in the Secure Enclave
   via CryptoKit `SecureEnclave.P256.Signing.PrivateKey` (`.userPresence` ACL).
   Writes exactly two files at the `-f` path, just like `ssh-keygen`:
   `<-f>` = the **handle file** (the opaque `dataRepresentation` blob, no usable
   secret — consumed only by our agent, never by `ssh`), and `<-f>.pub` = a
   standard `ecdsa-sha2-nistp256 …` line. Default `-f` is
   `~/.ssh/id_ecdsa_se` (separate from `ssh-keygen`'s `~/.ssh/id_ecdsa` so it
   doesn't clobber); the user may pass `-f ~/.ssh/id_ecdsa` to **promote it to
   the main identity**. Honors `-f`/`-C`/`-t ecdsa`; rejects
   `ed25519`/`rsa`/`-b`/`-N` with honest errors (SE is P-256-only; biometric
   replaces the passphrase).
2. **agent** — ssh-agent protocol over a Unix socket. Stateless: on each
   `REQUEST_IDENTITIES (11)→IDENTITIES_ANSWER (12)` it scans `~/.ssh` for handle
   files (recognized by a magic header) and returns their pubkeys; on
   `SIGN_REQUEST (13)→SIGN_RESPONSE (14)` it loads the handle matching the
   requested pubkey, reconstructs the SE key, and signs (Touch ID fires here).
   Other messages → `SSH_AGENT_FAILURE`. The **only** runtime artifact is the
   socket; place it in the existing `~/.ssh` (e.g. `~/.ssh/se-agent.sock`) so we
   create no new folder, and it gives a stable path for
   `-o IdentityAgent=~/.ssh/se-agent.sock`. Optionally accepts explicit handle
   paths as args; default is scan-`~/.ssh`. Provides `-E` env-emitter + lazy
   singleton daemon at that socket.

### State model: stateless agent, handle files in `~/.ssh`

There is **no app store and no `~/.se-ssh` folder**. The persistent "state" is
just the key files `ssh-keygen`-style usage already produces, living where normal
keys live:

```
~/.ssh/
  id_ecdsa_se        # handle file: magic header + opaque SE dataRepresentation
                     #   blob (no usable secret; read only by our agent)
  id_ecdsa_se.pub    # standard ecdsa-sha2-nistp256 … line
  se-agent.sock      # the one runtime artifact (recreated per run)
```

Why this works without entitlements: the `dataRepresentation` blob is decryptable
only by this Mac's SE and usable across our two separate binaries **without a
shared keychain-access-group** (which we can't have anyway — no signing
identity). So we deliberately use this CryptoKit path, **not** the
Security-framework/Keychain-access-group approach. The agent reconstructs the key
from the handle file on demand; nothing is registered or cached.

ACL is fixed at **`.userPresence`** (Touch ID with login-password fallback,
durable across fingerprint changes) — see Decisions.

### Wire formats (already pinned)

- **Public key:** `string "ecdsa-sha2-nistp256" ‖ string "nistp256" ‖ string Q`,
  Q = 65-byte `0x04‖X‖Y` from `publicKey.x963Representation`, base64'd.
- **Signature:** CryptoKit `signature(for: data)` (SHA-256 + ECDSA-P256) →
  `.rawRepresentation` (r‖s, 32 each) → encode r and s as SSH **mpints**
  (mind the 0x00 pad when the high bit is set) → wrap as
  `string "ecdsa-sha2-nistp256" ‖ string (mpint r ‖ mpint s)`.

## Constraints surfaced by machine inventory

- macOS 26.5.1 (Tahoe), Apple Silicon. **Swift 6.3.2, SwiftPM, Command Line
  Tools only — no full Xcode.app** (no `xcodebuild`/Xcode signing UI; use
  `codesign` from CLT). SwiftPM ad-hoc-signs Apple-Silicon binaries by default.
- **Zero code-signing identities** (`security find-identity -p codesigning` →
  0). No Apple Developer account. Consequences:
  - **Ad-hoc signing only.** No team-scoped entitlements, no keychain-access
    groups, no notarization yet. This is *why* we use the file-store.
  - **OSS distribution = build-from-source** for now (users run `swift build`,
    which ad-hoc-signs locally). Pre-built/notarized binaries or a Homebrew
    bottle require an Apple Developer ID + notarization — a later step gated on
    getting the account.
- Stock tooling present for verification: OpenSSH **10.3p1** at
  `/opt/homebrew/bin` (ssh/ssh-add/ssh-keygen), `sc_auth`, Homebrew.

## #1 feasibility risk — front-loaded as Milestone 0

Whether an **ad-hoc-signed CLI** can create an SE key with a biometric
access-control policy and actually trigger a **Touch ID** prompt on signing.
If ad-hoc proves insufficient (needs a self-signed cert + entitlements, or a real
Developer identity), that must be resolved before building anything else.

---

## Build milestones (risk-ordered)

Each milestone has a deliverable and an exit criterion. The single load-bearing
unknown is answered first; the highest-volume *pure* code is built before it
touches the SE.

### M0 — SE + Touch ID feasibility spike (go/no-go)
Throwaway `Sources/spike/` executable, built and run under the **exact signing
posture we'll ship** (SwiftPM default ad-hoc; confirm `codesign -dvvv` shows
`flags=0x2(adhoc)`). Steps, cheapest disproof first:
- 0a. Create `SecureEnclave.P256.Signing.PrivateKey()` (no ACL), persist
  `.dataRepresentation`, reload it in a **second process run**, sign. Proves SE
  works at all under ad-hoc.
- 0b. Add `SecAccessControlCreateWithFlags(..., [.privateKeyUsage, .userPresence], …)`;
  run interactively, confirm the **Touch ID sheet fires** and signing succeeds.
- 0c. Same, but create and sign in separate process invocations (cold blob reload).

**Exit:** a documented, reproducible result that an ad-hoc-signed CLI can create
a presence-gated SE key and sign behind a real Touch ID prompt, blob reloadable
across processes. **If it can't → STOP and escalate the signing decision**
(self-signed cert + entitlements, or get an Apple Developer ID) before any other
code. Capture the result as a written note in the repo.

### M1 — Package skeleton + pure wire library (no SE)
`Package.swift` + pure `SSHWire` target: SSH `uint32`/`string`/**`mpint`**
primitives, public-key blob builder, OpenSSH `.pub` line formatter, signature
blob builder (input = raw 64-byte r‖s), and ssh-agent message framing for
11/12/13/14 (+ FAILURE for the rest). **Keeping `SSHWire` SE-free is what makes
~90% of the suite CI-able.**
**Exit:** unit tests green against known-good vectors (Part: tests); round-trip
`decode(encode(x)) == x`.

### M2 — keygen tool (`se-ssh-keygen`)
Flag parser (`-f`, `-C`, `-t ecdsa`; honest rejections for ed25519/rsa/`-b`/`-N`).
Creates the `.userPresence` SE key (M0 recipe), writes exactly two files at the
`-f` path — `<-f>` (handle file: magic header + blob) and `<-f>.pub` (M1 encoder
line). Default `-f` = `~/.ssh/id_ecdsa_se`; passing `-f ~/.ssh/id_ecdsa` promotes
it to the main identity (refuse to overwrite an existing real private key without
explicit confirmation).
**Exit:** `ssh-keygen -l -f <path>.pub` fingerprints it without error; line shape
matches a stock `ssh-keygen -t ecdsa` `.pub`; the handle file carries the magic
header; errors exit non-zero with stderr only (nothing on stdout).

### M3 — agent socket + protocol (stateless)
`se-ssh-agent` core: bind Unix socket at `~/.ssh/se-agent.sock`, accept loop,
dispatch via M1 framing.
- **3a (no biometrics):** `REQUEST_IDENTITIES (11) → IDENTITIES_ANSWER (12)` —
  scan `~/.ssh` for handle files (magic header), return their pubkey blobs +
  comments. No signing ⇒ no Touch ID ⇒ fully scriptable. Nothing cached.
- **3b (biometric):** `SIGN_REQUEST (13) → SIGN_RESPONSE (14)` — find the handle
  whose pubkey matches the request, reload, `signature(for:)` (Touch ID), encode
  signature blob.
- Stub all else with `SSH_AGENT_FAILURE`.
- **macOS socket hygiene:** validate expanded `sun_path` ≤ 103 bytes (else clear
  error, no silent truncation); socket lives in the existing `~/.ssh` (no new
  folder); socket `0600`; unlink stale socket on startup; expand `~` defensively
  in-process.

**Exit:** `SSH_AUTH_SOCK=~/.ssh/se-agent.sock ssh-add -L` returns the key and
`ssh-add -l` shows a fingerprint matching the `.pub` — i.e. **stock `ssh-add`
parses our wire output** (authoritative check on 11/12 + pubkey bytes).

### M4 — End-to-end against real OpenSSH (the crypto proof)
Authorize the key (`ssh-copy-id -i <path>.pub localhost` or append to
`authorized_keys`); stand up stock sshd (macOS Remote Login, or a throwaway
`/opt/homebrew/sbin/sshd -d -p 2222 -f <tmp_conf>`).
**Exit:** `ssh -vvv -o IdentityAgent=~/.ssh/se-agent.sock -p 2222 localhost`
reaches `Authentication succeeded (publickey)` with `ecdsa-sha2-nistp256`, Touch
ID firing at the sign step; server-side `sshd -d` confirms the offered type is
plain `ecdsa-sha2-nistp256`, **never** `sk-ecdsa-…`. This is the definitive proof
the signature bytes are accepted by an unmodified verifier.

### M5 — eval / daemon ergonomics
`se-ssh-agent -E`: emit **only** eval-able shell to stdout
(`SSH_AUTH_SOCK=…; export …;`), diagnostics to stderr; Bourne/csh/fish variants
(`$SHELL` detect or `-s sh|csh|fish`). Lazy singleton: if no live daemon at the
fixed socket, fork a detached one then emit env; if alive, just emit env. Note:
the daemon needs the user's **GUI session** for Touch ID, so it's a per-user
background process / **LaunchAgent (not a LaunchDaemon)** — don't detach it out of
the GUI session.
**Exit:** `eval $(se-ssh-agent -E)` works in sh/csh/fish; a second eval spawns no
duplicate (`pgrep` shows one); stdout alone lints clean via `sh -n`.

### M6 — CI + packaging & distribution posture
- **CI:** `.github/workflows/ci.yml` on a `macos-…` runner: `swift build` +
  `swift test` (runs `SSHWireTests` + `AgentIntegrationTests`, including the
  injected-key e2e; `SEManualTests` excluded since `SE_MANUAL` is unset). This is
  the standing guard the "full seam" decision buys us.
- **Packaging:** `swift build -c release`, explicit ad-hoc sign, multicall/install
  layout, README documenting build-from-source + the no-Developer-account caveats.

**Exit:** CI green on a clean checkout; `swift build -c release` reproduces
M0–M5 behavior; `codesign -dv` confirms ad-hoc; README states the notarization
gap honestly.

## Test strategy (layered)

Fault line: **pure byte logic (CI-able, vector-checkable)** vs.
**SE/biometric/socket (hardware + interactive, local-only)**. Push everything
possible to the first side.

**Layer A — unit (CI, no SE/hardware):** all of `SSHWire`. Highest-value cases:
- **mpint high-bit padding** (the classic bug): leading byte `0x80–0xff` ⇒ one
  `0x00` prepended; `0x00–0x7f` ⇒ none; strip leading zeros in the raw 32-byte
  r/s; r or s shorter than 32 bytes encodes minimally.
- pubkey blob & `.pub` line; signature blob from fixed raw r‖s; agent framing
  (incl. truncated/oversized length prefix → graceful, unknown type → FAILURE);
  keygen flag parser; `-E` shell emitter.
- **Source vectors from real tooling, don't hand-author bytes:** decode a stock
  `ssh-keygen -t ecdsa` `.pub` middle field (`awk '{print $2}' | base64 -d | xxd`)
  for the canonical pubkey blob; commit captured signature fixtures; cross-check
  fingerprints via `ssh-keygen -l -f`.
- **Testability seam:** the signature builder takes raw 64-byte r‖s (not an SE
  key), so tests feed r‖s from a plain CryptoKit `P256.Signing.PrivateKey` (no
  SE, no Touch ID) and verify the full encode path with an independent verifier.

**Layer B — integration (CI on a Mac runner / scriptable local), biometrics
isolated:** start agent, point `SSH_AUTH_SOCK` at it, drive with **stock
`ssh-add -L`/`-l`** (no signing ⇒ no Touch ID — the most valuable automatable
test, since `ssh-add` is an independent parser of our wire output); `sun_path`
over-length refusal; stale-socket re-bind; singleton (two evals → one daemon).

**Layer C — end-to-end:**
- *Automatable variant (committed):* inject a plain in-process P256 key into the
  sign path so the whole encode → real-sshd `publickey` auth runs with **no
  Touch ID**; assert exit 0 + verbose `ecdsa-sha2-nistp256` acceptance. The
  injection is behind a **compile-time/test-only flag** (e.g. a `SEKeyStore`
  protocol with an `InMemoryP256` conformer wired only in the test target) so it
  **cannot ship in the release product** — pin this in code review.
- *Manual variant (the real proof):* identical flow with the **actual SE-backed**
  agent; human confirms Touch ID + success; record `ssh -vvv`.

**Cannot be automated in CI:** any real Touch ID / SE sign (needs a GUI session +
enrolled finger + per-machine SE; absent on hosted CI), and the M0 spike itself.
These are **documented manual checks**. Suite split: `SSHWireTests` (pure, CI),
`AgentIntegrationTests` (CI, non-biometric + injected-key e2e), `SEManualTests`
(gated by `SE_MANUAL=1`, real hardware, with exact human steps + expected
`ssh -vvv` lines in the README).

## SwiftPM / ad-hoc-signing gotchas (load-bearing)

- Test the **built binary on disk** (`.build/release/…`), not just `swift run` —
  SE/LocalAuthentication behavior depends on the signed Mach-O the kernel sees.
- **No team-scoped entitlements** (`com.apple.developer.*`) — ad-hoc can't satisfy
  them; the CryptoKit `dataRepresentation` path exists precisely to need none.
  No `--entitlements`, no `kSecAttrAccessGroup`, no shared keychain group.
- `SecAccessControl` must include **`.privateKeyUsage`** with the presence flag or
  signing fails opaquely. Pin the exact flag set in M0.
- Stay **pure SwiftPM** (`swift build`/`swift test`) — `xcodebuild` here is a CLT
  shim that fails without Xcode.app; introduce no `.xcodeproj` step.
- Link `CryptoKit`/`Security`/`LocalAuthentication` (auto via `import`, but verify
  in the spike).

## Distribution (no Developer account)

- **Today: build-from-source** is the only clean channel — `git clone &&
  swift build -c release` yields locally ad-hoc-signed binaries with no Gatekeeper
  friction (locally built ⇒ not quarantined). README says this plainly.
- Prebuilt downloads would be quarantined and Gatekeeper-blocked (ad-hoc ≠
  notarized); document the `xattr -dr com.apple.quarantine` / right-click-open
  workaround, don't pretend it's notarized.
- **Later, gated on an Apple Developer ID ($99/yr):** Developer ID signing +
  `notarytool` + `stapler`, hardened runtime; Homebrew = a **source-build
  formula** now (a binary cask needs notarized artifacts).

## Package layout / files to create

(`/Users/alonlivne/botanica-ssh` is empty today.)
- `Package.swift` — pure `SSHWire` lib + `SEKeyStore` lib + executable target(s)
  (two thin products, or one multicall binary dispatching on `argv[0]`).
- `Sources/SSHWire/` — wire encoders/decoders, mpint, agent framing, `-E` emitter
  (the CI-able core; no SE).
- `Sources/SEKeyStore/` — SE key create (`SecureEnclave.P256` + `SecAccessControl`)
  + handle-file write/read in `~/.ssh` (magic header + blob), and the stateless
  `~/.ssh` scan that maps pubkeys ↔ handle files. No registry, no store folder.
- `Sources/se-ssh-keygen/`, `Sources/se-ssh-agent/` — the two CLIs.
- `Sources/spike/` — M0 throwaway (never ships in release).
- `Tests/SSHWireTests`, `Tests/AgentIntegrationTests`, `Tests/SEManualTests`.
- `.github/workflows/ci.yml` — macOS runner, `swift build` + `swift test`.

## Decisions (resolved)
1. **Key ACL: `.userPresence`** — Touch ID with login-password fallback, durable
   across fingerprint changes. Already reflected in M0/M2.
2. **Testing: full automation seam + CI** — the test-only plain-key injection
   (Layer C automatable variant) and a GitHub Actions macOS workflow are in scope.
   Real-SE/Touch-ID paths remain gated `SEManualTests`.

(Naming: keep the `se-ssh-*` working prefix for now; the "cooler name" is
deferred to after it works, per your call.)
