# M0 result: SE + Touch ID feasibility spike — **GO**

**Date:** 2026-06-25 · **Machine:** arm64 macOS 26.5.1, Swift 6.3.2, CLT only, 0 codesigning identities.

## Question (the project's single load-bearing risk)
Can an **ad-hoc-signed** CLI (no Apple Developer ID, no entitlements, no
keychain-access-group) create a Secure Enclave P-256 key with a biometric
(`.userPresence`) access policy, and **sign behind a real Touch ID prompt**, with
the wrapped key blob reloadable **across separate process invocations**?

## Answer: YES on all counts.

### Signing posture of the binary under test (`.build/debug/spike`)
```
CodeDirectory ... flags=0x2(adhoc)
Signature=adhoc
TeamIdentifier=not set
entitlements: only com.apple.security.get-task-allow  (debug-build artifact; absent in release)
```
This is the exact posture we ship: ad-hoc, no team-scoped Developer entitlements.

### Evidence (CryptoKit `SecureEnclave.P256.Signing.PrivateKey`)
- **0a — SE works under ad-hoc + cross-process reload, no biometrics.**
  `gen-noacl` created a key (pub=65B `x963`, blob=284B `dataRepresentation`);
  a **separate** `sign-noacl` process reloaded the blob and signed (64B raw r‖s),
  `isValidSignature == true`, **no prompt**. Proves the wrapped blob is
  SE/device-bound, not App-ID-bound — reloadable across processes with no shared
  keychain group.
- **0b — `.userPresence` key signs behind Touch ID (in-process).**
  Access control = `SecAccessControlCreateWithFlags(nil,
  kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence])`.
  Creation did **not** prompt; `signature(for:)` fired a real **Touch ID** sheet;
  approved → `valid=true`.
- **0c — the production scenario: cold-reload + sign across processes (Touch ID).**
  `gen-acl` created+persisted a presence-gated key (no prompt). A **separate**
  `sign-acl` process cold-reloaded the blob via `init(dataRepresentation:)` and
  signed → **Touch ID fired**, `valid=true`. This mirrors keygen (one process) and
  agent (another process) exactly.

### Facts pinned for the build
- `publicKey.x963Representation` = **65 bytes** (`0x04‖X‖Y`).
- `dataRepresentation` = **~284 bytes** opaque SEP-wrapped blob (no usable secret).
- `signature(for:).rawRepresentation` = **64 bytes** (r‖s, 32 each).
- **`.privateKeyUsage` is required** in the access-control flags alongside the
  presence flag, or signing fails.
- **Key creation does not prompt**; only signing does.
- The access policy is bound to the key in the SE — reloading via
  `init(dataRepresentation:)` re-enforces Touch ID on sign with no need to
  re-specify the access control.

### Corroborating prior art (from the verification pass)
`maxgoedjen/secretive` (v3 CryptoKit path) and `bioenv` (ad-hoc CLI, 2026) use the
same file-blob + CryptoKit design; Apple DTS retracted the old "SE key is tied to
App ID" claim (it's device-bound). secretive carries no SE entitlement — its
keychain/Team-ID coupling exists only because it shares the blob between two
*separately-signed* executables via the keychain, which our single-binary
file-blob design avoids entirely.

## Decision
**GO.** No signing escalation needed. Proceed to M1–M4 on the ad-hoc/file-blob path.
