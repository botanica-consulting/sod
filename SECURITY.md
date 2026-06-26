# Security Policy

`sod` guards SSH authentication keys, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue for a vulnerability.** Instead, either:

- Use GitHub's **private vulnerability reporting** (the *Report a vulnerability*
  button under the repository's *Security* tab), or
- Email **security@botanica.consulting** with details and, if possible, a proof of
  concept.

We aim to acknowledge a report within **3 business days** and to agree on a
disclosure timeline with you. Please give us a reasonable window to ship a fix
before any public disclosure.

## Supported versions

Until a 1.0 release, only the latest tagged release (and `main`) receive security
fixes.

## Scope notes

- The private key is generated in and never leaves the Secure Enclave; the on-disk
  handle (`~/.ssh/id_sod`) is an opaque, device-bound blob with no usable secret.
  Reports that assume the handle file contains a private key are out of scope.
- Touch ID (`.userPresence`) is enforced by the Secure Enclave at signature time, not
  by the agent. The PKCS#11 PIN sent by stock `ssh-add -s` is intentionally ignored.
- The agent listens on a `0600` unix socket under `~/.ssh` and never modifies your
  default `SSH_AUTH_SOCK` unless you `eval` it.
