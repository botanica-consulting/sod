---
name: Bug report
about: Something isn't working
labels: bug
---

**What happened**
A clear description of the bug.

**Steps to reproduce**
1. `sod ssh-keygen ...`
2. `sod ssh-agent ...`
3. `sod ssh-add ...`
4. ...

**Expected vs actual**

**Environment**
- `sod --version`:
- macOS version:
- Mac: Apple Silicon / Intel + T2
- Backend: real Secure Enclave / `SE_SSH_MOCK=1`
- OpenSSH (`ssh -V`):

**Logs**
Relevant stderr from `sod ...`, or the agent log at `~/.ssh/sod-agent.sock.log`.
Do NOT paste private keys (there are none in the handle file, but still).
