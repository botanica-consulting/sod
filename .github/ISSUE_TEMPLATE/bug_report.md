---
name: Bug report
about: Something isn't working
labels: bug
---

**What happened**
A clear description of the bug.

**Steps to reproduce**
1. `sd ssh-keygen ...`
2. `sd ssh-agent ...`
3. `sd ssh-add ...`
4. ...

**Expected vs actual**

**Environment**
- `sd --version`:
- macOS version:
- Mac: Apple Silicon / Intel + T2
- Backend: real Secure Enclave / `SE_SSH_MOCK=1`
- OpenSSH (`ssh -V`):

**Logs**
Relevant stderr from `sd ...`, or the agent log at `~/.ssh/sod-agent.sock.log`.
Do NOT paste private keys (there are none in the handle file, but still).
