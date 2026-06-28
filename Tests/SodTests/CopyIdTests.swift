import SodKit

/// `sd ssh-copy-id` argument handling — pure, so it runs without a Secure Enclave or mock.
func runCopyIdSuite(_ h: Harness) {
    // No identity given → the default sod pub is injected as -i.
    h.ok(!sshCopyIdHasIdentity(["user@host"]), "no -i present")
    h.eq(
        sshCopyIdArgs(["user@host"], defaultPub: "/k.pub"),
        ["-i", "/k.pub", "user@host"], "default -i prepended")

    // Other ssh-copy-id flags are not mistaken for an identity, and order is preserved.
    h.ok(!sshCopyIdHasIdentity(["-p", "2222", "host"]), "-p is not -i")
    h.eq(
        sshCopyIdArgs(["-p", "2222", "host"], defaultPub: "/k.pub"),
        ["-i", "/k.pub", "-p", "2222", "host"], "default prepended ahead of other flags")

    // An explicit identity (separate `-i file` or combined `-i<file>`) is left untouched.
    h.ok(sshCopyIdHasIdentity(["-i", "/my.pub", "host"]), "-i separate detected")
    h.eq(
        sshCopyIdArgs(["-i", "/my.pub", "host"], defaultPub: "/k.pub"),
        ["-i", "/my.pub", "host"], "explicit -i kept verbatim")
    h.ok(sshCopyIdHasIdentity(["-i/my.pub", "host"]), "-i<file> combined form detected")
}
