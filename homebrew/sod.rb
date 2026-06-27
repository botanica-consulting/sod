# Template for the tap formula. The LIVE copy belongs at:
#   botanica-consulting/homebrew-tap → Formula/sod.rb   (so `brew install botanica-consulting/tap/sod`)
#
# release.yml (scripts/publish-formula.sh) fills __VERSION__ / __URL__ / __SHA256__ from
# each tagged release and pushes the rendered formula to the tap. This installs the
# prebuilt, Developer-ID-signed universal binary straight from the GitHub Release — no
# Xcode, no source build. Homebrew strips the download quarantine, so Gatekeeper is
# satisfied without a separate notarization of the bare binary.
class Sod < Formula
  desc "Secure-Enclave-backed SSH agent and keygen (Touch ID on every signature)"
  homepage "https://github.com/botanica-consulting/sod"
  version "__VERSION__"
  url "__URL__"
  sha256 "__SHA256__"
  license "MIT"

  depends_on macos: :ventura          # macOS 13+ (Secure Enclave)

  def install
    bin.install "sd"
    man1.install "sd.1"
  end

  def caveats
    <<~EOS
      Set sod up to run at login (it never edits your shell files — it prints the
      line for you to paste):

        sd ssh-keygen    # if you don't have a key yet
        sd install       # run the agent at login + print the SSH_AUTH_SOCK line

      Before `brew uninstall`, run `sd uninstall` to remove the login agent.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sd --version")
    assert_match "usage", shell_output("#{bin}/sd ssh-keygen --help 2>&1")
  end
end
