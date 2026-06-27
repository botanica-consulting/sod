# Source-of-truth for the tap formula at botanica-consulting/homebrew-tap →
# Formula/sod.rb (so `brew install botanica-consulting/tap/sod`). It builds sod from
# source. On a tagged release, scripts/publish-formula.sh fills __TAG__ / __REVISION__
# below and pushes the rendered formula to the tap (see release.yml; gated on
# HOMEBREW_TAP_TOKEN). Before the first tag, `brew install --HEAD …/tap/sod` builds main.
class Sod < Formula
  desc "Secure-Enclave-backed SSH agent and keygen (Touch ID on every signature)"
  homepage "https://github.com/botanica-consulting/sod"
  url "https://github.com/botanica-consulting/sod.git", tag: "__TAG__", revision: "__REVISION__"
  license "MIT"
  head "https://github.com/botanica-consulting/sod.git", branch: "main"

  depends_on xcode: ["15.0", :build]
  depends_on macos: :ventura          # macOS 13+

  def install
    # Sources/sod/Version.swift (defines Build.version) is generated + gitignored, so a
    # brew checkout lacks it. Generate it before building; gen-version.sh uses SOD_VERSION
    # when there's no .git (as in a release tarball checkout).
    ENV["SOD_VERSION"] = version.to_s
    system "bash", "scripts/gen-version.sh"
    system "swift", "build", "--configuration", "release",
           "--arch", "arm64", "--arch", "x86_64", "--disable-sandbox"
    bin.install ".build/apple/Products/Release/sd"
    man1.install "man/sd.1"
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
