# Mirror of the tap formula. The live copy belongs at:
#   botanica-consulting/homebrew-tap → Formula/sod.rb   (so `brew install botanica-consulting/tap/sod`)
# Fill in `revision` with the tagged commit SHA when cutting a release.
class Sod < Formula
  desc "Secure-Enclave-backed SSH agent and keygen (Touch ID on every signature)"
  homepage "https://github.com/botanica-consulting/sod"
  url "https://github.com/botanica-consulting/sod.git", tag: "v0.1.0", revision: "FILL_IN_40CHAR_SHA"
  license "MIT"
  head "https://github.com/botanica-consulting/sod.git", branch: "main"

  depends_on xcode: ["15.0", :build]
  depends_on macos: :ventura          # macOS 13+

  def install
    ENV["SOD_VERSION"] = version.to_s   # gen-version.sh override (no .git in a brew checkout)
    system "swift", "build", "--configuration", "release",
           "--arch", "arm64", "--arch", "x86_64", "--disable-sandbox"
    bin.install ".build/apple/Products/Release/sod"
    man1.install "man/sod.1"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sod --version")
    assert_match "usage", shell_output("#{bin}/sod ssh-keygen --help 2>&1")
  end
end
