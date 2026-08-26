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

  depends_on macos: :ventura          # macOS 13+
  # No `depends_on xcode`: a single-arch source build needs only the Command Line Tools.
  # (A universal `swift build --arch …` would require full Xcode/xcbuild; brew compiles
  # locally for THIS machine, so single-arch is correct. The distributed .pkg stays universal.)

  def install
    # Sources/sod/Version.swift (defines Build.version) is generated + gitignored, so a
    # brew checkout lacks it. Generate it before building; gen-version.sh uses SOD_VERSION
    # when there's no .git (as in a release tarball checkout).
    ENV["SOD_VERSION"] = version.to_s
    system "bash", "scripts/gen-version.sh"
    # Build only the `sd` product (skips compiling the sod-tests target).
    system "swift", "build", "--configuration", "release", "--disable-sandbox", "--product", "sd"
    bin.install ".build/release/sd"
    man1.install "man/sd.1"
    # Completions are emitted by the binary (swift-argument-parser), so they always
    # match the CLI. base_name "sd" keeps the files named after the command, not "sod".
    generate_completions_from_executable(bin/"sd", "--generate-completion-script",
                                         base_name: "sd", shells: [:bash, :zsh, :fish],
                                         shell_parameter_format: :arg)
  end

  def caveats
    <<~EOS
      Run `sd install` to finish setup.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sd --version")
    assert_match "usage", shell_output("#{bin}/sd ssh-keygen --help 2>&1")
  end
end
