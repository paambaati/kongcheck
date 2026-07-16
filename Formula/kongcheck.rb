class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.2.0"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.2.0/kongcheck-darwin-arm64"
      sha256 "7d39123aff16e0754abe14d51f75e4c3d72ed74ec4f3a3017cea739376eb2849"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.2.0/kongcheck-darwin-x64"
      sha256 "30b1ba26f777899403ea895f41cbe6ef8b6828bfd5447ba25b5844b7053af013"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.2.0/kongcheck-linux-arm64"
      sha256 "9763fe3413375e2c3233f0cd633c5bea70c15ab5057c97d952f6fae126ae9335"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.2.0/kongcheck-linux-x64"
      sha256 "72fc8344a7b4babf66e84cc3db0d78c547ebf6584dfa615f8a6e5ec0810dd9a2"
    end
  end

  def install
    binary = Dir["kongcheck-*"].first
    bin.install binary => "kongcheck"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/kongcheck --version")
  end
end
