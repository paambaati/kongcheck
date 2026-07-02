class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.1.4"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.4/kongcheck-darwin-arm64"
      sha256 "dbd5b07d957cfb9c7d848e91c44ca03b102b80659ebdac6b0d9cba7011740fb7"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.4/kongcheck-darwin-x64"
      sha256 "6f63eb113409a2640a3acccd67262e8c21bbf355a7443e18e855555f157bb692"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.4/kongcheck-linux-arm64"
      sha256 "0ef4ae27ee81aea1fbdcdd565c5362e53628ed8878510ef8a5f8ccb000bed4a6"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.4/kongcheck-linux-x64"
      sha256 "2f7f3fbbc25cbe3c92776fe374fbe39c9341ffdb30ab936f73b282cd275e693d"
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
