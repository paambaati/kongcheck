class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.1.5"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.5/kongcheck-darwin-arm64"
      sha256 "cee46d2fc561090c8420c67c9bd3ce9fba8f4e6abed1f7a4ded319d83c3195d5"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.5/kongcheck-darwin-x64"
      sha256 "f2a0f30e03c57f90342e657cb8e3bd8c46380b10357b7d1559a20e53cde7616c"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.5/kongcheck-linux-arm64"
      sha256 "dde585c5fd14e091cdf993ba9505b5c8eb1387ae6d6d9b87a7bb76b6e3feecc8"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.5/kongcheck-linux-x64"
      sha256 "888c9a83ad36ea62b011b6d2c7ee2c5b811bbbfc38c7efc6aa95a5bddd73044f"
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
