class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.1.7"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.7/kongcheck-darwin-arm64"
      sha256 "d2487b3f239f67a2e2f79ac3de01232fc90d8b88c3e35d3ba95f119acb036ff4"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.7/kongcheck-darwin-x64"
      sha256 "6d7e02063279e8bac2cf480856cc777cf1e9c7fc13e8c30838557834102400df"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.7/kongcheck-linux-arm64"
      sha256 "19dea21c1b9e588de4f13591b493b5bee84d736aa3491a5840e992574d4a3860"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.7/kongcheck-linux-x64"
      sha256 "f553e961f6ac46eadd593941d3a841ca63bdd750cd7ae8e8e3d4f18a7dc3d4a2"
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
