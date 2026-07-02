class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.1.3"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.3/kongcheck-darwin-arm64"
      sha256 "50cabf0cf29bb459c36f0e3856e51669abc8a35f3e5119e292c6fc4b41c935fb"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.3/kongcheck-darwin-x64"
      sha256 "27329b17a41065d6c6b9930362ec03ced1f51876d56f80c40ec4ff563752b99f"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.3/kongcheck-linux-arm64"
      sha256 "5d51442b8e6ecb235aa902180e1e7924b3f5727077c00930d7b6ab0b7db37a33"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.3/kongcheck-linux-x64"
      sha256 "4782fb55774ae01306302d70619848abf3422403440b7403e4afda0b8b2cd5e3"
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
