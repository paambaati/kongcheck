class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.1.6"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.6/kongcheck-darwin-arm64"
      sha256 "9a2ee8a6bc77edfc2a2935027a33f4253c830f8294b36fdb8c443fb251210df8"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.6/kongcheck-darwin-x64"
      sha256 "5c96ae88e531ff1710ddea2d89a5319c7ccec52d18d04a91c8cbea388ede731a"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.6/kongcheck-linux-arm64"
      sha256 "f41e76edffed7a21824fbac1a1a34e5973edbf0b11688b6cc9d6a11d1d5440e3"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.1.6/kongcheck-linux-x64"
      sha256 "f19c333a3c8765ed862a17b835e83cfb613a92ccfa392b5137afbafc241ab498"
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
