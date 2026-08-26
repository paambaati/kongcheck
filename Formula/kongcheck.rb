class Kongcheck < Formula
  desc "CLI tool for detecting Kong Konnect route collisions and shadowing"
  homepage "https://github.com/paambaati/kongcheck"
  license "MIT"
  version "1.3.0"

  on_macos do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.3.0/kongcheck-darwin-arm64"
      sha256 "73cc50225846d4bf0bd9baa4ed836fd55582a5b52fe617079ec2ca25e9cd2d78"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.3.0/kongcheck-darwin-x64"
      sha256 "44e91c2196996c886060ecc867dabddb7a9d3037e80826659cae3972d0624cfb"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.3.0/kongcheck-linux-arm64"
      sha256 "3b7dffef3e2e7a26cce169fcf6289b4a78fe5f202e72d07023ee1b013c2e82d3"
    end
    on_intel do
      url "https://github.com/paambaati/kongcheck/releases/download/v1.3.0/kongcheck-linux-x64"
      sha256 "1d30c60f20d08ea7a4b1082ad9cedf134381cb8493ca487aed2b1cbb2bc69e3e"
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
