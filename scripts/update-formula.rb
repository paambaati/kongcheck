#!/usr/bin/env ruby
# frozen_string_literal: true

# Renders Formula/kongcheck.rb from Formula/kongcheck.rb.erb.
# Called by .github/workflows/release.yml; must be run from the repo root.
#
# Required environment variables:
#   SHA_DARWIN_ARM64  SHA256 of the darwin-arm64 binary
#   SHA_DARWIN_X64    SHA256 of the darwin-x64 binary
#   SHA_LINUX_X64     SHA256 of the linux-x64 binary
#   SHA_LINUX_ARM64   SHA256 of the linux-arm64 binary

require 'erb'
require 'json'

version          = JSON.parse(File.read('package.json'))['version']
sha_darwin_arm64 = ENV.fetch('SHA_DARWIN_ARM64')
sha_darwin_x64   = ENV.fetch('SHA_DARWIN_X64')
sha_linux_x64    = ENV.fetch('SHA_LINUX_X64')
sha_linux_arm64  = ENV.fetch('SHA_LINUX_ARM64')

template = File.read('Formula/kongcheck.rb.erb')
output   = ERB.new(template, trim_mode: '-').result(binding)

File.write('Formula/kongcheck.rb', output)
puts "Formula/kongcheck.rb updated to v#{version}"
