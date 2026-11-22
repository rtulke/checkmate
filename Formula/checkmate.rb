class Checkmate < Formula
  desc "Command-based compliance checks for Linux, macOS and Windows"
  homepage "https://github.com/rtulke/checkmate"
  url "https://github.com/rtulke/checkmate/archive/refs/tags/v2.2.0.tar.gz"
  sha256 "f7d59bca4a5650f0a958f54476d04287ed16487aefcc1ff17e5c9c9cc595196b"
  license "Apache-2.0"
  head "https://github.com/rtulke/checkmate.git", branch: "main"

  depends_on "go" => :build

  def install
    pkg_version = build.head? ? "HEAD-#{Utils.git_short_head}" : version.to_s
    system "go", "build", *std_go_args(ldflags: "-s -w -X main.version=#{pkg_version}"), "./cmd/checkmate"

    date = Time.now.utc.strftime("%Y-%m-%d")
    {"checkmate.1" => man1, "checkmate-policy.5" => man5}.each do |page, dir|
      inreplace "packaging/man/#{page}", "@VERSION@", pkg_version
      inreplace "packaging/man/#{page}", "@DATE@", date
      dir.install "packaging/man/#{page}"
    end

    rm Dir["examples/**/*.go"]
    pkgshare.install "cis", "stig", "examples"
    doc.install "README.md", "README_de.md"
  end

  def caveats
    <<~EOS
      Policies are installed in:
        #{opt_pkgshare}/cis       CIS Benchmarks
        #{opt_pkgshare}/stig      DISA STIGs
        #{opt_pkgshare}/examples  examples, BSI, Si001, MITRE ATT&CK

      For example:
        sudo checkmate run #{opt_pkgshare}/cis/macos15.yml --tags cis-level-1
    EOS
  end

  test do
    assert_match "checkmate", shell_output("#{bin}/checkmate version")
    system bin/"checkmate", "validate", pkgshare/"examples/getting-started.yml"
  end
end
