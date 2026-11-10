class P2p < Formula
  desc "Decentralized end-to-end encrypted chat over a Kademlia DHT"
  homepage "https://github.com/immersedin/enB"
  url "https://github.com/immersedin/enB/archive/refs/tags/v0.3.4.tar.gz"
  sha256 "b9a512f2eb0aea00618f9f9c17f7d44cf0a8b4f24e0280ff185cef2326351fe4"
  head "https://github.com/immersedin/enB.git", branch: "main"

  depends_on "cmake" => :build
  depends_on "ninja" => :build
  depends_on "asio"
  depends_on "libsodium"
  depends_on "sqlcipher"
  depends_on "ftxui"

  def install
    system "cmake", "-S", ".", "-B", "build",
           "-DCMAKE_BUILD_TYPE=Release",
           "-GNinja",
           *std_cmake_args
    system "cmake", "--build", "build"
    bin.install "build/p2p"
  end

  test do
    assert_match "ALL PASS", shell_output("#{bin}/p2p --selftest")
  end
end
