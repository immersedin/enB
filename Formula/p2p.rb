class P2p < Formula
  desc "Decentralized end-to-end encrypted chat over a Kademlia DHT"
  homepage "https://github.com/immersedin/enB"
  url "https://github.com/immersedin/enB/archive/refs/tags/v0.3.8.tar.gz"
  sha256 "c0d72d3103b5834831ca049d71351b6b49967a67e2a58242d52cc8e18829c9ef"
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
