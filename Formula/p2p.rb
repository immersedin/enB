class P2p < Formula
  desc "Decentralized end-to-end encrypted chat over a Kademlia DHT"
  homepage "https://github.com/immersedin/enB"
  url "https://github.com/immersedin/enB/archive/refs/tags/v0.4.2.tar.gz"
  sha256 "6f5d8d1fa2be2bc81180e37f30cc7294f50790c169bc950454267455ecb40a41"
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
