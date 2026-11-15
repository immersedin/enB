class P2p < Formula
  desc "Decentralized end-to-end encrypted chat over a Kademlia DHT"
  homepage "https://github.com/immersedin/enB"
  url "https://github.com/immersedin/enB/archive/refs/tags/v0.5.1.tar.gz"
  sha256 "4c8c18a04d4b608fc1178d1e3831cc99ecae3b14515cf657187d03fe4a66fdd0"
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
