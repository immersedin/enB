class Radius < Formula
  desc "Decentralized end-to-end encrypted chat over a Kademlia DHT"
  homepage "https://github.com/immersedin/enB"
  url "https://github.com/immersedin/enB/archive/refs/tags/v0.5.3.tar.gz"
  sha256 "ba2a7bdbc6504181b3eecd58f9f6a6aa92131dae54b259cc2d15635636c59214"
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
    bin.install "build/radius"
  end

  test do
    assert_match "ALL PASS", shell_output("#{bin}/radius --selftest")
  end
end
