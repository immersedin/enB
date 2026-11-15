#!/bin/bash
# Build the Radius chat TUI application.
set -euo pipefail
cd "$(dirname "$0")"

BUILD_DIR="cmake-build-debug"

# Dependencies (Homebrew):
#   brew install ftxui sqlcipher libsodium asio

cmake -S . -B "$BUILD_DIR" -DCMAKE_BUILD_TYPE=Debug
cmake --build "$BUILD_DIR" -j"$(sysctl -n hw.ncpu)"

echo "Built: $BUILD_DIR/radius"
