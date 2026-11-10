#!/bin/bash
# Build (if needed) and run the p2p chat TUI application.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x "cmake-build-debug/p2p" ]; then
    ./build.sh
fi

exec ./cmake-build-debug/p2p
