#!/bin/bash
# Build (if needed) and run the Radius chat TUI application.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -x "cmake-build-debug/radius" ]; then
    ./build.sh
fi

exec ./cmake-build-debug/radius
