# Build the p2p chat TUI application on Windows via vcpkg (MSVC, static deps).
# Produces build/Release/p2p.exe — a single-file binary for Windows 10 x64.
param(
    [string]$VcpkgTriplet = "x64-windows-static-md",
    [string]$VcpkgRoot = $(if ($env:VCPKG_INSTALLATION_ROOT) { $env:VCPKG_INSTALLATION_ROOT } else { "C:\vcpkg" })
)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$vcpkg = Join-Path $VcpkgRoot "vcpkg.exe"
& $vcpkg install asio libsodium sqlcipher ftxui --triplet $VcpkgTriplet

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release `
    -DCMAKE_TOOLCHAIN_FILE="$VcpkgRoot/scripts/buildsystems/vcpkg.cmake" `
    -DVCPKG_TARGET_TRIPLET=$VcpkgTriplet
cmake --build build --config Release

Write-Host "Built: $(Join-Path $PSScriptRoot 'build/Release/p2p.exe')"
