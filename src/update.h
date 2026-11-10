#pragma once

#include <string>

// Auto-update support: queries GitHub releases for the latest version,
// downloads the matching asset and replaces the running binary.
namespace updater {

struct ReleaseInfo {
    std::string tag;           // e.g. "v0.1.2"
    std::string asset_name;    // e.g. "p2p-macos-arm64.zip"
    std::string download_url;
};

// Version baked in at build time (APP_VERSION define).
const char* current_version();

// Query GitHub for the latest release. Returns false on network or
// parse errors; `err` (optional) gets a human-readable reason.
bool fetch_latest(ReleaseInfo& out, std::string* err = nullptr);

// Compare dotted versions ("0.1.2" vs "0.1.10"); an optional leading
// 'v' is ignored. Returns <0, 0 or >0.
int compare_versions(const std::string& a, const std::string& b);

// Download the release asset, unpack it, replace the running binary and
// spawn the new instance. On success this returns true and the caller
// should exit the UI loop — a new process has been (or will be) started.
// On failure returns false and `err` describes why.
bool apply_update(const ReleaseInfo& rel, std::string& err);

}  // namespace updater
