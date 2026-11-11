#include "update.h"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

#ifndef APP_VERSION
#define APP_VERSION "0.0.0"
#endif
#ifndef P2P_UPDATE_REPO
#define P2P_UPDATE_REPO "immersedin/enB"
#endif
#ifndef P2P_UPDATE_ASSET
#define P2P_UPDATE_ASSET ""
#endif

namespace fs = std::filesystem;

namespace updater {
namespace {

std::string exe_name() {
#ifdef _WIN32
    return "p2p.exe";
#else
    return "p2p";
#endif
}

fs::path self_exe() {
#ifdef _WIN32
    wchar_t buf[32768];
    DWORD n = GetModuleFileNameW(nullptr, buf, sizeof(buf) / sizeof(buf[0]));
    return n ? fs::path(std::wstring(buf, n)) : fs::path();
#elif defined(__APPLE__)
    char buf[PATH_MAX];
    uint32_t size = sizeof(buf);
    if (_NSGetExecutablePath(buf, &size) == 0) {
        std::error_code ec;
        fs::path p = fs::canonical(fs::path(buf), ec);
        return ec ? fs::path(buf) : p;
    }
    return fs::path(buf);
#else
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n <= 0) return fs::path();
    buf[n] = '\0';
    return fs::path(buf);
#endif
}

std::string pid_string() {
#ifdef _WIN32
    return std::to_string(GetCurrentProcessId());
#else
    return std::to_string(getpid());
#endif
}

// Double-quote a path for the system shell.
std::string sq(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\\\"";
        out += c;
    }
    return out + "\"";
}

bool cmd_ok(const std::string& cmd) {
    int r = std::system(cmd.c_str());
#ifdef _WIN32
    return r == 0;
#else
    return r != -1 && WEXITSTATUS(r) == 0;
#endif
}

// Run curl; stderr goes to <dest>.curl.err so it cannot corrupt the TUI.
bool curl_to_file(const std::string& url, const std::vector<std::string>& headers,
                  const fs::path& dest, std::string& err) {
    fs::path errf = dest.parent_path() / (dest.filename().string() + ".err");
    std::string cmd = "curl -fSL --connect-timeout 10 --retry 2";
    for (const auto& h : headers) cmd += " -H " + sq(h);
    cmd += " -o " + sq(dest.string()) + " " + sq(url) + " 2>" + sq(errf.string());
    if (cmd_ok(cmd)) return true;
    std::ifstream ef(errf);
    std::stringstream ss;
    ss << ef.rdbuf();
    err = ss.str();
    auto b = err.find_first_not_of(" \t\r\n");
    auto e = err.find_last_not_of(" \t\r\n");
    err = (b == std::string::npos) ? "download failed" : err.substr(b, e - b + 1);
    return false;
}

// Extract a JSON string value for `key` within [from, end). Returns the
// position just past the closing quote via `next`.
bool json_string(const std::string& js, const std::string& key, size_t from,
                 size_t end, std::string& out, size_t* next = nullptr) {
    std::string pat = "\"" + key + "\"";
    size_t p = js.find(pat, from);
    if (p == std::string::npos || p >= end) return false;
    p = js.find(':', p + pat.size());
    if (p == std::string::npos || p >= end) return false;
    p = js.find('"', p + 1);
    if (p == std::string::npos || p >= end) return false;
    ++p;
    std::string v;
    while (p < end && p < js.size()) {
        char c = js[p];
        if (c == '\\' && p + 1 < js.size() && p + 1 < end) {
            v += js[p + 1];
            p += 2;
            continue;
        }
        if (c == '"') break;
        v += c;
        ++p;
    }
    out = v;
    if (next) *next = p + 1;
    return true;
}

// Bounds of the JSON object containing position `pos` (brace matching,
// good enough for the GitHub releases payload).
std::pair<size_t, size_t> object_bounds(const std::string& js, size_t pos) {
    size_t start = std::string::npos, end = std::string::npos;
    int depth = 0;
    for (size_t i = pos; i-- > 0;) {
        if (js[i] == '}') ++depth;
        else if (js[i] == '{') {
            if (depth == 0) { start = i; break; }
            --depth;
        }
    }
    depth = 0;
    for (size_t i = pos; i < js.size(); ++i) {
        if (js[i] == '{') ++depth;
        else if (js[i] == '}') {
            if (depth == 0) { end = i + 1; break; }
            --depth;
        }
    }
    return {start, end};
}

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

}  // namespace

const char* current_version() { return APP_VERSION; }

int compare_versions(const std::string& a, const std::string& b) {
    auto parts = [](std::string v) {
        std::vector<int> out;
        size_t i = v.find_first_of("0123456789");
        if (i == std::string::npos) return out;
        v = v.substr(i);
        std::stringstream ss(v);
        std::string part;
        while (std::getline(ss, part, '.')) {
            int n = 0;
            for (char c : part) {
                if (!std::isdigit(static_cast<unsigned char>(c))) break;
                n = n * 10 + (c - '0');
            }
            out.push_back(n);
        }
        return out;
    };
    auto pa = parts(a), pb = parts(b);
    size_t n = std::max(pa.size(), pb.size());
    for (size_t i = 0; i < n; ++i) {
        int x = i < pa.size() ? pa[i] : 0;
        int y = i < pb.size() ? pb[i] : 0;
        if (x != y) return x < y ? -1 : 1;
    }
    return 0;
}

bool fetch_latest(ReleaseInfo& out, std::string* err) {
    auto fail = [&](const std::string& m) {
        if (err) *err = m;
        return false;
    };

    fs::path tmp;
    try {
        tmp = fs::temp_directory_path() /
              ("p2p-rel-" + pid_string());
        fs::create_directories(tmp);
    } catch (const std::exception& e) {
        return fail(std::string("temp dir: ") + e.what());
    }
    fs::path json_path = tmp / "latest.json";
    std::string api = "https://api.github.com/repos/" P2P_UPDATE_REPO
                      "/releases/latest";
    std::string dl_err;
    if (!curl_to_file(api,
                      {"Accept: application/vnd.github+json",
                       "User-Agent: p2p-chat"},
                      json_path, dl_err)) {
        fs::remove_all(tmp);
        return fail("cannot reach GitHub: " + dl_err);
    }

    std::string js = read_file(json_path);
    fs::remove_all(tmp);

    std::string tag;
    if (!json_string(js, "tag_name", 0, js.size(), tag) || tag.empty())
        return fail("no release tag in response");
    out.tag = tag;

    // Locate the asset object whose "name" matches our platform package.
    const std::string asset = P2P_UPDATE_ASSET;
    size_t pos = 0;
    while ((pos = js.find("\"browser_download_url\"", pos)) !=
           std::string::npos) {
        auto [s, e] = object_bounds(js, pos);
        if (s == std::string::npos) break;
        std::string name, url;
        json_string(js, "name", s, e, name);
        json_string(js, "browser_download_url", s, e, url);
        if (name == asset && !url.empty()) {
            out.asset_name = name;
            out.download_url = url;
            return true;
        }
        ++pos;
    }
    return fail("release " + tag + " has no asset " + asset);
}

bool apply_update(const ReleaseInfo& rel, std::string& err) {
    auto fail = [&](const std::string& m) {
        err = m;
        return false;
    };

    if (P2P_UPDATE_ASSET[0] == '\0' || rel.download_url.empty())
        return fail("no update package for this platform");
    if (compare_versions(rel.tag, current_version()) <= 0)
        return fail("already up to date");

    fs::path self;
    try {
        self = self_exe();
    } catch (...) {
    }
    if (self.empty()) return fail("cannot locate own executable");

    // Work inside a hidden dir next to the executable: same filesystem
    // (required for atomic rename / MoveFile) and easy cleanup.
    fs::path work;
    try {
        work = self.parent_path() /
               (".p2p-update-" + pid_string());
        fs::create_directories(work / "extract");
    } catch (const std::exception& e) {
        return fail(std::string("work dir: ") + e.what());
    }
    auto cleanup = [&] { std::error_code ec; fs::remove_all(work, ec); };

    fs::path zip = work / "update.zip";
    std::string dl_err;
    if (!curl_to_file(rel.download_url, {}, zip, dl_err)) {
        cleanup();
        return fail("download failed: " + dl_err);
    }

    if (!cmd_ok("tar -xf " + sq(zip.string()) + " -C " +
                sq((work / "extract").string()))) {
        cleanup();
        return fail("failed to unpack update archive");
    }

    // Find the payload binary inside the archive.
    fs::path bin, payload_dir;
    std::error_code ec;
    for (fs::recursive_directory_iterator it(work / "extract", ec), end;
         !ec && it != end; it.increment(ec)) {
        if (it->is_regular_file() &&
            it->path().filename() == exe_name()) {
            bin = it->path();
            payload_dir = it->path().parent_path();
            break;
        }
    }
    if (bin.empty()) {
        cleanup();
        return fail("update archive has no " + exe_name());
    }

#ifdef _WIN32
    // A running .exe cannot be overwritten, but it CAN be renamed.
    // Move it aside, move the new binary into place, relaunch, exit.
    fs::path old = self;
    old += ".old";
    fs::remove(old, ec);
    if (!MoveFileW(self.wstring().c_str(), old.wstring().c_str())) {
        cleanup();
        return fail("cannot move current executable aside");
    }
    if (!MoveFileW(bin.wstring().c_str(), self.wstring().c_str())) {
        MoveFileW(old.wstring().c_str(), self.wstring().c_str());
        cleanup();
        return fail("cannot install new executable");
    }
    std::wstring cmdline = L"\"" + self.wstring() + L"\"";
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(self.wstring().c_str(), cmdline.data(), nullptr,
                        nullptr, FALSE, DETACHED_PROCESS |
                            CREATE_NEW_PROCESS_GROUP,
                        nullptr, nullptr, &si, &pi)) {
        cleanup();
        return fail("update installed but relaunch failed");
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    cleanup();
    return true;
#else
    fs::path spawn_exe = self;

    // Nearest enclosing .app bundle, if any.
    auto app_ancestor = [](const fs::path& p) {
        for (fs::path d = p.parent_path(); !d.empty() && d != d.root_path();
             d = d.parent_path())
            if (d.extension() == ".app") return d;
        return fs::path();
    };
    fs::path self_bundle = app_ancestor(self);
    fs::path src_bundle = app_ancestor(bin);

    if (!self_bundle.empty() && !src_bundle.empty()) {
        // The release asset is a whole .app (binary + bundled dylibs +
        // signature, install names rewritten to @rpath). Replacing only
        // the Mach-O inside the installed bundle would break its
        // signature and leave the new binary unable to find its dylibs,
        // so swap the entire bundle instead.
        fs::path dst = self_bundle;
        fs::path old = dst;
        old += ".p2p-old";
        fs::remove_all(old, ec);
        fs::rename(dst, old, ec);
        if (ec) {
            cleanup();
            return fail("cannot move current app aside");
        }
        std::error_code ec2;
        fs::copy(src_bundle, dst, fs::copy_options::recursive, ec2);
        if (ec2) {
            fs::rename(old, dst, ec);
            cleanup();
            return fail("cannot install new app bundle");
        }
        // Re-sign ad-hoc so the copied bundle is accepted (arm64
        // requires at least an ad-hoc signature on every Mach-O).
        cmd_ok("codesign --force --deep --sign - " + sq(dst.string()));
        spawn_exe = dst / bin.lexically_relative(src_bundle);
        fs::permissions(spawn_exe,
                        fs::perms::owner_exec | fs::perms::group_exec |
                            fs::perms::others_exec,
                        fs::perm_options::add, ec);
        // The old bundle's files can be unlinked while the process
        // keeps running from its inode; best effort.
        fs::remove_all(old, ec);
    } else {
        // Copy every payload file next to the running binary via
        // write-temp + rename (atomic; safe over a running executable).
        fs::path target_dir = self.parent_path();
        for (const auto& de :
             fs::directory_iterator(payload_dir, ec)) {
            if (ec || !de.is_regular_file()) continue;
            fs::path dst = target_dir / de.path().filename();
            fs::path tmpf =
                target_dir / (de.path().filename().string() + ".p2p-new");
            fs::copy_file(de.path(), tmpf,
                          fs::copy_options::overwrite_existing, ec);
            if (ec) {
                cleanup();
                return fail("cannot write " +
                            dst.filename().string());
            }
            fs::permissions(
                tmpf,
                fs::perms::owner_all | fs::perms::group_read |
                    fs::perms::others_read | fs::perms::owner_exec |
                    fs::perms::group_exec | fs::perms::others_exec,
                fs::perm_options::replace, ec);
            fs::rename(tmpf, dst, ec);
            if (ec) {
                std::error_code ec2;
                fs::remove(tmpf, ec2);
                cleanup();
                return fail("cannot replace " +
                            dst.filename().string());
            }
        }
    }

    // Spawn the new instance slightly later, then let the caller exit.
    pid_t pid = fork();
    if (pid == 0) {
        usleep(400000);
        setsid();
        execl(spawn_exe.c_str(), "p2p", static_cast<char*>(nullptr));
        _exit(127);
    }
    cleanup();
    return pid > 0;
#endif
}

}  // namespace updater
