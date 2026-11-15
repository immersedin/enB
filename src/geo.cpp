#include "geo.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "endpoint.h"

#if !defined(__APPLE__) && !defined(_WIN32) && !defined(__linux__)
// CoreLocation (macOS), WinRT Geolocator (Windows) and GeoClue2 (Linux)
// implementations live in geo_macos.mm / geo_windows.cpp / geo_linux.cpp.
std::optional<GeoFix> platform_location() { return std::nullopt; }
#endif

namespace fs = std::filesystem;

namespace {

std::string own_pid() {
#ifdef _WIN32
    return std::to_string(GetCurrentProcessId());
#else
    return std::to_string(getpid());
#endif
}

// GET `url` with curl into a temp file and return its body. Returns ""
// on any failure. Mirrors the curl-based download in update.cpp.
std::string curl_get(const std::string& url, int max_time) {
    fs::path dir;
    try {
        dir = fs::temp_directory_path();
    } catch (...) {
        return "";
    }
    fs::path out = dir / ("p2p-geo-" + own_pid() + ".json");
    fs::path errf = dir / ("p2p-geo-" + own_pid() + ".err");
    std::string cmd = "curl -fsSL --connect-timeout 5 --max-time " +
                      std::to_string(max_time) + " -o " + "\"" +
                      out.string() + "\" \"" + url + "\" 2>\"" +
                      errf.string() + "\"";
    int rc = std::system(cmd.c_str());
    std::string body;
    if (rc == 0) {
        std::ifstream f(out, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        body = ss.str();
    }
    std::error_code ec;
    fs::remove(out, ec);
    fs::remove(errf, ec);
    return body;
}

// Extract a JSON string value for `key` (first occurrence).
bool json_string(const std::string& js, const std::string& key,
                 std::string& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = js.find(pat);
    if (p == std::string::npos) return false;
    p = js.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    p = js.find('"', p + 1);
    if (p == std::string::npos) return false;
    ++p;
    std::string v;
    while (p < js.size()) {
        char c = js[p];
        if (c == '\\' && p + 1 < js.size()) {
            v += js[p + 1];
            p += 2;
            continue;
        }
        if (c == '"') break;
        v += c;
        ++p;
    }
    out = v;
    return true;
}

bool json_number(const std::string& js, const std::string& key,
                 double& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = js.find(pat);
    if (p == std::string::npos) return false;
    p = js.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    ++p;
    while (p < js.size() &&
           (js[p] == ' ' || js[p] == '\t' || js[p] == '\n' || js[p] == '\r'))
        ++p;
    char* end = nullptr;
    out = std::strtod(js.c_str() + p, &end);
    return end != js.c_str() + p;
}

}  // namespace

GeoInfo fetch_geo_info(const std::string& fallback_ip) {
    GeoInfo g;

    // Precise device position first — it can take up to ~20 s while
    // CoreLocation/WinRT acquires a fix, so start it before the network
    // call. (platform_location is a stub returning nullopt elsewhere.)
    if (auto fix = platform_location()) {
        g.precise = true;
        g.lat = fix->lat;
        g.lon = fix->lon;
        g.accuracy_m = fix->accuracy_m;
        g.ok = true;
    }

    // IP-based geolocation: ipwho.is is keyless and HTTPS.
    std::string js = curl_get("https://ipwho.is/", 20);
    if (!js.empty()) {
        std::string ip, city, region, country, isp;
        double lat = 0, lon = 0;
        json_string(js, "ip", ip);
        json_string(js, "city", city);
        json_string(js, "region", region);
        json_string(js, "country", country);
        json_string(js, "isp", isp);  // inside "connection"
        json_number(js, "latitude", lat);
        json_number(js, "longitude", lon);
        if (!ip.empty() || lat != 0 || lon != 0 || !city.empty() ||
            !country.empty()) {
            if (!ip.empty()) g.ip = ip;
            g.city = city;
            g.region = region;
            g.country = country;
            g.isp = isp;
            if (!g.precise && (lat != 0 || lon != 0)) {
                g.lat = lat;
                g.lon = lon;
            }
            g.ok = true;
        }
    }
    if (g.ip.empty()) g.ip = fallback_ip;

    // Local interface addresses (LAN IPs).
    for (auto& ep : local_endpoints(1)) {
        if (std::find(g.local_ips.begin(), g.local_ips.end(), ep.addr) ==
            g.local_ips.end())
            g.local_ips.push_back(ep.addr);
    }
    return g;
}
