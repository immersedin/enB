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
    std::string cmd = "curl -fsSL -A \"p2p-chat\" "
                      "--connect-timeout 5 --max-time " +
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

// Percent-encode a URL query value (' ' becomes '+').
std::string url_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else if (c == ' ') {
            out += '+';
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

// Brace-matched top-level {...} objects of a JSON array.
std::vector<std::string> json_objects(const std::string& js) {
    std::vector<std::string> out;
    for (size_t i = 0; i < js.size(); ++i) {
        if (js[i] != '{') continue;
        int depth = 0;
        size_t start = i;
        for (; i < js.size(); ++i) {
            if (js[i] == '{') ++depth;
            else if (js[i] == '}' && --depth == 0) break;
        }
        if (i >= js.size()) break;
        out.push_back(js.substr(start, i - start + 1));
    }
    return out;
}

// "10,381,222" style grouping for population counts.
std::string format_count(double v) {
    std::string s = std::to_string(static_cast<long long>(v));
    for (int i = static_cast<int>(s.size()) - 3; i > 0; i -= 3)
        s.insert(static_cast<size_t>(i), ",");
    return s;
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

std::vector<PlaceHit> search_places(const std::string& query,
                                    int max_results,
                                    const std::string& cursor,
                                    std::string* next_cursor) {
    std::vector<PlaceHit> out;
    if (query.empty() || max_results <= 0) return out;
    // api.cityapi.org — GeoNames settlement data, keyless.
    std::string url = "https://api.cityapi.org/v1/cities?search=" +
                      url_encode(query) + "&limit=" +
                      std::to_string(max_results);
    if (!cursor.empty()) url += "&cursor=" + url_encode(cursor);
    std::string js = curl_get(url, 20);
    if (js.empty()) return out;

    // Pagination token for the next page.
    if (next_cursor) {
        size_t p = js.find("\"next_cursor\"");
        if (p != std::string::npos) {
            p = js.find(':', p);
            if (p != std::string::npos) {
                p = js.find('"', p + 1);
                if (p != std::string::npos) {
                    size_t e = js.find('"', p + 1);
                    if (e != std::string::npos)
                        *next_cursor = js.substr(p + 1, e - p - 1);
                }
            }
        }
    }

    // Isolate the "data" array so the root object's braces do not
    // swallow the per-city objects during brace matching.
    size_t d = js.find("\"data\"");
    if (d == std::string::npos) return out;
    d = js.find('[', d);
    if (d == std::string::npos) return out;
    size_t m = js.find("\"meta\"", d);
    std::string arr = js.substr(d + 1,
                                m == std::string::npos
                                    ? std::string::npos
                                    : m - d - 1);

    for (auto& obj : json_objects(arr)) {
        PlaceHit h;
        json_string(obj, "name", h.name);
        if (h.name.empty()) json_string(obj, "ascii_name", h.name);
        std::string cc;
        json_string(obj, "country_code", cc);
        double pop = 0;
        bool has_pop = json_number(obj, "population", pop);
        // latitude/longitude are JSON numbers (population may be null).
        if (!json_number(obj, "latitude", h.lat) ||
            !json_number(obj, "longitude", h.lon))
            continue;
        h.detail = h.name;
        if (!cc.empty()) h.detail += ", " + cc;
        if (has_pop && pop > 0) h.detail += " — pop " + format_count(pop);
        if (h.name.empty()) continue;
        out.push_back(std::move(h));
        if (static_cast<int>(out.size()) >= max_results) break;
    }
    return out;
}
