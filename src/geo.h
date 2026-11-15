#pragma once

#include <optional>
#include <string>
#include <vector>

// A precise device position fix (GPS/Wi-Fi positioning), as opposed to
// IP-based geolocation which is only city-accurate.
struct GeoFix {
    double lat = 0;
    double lon = 0;
    double accuracy_m = -1;  // horizontal accuracy, -1 = unknown
};

// Device-level positioning. Implemented with CoreLocation on macOS
// (returns nullopt when the binary is not inside a signed .app bundle
// with a location usage description, or when permission is denied) and
// with WinRT Windows.Devices.Geolocation.Geolocator on Windows (the
// system consent prompt appears on first use) and with GeoClue2 on
// Linux (system D-Bus, ~20 s timeout). Denied/unavailable/missing
// service returns nullopt. Other platforms return nullopt.
std::optional<GeoFix> platform_location();

struct GeoInfo {
    bool ok = false;        // at least one source produced data
    bool precise = false;   // coords come from device positioning
    double lat = 0;
    double lon = 0;
    double accuracy_m = -1;
    std::string ip;         // public IP (best known)
    std::string city;
    std::string region;
    std::string country;
    std::string isp;
    std::vector<std::string> local_ips;  // non-loopback interface addrs
};

// Gather everything the UI needs to show "where am I". Blocking — call
// from a worker thread. `fallback_ip` is used when the geo service does
// not report the client IP (e.g. the DHT-observed public endpoint).
GeoInfo fetch_geo_info(const std::string& fallback_ip = "");
