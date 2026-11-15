#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Civilian danger assessment: a 0-100 danger index computed from the
// user's position and a set of manually reported combat events, mapped
// onto five levels (1 = critical .. 5 = no threat detected).
//
// Model (see al.md spec):
//   per-event contribution p_i = 100 * I_i * S_i * T_i * C_i
//     S_i = exp(-d_i^2 / (2 L_kind^2))   spatial Gaussian decay
//     T_i = 1 (ongoing) or exp(-age/tau) temporal decay
//     C_i = confidence from independent confirmations
//     I_i = intensity factor
//   combined index = 100 * (1 - prod(1 - p_i/100))  (noisy-OR, so one
//   well-confirmed event is never diluted by averaging)
//
// All numeric parameters are INITIAL CALIBRATION VALUES — they must be
// re-fit against historical civilian-harm data before production use.

enum class EventKind : uint8_t { Shelling = 0, Strike, Ground, Other };

struct DangerEvent {
    double lat = 0;
    double lon = 0;
    int64_t ts = 0;        // unix seconds when the event happened
    EventKind kind = EventKind::Other;
    int intensity = 1;     // 1..3 (light / moderate / heavy)
    int confirmations = 2; // independent confirmations
    bool ongoing = false;  // still in progress
    std::string note;
};

struct DangerContributor {
    size_t event_index = 0;
    double dist_km = 0;      // effective distance (uncertainty removed)
    double raw_dist_km = 0;  // true distance
    double contribution = 0; // 0..100
    double spatial = 0;
    double temporal = 0;
    double confidence = 0;
};

struct DangerAssessment {
    bool computed = false;  // false when no usable position is known
    int index = 0;          // 0..100
    int level = 5;          // 1..5
    double geo_uncertainty_km = 0;
    int events_used = 0;
    std::vector<DangerContributor> top;  // strongest contributors
};

const char* kind_name(EventKind k);
EventKind parse_kind(const std::string& s, bool* ok = nullptr);

// Great-circle distance in km.
double geo_distance_km(double lat1, double lon1, double lat2, double lon2);

// Deduplicate reports: same kind, centres within 3 km and times within
// 12 h are treated as one event (keeps the freshest timestamp, the max
// confirmations, and ongoing if any report says so).
std::vector<DangerEvent> dedup_events(const std::vector<DangerEvent>& in);

// Core model. `geo_uncertainty_km` is the user's position error
// (GPS ~0.05 km, IP geolocation ~25 km); it is subtracted from every
// distance — a conservative choice for civilian protection.
// `events` should already be deduplicated. `has_position` false yields
// computed=false.
DangerAssessment assess_danger(bool has_position, double lat, double lon,
                               double geo_uncertainty_km, int64_t now,
                               const std::vector<DangerEvent>& events);

// English level label, e.g. "critical".
const char* level_name(int level);

// Line-based persistence (one event per line, whitespace-separated,
// note may contain spaces). Used for data_dir/danger.txt.
bool save_events(const std::string& path,
                 const std::vector<DangerEvent>& events);
std::vector<DangerEvent> load_events(const std::string& path);
