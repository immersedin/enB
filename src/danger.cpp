#include "danger.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace {

constexpr double kPi = 3.14159265358979323846;

// ---- calibration parameters (INITIAL VALUES, need empirical fit) ----
// L_kind: spatial scale of influence, km. A munition's hazard footprint
// is much smaller than the area where civilians may be affected by
// shelling; strikes get the widest footprint because blast/fragmentation
// reports cluster around wider areas.
struct KindParams {
    double L_km;    // Gaussian spatial scale
    double tau_h;   // temporal decay constant, hours
};
KindParams params_for(EventKind k) {
    switch (k) {
        case EventKind::Shelling: return {12.0, 48.0};
        case EventKind::Strike:   return {25.0, 24.0};
        case EventKind::Ground:   return {8.0, 96.0};
        case EventKind::Other:    return {10.0, 48.0};
    }
    return {10.0, 48.0};
}

// Fixed uncertainty of a manually entered event coordinate, km.
constexpr double kEventUncKm = 1.0;
// Dedup window: same kind, this close in space and time -> one event.
constexpr double kDedupDistKm = 3.0;
constexpr int64_t kDedupTimeS = 12 * 3600;
// Reports older than this contribute ~nothing and are ignored entirely.
constexpr int64_t kMaxAgeS = 30LL * 24 * 3600;

// Level thresholds on the 0-100 index. Chosen so that only a nearby,
// fresh, well-confirmed event reaches level 1.
constexpr int kLevel1 = 70;
constexpr int kLevel2 = 45;
constexpr int kLevel3 = 20;
constexpr int kLevel4 = 3;

double clamp01(double v) { return std::min(1.0, std::max(0.0, v)); }

}  // namespace

const char* kind_name(EventKind k) {
    switch (k) {
        case EventKind::Shelling: return "shelling";
        case EventKind::Strike:   return "strike";
        case EventKind::Ground:   return "ground";
        case EventKind::Other:    return "other";
    }
    return "other";
}

EventKind parse_kind(const std::string& s, bool* ok) {
    std::string t;
    for (char c : s) t += static_cast<char>(std::tolower(c));
    if (t == "shelling" || t == "shell" || t == "artillery") {
        if (ok) *ok = true;
        return EventKind::Shelling;
    }
    if (t == "strike" || t == "missile" || t == "airstrike" ||
        t == "bomb") {
        if (ok) *ok = true;
        return EventKind::Strike;
    }
    if (t == "ground" || t == "infantry" || t == "clash") {
        if (ok) *ok = true;
        return EventKind::Ground;
    }
    if (t == "other") {
        if (ok) *ok = true;
        return EventKind::Other;
    }
    if (ok) *ok = false;
    return EventKind::Other;
}

double geo_distance_km(double lat1, double lon1, double lat2, double lon2) {
    constexpr double kR = 6371.0;  // Earth mean radius, km
    double p1 = lat1 * kPi / 180.0, p2 = lat2 * kPi / 180.0;
    double dp = (lat2 - lat1) * kPi / 180.0;
    double dl = (lon2 - lon1) * kPi / 180.0;
    double a = std::sin(dp / 2) * std::sin(dp / 2) +
               std::cos(p1) * std::cos(p2) * std::sin(dl / 2) *
                   std::sin(dl / 2);
    return 2 * kR * std::asin(std::sqrt(std::min(1.0, a)));
}

const char* level_name(int level) {
    switch (level) {
        case 1: return "critical";
        case 2: return "high";
        case 3: return "elevated";
        case 4: return "low";
        case 5: return "none detected";
    }
    return "?";
}

std::vector<DangerEvent> dedup_events(const std::vector<DangerEvent>& in) {
    std::vector<DangerEvent> out;
    for (const auto& e : in) {
        bool merged = false;
        for (auto& o : out) {
            if (o.kind != e.kind) continue;
            if (std::llabs(o.ts - e.ts) > kDedupTimeS) continue;
            if (geo_distance_km(o.lat, o.lon, e.lat, e.lon) >
                kDedupDistKm)
                continue;
            // Same event reported twice: keep freshest data.
            if (e.ts > o.ts) o.ts = e.ts;
            o.confirmations = std::max(o.confirmations, e.confirmations);
            o.intensity = std::max(o.intensity, e.intensity);
            o.ongoing = o.ongoing || e.ongoing;
            if (o.note.empty()) o.note = e.note;
            merged = true;
            break;
        }
        if (!merged) out.push_back(e);
    }
    return out;
}

DangerAssessment assess_danger(bool has_position, double lat, double lon,
                               double geo_uncertainty_km, int64_t now,
                               const std::vector<DangerEvent>& events) {
    DangerAssessment a;
    a.geo_uncertainty_km = geo_uncertainty_km;
    if (!has_position) return a;
    a.computed = true;

    double survive = 1.0;  // product of (1 - p_i/100)
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& e = events[i];
        if (now - e.ts > kMaxAgeS || e.ts - now > 3600) continue;

        auto kp = params_for(e.kind);
        double raw = geo_distance_km(lat, lon, e.lat, e.lon);
        // Conservative: subtract BOTH the user's and the event's
        // position uncertainty — protection-oriented, never optimistic.
        double d = std::max(0.0, raw - geo_uncertainty_km - kEventUncKm);

        double spatial = std::exp(-(d * d) / (2 * kp.L_km * kp.L_km));
        double age_h = std::max(0.0, (now - e.ts) / 3600.0);
        double temporal =
            e.ongoing ? 1.0 : std::exp(-age_h / kp.tau_h);
        double confidence = clamp01(e.confirmations / 3.0);
        double intensity = clamp01(e.intensity / 3.0);

        double p = 100.0 * intensity * spatial * temporal * confidence;
        p = std::min(100.0, p);

        ++a.events_used;
        survive *= 1.0 - p / 100.0;
        a.top.push_back({i, d, raw, p, spatial, temporal, confidence});
    }
    a.index = static_cast<int>(std::lround(100.0 * (1.0 - survive)));

    if (a.index >= kLevel1) a.level = 1;
    else if (a.index >= kLevel2) a.level = 2;
    else if (a.index >= kLevel3) a.level = 3;
    else if (a.index >= kLevel4) a.level = 4;
    else a.level = 5;

    std::sort(a.top.begin(), a.top.end(),
              [](const DangerContributor& x, const DangerContributor& y) {
                  return x.contribution > y.contribution;
              });
    if (a.top.size() > 5) a.top.resize(5);
    return a;
}

bool save_events(const std::string& path,
                 const std::vector<DangerEvent>& events) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    for (const auto& e : events) {
        f << e.ts << " " << e.lat << " " << e.lon << " "
          << kind_name(e.kind) << " " << e.intensity << " "
          << e.confirmations << " " << (e.ongoing ? 1 : 0);
        // note: rest of line, spaces allowed
        std::string note = e.note;
        for (auto& c : note)
            if (c == '\n' || c == '\r') c = ' ';
        if (!note.empty()) f << " " << note;
        f << "\n";
    }
    return static_cast<bool>(f);
}

std::vector<DangerEvent> load_events(const std::string& path) {
    std::vector<DangerEvent> out;
    std::ifstream f(path);
    if (!f) return out;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        DangerEvent e;
        std::string kind;
        int ongoing = 0;
        if (!(iss >> e.ts >> e.lat >> e.lon >> kind >> e.intensity >>
              e.confirmations >> ongoing))
            continue;
        bool ok = false;
        e.kind = parse_kind(kind, &ok);
        if (!ok) continue;
        e.ongoing = ongoing != 0;
        std::getline(iss, e.note);
        if (!e.note.empty() && e.note.front() == ' ')
            e.note.erase(e.note.begin());
        out.push_back(e);
    }
    return out;
}
