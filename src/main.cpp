// Radius — FTXUI frontend.
//
// Security stack:
//   - Noise_XX_25519_ChaChaPoly_SHA256 handshake (mutual auth via DH)
//   - Ed25519 identity signatures binding the signing key to the DH key
//   - Double Ratchet session layer (per-message X25519 DH + KDF chain)
//   - SQLCipher-encrypted SQLite for friends and history
//   - Identity keys stored as 0600 files (desktop equivalent of a
//     platform keystore; on Android/iOS this maps to Keystore/Keychain)
//
// All actions are driven by slash commands typed into the input line:
//   /help /friends /add <name> <host> <port> /remove <name>
//   /chat <name> /close /quit
//   /peerid /invite /connect /copyid
// Plain text is sent to the currently open chat.
// PgUp/PgDn, arrows and the mouse wheel scroll the console/chat panes.

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <cctype>
#include <cstring>
#include <iterator>
#include <memory>
#include <map>
#include <sstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#if !defined(_WIN32)
#include <sys/wait.h>
#endif

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/screen/terminal.hpp>

#include "ai.h"
#include "audio.h"
#include "crypto.h"
#include "danger.h"
#include "db.h"
#include "dht.h"
#include "endpoint.h"
#include "geo.h"
#include "invite.h"
#include "net.h"
#include "news.h"
#include "selftest.h"
#include "update.h"

#ifndef APP_VERSION
#define APP_VERSION "dev"
#endif

using namespace ftxui;
namespace fs = std::filesystem;

namespace {

struct ChatLine {
    bool outgoing = false;
    std::string text;
};

struct FriendView {
    Friend f;
    bool online = false;
    std::string peer_key;  // x25519 pub hex, known after first handshake
    std::string display_name;
    std::vector<ChatLine> lines;
    bool history_loaded = false;
    int chat_scroll = 0;  // lines scrolled up from the bottom; 0 = latest
};

// A city tracked for danger assessment. Coordinates come from
// `/city add <lat> <lon>` or a Nominatim place search.
struct TrackedCity {
    std::string name;
    double lat = 0;
    double lon = 0;
};

struct Config {
    int port = 5555;
    int dht_port = 0;  // 0 = same number as port (UDP)
    std::string name = "me";
    std::vector<std::string> bootstraps;  // raw "host:port" DHT endpoints
    std::string openai_key;               // legacy: for /danger ai
    std::string ai_key;                   // AI provider key (Groq etc.)
    std::string ai_base;                  // chat-completions URL (optional)
    std::string ai_model;                 // model name (optional)
    bool sound_enabled = true;  // chime on danger-level changes
    bool sound_level[5] = {true, true, true, true, true};  // L1..L5
    // Chosen notification sound per level; "" = platform default.
    std::string sound_pick[5];
    // Output device id ("" = system default).
    std::string sound_out;
};

Config load_config(const std::string& path) {
    Config c;
    std::ifstream f(path);
    std::string line;
    auto onoff = [](const std::string& v) {
        std::string s;
        for (char ch : v)
            s += static_cast<char>(
                std::tolower(static_cast<unsigned char>(ch)));
        return !(s.empty() || s == "0" || s == "off" ||
                 s == "false" || s == "no");
    };
    auto trim = [](std::string& s) {
        auto b = s.find_first_not_of(" \t\r\n");
        auto e = s.find_last_not_of(" \t\r\n");
        s = (b == std::string::npos) ? "" : s.substr(b, e - b + 1);
    };
    while (std::getline(f, line)) {
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string k = line.substr(0, pos), v = line.substr(pos + 1);
        trim(k);
        trim(v);
        if (k == "port") {
            try {
                c.port = std::stoi(v);
            } catch (...) {
            }
        } else if (k == "dht_port") {
            try {
                c.dht_port = std::stoi(v);
            } catch (...) {
            }
        } else if (k == "name") {
            c.name = v;
        } else if (k == "bootstrap") {
            if (!v.empty()) c.bootstraps.push_back(v);
        } else if (k == "openai_key") {
            c.openai_key = v;
        } else if (k == "ai_key") {
            c.ai_key = v;
        } else if (k == "ai_base") {
            c.ai_base = v;
        } else if (k == "ai_model") {
            c.ai_model = v;
        } else if (k == "sound") {
            c.sound_enabled = onoff(v);
        } else if (k.size() == 8 && k.rfind("sound_l", 0) == 0 &&
                   k[7] >= '1' && k[7] <= '5') {
            c.sound_level[k[7] - '1'] = onoff(v);
        } else if (k.size() == 11 && k.rfind("sound_pick", 0) == 0 &&
                   k[10] >= '1' && k[10] <= '5') {
            c.sound_pick[k[10] - '1'] = v;
        } else if (k == "sound_out") {
            c.sound_out = v;
        }
    }
    return c;
}

std::vector<std::string> split_args(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string w;
    while (iss >> w) out.push_back(w);
    return out;
}

std::string to_lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(c));
    return s;
}

std::string peer_id_hex(const Identity& id) {
    return crypto::to_hex(id.x25519.pub.data(), 32);
}

std::string short_id(const std::string& hex_id) {
    return hex_id.substr(0, 16);
}

bool is_peer_id(const std::string& s) {
    if (s.size() != 64) return false;
    for (char c : s)
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

// Read an invitation code from a file (e.g. one written by
// `/invite save <file>`). Returns the first whitespace-separated
// token; empty string on failure.
std::string read_code_file(const std::string& path) {
    std::ifstream f(path);
    if (!f) return "";
    std::string content((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
    auto b = content.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    auto e = content.find_first_of(" \t\r\n", b);
    return content.substr(b, e == std::string::npos ? e : e - b);
}

int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

int64_t unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

// Local YYYY-MM-DD used for daily log file names.
std::string today_log_name() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[16];
    std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
    return buf;
}

// Text rows available for the scrollable pane. The fixed chrome around it
// is: header (1) + separator (1) + input (1) + status line (1) +
// window border (2) + inner padding (2).
int pane_rows() {
    return std::max(3, Terminal::Size().dimy - 8);
}

// Copy `text` to the OS clipboard via a platform tool. The payload goes
// through a temp file so no shell escaping of the text is needed.
bool copy_to_clipboard(const std::string& text) {
    fs::path tmp = fs::temp_directory_path() / "radius-clipboard.txt";
    {
        std::ofstream f(tmp, std::ios::trunc);
        f << text << "\n";
        if (!f) return false;
    }
    const std::string q = "'" + tmp.string() + "'";
#ifdef _WIN32
    return std::system(("clip < " + q).c_str()) == 0;
#elif defined(__APPLE__)
    return std::system(("pbcopy < " + q).c_str()) == 0;
#else
    if (std::system(("wl-copy < " + q + " 2>/dev/null").c_str()) == 0)
        return true;
    if (std::system(("xclip -selection clipboard < " + q +
                     " 2>/dev/null").c_str()) == 0)
        return true;
    return std::system(("xsel --clipboard --input < " + q +
                        " 2>/dev/null").c_str()) == 0;
#endif
}

}  // namespace

// ------------------------------------------------------------------
// Application state shared between UI and network threads.
// ------------------------------------------------------------------
struct ChatApp {
    std::string data_dir;
    Config config;
    Identity identity;
    Database db;
    std::unique_ptr<Net> net;
    std::unique_ptr<Dht> dht;

    std::vector<FriendView> friends;
    int64_t open_friend_id = -1;

    enum class Mode { Home, Chat };
    Mode mode = Mode::Home;

    std::vector<std::string> console;  // command output on Home screen
    int console_scroll = 0;            // lines scrolled up; 0 = latest
    // Daily file mirror of the console: data_dir/logs/YYYY-MM-DD.log,
    // reopened when the date rolls over. Guarded by log_mu.
    std::mutex log_mu;
    std::ofstream log_file;
    std::string log_date;
    std::string notice;

    std::mutex inbox_mu;
    std::vector<std::pair<std::string, std::string>> inbox;  // key,text
    struct Status {
        int64_t friend_id;
        std::string peer_key;
        bool online;
        std::string name;
    };
    std::vector<Status> statuses;
    std::vector<std::string> notices;  // one-shot messages from worker threads

    // Auto-update state. latest_release/update_available are guarded by
    // update_mu; update_running is atomic.
    mutable std::mutex update_mu;
    updater::ReleaseInfo latest_release;
    std::atomic<bool> update_running{false};

    // Geolocation state, filled in by a worker thread after startup.
    mutable std::mutex geo_mu;
    GeoInfo geo;
    bool geo_done = false;

    // Manually reported combat events for the danger assessment.
    // Only touched on the UI thread.
    std::vector<DangerEvent> danger_events;

    // Cities tracked for danger assessment (persisted in
    // cities.txt). `cities` is UI-thread only; `city_hits` and
    // `city_pending_add` are touched by the place-search worker under
    // city_mu.
    std::vector<TrackedCity> cities;
    mutable std::mutex city_mu;
    std::vector<PlaceHit> city_hits;
    std::string city_cursor;       // next_cursor of the last page
    std::string city_last_query;   // UI thread only
    std::atomic<bool> city_search_running{false};
    std::vector<PlaceHit> city_pending_add;

    // AI (LLM) danger verdict shown on the Main tab. ai_danger is
    // written by the worker thread under ai_mu.
    struct AiDanger {
        bool running = false;
        bool have_verdict = false;
        int level = 0;
        int index = -1;
        std::string reason;
        std::string error;
        std::string model;
        int64_t ts = 0;  // last attempt, unix seconds
    };
    mutable std::mutex ai_mu;
    AiDanger ai_danger;
    // Per-city AI verdicts keyed by city name; guarded by ai_mu.
    struct CityVerdict {
        bool running = false;
        bool have = false;
        int level = 0;
        int index = -1;
        std::string reason;
        std::string error;
        std::string model;
        int64_t ts = 0;       // last finished attempt
        int64_t updated = 0;  // last successful refresh
    };
    std::map<std::string, CityVerdict> city_ai;
    // Sequential refresh rotation over all locations: refresh_targets()
    // order is own location first (once geo resolves), then tracked
    // cities. refresh_next advances only after a successful request —
    // a failed location is retried once ~60 s later before moving on.
    // refresh_fails counts consecutive failures of the current target.
    std::atomic<size_t> refresh_next{0};
    std::atomic<int64_t> refresh_last_query{0};
    std::atomic<bool> refresh_running{false};
    std::atomic<int> refresh_fails{0};
    // Per-city AI exchange logs: data_dir/logs/cities/<name>.log,
    // one lazily-opened ofstream per city guarded by city_log_mu.
    mutable std::mutex city_log_mu;
    std::map<std::string, std::ofstream> city_logs;
    // Danger level the sound notifier last chimed for; -1 = unprimed.
    int sound_last_level = -1;
    // Repeating-alert state (UI thread only): deadline of the next
    // repeat in steady-clock ms, and whether /sound ack muted the
    // current alert until the level changes.
    int64_t sound_alarm_next_ms = 0;
    bool sound_alarm_acked = false;

    ChatApp(const std::string& dir, const Config& cfg)
        : data_dir(dir), config(cfg), db(dir) {}

    FriendView* find_by_id(int64_t id) {
        for (auto& fv : friends)
            if (fv.f.id == id) return &fv;
        return nullptr;
    }
    FriendView* find_by_peer_key(const std::string& key) {
        for (auto& fv : friends)
            if (!fv.peer_key.empty() && fv.peer_key == key) return &fv;
        return nullptr;
    }
    // Case-insensitive name lookup; also accepts unique prefix.
    FriendView* find_by_name(const std::string& name) {
        std::string want = to_lower(name);
        FriendView* found = nullptr;
        int matches = 0;
        for (auto& fv : friends) {
            std::string have = to_lower(fv.display_name);
            if (have == want) {
                found = &fv;
                ++matches;
            } else if (have.rfind(want, 0) == 0 && !want.empty()) {
                if (!found) found = &fv;
                ++matches;
            }
        }
        return matches == 1 ? found : nullptr;
    }
};

namespace {

void say(ChatApp& app, const std::string& line) {
    app.console.push_back(line);
    if (app.console.size() > 200) app.console.erase(app.console.begin());
    // Mirror every console line into today's log file so the session
    // history survives restarts and the 200-line in-memory cap.
    std::lock_guard lk(app.log_mu);
    std::string date = today_log_name();
    if (date != app.log_date) {
        app.log_file.close();
        fs::create_directories(app.data_dir + "/logs");
        app.log_file.open(app.data_dir + "/logs/" + date + ".log",
                          std::ios::app);
        app.log_date = date;
    }
    if (app.log_file) app.log_file << line << "\n";
}

// Post a message from a worker thread; `wake` must trigger a UI redraw
// (e.g. screen.PostEvent(Event::Custom)).
void post_notice(ChatApp& app, const std::string& msg,
                 const std::function<void()>& wake) {
    {
        std::lock_guard lk(app.inbox_mu);
        app.notices.push_back(msg);
    }
    if (wake) wake();
}

// Local "YYYY-MM-DD HH:MM:SS" timestamp for log file lines.
std::string local_timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
    char buf[24];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

// ------------------------------------------------------------------
// Tracked cities (/city)
// ------------------------------------------------------------------

// City-center coordinates are a point estimate; 10 km is the
// city-scale position uncertainty fed into the danger model.
constexpr double kCityUncertaintyKm = 10.0;

std::vector<TrackedCity> load_cities(const std::string& path) {
    std::vector<TrackedCity> out;
    std::ifstream f(path);
    std::string line;
    while (std::getline(f, line)) {
        auto p1 = line.find('|');
        if (p1 == std::string::npos) continue;
        auto p2 = line.find('|', p1 + 1);
        if (p2 == std::string::npos) continue;
        TrackedCity c;
        c.name = line.substr(0, p1);
        try {
            c.lat = std::stod(line.substr(p1 + 1, p2 - p1 - 1));
            c.lon = std::stod(line.substr(p2 + 1));
        } catch (...) {
            continue;
        }
        out.push_back(c);
    }
    return out;
}

void save_cities(const std::string& path,
                 const std::vector<TrackedCity>& cities) {
    std::ofstream f(path, std::ios::trunc);
    if (!f) return;
    for (auto& c : cities) {
        std::string name = c.name;
        for (auto& ch : name)
            if (ch == '|' || ch == '\n' || ch == '\r') ch = ' ';
        f << name << "|" << c.lat << "|" << c.lon << "\n";
    }
}

// Display name stored for a settlement hit: "Name, CC" from the API
// detail (the population suffix is dropped), else the short name.
std::string city_hit_name(const PlaceHit& h) {
    std::string n = h.detail.empty() ? h.name : h.detail;
    size_t dash = n.find(" — ");
    if (dash != std::string::npos) n = n.substr(0, dash);
    if (n.size() > 70) {
        size_t c = n.rfind(',', 70);
        n = n.substr(0, c == std::string::npos ? 70 : c);
    }
    return n;
}

// Danger assessment for a tracked city's coordinates. `evs` should
// already be deduplicated.
DangerAssessment assess_tracked_city(const TrackedCity& c,
                                     const std::vector<DangerEvent>& evs) {
    return assess_danger(true, c.lat, c.lon, kCityUncertaintyKm,
                         unix_now(), evs);
}

// Add a tracked city (UI thread only). Reports the resulting danger
// level. Returns false for duplicates.
bool add_tracked_city(ChatApp& app, const std::string& name,
                      double lat, double lon) {
    std::string n = name;
    auto b = n.find_first_not_of(" \t");
    auto e = n.find_last_not_of(" \t");
    n = b == std::string::npos ? "" : n.substr(b, e - b + 1);
    if (n.empty()) {
        char buf[48];
        std::snprintf(buf, sizeof buf, "%.4f, %.4f", lat, lon);
        n = buf;
    }
    for (auto& c : app.cities) {
        if (to_lower(c.name) == to_lower(n) ||
            geo_distance_km(c.lat, c.lon, lat, lon) < 1.0) {
            say(app, "city already tracked: " + c.name);
            return false;
        }
    }
    TrackedCity c;
    c.name = n;
    c.lat = lat;
    c.lon = lon;
    app.cities.push_back(c);
    save_cities(app.data_dir + "/cities.txt", app.cities);
    auto evs = dedup_events(app.danger_events);
    auto a = assess_tracked_city(c, evs);
    say(app, "tracking " + n + " (" + std::to_string(lat) + ", " +
               std::to_string(lon) + ") — danger L" +
               std::to_string(a.level) + " (" + level_name(a.level) +
               "), index " + std::to_string(a.index) + "/100");
    return true;
}

// ------------------------------------------------------------------
// Per-city logs and the sequential location-refresh rotation
// ------------------------------------------------------------------

// Filesystem-safe log file stem for a city name: everything outside
// [A-Za-z0-9._-] collapses to '_'.
std::string city_log_stem(const std::string& name) {
    std::string s;
    bool last_us = false;
    for (unsigned char ch : name) {
        if (std::isalnum(ch) || ch == '.' || ch == '-') {
            s += static_cast<char>(std::tolower(ch));
            last_us = false;
        } else if (!last_us && !s.empty()) {
            s += '_';
            last_us = true;
        }
    }
    while (!s.empty() && (s.back() == '_' || s.back() == '.'))
        s.pop_back();
    if (s.empty()) s = "city";
    if (s.size() > 60) s = s.substr(0, 60);
    return s;
}

std::string city_log_path(const ChatApp& app, const std::string& name) {
    return app.data_dir + "/logs/cities/" + city_log_stem(name) + ".log";
}

// Append one timestamped line to the city's dedicated log file
// (data_dir/logs/cities/<name>.log). Safe to call from worker
// threads; the ofstream stays open for the session.
void city_log_write(ChatApp& app, const std::string& city,
                    const std::string& line) {
    std::string stem = city_log_stem(city);
    std::lock_guard lk(app.city_log_mu);
    auto it = app.city_logs.find(stem);
    if (it == app.city_logs.end()) {
        fs::create_directories(app.data_dir + "/logs/cities");
        auto res = app.city_logs.emplace(
            stem, std::ofstream(app.data_dir + "/logs/cities/" + stem +
                                    ".log",
                                std::ios::app));
        it = res.first;
    }
    if (!it->second) return;
    it->second << "[" << local_timestamp() << "] " << line << "\n";
    it->second.flush();
}

// "City, Country" label for the user's own location (falls back to
// "current location"). Caller must hold geo_mu.
std::string geo_place_label(const GeoInfo& g) {
    std::string place;
    if (!g.city.empty()) place = g.city;
    if (!g.country.empty()) {
        if (!place.empty()) place += ", ";
        place += g.country;
    }
    return place.empty() ? "current location" : place;
}

// Ordered refresh targets: own location first (once the geo fix
// resolved), then tracked cities in tracking order.
struct RefreshTarget {
    bool own = false;
    std::string name;
};
std::vector<RefreshTarget> refresh_targets(const ChatApp& app) {
    std::vector<RefreshTarget> t;
    {
        std::lock_guard lk(app.geo_mu);
        if (app.geo_done)
            t.push_back({true, geo_place_label(app.geo)});
    }
    for (auto& c : app.cities) t.push_back({false, c.name});
    return t;
}

// Run a cityapi.org settlement search on a worker thread. Results
// land in app.city_hits (for `/city add #<n>`) and are mirrored to the
// log; `more` appends the next page instead of replacing the list.
// With add_top the best hit is queued for tracking.
void run_city_search(ChatApp& app, const std::string& query,
                     bool add_top, bool more,
                     const std::function<void()>& wake) {
    if (app.city_search_running.exchange(true)) {
        post_notice(app, "city search already running", wake);
        return;
    }
    if (!more) app.city_last_query = query;
    say(app, std::string(more ? "loading more results for \""
                              : "searching places for \"") +
             query + "\"...");
    std::thread([&app, query, add_top, more, wake]() {
        std::string cursor;
        if (more) {
            std::lock_guard lk(app.city_mu);
            cursor = app.city_cursor;
            if (cursor.empty()) {
                app.city_search_running = false;
                post_notice(app,
                            "no more results — refine the query",
                            wake);
                if (wake) wake();
                return;
            }
        }
        std::string next;
        auto hits = search_places(query, 25, cursor, &next);
        size_t base = 0;
        {
            std::lock_guard lk(app.city_mu);
            if (!more) app.city_hits.clear();
            base = app.city_hits.size();
            app.city_hits.insert(app.city_hits.end(), hits.begin(),
                                 hits.end());
            app.city_cursor = next;
            if (add_top && !app.city_hits.empty())
                app.city_pending_add.push_back(app.city_hits.front());
            app.city_search_running = false;
        }
        if (hits.empty()) {
            post_notice(app, "city search: no results for \"" + query +
                                 "\"", wake);
        } else {
            for (size_t i = 0; i < hits.size(); ++i) {
                std::string line = "  #" + std::to_string(base + i) +
                                   " " + city_hit_name(hits[i]);
                char buf[64];
                std::snprintf(buf, sizeof buf, " — %.4f, %.4f",
                              hits[i].lat, hits[i].lon);
                line += buf;
                if (!hits[i].detail.empty() &&
                    hits[i].detail != city_hit_name(hits[i]))
                    line += "  (" + hits[i].detail + ")";
                post_notice(app, line, wake);
            }
            post_notice(app, "add one with /city add #<n>", wake);
            if (!next.empty())
                post_notice(app, "more results: /city more", wake);
        }
        if (wake) wake();
    }).detach();
}

void drain_inbox(ChatApp& app) {
    std::vector<std::pair<std::string, std::string>> items;
    std::vector<ChatApp::Status> sts;
    std::vector<std::string> notes;
    {
        std::lock_guard lk(app.inbox_mu);
        items.swap(app.inbox);
        sts.swap(app.statuses);
        notes.swap(app.notices);
    }
    for (auto& n : notes) say(app, n);
    for (auto& [key, text] : items) {
        FriendView* fv = app.find_by_peer_key(key);
        if (!fv) continue;
        fv->lines.push_back({false, text});
        app.db.add_message(fv->f.id, false, text);
    }
    for (auto& st : sts) {
        FriendView* fv = nullptr;
        if (st.friend_id >= 0) fv = app.find_by_id(st.friend_id);
        if (!fv && !st.peer_key.empty()) fv = app.find_by_peer_key(st.peer_key);
        if (!fv) continue;
        fv->online = st.online;
        if (!st.peer_key.empty()) fv->peer_key = st.peer_key;
        if (!st.name.empty()) fv->display_name = st.name;
        if (st.online) say(app, fv->display_name + " is online");
    }
    // Cities queued by a finished place search (worker thread).
    std::vector<PlaceHit> pending_cities;
    {
        std::lock_guard lk(app.city_mu);
        pending_cities.swap(app.city_pending_add);
    }
    for (auto& h : pending_cities)
        add_tracked_city(app, city_hit_name(h), h.lat, h.lon);
}

void reload_friends(ChatApp& app) {
    app.friends.clear();
    for (auto& f : app.db.list_friends()) {
        FriendView fv;
        fv.f = f;
        fv.peer_key = f.x25519_pub;
        fv.display_name = f.name;
        app.friends.push_back(std::move(fv));
    }
    if (app.open_friend_id >= 0 && !app.find_by_id(app.open_friend_id))
        app.open_friend_id = -1;
}

void open_chat(ChatApp& app, FriendView& fv) {
    app.open_friend_id = fv.f.id;
    app.mode = ChatApp::Mode::Chat;
    fv.chat_scroll = 0;
    if (!fv.history_loaded) {
        fv.lines.clear();
        for (auto& m : app.db.messages_for(fv.f.id))
            fv.lines.push_back({m.outgoing, m.body});
        fv.history_loaded = true;
    }
    if (app.net && !app.net->has_session(fv.peer_key)) {
        app.net->connect_to(fv.f);
        say(app, "connecting to " + fv.f.name + "...");
    }
}

// ------------------------------------------------------------------
// Danger assessment helpers
// ------------------------------------------------------------------
void save_danger_events(ChatApp& app) {
    save_events(app.data_dir + "/danger.txt", app.danger_events);
}

// User position + uncertainty (km) for the danger model.
bool danger_position(const ChatApp& app, double& lat, double& lon,
                     double& unc_km) {
    std::lock_guard lk(app.geo_mu);
    if (!app.geo_done || !app.geo.ok ||
        (app.geo.lat == 0 && app.geo.lon == 0))
        return false;
    lat = app.geo.lat;
    lon = app.geo.lon;
    unc_km = app.geo.precise
                 ? std::max(0.05, app.geo.accuracy_m / 1000.0)
                 : 25.0;  // IP geolocation is city-level at best
    return true;
}

DangerAssessment assess_now(const ChatApp& app) {
    double lat = 0, lon = 0, unc = 0;
    bool has = danger_position(app, lat, lon, unc);
    return assess_danger(has, lat, lon, unc, unix_now(),
                         dedup_events(app.danger_events));
}

// Effective danger level shown in the UI: the AI verdict wins when
// present, otherwise the local statistical model. 0 = unknown.
int effective_danger_level(const ChatApp& app) {
    ChatApp::AiDanger ai;
    {
        std::lock_guard lk(app.ai_mu);
        ai = app.ai_danger;
    }
    auto a = assess_now(app);
    return ai.have_verdict ? ai.level : (a.computed ? a.level : 0);
}

// Append the current sound settings to config.ini. Scalar keys are
// last-one-wins on load, so appending overrides earlier values.
void save_sound_config(const ChatApp& app) {
    std::ofstream cfg(app.data_dir + "/config.ini", std::ios::app);
    cfg << "sound=" << (app.config.sound_enabled ? "on" : "off")
        << "\n";
    for (int i = 1; i <= 5; ++i)
        cfg << "sound_l" << i << "="
            << (app.config.sound_level[i - 1] ? "on" : "off") << "\n";
    cfg << "sound_out=" << app.config.sound_out << "\n";
    for (int i = 1; i <= 5; ++i)
        cfg << "sound_pick" << i << "=" << app.config.sound_pick[i - 1]
            << "\n";
}

// ---------------------------------------------------------------
// Notification sounds
// ---------------------------------------------------------------

struct SoundFile {
    std::string name;  // file name without extension
    std::string path;  // absolute path
};

// Notification sound files offered by the platform, sorted by name.
std::vector<SoundFile> list_sound_files() {
    std::vector<std::pair<std::string, std::vector<std::string>>> roots;
#if defined(__APPLE__)
    roots.push_back({"/System/Library/Sounds",
                     {".aiff", ".aif", ".wav", ".mp3", ".m4a", ".caf"}});
#elif defined(_WIN32)
    const char* sysroot = std::getenv("SystemRoot");
    roots.push_back({sysroot ? std::string(sysroot) + "\\Media"
                             : "C:\\Windows\\Media",
                     {".wav"}});
#else
    roots.push_back({"/usr/share/sounds/freedesktop/stereo",
                     {".oga", ".ogg", ".wav"}});
    roots.push_back({"/usr/share/sounds", {".wav", ".ogg", ".oga"}});
#endif
    std::vector<SoundFile> out;
    for (auto& [dir, exts] : roots) {
        std::error_code ec;
        if (!fs::is_directory(dir, ec)) continue;
        for (auto& e : fs::directory_iterator(dir, ec)) {
            if (!e.is_regular_file(ec)) continue;
            std::string ext = to_lower(e.path().extension().string());
            if (std::find(exts.begin(), exts.end(), ext) == exts.end())
                continue;
            std::string name = e.path().stem().string();
            bool dup = false;
            for (auto& f : out)
                if (to_lower(f.name) == to_lower(name)) {
                    dup = true;
                    break;
                }
            if (!dup) out.push_back({name, e.path().string()});
        }
    }
    std::sort(out.begin(), out.end(), [](const SoundFile& a,
                                         const SoundFile& b) {
        return to_lower(a.name) < to_lower(b.name);
    });
    return out;
}

// Resolve a sound pick (stem or file name, case-insensitive) to a path.
// Absolute paths to existing files are accepted as custom sounds.
std::string sound_file_path(const std::string& pick) {
    if (pick.empty()) return "";
    if ((pick.find('/') != std::string::npos ||
         pick.find('\\') != std::string::npos) &&
        fs::exists(pick))
        return pick;
    std::string want = to_lower(pick);
    for (auto& f : list_sound_files()) {
        if (to_lower(f.name) == want) return f.path;
        std::string fn = to_lower(fs::path(f.path).filename().string());
        if (fn == want) return f.path;
    }
    return "";
}

// Display name for a stored sound pick.
std::string sound_pick_label(const std::string& pick) {
    if (pick.empty()) return "auto";
    std::string path = sound_file_path(pick);
    return path.empty() ? pick + " (missing)" : pick;
}

// Run a player command; returns the process exit code (0 = success).
int player_status(const std::string& cmd) {
    int rc = std::system(cmd.c_str());
#if defined(_WIN32)
    return rc;
#else
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    if (WIFSIGNALED(rc)) return 128 + WTERMSIG(rc);
    return rc;
#endif
}

// Play a short notification sound for danger level 1..5. Blocking —
// callers should run it on a worker thread. Returns the player exit
// code; 0 means the sound was played.
int play_sound(const Config& cfg, int level) {
    int li = std::clamp(level, 1, 5);
    std::string path = sound_file_path(cfg.sound_pick[li - 1]);
#if defined(__APPLE__)
    std::string cmd;
    if (!path.empty()) {
        cmd = "afplay \"" + path + "\"";
    } else {
        static const char* kSounds[] = {"", "Basso", "Funk", "Ping",
                                        "Pop", "Tink"};
        cmd = "afplay /System/Library/Sounds/" +
              std::string(kSounds[li]) + ".aiff";
    }
    // Route through the chosen output device by briefly making it the
    // system default; afplay cannot target a device directly.
    static std::mutex play_mu;
    std::lock_guard lk(play_mu);
    std::string prev;
    bool switched = false;
    if (!cfg.sound_out.empty()) {
        prev = default_output_device_id();
        if (prev != cfg.sound_out)
            switched = set_default_output_device(cfg.sound_out);
    }
    int rc = player_status(cmd);
    if (switched) set_default_output_device(prev);
    return rc;
#elif defined(_WIN32)
    if (!path.empty()) {
        return player_status(
            "powershell -NoProfile -Command \"(New-Object "
            "System.Media.SoundPlayer '" +
            path + "').PlaySync()\"");
    }
    int freq = 300 + li * 120;
    return player_status(
        "powershell -NoProfile -Command \"[console]::beep(" +
        std::to_string(freq) + ",300)\"");
#else
    std::string dev = cfg.sound_out.empty()
                          ? ""
                          : " --device=\"" + cfg.sound_out + "\"";
    if (!path.empty()) {
        // Retry without the device if the chosen sink is gone.
        return player_status("(paplay" + dev + " \"" + path +
                             "\" 2>/dev/null || paplay \"" + path +
                             "\" 2>/dev/null)");
    }
    return player_status(
        "(paplay" + dev +
        " /usr/share/sounds/freedesktop/stereo/"
        "alarm-clock-elapsed.oga 2>/dev/null || paplay" + dev +
        " /usr/share/sounds/freedesktop/stereo/bell.oga "
        "2>/dev/null || printf '\\a')");
#endif
}

// Resolve a sound pick argument to its canonical stored form: the
// system sound's stem, or the custom file path itself. "auto"/"default"/
// "none" clears the pick.
std::pair<bool, std::string> resolve_sound_pick(const std::string& want) {
    std::string lw = to_lower(want);
    if (lw == "auto" || lw == "default" || lw == "none")
        return {true, ""};
    if ((want.find('/') != std::string::npos ||
         want.find('\\') != std::string::npos) &&
        fs::exists(want))
        return {true, want};
    for (auto& f : list_sound_files()) {
        if (to_lower(f.name) == lw ||
            to_lower(fs::path(f.path).filename().string()) == lw)
            return {true, f.name};
    }
    return {false, ""};
}

// Fire-and-forget chime for danger level changes; reports failures to
// the log so a silent player is diagnosable.
void play_sound_bg(ChatApp& app, int level,
                   const std::function<void()>& wake) {
    Config cfg = app.config;
    int l = std::clamp(level, 1, 5);
    std::string what = sound_pick_label(cfg.sound_pick[l - 1]);
    std::thread([&app, cfg, l, what, wake]() mutable {
        int rc = play_sound(cfg, l);
        if (rc != 0)
            post_notice(app, "sound playback failed (exit " +
                                 std::to_string(rc) + ", " + what +
                                 ") — check /sound out",
                        wake);
    }).detach();
}

// Test-play a level's sound and report the outcome to the log.
void test_sound(ChatApp& app, int level,
                const std::function<void()>& wake) {
    int l = std::clamp(level, 1, 5);
    std::string what = sound_pick_label(app.config.sound_pick[l - 1]);
    say(app, "playing test sound (L" + std::to_string(l) + ", " +
                 what + ")");
    Config cfg = app.config;
    std::thread([&app, cfg, l, what, wake]() mutable {
        int rc = play_sound(cfg, l);
        post_notice(
            app, rc == 0 ? "test sound played (" + what + ")"
                         : "test sound FAILED (exit " +
                               std::to_string(rc) + ", " + what +
                               ") — check /sound out",
            wake);
    }).detach();
}

// Threat levels whose alert repeats until the situation changes or
// the user acknowledges it. L4/L5 stay single chimes.
constexpr int kSoundAlarmMaxLevel = 3;
constexpr int64_t kSoundRepeatMs = 3000;

// Chime when the effective danger level changes, then keep repeating
// the alert sound for threat levels so it can wake someone. The first
// call only primes the baseline so startup doesn't play a sound.
void check_danger_sound(ChatApp& app) {
    int lvl = effective_danger_level(app);
    if (app.sound_last_level == -1) {
        app.sound_last_level = lvl;
        return;
    }
    if (lvl != app.sound_last_level) {
        app.sound_last_level = lvl;
        app.sound_alarm_acked = false;
        app.sound_alarm_next_ms = 0;
        if (app.config.sound_enabled && lvl >= 1 && lvl <= 5 &&
            app.config.sound_level[lvl - 1])
            play_sound_bg(app, lvl, nullptr);
    }
    bool alert = app.config.sound_enabled && lvl >= 1 &&
                 lvl <= kSoundAlarmMaxLevel &&
                 app.config.sound_level[lvl - 1] &&
                 !app.sound_alarm_acked;
    if (!alert) {
        app.sound_alarm_next_ms = 0;
        return;
    }
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now()
                          .time_since_epoch())
                      .count();
    if (app.sound_alarm_next_ms == 0) {
        app.sound_alarm_next_ms = now + kSoundRepeatMs;
    } else if (now >= app.sound_alarm_next_ms) {
        app.sound_alarm_next_ms = now + kSoundRepeatMs;
        play_sound_bg(app, lvl, nullptr);
    }
}

// The "Reported combat events ..." + local-model-verdict section
// shared by the own-location and per-city AI prompts.
std::string combat_events_block(const std::vector<DangerEvent>& evs,
                                int64_t now,
                                const DangerAssessment& a) {
    std::ostringstream p;
    p << "Reported combat events (" << evs.size() << "):\n";
    if (evs.empty()) p << "(none)\n";
    for (size_t i = 0; i < evs.size(); ++i) {
        const auto& e = evs[i];
        double age_h = std::max(0.0, (now - e.ts) / 3600.0);
        p << "#" << i << " " << kind_name(e.kind) << " at " << e.lat
          << "," << e.lon << ", " << (e.ongoing ? "ongoing" : "ended")
          << ", happened " << age_h << "h ago, intensity "
          << e.intensity << "/3, confirmations " << e.confirmations
          << "/10";
        if (!e.note.empty()) p << ", note: " << e.note;
        p << "\n";
    }
    if (a.computed) {
        p << "\nLocal statistical model verdict: level " << a.level
          << " (" << level_name(a.level) << "), index " << a.index
          << "/100. Use it as a reference but apply your own judgement.\n";
    }
    return p.str();
}

// Prompt for the AI danger assessment of a tracked city: city-center
// position + all known combat events + the local model's verdict.
std::string build_city_prompt(const ChatApp& app,
                              const TrackedCity& c) {
    auto evs = dedup_events(app.danger_events);
    int64_t now = unix_now();
    auto a = assess_tracked_city(c, evs);
    std::ostringstream p;
    p << "Assess the civilian danger level for a person located in "
      << c.name << " — city-center estimate at " << c.lat << ", "
      << c.lon << " (position uncertainty ±"
      << static_cast<int>(kCityUncertaintyKm) << " km).\n\n";
    p << "Current Unix time: " << now << "\n\n";
    p << combat_events_block(evs, now, a);
    p << "\nReturn LEVEL, INDEX and a one-sentence REASON.";
    return p.str();
}

// Prompt for the AI (ChatGPT) danger assessment: position + all known
// combat events + the local model's verdict for reference.
std::string build_danger_prompt(const ChatApp& app) {
    double lat = 0, lon = 0, unc = 0;
    bool has = danger_position(app, lat, lon, unc);
    bool precise = false;
    std::string city, country;
    {
        std::lock_guard lk(app.geo_mu);
        precise = app.geo.precise;
        city = app.geo.city;
        country = app.geo.country;
    }
    auto evs = dedup_events(app.danger_events);
    int64_t now = unix_now();
    auto a = assess_now(app);

    std::ostringstream p;
    p << "Assess the civilian danger level for a person located at ";
    if (has) {
        p << lat << ", " << lon << " (position uncertainty ±";
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.1f", unc);
        p << buf << " km, " << (precise ? "GPS" : "IP geolocation")
          << ")";
    } else {
        p << "UNKNOWN (no position fix available)";
    }
    if (!city.empty() || !country.empty()) {
        p << " — ";
        if (!city.empty()) p << city;
        if (!city.empty() && !country.empty()) p << ", ";
        p << country;
    }
    p << ".\n\nCurrent Unix time: " << now << "\n\n";
    p << combat_events_block(evs, now, a);
    p << "\nReturn LEVEL, INDEX and a one-sentence REASON.";
    return p.str();
}

// Parse "LEVEL: n" / "INDEX: n" out of the model reply.
bool parse_ai_verdict(const std::string& reply, int& level,
                      int& index) {
    bool got_l = false, got_i = false;
    auto find_num = [&](const char* key, int& out) {
        size_t p = reply.find(key);
        if (p == std::string::npos) return false;
        p += std::strlen(key);
        while (p < reply.size() &&
               (reply[p] == ' ' || reply[p] == ':' || reply[p] == '\n'))
            ++p;
        char* end = nullptr;
        long v = std::strtol(reply.c_str() + p, &end, 10);
        if (end == reply.c_str() + p) return false;
        out = static_cast<int>(v);
        return true;
    };
    got_l = find_num("LEVEL", level);
    got_i = find_num("INDEX", index);
    return got_l && got_i;
}

// Extract the "REASON: ..." line from the model reply.
std::string parse_ai_reason(const std::string& reply) {
    size_t p = reply.find("REASON");
    if (p == std::string::npos) return "";
    p = reply.find(':', p);
    if (p == std::string::npos) return "";
    ++p;
    size_t e = reply.find('\n', p);
    std::string s = reply.substr(p, e == std::string::npos ? e : e - p);
    auto b = s.find_first_not_of(" \t\r");
    auto en = s.find_last_not_of(" \t\r");
    return b == std::string::npos ? "" : s.substr(b, en - b + 1);
}

// Human "12s/5m/3h/2d ago" for timestamps.
std::string format_age(int64_t ts) {
    int64_t d = std::max<int64_t>(0, unix_now() - ts);
    if (d < 60) return std::to_string(d) + "s ago";
    if (d < 3600) return std::to_string(d / 60) + "m ago";
    if (d < 86400) return std::to_string(d / 3600) + "h ago";
    return std::to_string(d / 86400) + "d ago";
}

// Danger level -> color, shared by the header badge and the Main tab.
Color level_color(int level) {
    switch (level) {
        case 1: return Color::Red;
        case 2: return (Color::RGB)(255, 140, 0);
        case 3: return Color::Yellow;
        case 4: return Color::Green;
        default: return Color::GrayDark;
    }
}

// Brighter variant of level_color, used for the pulsing hero glyphs.
Color level_color_hot(int level) {
    switch (level) {
        case 1: return Color::RGB(255, 90, 90);
        case 2: return Color::RGB(255, 190, 90);
        case 3: return Color::RGB(255, 255, 140);
        case 4: return Color::RGB(140, 255, 140);
        default: return Color::RGB(215, 215, 215);
    }
}

// Shared AI danger-assessment worker (runs on a detached thread):
// fetches Google News for `news_query` (empty = lookup skipped),
// appends the reports to `prompt`, mirrors the whole exchange into
// the log, calls the model and reports the parsed verdict through
// `finish` (invoked on the worker thread).
// `log_city` non-empty mirrors every exchange line into that city's
// dedicated log file (logs/cities/<name>.log) in addition to the
// console.
void ai_danger_worker(
    ChatApp& app, const std::function<void()>& wake,
    ai::AiEndpoint ep, const std::string& prompt,
    const std::string& news_query, const std::string& log_city,
    const std::function<void(bool ok, int level, int index,
                             const std::string& reason,
                             const std::string& error)>& finish) {
    // Fetch the latest news so the verdict reflects the current
    // situation, not just user-reported events.
    std::ostringstream np;
    std::vector<news::Item> items;
    std::string news_err;
    if (news_query.empty()) {
        np << "\nRecent news reports about the area: lookup "
              "skipped (location unknown)\n";
    } else {
        items = news::google_news(news_query, 10, &news_err);
        np << "\nRecent news reports about the area (unverified, "
              "may be unrelated or stale):\n";
        if (items.empty()) {
            np << "(none";
            if (!news_err.empty()) np << ": " << news_err;
            np << ")\n";
        } else {
            for (auto& it : items) {
                std::string t = it.title;
                if (t.size() > 200) t = t.substr(0, 200) + "...";
                np << "- " << t;
                if (!it.source.empty()) np << " (" << it.source << ")";
                if (!it.published.empty())
                    np << " — " << it.published;
                np << "\n";
            }
        }
    }
    np << "Weigh these reports alongside the events above; "
          "nearby recent events matter most.\n";
    std::string full_prompt = prompt + np.str();
    // Mirror the exact request (system + user prompt incl. the
    // news section) into the log tab and the per-city log file;
    // post_notice is the thread-safe path.
    auto emit = [&](const std::string& s) {
        post_notice(app, s, wake);
        if (!log_city.empty()) city_log_write(app, log_city, s);
    };
    auto dump = [&](const char* tag, const std::string& text) {
        emit(std::string("  ai> ") + tag);
        std::istringstream ss(text);
        std::string ln;
        while (std::getline(ss, ln)) {
            if (!ln.empty() && ln.back() == '\r') ln.pop_back();
            if (!ln.empty()) emit("  ai>   " + ln);
        }
    };
    dump("[system]", ai::kDangerSystemPrompt);
    dump("[request]", full_prompt);
    if (!items.empty()) {
        emit("  news> " + std::to_string(items.size()) +
             " recent reports included");
    } else if (!news_err.empty()) {
        emit("  news> lookup failed: " + news_err);
    }
    std::string err;
    std::string reply = ai::danger_assessment(ep, full_prompt, &err);
    int level = 0, index = -1;
    bool ok = !reply.empty() && parse_ai_verdict(reply, level, index);
    if (ok) {
        finish(true, level, index, parse_ai_reason(reply), "");
    } else {
        finish(false, 0, -1, "",
               reply.empty() ? ("request failed: " + err)
                             : "could not parse AI reply");
    }
    // Mirror the reply into the log tab.
    if (!reply.empty()) {
        std::istringstream rs(reply);
        std::string ln;
        while (std::getline(rs, ln)) {
            if (!ln.empty() && ln.back() == '\r') ln.pop_back();
            if (!ln.empty()) emit("  ai| " + ln);
        }
    } else {
        emit("AI assessment failed: " + err);
    }
    if (wake) wake();
}

ai::AiEndpoint ai_endpoint_from_config(const Config& cfg) {
    ai::AiEndpoint ep;
    if (!cfg.ai_base.empty()) ep.base_url = cfg.ai_base;
    if (!cfg.ai_model.empty()) ep.model = cfg.ai_model;
    ep.api_key = cfg.ai_key;
    return ep;
}

// Launch the AI danger assessment for the user's own location.
// `done(ok)` runs on the worker thread when the attempt finishes.
void start_own_ai(ChatApp& app, const std::function<void()>& wake,
                  const std::function<void(bool)>& done) {
    ai::AiEndpoint ep = ai_endpoint_from_config(app.config);
    std::string prompt = build_danger_prompt(app);
    {
        std::lock_guard lk(app.ai_mu);
        app.ai_danger.running = true;
        app.ai_danger.error.clear();
        app.ai_danger.model = ep.model;
    }
    say(app, "querying " + ep.model + " for your location...");
    std::thread([&app, wake, prompt, ep, done]() {
        // News query from the resolved geo city/country; the own
        // location gets a dedicated log file like the cities do.
        std::string city, country, log_city;
        {
            std::lock_guard lk(app.geo_mu);
            city = app.geo.city;
            country = app.geo.country;
            log_city = "own-" + city_log_stem(geo_place_label(app.geo));
        }
        city_log_write(app, log_city,
                       "=== " + local_timestamp() + " query " +
                           ep.model + " for own location ===");
        std::string news_query;
        if (!city.empty() || !country.empty()) {
            std::string q;
            if (!city.empty()) q += "\"" + city + "\" ";
            if (!country.empty()) q += country + " ";
            q += "обстріл OR обстрел OR shelling OR rocket OR strike "
                 "OR attack OR explosion";
            news_query = q;
        }
        ai_danger_worker(
            app, wake, ep, prompt, news_query, log_city,
            [&app, log_city, done](bool ok, int level, int index,
                                   const std::string& reason,
                                   const std::string& error) {
                {
                    std::lock_guard lk(app.ai_mu);
                    auto& d = app.ai_danger;
                    d.running = false;
                    d.ts = unix_now();
                    if (ok) {
                        d.have_verdict = true;
                        d.level = level;
                        d.index = index;
                        d.reason = reason;
                        d.error.clear();
                        city_log_write(
                            app, log_city,
                            "verdict: L" + std::to_string(level) +
                                " index " + std::to_string(index) +
                                "/100" +
                                (reason.empty() ? ""
                                                : " — " + reason));
                    } else {
                        d.error = error;
                        city_log_write(app, log_city,
                                       "FAILED: " + error);
                    }
                }
                done(ok);
            });
    }).detach();
}

// Launch the AI danger assessment for one tracked city. The whole
// exchange is mirrored into the console and the city's dedicated log
// file (logs/cities/<name>.log). `done(ok)` runs on the worker
// thread when the attempt finishes.
void start_city_ai(ChatApp& app, const TrackedCity& city,
                   const std::function<void()>& wake,
                   const std::function<void(bool)>& done) {
    ai::AiEndpoint ep = ai_endpoint_from_config(app.config);
    std::string prompt = build_city_prompt(app, city);
    std::string city_name = city.name;
    {
        std::lock_guard lk(app.ai_mu);
        auto& v = app.city_ai[city_name];
        v.running = true;
        v.error.clear();
        v.model = ep.model;
    }
    say(app, "querying " + ep.model + " for " + city.name + "...");
    city_log_write(app, city_name,
                   "=== " + local_timestamp() + " query " + ep.model +
                       " for " + city_name + " ===");
    // News query: the settlement name without the ", CC" suffix.
    std::string news_name = city.name;
    auto comma = news_name.find(',');
    if (comma != std::string::npos) news_name = news_name.substr(0, comma);
    auto b = news_name.find_last_not_of(" \t");
    news_name = b == std::string::npos ? "" : news_name.substr(0, b + 1);
    std::string news_query = "\"" + news_name +
                             "\" обстріл OR обстрел OR shelling OR rocket "
                             "OR strike OR attack OR explosion";
    std::thread([&app, wake, prompt, ep, news_query, city_name, done]() {
        ai_danger_worker(
            app, wake, ep, prompt, news_query, city_name,
            [&app, city_name, done](bool ok, int level, int index,
                                    const std::string& reason,
                                    const std::string& error) {
                {
                    std::lock_guard lk(app.ai_mu);
                    auto& v = app.city_ai[city_name];
                    v.running = false;
                    v.ts = unix_now();
                    if (ok) {
                        v.have = true;
                        v.level = level;
                        v.index = index;
                        v.reason = reason;
                        v.error.clear();
                        v.updated = unix_now();
                        city_log_write(
                            app, city_name,
                            "verdict: L" + std::to_string(level) +
                                " index " + std::to_string(index) +
                                "/100" +
                                (reason.empty() ? ""
                                                : " — " + reason));
                    } else {
                        v.error = error;
                        city_log_write(app, city_name,
                                       "FAILED: " + error);
                    }
                }
                done(ok);
            });
    }).detach();
}

// Kick off the AI danger assessment for the next location in the
// rotation (own location first, then tracked cities — see
// refresh_targets). Locations are refreshed strictly one at a time,
// one attempt per ~60 s. The rotation index advances only on success:
// a failed request is retried once ~60 s later, and if the retry
// fails too the queue moves on to the next location.
// Returns false when there are no targets yet.
bool kick_location_refresh(ChatApp& app,
                           const std::function<void()>& wake) {
    auto targets = refresh_targets(app);
    if (targets.empty()) return false;
    int64_t now = unix_now();
    if (now - app.refresh_last_query.load() < 60) return true;
    if (app.refresh_running.exchange(true)) return true;
    size_t idx = app.refresh_next % targets.size();
    app.refresh_next = idx;  // re-anchor in case the list changed
    app.refresh_last_query = now;
    RefreshTarget t = targets[idx];

    auto done = [&app, idx](bool ok) {
        if (ok) {
            app.refresh_next = idx + 1;
            app.refresh_fails = 0;
        } else {
            int fails = app.refresh_fails.fetch_add(1);
            if (fails == 0) {
                // First failure: keep this target — it is retried
                // on the next tick (~60 s after this attempt ended).
            } else {
                // Retry failed as well: move on to the next location.
                app.refresh_next = idx + 1;
                app.refresh_fails = 0;
            }
            app.refresh_last_query = unix_now();
        }
        app.refresh_running = false;
    };
    if (t.own) {
        start_own_ai(app, wake, done);
        return true;
    }
    const TrackedCity* city = nullptr;
    for (auto& c : app.cities)
        if (c.name == t.name) {
            city = &c;
            break;
        }
    if (!city) {  // removed while queued — skip it
        app.refresh_running = false;
        app.refresh_next = idx + 1;
        return true;
    }
    start_city_ai(app, *city, wake, done);
    return true;
}

// ------------------------------------------------------------------
// Peer-id / invitation helpers
// ------------------------------------------------------------------
// Find a friend by peer id (x25519 pub hex), creating a placeholder
// record when unknown. Peer-id friends have no host/port — their
// address is resolved through the DHT at connect time.
Friend ensure_peer_friend(ChatApp& app, const std::string& pid_hex,
                          const std::string& name_hint) {
    if (auto f = app.db.find_friend_by_key(pid_hex)) return *f;
    Friend f;
    f.name = name_hint.empty() ? "peer-" + short_id(pid_hex) : name_hint;
    f.host = "";
    f.port = 0;
    f.x25519_pub = pid_hex;
    f.created_at = unix_now();
    f.id = app.db.add_friend(f);
    reload_friends(app);
    if (auto* fv = app.find_by_peer_key(pid_hex)) return fv->f;
    return f;
}

// ------------------------------------------------------------------
// Slash commands
// ------------------------------------------------------------------
struct CmdSpec {
    const char* name;
    const char* usage;  // empty = takes no arguments
};

const CmdSpec kCommands[] = {
    {"/help", ""},      {"/friends", ""},  {"/peerid", ""},
    {"/dht", ""},       {"/close", ""},    {"/update", ""},
    {"/version", ""},   {"/quit", ""},     {"/exit", ""},
    {"/add", "<name> <host> <port>"},
    {"/remove", "<name>"},
    {"/chat", "<name>"},
    {"/open", "<name>"},
    {"/connect", "<invite-code | peer-id | name | file> [name]"},
    {"/invite", "[ttl] [save <file>]"},
    {"/copyid", "<name>"},
    {"/bootstrap", "<host:port>"},
    {"/event", "add|remove|list|clear ..."},
    {"/events", ""},
    {"/danger", "[ai]"},
    {"/city", "search|add|remove|list|log|logs|clear ..."},
    {"/sound", "[on|off|test|ack|sounds|pick|out|levels ...]"},
};

const CmdSpec* find_cmd(const std::string& name) {
    for (auto& c : kCommands)
        if (name == c.name) return &c;
    return nullptr;
}

bool takes_friend_name(const std::string& cmd) {
    return cmd == "/chat" || cmd == "/open" || cmd == "/remove" ||
           cmd == "/connect" || cmd == "/copyid";
}

// Live hint shown in the status line while the user types a command.
// Returns "" when there is nothing useful to suggest.
std::string command_hint(const ChatApp& app, const std::string& text) {
    if (text.size() < 2 || text[0] != '/') return "";
    auto sp = text.find_first_of(" \t");
    std::string cmd =
        to_lower(sp == std::string::npos ? text : text.substr(0, sp));

    if (sp == std::string::npos) {
        // Still typing the command name — list prefix matches.
        std::string out;
        for (auto& c : kCommands) {
            std::string name = c.name;
            if (cmd.size() >= name.size() ||
                name.compare(0, cmd.size(), cmd) != 0)
                continue;
            if (!out.empty()) out += ", ";
            out += name;
            if (c.usage[0]) out += " " + std::string(c.usage);
            if (out.size() > 90) {
                out += "...";
                break;
            }
        }
        return out.empty() ? "" : "commands: " + out;
    }

    const CmdSpec* spec = find_cmd(cmd);
    if (!spec) return "";

    // Complete the last argument against friend names.
    if (takes_friend_name(cmd)) {
        std::string rest = text.substr(sp + 1);
        auto lp = rest.find_last_of(" \t");
        std::string want = to_lower(lp == std::string::npos
                                        ? rest
                                        : rest.substr(lp + 1));
        std::string out;
        for (auto& fv : app.friends) {
            std::string have = to_lower(fv.display_name);
            if (have.rfind(want, 0) != 0) continue;
            if (!out.empty()) out += ", ";
            out += fv.display_name;
        }
        if (!out.empty()) return "friends: " + out;
    }

    // Show usage while required arguments are missing.
    int need = 0;
    if (cmd == "/add") need = 3;
    else if (cmd == "/bootstrap") need = 1;
    else if (takes_friend_name(cmd)) need = 1;
    int have = static_cast<int>(split_args(text).size()) - 1;
    if (spec->usage[0] && have < need)
        return std::string(spec->name) + " " + spec->usage;
    return "";
}

void execute_command(ChatApp& app, const std::string& line,
                     const std::function<void()>& wake,
                     const std::function<void()>& quit) {
    auto args = split_args(line);
    if (args.empty()) return;
    std::string cmd = to_lower(args[0]);

    if (cmd == "/help") {
        say(app, "commands:");
        say(app, "  /friends              list friends");
        say(app, "  /add <name> <host> <port>   add friend & connect");
        say(app, "  /remove <name>        remove friend");
        say(app, "  /chat <name>          open chat (auto-connects)");
        say(app, "  /connect <arg> [name]  connect by invite code,");
        say(app, "                       peer id, friend name or a");
        say(app, "                       file holding the code; optional");
        say(app, "                       [name] renames a new peer");
        say(app, "  /invite [ttl] [save <file>]  create invitation");
        say(app, "                       (code is copied to clipboard)");
        say(app, "  /peerid               show & copy this peer's id");
        say(app, "  /copyid <name>        copy friend's peer id");
        say(app, "  /dht                  DHT status");
        say(app, "  /bootstrap <host:port>  add DHT bootstrap node");
        say(app, "  /event add <lat> <lon> [kind] [age=<h>] [conf=<n>]");
        say(app, "                       [ongoing|ended] [note]  report");
        say(app, "                       a combat event (kinds:");
        say(app, "                       shelling|strike|ground|other)");
        say(app, "  /event remove <n> /events /events clear");
        say(app, "  /danger [ai]           civilian danger assessment;");
        say(app, "                       'ai' asks an LLM (Pollinations,");
        say(app, "                       no key needed)");
        say(app, "  /city search <query>  find settlements (cityapi.org)");
        say(app, "  /city more              next page of last search");
        say(app, "  /city add <lat> <lon> [name]   track a city");
        say(app, "  /city add <query>      track top search hit");
        say(app, "  /city add #<n>         track /city search hit n");
        say(app, "  /city remove <name|#n> /city list /city clear");
        say(app, "  /city log <name> /city logs");
        say(app, "                       per-city AI logs "
                 "(logs/cities/<name>.log)");
        say(app, "                       each city gets its own danger");
        say(app, "                       level on the Main tab");
        say(app, "  /sound [on|off|test [lvl]|ack|sounds|levels ...]");
        say(app, "                       danger-level notification sounds;");
        say(app, "                       L1-L3 repeat as an alarm, /sound");
        say(app, "                       ack silences until the level changes");
        say(app, "                       /sound pick <lvl|all> <sound|auto>");
        say(app, "                       /sound out [device]  output device");
        say(app, "  /close                back to console");
        say(app, "  /update               check GitHub for updates & install");
        say(app, "  /version              show version info");
        say(app, "  /quit                 exit");
        say(app, "any other text is sent to the open chat");
        say(app, "PgUp/PgDn, arrows, wheel: scroll console/chat");
    } else if (cmd == "/friends") {
        if (app.friends.empty()) {
            say(app, "no friends — use /add <name> <host> <port>");
        }
        for (auto& fv : app.friends) {
            std::string where = fv.f.host.empty()
                                    ? "dht:" + short_id(fv.f.x25519_pub)
                                    : fv.f.host + ":" +
                                          std::to_string(fv.f.port);
            say(app, std::string("  ") + (fv.online ? "(*)" : "( )") +
                       " " + fv.display_name + "  " + where +
                       (fv.f.id == app.open_friend_id ? "   <open>" : ""));
        }
    } else if (cmd == "/add") {
        if (args.size() != 4) {
            say(app, "usage: /add <name> <host> <port>");
            return;
        }
        int port = 0;
        try {
            port = std::stoi(args[3]);
        } catch (...) {
        }
        if (port <= 0 || port > 65535) {
            say(app, "invalid port");
            return;
        }
        if (app.find_by_name(args[1])) {
            say(app, "friend '" + args[1] + "' already exists");
            return;
        }
        Friend f;
        f.name = args[1];
        f.host = args[2];
        f.port = port;
        f.created_at =
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
        f.id = app.db.add_friend(f);
        if (f.id < 0) {
            say(app, "failed to save friend");
            return;
        }
        reload_friends(app);
        if (auto* fv = app.find_by_name(args[1])) {
            if (app.net) app.net->connect_to(fv->f);
            say(app, "added " + args[1] + ", connecting...");
        }
    } else if (cmd == "/remove") {
        if (args.size() != 2) {
            say(app, "usage: /remove <name>");
            return;
        }
        auto* fv = app.find_by_name(args[1]);
        if (!fv) {
            say(app, "no such friend: " + args[1]);
            return;
        }
        if (!fv->peer_key.empty() && app.net)
            app.net->drop_session(fv->peer_key);
        app.db.remove_friend(fv->f.id);
        if (app.open_friend_id == fv->f.id) {
            app.open_friend_id = -1;
            app.mode = ChatApp::Mode::Home;
        }
        reload_friends(app);
        say(app, "removed " + args[1]);
    } else if (cmd == "/chat" || cmd == "/open") {
        if (args.size() != 2) {
            say(app, "usage: /chat <name>");
            return;
        }
        auto* fv = app.find_by_name(args[1]);
        if (!fv) {
            say(app, "no such friend: " + args[1]);
            return;
        }
        open_chat(app, *fv);
    } else if (cmd == "/close") {
        app.open_friend_id = -1;
        app.mode = ChatApp::Mode::Home;
    } else if (cmd == "/version") {
        say(app, "version " + std::string(updater::current_version()));
        std::lock_guard lk(app.update_mu);
        if (!app.latest_release.tag.empty())
            say(app, "latest release: " + app.latest_release.tag);
    } else if (cmd == "/update") {
        if (app.update_running.exchange(true)) {
            say(app, "update already in progress");
            return;
        }
        updater::ReleaseInfo rel;
        {
            std::lock_guard lk(app.update_mu);
            rel = app.latest_release;
        }
        std::thread([&app, wake, quit, rel]() mutable {
            auto fail = [&](const std::string& m) {
                app.update_running = false;
                post_notice(app, m, wake);
            };
            updater::ReleaseInfo r = rel;
            std::string err;
            if (r.download_url.empty() &&
                !updater::fetch_latest(r, &err)) {
                fail("update check failed: " + err);
                return;
            }
            if (updater::compare_versions(r.tag,
                                          updater::current_version()) <= 0) {
                fail("already up to date (v" +
                     std::string(updater::current_version()) + ")");
                return;
            }
            post_notice(app, "downloading " + r.tag + "...", wake);
            if (updater::apply_update(r, err)) {
                // New instance spawned; leave the UI loop.
                quit();
                return;
            }
            fail("update failed: " + err);
        }).detach();
        say(app, "checking for updates...");
    } else if (cmd == "/peerid") {
        std::string pid = peer_id_hex(app.identity);
        say(app, "peer id: " + pid);
        say(app, "short:   " + short_id(pid));
        if (copy_to_clipboard(pid))
            say(app, "peer id copied to clipboard");
        else
            say(app, "could not copy to clipboard");
        if (app.dht) {
            Endpoint ue{Endpoint::Family::IPv6, "::",
                        static_cast<uint16_t>(app.config.dht_port)};
            say(app, "dht:     " + ue.str() + " (UDP)");
            if (auto obs = app.dht->observed_public_endpoint())
                say(app, "observed:" + obs->str() + " (public view)");
        }
    } else if (cmd == "/dht") {
        if (!app.dht) {
            say(app, "DHT is disabled");
        } else {
            say(app, "dht nodes known: " +
                       std::to_string(app.dht->known_nodes()));
            say(app, "records stored:  " +
                       std::to_string(app.dht->stored_records()));
            if (auto obs = app.dht->observed_public_endpoint())
                say(app, "observed public endpoint: " + obs->str());
            else
                say(app, "no public endpoint observed yet "
                         "(behind NAT or no DHT contact)");
        }
    } else if (cmd == "/bootstrap") {
        if (args.size() != 2) {
            say(app, "usage: /bootstrap <host:port>   (DHT UDP endpoint)");
            return;
        }
        auto eps = resolve_endpoint(args[1]);
        if (eps.empty()) {
            say(app, "bad endpoint — use host:port, name:port or "
                     "[v6]:port");
            return;
        }
        for (auto& ep : eps)
            if (app.dht) app.dht->add_bootstrap(ep);
        std::ofstream cfg(app.data_dir + "/config.ini",
                          std::ios::app);
        cfg << "bootstrap=" << args[1] << "\n";
        say(app, "bootstrap node added: " + args[1] +
                   " (" + std::to_string(eps.size()) + " address(es))");
    } else if (cmd == "/invite") {
        int64_t ttl = 300;
        bool save_file = false;
        std::string file;
        for (size_t i = 1; i < args.size(); ++i) {
            if (args[i] == "save" && i + 1 < args.size()) {
                save_file = true;
                file = args[++i];
            } else {
                try {
                    ttl = std::stoll(args[i]);
                } catch (...) {
                }
            }
        }
        if (ttl < 30) ttl = 30;
        if (ttl > 86400) ttl = 86400;

        Invitation inv;
        inv.peer_id = app.identity.x25519.pub;
        inv.ed_pub = app.identity.ed25519.pub;
        inv.name = app.config.name;
        inv.issued_at = unix_now();
        inv.ttl = ttl;
        // Bootstrap hints: our DHT endpoint as seen locally and, when
        // known, our public IP (NAT-friendly).
        if (app.dht) {
            for (auto& ep : local_endpoints(
                     static_cast<uint16_t>(app.config.dht_port)))
                inv.dht_hints.push_back(ep);
            if (auto obs = app.dht->observed_public_endpoint()) {
                Endpoint pub{obs->family, obs->addr,
                             static_cast<uint16_t>(app.config.dht_port)};
                if (endpoint_is_public(pub) &&
                    std::find(inv.dht_hints.begin(), inv.dht_hints.end(),
                              pub) == inv.dht_hints.end())
                    inv.dht_hints.push_back(pub);
            }
            if (inv.dht_hints.empty()) {
                Endpoint any{Endpoint::Family::IPv6, "::",
                             static_cast<uint16_t>(app.config.dht_port)};
                inv.dht_hints.push_back(any);
            }
        }
        crypto::Bytes blob = invitation_encode(inv, app.identity);
        std::string code = base64url_encode(blob);
        say(app, "Invitation created.");
        say(app, "Peer ID: " + peer_id_hex(app.identity));
        say(app, "Name:    " + inv.name);
        say(app, "Expires: in " + std::to_string(ttl) + " s");
        if (save_file) {
            std::ofstream f(file, std::ios::trunc);
            f << code << "\n";
            say(app, "saved to " + file);
        } else {
            say(app, "Invitation code:");
            for (size_t i = 0; i < code.size(); i += 96)
                say(app, "  " + code.substr(i, 96));
            if (copy_to_clipboard(code))
                say(app, "code copied to clipboard");
            else
                say(app, "could not copy to clipboard");
            say(app, "(use /invite save <file> to export, "
                     "/connect <code> to redeem)");
        }
    } else if (cmd == "/connect") {
        if (args.size() < 2 || args.size() > 3) {
            say(app, "usage: /connect <invite-code | peer-id | name | "
                     "file> [name]");
            return;
        }
        std::string arg = args[1];
        std::string name_hint = args.size() == 3 ? args[2] : "";

        // An existing file means the invitation code lives inside it
        // (see /invite save <file>); read the first token as the code.
        if (fs::is_regular_file(arg)) {
            std::string code = read_code_file(arg);
            if (code.empty()) {
                say(app, "could not read invitation code from " + arg);
                return;
            }
            arg = code;
        }

        crypto::Bytes blob;
        bool handled = false;
        if (base64url_decode(arg, blob)) {
            Invitation inv;
            if (invitation_decode(blob, inv, unix_now())) {
                handled = true;
                if (app.dht)
                    for (auto& ep : inv.dht_hints) app.dht->add_bootstrap(ep);
                std::string pid_hex = crypto::to_hex(inv.peer_id.data(),
                                                     32);
                Friend f = ensure_peer_friend(
                    app, pid_hex,
                    !name_hint.empty() ? name_hint : inv.name);
                say(app, "accepted invitation from " +
                           (inv.name.empty() ? pid_hex.substr(0, 16)
                                             : inv.name) +
                           " — resolving via DHT...");
                if (app.net) app.net->connect_to(f);
            }
        }
        if (!handled) {
            std::string lower = to_lower(arg);
            if (is_peer_id(lower)) {
                Friend f = ensure_peer_friend(app, lower,
                                              name_hint);
                say(app, "connecting to peer " + short_id(lower) +
                           " via DHT...");
                if (app.net) app.net->connect_to(f);
                handled = true;
            } else if (auto* fv = app.find_by_name(arg)) {
                say(app, "connecting to " + fv->display_name + "...");
                if (app.net) app.net->connect_to(fv->f);
                handled = true;
            }
        }
        if (!handled)
            say(app, "unrecognized argument — not an invitation code, "
                     "peer id, contact name or readable file");
    } else if (cmd == "/copyid") {
        if (args.size() != 2) {
            say(app, "usage: /copyid <name>");
            return;
        }
        auto* fv = app.find_by_name(args[1]);
        if (!fv) {
            say(app, "no such friend: " + args[1]);
            return;
        }
        std::string key = !fv->peer_key.empty() ? fv->peer_key
                                                : fv->f.x25519_pub;
        if (key.empty()) {
            say(app, "peer id unknown — connect to " + args[1] + " first");
            return;
        }
        if (copy_to_clipboard(key))
            say(app, "peer id of " + fv->display_name +
                       " copied to clipboard");
        else
            say(app, "could not copy to clipboard");
    } else if (cmd == "/event") {
        if (args.size() < 2) {
            say(app, "usage: /event add|remove|list|clear ...  "
                     "(see /help)");
            return;
        }
        std::string sub = to_lower(args[1]);
        if (sub == "add") {
            if (args.size() < 4) {
                say(app, "usage: /event add <lat> <lon> [kind] "
                         "[age=<h>] [conf=<n>] [sev=<1-3>] "
                         "[ongoing|ended] [note...]");
                say(app, "kinds: shelling|strike|ground|other");
                return;
            }
            double lat = 0, lon = 0;
            try {
                lat = std::stod(args[2]);
                lon = std::stod(args[3]);
            } catch (...) {
            }
            if (lat < -90 || lat > 90 || lon < -180 || lon > 180) {
                say(app, "invalid coordinates");
                return;
            }
            DangerEvent e;
            e.lat = lat;
            e.lon = lon;
            e.ts = unix_now();
            double age_h = 0;
            bool status_set = false, kind_set = false;
            std::vector<std::string> note_words;
            for (size_t i = 4; i < args.size(); ++i) {
                const std::string& a = args[i];
                if (a.rfind("age=", 0) == 0) {
                    try {
                        age_h = std::stod(a.substr(4));
                    } catch (...) {
                    }
                } else if (a.rfind("conf=", 0) == 0) {
                    try {
                        e.confirmations = std::stoi(a.substr(5));
                    } catch (...) {
                    }
                } else if (a.rfind("sev=", 0) == 0) {
                    try {
                        e.intensity = std::stoi(a.substr(4));
                    } catch (...) {
                    }
                } else if (a == "ongoing" || a == "ended") {
                    e.ongoing = (a == "ongoing");
                    status_set = true;
                } else {
                    bool ok = false;
                    EventKind k = parse_kind(a, &ok);
                    if (ok && !kind_set) {
                        e.kind = k;
                        kind_set = true;
                    } else {
                        note_words.push_back(a);
                    }
                }
            }
            if (!status_set) e.ongoing = (age_h == 0);
            e.confirmations = std::clamp(e.confirmations, 1, 10);
            e.intensity = std::clamp(e.intensity, 1, 3);
            if (age_h < 0) age_h = 0;
            e.ts = unix_now() - static_cast<int64_t>(age_h * 3600);
            std::string note;
            for (auto& w : note_words) {
                if (!note.empty()) note += " ";
                note += w;
            }
            e.note = note;
            app.danger_events.push_back(e);
            app.danger_events = dedup_events(app.danger_events);
            save_danger_events(app);
            app.refresh_next = 0;
            app.refresh_fails = 0;
            app.refresh_last_query = 0;
            kick_location_refresh(app, wake);
            say(app, "event added: " + std::string(kind_name(e.kind)) +
                       " at " + std::to_string(lat) + "," +
                       std::to_string(lon) + " (" +
                       std::to_string(app.danger_events.size()) +
                       " stored)");
        } else if (sub == "remove") {
            if (args.size() != 3) {
                say(app, "usage: /event remove <n>   (n from /events)");
                return;
            }
            int n = -1;
            try {
                n = std::stoi(args[2]);
            } catch (...) {
            }
            if (n < 0 || n >= static_cast<int>(app.danger_events.size())) {
                say(app, "no such event index");
                return;
            }
            app.danger_events.erase(app.danger_events.begin() + n);
            save_danger_events(app);
            app.refresh_next = 0;
            app.refresh_fails = 0;
            app.refresh_last_query = 0;
            kick_location_refresh(app, wake);
            say(app, "event removed");
        } else if (sub == "clear") {
            app.danger_events.clear();
            save_danger_events(app);
            app.refresh_next = 0;
            app.refresh_fails = 0;
            app.refresh_last_query = 0;
            kick_location_refresh(app, wake);
            say(app, "all events cleared");
        } else {
            say(app, "usage: /event add|remove|list|clear ...");
        }
    } else if (cmd == "/events") {
        if (app.danger_events.empty()) {
            say(app, "no combat events — /event add <lat> <lon> ...");
        }
        double lat = 0, lon = 0, unc = 0;
        bool has = danger_position(app, lat, lon, unc);
        int64_t now = unix_now();
        for (size_t i = 0; i < app.danger_events.size(); ++i) {
            const auto& e = app.danger_events[i];
            double age_h = std::max(0.0, (now - e.ts) / 3600.0);
            std::string line = "  #" + std::to_string(i) + " " +
                               kind_name(e.kind) + " " +
                               std::to_string(e.lat) + "," +
                               std::to_string(e.lon);
            char age[32];
            std::snprintf(age, sizeof(age), "%.1f", age_h);
            line += "  age " + std::string(age) + "h";
            line += e.ongoing ? "  ONGOING" : "  ended";
            line += "  conf " + std::to_string(e.confirmations);
            if (has) {
                char dist[32];
                std::snprintf(dist, sizeof(dist), "%.1f",
                              geo_distance_km(lat, lon, e.lat, e.lon));
                line += "  dist " + std::string(dist) + "km";
            }
            if (!e.note.empty()) line += "  — " + e.note;
            say(app, line);
        }
    } else if (cmd == "/danger") {
        if (args.size() > 1 && to_lower(args[1]) == "ai") {
            {
                std::lock_guard lk(app.geo_mu);
                if (!app.geo_done) {
                    say(app, "AI assessment unavailable — "
                             "waiting for location fix");
                    return;
                }
            }
            if (app.refresh_running.load()) {
                say(app, "AI assessment already in progress");
                return;
            }
            // Queue own location first and skip the 60 s throttle.
            app.refresh_next = 0;
            app.refresh_fails = 0;
            app.refresh_last_query = 0;
            kick_location_refresh(app, wake);
            say(app, "AI assessment requested — locations refresh one "
                     "at a time, ~60 s apart");
            return;
        }
        double lat = 0, lon = 0, unc = 0;
        bool has = danger_position(app, lat, lon, unc);
        auto evs = dedup_events(app.danger_events);
        auto a = assess_danger(has, lat, lon, unc, unix_now(), evs);
        if (!a.computed) {
            say(app, "position unknown — waiting for geo fix");
        } else {
            say(app, "danger level: L" + std::to_string(a.level) + " (" +
                       level_name(a.level) + "), index " +
                       std::to_string(a.index) + "/100");
            say(app, "position uncertainty: ±" +
                       std::to_string(static_cast<int>(unc)) + " km");
            if (a.top.empty()) {
                say(app, "no combat events affect this position — "
                         "level 5 means 'no threat detected', "
                         "not a safety guarantee");
            }
            for (auto& c : a.top) {
                const auto& e = evs[c.event_index];
                char line[256];
                std::snprintf(
                    line, sizeof(line),
                    "  #%zu %s %.1fkm away (eff %.1fkm), age %.1fh, "
                    "contribution %.0f",
                    c.event_index, kind_name(e.kind), c.raw_dist_km,
                    c.dist_km,
                    std::max(0.0, (unix_now() - e.ts) / 3600.0),
                    c.contribution);
                say(app, line);
            }
        }
    } else if (cmd == "/city") {
        auto join_rest = [&](size_t from) {
            std::string s;
            for (size_t i = from; i < args.size(); ++i) {
                if (i > from) s += " ";
                s += args[i];
            }
            return s;
        };
        std::string sub = args.size() > 1 ? to_lower(args[1]) : "list";
        if (sub == "list") {
            if (app.cities.empty()) {
                say(app, "no cities tracked — /city search <query> or "
                         "/city add <lat> <lon> [name]");
            } else {
                auto evs = dedup_events(app.danger_events);
                for (size_t i = 0; i < app.cities.size(); ++i) {
                    const auto& c = app.cities[i];
                    auto a = assess_tracked_city(c, evs);
                    int lvl = a.level, idx = a.index;
                    bool ai_verdict = false;
                    int64_t upd = 0;
                    {
                        std::lock_guard lk(app.ai_mu);
                        auto it = app.city_ai.find(c.name);
                        if (it != app.city_ai.end()) {
                            upd = it->second.updated;
                            if (it->second.have) {
                                lvl = it->second.level;
                                idx = it->second.index;
                                ai_verdict = true;
                            }
                        }
                    }
                    char buf[320];
                    std::snprintf(
                        buf, sizeof(buf),
                        "  #%zu %s — %.4f, %.4f — L%d (%s), "
                        "index %d/100%s",
                        i, c.name.c_str(), c.lat, c.lon, lvl,
                        level_name(lvl), idx,
                        ai_verdict ? " ai" : "");
                    say(app, buf);
                    if (upd)
                        say(app, "     updated " + format_age(upd));
                }
            }
        } else if (sub == "clear") {
            app.cities.clear();
            save_cities(app.data_dir + "/cities.txt", app.cities);
            {
                std::lock_guard lk(app.ai_mu);
                app.city_ai.clear();
            }
            app.refresh_next = 0;
            app.refresh_fails = 0;
            say(app, "tracked cities cleared");
        } else if (sub == "remove") {
            if (args.size() != 3) {
                say(app, "usage: /city remove <name|#n>");
                return;
            }
            std::string want = args[2];
            std::string num = want;
            if (!num.empty() && num[0] == '#') num.erase(num.begin());
            bool is_idx = !num.empty() &&
                          std::all_of(num.begin(), num.end(),
                                      [](char c) {
                                          return std::isdigit(
                                              static_cast<unsigned char>(
                                                  c));
                                      });
            size_t idx = app.cities.size();
            if (is_idx) {
                try {
                    long n = std::stol(num);
                    if (n >= 0 && static_cast<size_t>(n) <
                                     app.cities.size())
                        idx = static_cast<size_t>(n);
                } catch (...) {
                }
            } else {
                std::string lw = to_lower(want);
                size_t found = app.cities.size();
                int matches = 0;
                for (size_t i = 0; i < app.cities.size(); ++i) {
                    std::string hn = to_lower(app.cities[i].name);
                    if (hn == lw) {
                        found = i;
                        matches = 1;
                        break;
                    }
                    if (hn.find(lw) != std::string::npos) {
                        if (matches == 0) found = i;
                        ++matches;
                    }
                }
                if (matches == 1) idx = found;
            }
            if (idx == app.cities.size()) {
                say(app, "no such city — /city list to see tracked "
                         "cities");
                return;
            }
            say(app, "removed " + app.cities[idx].name);
            std::string removed_name = app.cities[idx].name;
            app.cities.erase(app.cities.begin() + idx);
            save_cities(app.data_dir + "/cities.txt", app.cities);
            {
                std::lock_guard lk(app.ai_mu);
                app.city_ai.erase(removed_name);
            }
            app.refresh_fails = 0;
        } else if (sub == "logs") {
            // List the per-city AI log files with size and mtime.
            fs::path dir = app.data_dir + "/logs/cities";
            std::vector<std::string> names;
            if (fs::exists(dir)) {
                for (auto& e : fs::directory_iterator(dir)) {
                    if (e.path().extension() == ".log")
                        names.push_back(
                            e.path().filename().string());
                }
            }
            std::sort(names.begin(), names.end());
            if (names.empty()) {
                say(app, "no per-city logs yet — they are written "
                         "after each city's AI refresh "
                         "(/city log <name> to view)");
            } else {
                say(app, "per-city logs (" +
                             std::to_string(names.size()) + "):");
                for (auto& fn : names) {
                    fs::path p = dir / fn;
                    std::error_code ec;
                    auto sz = fs::file_size(p, ec);
                    auto ft = fs::last_write_time(p, ec);
                    std::string mt = "?";
                    if (!ec) {
                        auto sctp = std::chrono::time_point_cast<
                            std::chrono::system_clock::duration>(
                            ft - fs::file_time_type::clock::now() +
                            std::chrono::system_clock::now());
                        std::time_t t =
                            std::chrono::system_clock::to_time_t(sctp);
                        char b[20];
                        std::strftime(b, sizeof b, "%Y-%m-%d %H:%M",
                                      std::localtime(&t));
                        mt = b;
                    }
                    say(app, "  " + fn + "  " +
                                 std::to_string(sz / 1024) + " KB  " + mt);
                }
            }
        } else if (sub == "log") {
            // Dump a city's dedicated AI log into the console.
            if (args.size() < 3) {
                say(app, "usage: /city log <name>   (/city logs lists "
                         "available logs)");
                return;
            }
            std::string want = join_rest(2);
            std::string lw = to_lower(want);
            std::string city_name;
            int matches = 0;
            for (auto& c : app.cities) {
                std::string hn = to_lower(c.name);
                if (hn == lw) {
                    city_name = c.name;
                    matches = 1;
                    break;
                }
                if (hn.find(lw) != std::string::npos) {
                    if (matches == 0) city_name = c.name;
                    ++matches;
                }
            }
            if (matches > 1) {
                say(app, "ambiguous city name — be more specific");
                return;
            }
            fs::path path;
            if (matches == 1) {
                path = city_log_path(app, city_name);
            } else {
                // No tracked-city match: look the name up among the
                // log files on disk (covers own-location and renamed
                // cities too).
                fs::path dir = app.data_dir + "/logs/cities";
                std::string want_stem = city_log_stem(want);
                std::vector<fs::path> hit;
                if (fs::exists(dir)) {
                    for (auto& e : fs::directory_iterator(dir)) {
                        std::string fn =
                            e.path().filename().string();
                        if (fn.size() < 5 ||
                            fn.substr(fn.size() - 4) != ".log")
                            continue;
                        std::string stem =
                            fn.substr(0, fn.size() - 4);
                        if (stem == want_stem ||
                            stem.find(want_stem) != std::string::npos ||
                            want_stem.find(stem) != std::string::npos)
                            hit.push_back(e.path());
                    }
                }
                if (hit.size() > 1) {
                    say(app, "ambiguous — /city logs lists files");
                    return;
                }
                if (hit.empty()) {
                    say(app, "no log for \"" + want +
                             "\" — /city logs lists existing files");
                    return;
                }
                path = hit.front();
                city_name = path.stem().string();
            }
            std::ifstream f(path);
            if (!f) {
                say(app, "cannot read " + path.string());
                return;
            }
            std::vector<std::string> lines;
            std::string ln;
            while (std::getline(f, ln)) lines.push_back(ln);
            say(app, "=== " + city_name + " log (" + path.string() +
                     ") ===");
            size_t from = lines.size() > 200 ? lines.size() - 200 : 0;
            if (from) say(app, "... (" + std::to_string(from) +
                                 " earlier lines omitted)");
            for (size_t i = from; i < lines.size(); ++i)
                say(app, lines[i]);
            say(app, "=== end of log ===");
        } else if (sub == "search") {
            std::string q = join_rest(2);
            if (q.empty()) {
                say(app, "usage: /city search <query>");
                return;
            }
            run_city_search(app, q, false, false, wake);
        } else if (sub == "more") {
            if (app.city_last_query.empty()) {
                say(app, "no city search yet — /city search <query> "
                         "first");
            } else {
                run_city_search(app, app.city_last_query, false, true,
                                wake);
            }
        } else if (sub == "add") {
            if (args.size() < 3) {
                say(app, "usage: /city add <lat> <lon> [name] | "
                         "<query> | #<n>");
                return;
            }
            bool handled = false;
            // Coordinates form: /city add <lat> <lon> [name...]
            if (args.size() >= 4) {
                try {
                    double lat = std::stod(args[2]);
                    double lon = std::stod(args[3]);
                    if (lat >= -90 && lat <= 90 && lon >= -180 &&
                        lon <= 180) {
                        add_tracked_city(app, join_rest(4), lat, lon);
                        handled = true;
                    }
                } catch (...) {
                }
            }
            if (!handled && args.size() == 3) {
                // "/city add #<n>" (or a bare index) picks a hit from
                // the most recent /city search.
                std::string num = args[2];
                if (!num.empty() && num[0] == '#') num.erase(num.begin());
                if (!num.empty() &&
                    std::all_of(num.begin(), num.end(), [](char c) {
                        return std::isdigit(
                            static_cast<unsigned char>(c));
                    })) {
                    std::vector<PlaceHit> hits;
                    {
                        std::lock_guard lk(app.city_mu);
                        hits = app.city_hits;
                    }
                    long n = -1;
                    try {
                        n = std::stol(num);
                    } catch (...) {
                    }
                    if (n >= 0 && static_cast<size_t>(n) < hits.size()) {
                        add_tracked_city(app, city_hit_name(hits[n]),
                                         hits[n].lat, hits[n].lon);
                    } else {
                        say(app, "no such search result — run "
                                 "/city search <query> first");
                    }
                    handled = true;
                }
            }
            if (!handled) {
                // Anything else is a settlement-name query: geocode it
                // via the city API and track the best hit.
                run_city_search(app, join_rest(2), true, false, wake);
            }
        } else {
            say(app, "usage: /city [search <query> | more | add <lat> "
                     "<lon> [name] | add <query> | add #<n> | remove "
                     "<name|#n> | list | log <name> | logs | clear]");
        }
    } else if (cmd == "/sound") {
        auto status = [&]() {
            std::string s = std::string("sound notifications: ") +
                            (app.config.sound_enabled ? "on" : "off") +
                            "   levels:";
            for (int i = 1; i <= 5; ++i)
                s += std::string(" L") + std::to_string(i) +
                     (app.config.sound_level[i - 1] ? "[x]" : "[ ]");
            say(app, s);
            std::string picks = "  picks:";
            for (int i = 1; i <= 5; ++i)
                picks += " L" + std::to_string(i) + "=" +
                         sound_pick_label(app.config.sound_pick[i - 1]);
            int alvl = effective_danger_level(app);
            std::string alarm = "off";
            if (app.sound_alarm_acked)
                alarm = "muted";
            else if (app.config.sound_enabled && alvl >= 1 &&
                     alvl <= kSoundAlarmMaxLevel &&
                     app.config.sound_level[alvl - 1])
                alarm = "repeating";
            say(app, picks + "   out: " +
                        output_device_label(app.config.sound_out) +
                        "   alarm: " + alarm);
        };
        if (args.size() == 1) {
            status();
        } else {
            std::string sub = to_lower(args[1]);
            if (sub == "on" || sub == "off") {
                app.config.sound_enabled = (sub == "on");
                save_sound_config(app);
                say(app, "sound notifications " + sub);
            } else if (sub == "test") {
                int lvl = effective_danger_level(app);
                if (args.size() > 2) {
                    try {
                        lvl = std::stoi(args[2]);
                    } catch (...) {
                    }
                }
                if (lvl < 1 || lvl > 5) lvl = 3;
                test_sound(app, lvl, wake);
            } else if (sub == "sounds") {
                auto files = list_sound_files();
                if (files.empty()) {
                    say(app, "no notification sounds found on this "
                             "platform");
                } else {
                    say(app, "available sounds (" +
                                 std::to_string(files.size()) + "):");
                    for (auto& f : files) say(app, "  " + f.name);
                    say(app, "custom files: /sound pick <lvl|all> "
                             "<path>");
                }
            } else if (sub == "pick") {
                if (args.size() < 4) {
                    say(app, "usage: /sound pick <1-5|all> "
                             "<sound|auto|path>");
                } else {
                    std::string lvl_spec = to_lower(args[2]);
                    std::string want;
                    for (size_t i = 3; i < args.size(); ++i) {
                        if (i > 3) want += " ";
                        want += args[i];
                    }
                    auto [ok, stored] = resolve_sound_pick(want);
                    if (!ok) {
                        say(app, "unknown sound '" + want +
                                     "' — /sound sounds to list");
                    } else {
                        bool any = false;
                        if (lvl_spec == "all") {
                            for (int i = 0; i < 5; ++i)
                                app.config.sound_pick[i] = stored;
                            any = true;
                        } else {
                            for (char c : lvl_spec)
                                if (c >= '1' && c <= '5') {
                                    app.config.sound_pick[c - '1'] =
                                        stored;
                                    any = true;
                                }
                        }
                        if (!any) {
                            say(app, "usage: /sound pick <1-5|all> "
                                     "<sound|auto|path>");
                        } else {
                            save_sound_config(app);
                            say(app, "sound pick " + lvl_spec + ": " +
                                         sound_pick_label(stored));
                            status();
                        }
                    }
                }
            } else if (sub == "out") {
                auto devs = list_output_devices();
                if (args.size() == 2) {
                    say(app, "output devices:");
                    say(app, "  " +
                             std::string(app.config.sound_out.empty()
                                             ? "*"
                                             : " ") +
                             " system default" +
                             (app.config.sound_out.empty()
                                  ? "  <current>"
                                  : ""));
                    for (auto& d : devs)
                        say(app, "  " +
                                     std::string(d.id ==
                                                          app.config
                                                              .sound_out
                                                      ? "*"
                                                      : " ") +
                                     " " +
                                     (d.name.empty() ? d.id : d.name));
                } else {
                    std::string want;
                    for (size_t i = 2; i < args.size(); ++i) {
                        if (i > 2) want += " ";
                        want += args[i];
                    }
                    std::string lw = to_lower(want);
                    if (lw == "default" || lw == "system") {
                        app.config.sound_out.clear();
                        save_sound_config(app);
                        say(app, "output: system default");
                    } else {
                        AudioDevice* found = nullptr;
                        int matches = 0;
                        for (auto& d : devs) {
                            if (to_lower(d.name) == lw ||
                                to_lower(d.id) == lw) {
                                found = &d;
                                matches = 1;
                                break;
                            }
                            if (!d.name.empty() &&
                                to_lower(d.name).find(lw) !=
                                    std::string::npos) {
                                if (!found) found = &d;
                                ++matches;
                            }
                        }
                        if (matches != 1 || !found) {
                            say(app, matches == 0
                                         ? "unknown output device — "
                                           "/sound out to list"
                                         : "ambiguous output device — "
                                           "/sound out to list");
                        } else {
                            app.config.sound_out = found->id;
                            save_sound_config(app);
                            say(app, "output: " +
                                         output_device_label(
                                             app.config.sound_out));
                        }
                    }
                }
            } else if (sub == "ack" || sub == "silence") {
                if (app.sound_alarm_acked) {
                    say(app, "alert already silenced");
                } else {
                    app.sound_alarm_acked = true;
                    app.sound_alarm_next_ms = 0;
                    say(app, "alert sound silenced — resumes on the "
                             "next level change");
                }
            } else if (sub == "levels") {
                if (args.size() == 2) {
                    status();
                } else {
                    std::string spec;
                    for (size_t i = 2; i < args.size(); ++i)
                        spec += to_lower(args[i]);
                    if (spec == "all" || spec == "none") {
                        bool v = spec == "all";
                        for (int i = 0; i < 5; ++i)
                            app.config.sound_level[i] = v;
                    } else {
                        for (int i = 0; i < 5; ++i)
                            app.config.sound_level[i] = false;
                        for (char c : spec)
                            if (c >= '1' && c <= '5')
                                app.config.sound_level[c - '1'] = true;
                    }
                    save_sound_config(app);
                    status();
                }
            } else {
                say(app, "usage: /sound [on|off|test [lvl]|ack|sounds|"
                         "pick <1-5|all> <sound|auto|path>|out "
                         "[device]|levels <1-5 list|all|none>]");
            }
        }
    } else if (cmd == "/quit" || cmd == "/exit") {
        app.net->stop();
        if (app.dht) app.dht->stop();
        std::exit(0);
    } else {
        say(app, "unknown command: " + args[0] + " (try /help)");
    }
}

// ------------------------------------------------------------------
// Components
// ------------------------------------------------------------------
Element pane_window(const std::vector<Element>& all, int scroll,
                    int& total_out);

Element render_friends(const ChatApp& app, int scroll, int& total_out) {
    std::vector<Element> all;
    if (app.friends.empty()) {
        all.push_back(text("no friends yet") | color(Color::GrayDark));
        all.push_back(text("/add <name> <host> <port>") |
                      color(Color::GrayDark));
    }
    for (auto& fv : app.friends) {
        bool open = fv.f.id == app.open_friend_id;
        std::string where = fv.f.host.empty()
                                ? "dht:" + short_id(fv.f.x25519_pub)
                                : fv.f.host + ":" +
                                      std::to_string(fv.f.port);
        Element name = text(fv.display_name);
        name = open ? name | bold | color(Color::Cyan)
                    : name | color(Color::White);
        all.push_back(hbox({
            text(fv.online ? "● " : "○ ") |
                color(fv.online ? Color::Green : Color::GrayDark),
            name,
            filler(),
            text(where) | color(Color::GrayDark),
        }));
    }
    return pane_window(all, scroll, total_out);
}

// Largest scroll offset that still shows the oldest line.
int max_scroll(size_t total) {
    int visible = pane_rows();
    if (total > static_cast<size_t>(visible)) --visible;
    if (visible < 1) visible = 1;
    return total > static_cast<size_t>(visible)
               ? static_cast<int>(total - visible)
               : 0;
}

// Range of `total` lines visible with `scroll` lines hidden below the
// viewport (scroll == 0 shows the newest lines). Returns [start, end).
std::pair<size_t, size_t> scroll_window(size_t total, int scroll,
                                        int visible) {
    if (visible < 1) visible = 1;
    size_t cap = static_cast<size_t>(visible);
    size_t off = total > cap ? std::min(static_cast<size_t>(std::max(
                                              scroll, 0)),
                                          total - cap)
                             : 0;
    size_t end = total - off;
    size_t start = end > cap ? end - cap : 0;
    return {start, end};
}

// Apply the shared scroll window to a list of row elements and report
// the total row count for scroll clamping.
Element pane_window(const std::vector<Element>& all, int scroll,
                    int& total_out) {
    int visible = pane_rows();
    bool overflow = all.size() > static_cast<size_t>(visible);
    if (overflow) --visible;  // room for the scroll indicator
    auto [start, end] = scroll_window(all.size(), scroll, visible);
    std::vector<Element> rows;
    if (overflow) {
        rows.push_back(text("  lines " + std::to_string(start + 1) + "-" +
                            std::to_string(end) + " of " +
                            std::to_string(all.size()) +
                            (scroll > 0 ? "  (scrolled up — PgDn/PgUp)"
                                        : "")) |
                       color(Color::GrayDark));
    }
    for (size_t i = start; i < end; ++i) rows.push_back(all[i]);
    total_out = static_cast<int>(all.size());
    return vbox(std::move(rows)) | flex | borderEmpty;
}

// Console/Logs tab line styling: AI request lines cyan, replies
// green, news lookups yellow, errors red, confirmations green.
Element console_line_element(const std::string& l) {
    // Substring match: /city log dumps carry a "[timestamp]" prefix.
    if (l.find("  ai>") != std::string::npos)
        return text(l) | color(Color::Cyan);
    if (l.find("  ai|") != std::string::npos)
        return text(l) | color(Color::Green);
    if (l.find("  news>") != std::string::npos)
        return text(l) | color(Color::Yellow);
    std::string low = to_lower(l);
    if (low.find("error") != std::string::npos ||
        low.find("failed") != std::string::npos)
        return text(l) | color(Color::Red);
    if (l.rfind("tracking ", 0) == 0 || low.rfind("added", 0) == 0)
        return text(l) | color(Color::Green);
    if (l.find("=== ") != std::string::npos)
        return text(l) | bold | color(Color::Yellow);
    if (l.rfind("querying ", 0) == 0 ||
        l.find(" query ") != std::string::npos)
        return text(l) | color(Color::Cyan);
    if (l.rfind("...", 0) == 0)
        return text(l) | color(Color::GrayDark);
    return text(l);
}

Element render_console(const ChatApp& app) {
    std::vector<Element> all;
    if (app.console.empty()) {
        all.push_back(text("Radius") | bold |
                      color(Color::Cyan));
        all.push_back(text("type /help for commands") |
                      color(Color::GrayDark));
    } else {
        for (auto& l : app.console)
            all.push_back(console_line_element(l));
    }
    int total;
    return pane_window(all, app.console_scroll, total);
}

Element render_chat_lines(const FriendView& fv) {
    std::vector<Element> all;
    if (fv.lines.empty()) {
        all.push_back(text("  no messages yet") |
                      color(Color::GrayDark));
    } else {
        for (auto& l : fv.lines) {
            all.push_back(hbox({
                text(l.outgoing ? "you: " : fv.display_name + ": ") |
                    color(l.outgoing ? Color::Green : Color::Cyan) |
                    bold,
                text(l.text),
            }));
        }
    }
    int total;
    return pane_window(all, fv.chat_scroll, total);
}

// 3x5 block font for the hero level readout ("L1".."L5").
const char* const* level_glyph(char c) {
    static const char* L[] = {"#..", "#..", "#..", "#..", "###"};
    static const char* G1[] = {".#.", "##.", ".#.", ".#.", ".##"};
    static const char* G2[] = {"###", "..#", "###", "#..", "###"};
    static const char* G3[] = {"###", "..#", ".##", "..#", "###"};
    static const char* G4[] = {"#.#", "#.#", "###", "..#", "..#"};
    static const char* G5[] = {"###", "#..", "###", "..#", "###"};
    switch (c) {
        case 'L': return L;
        case '1': return G1;
        case '2': return G2;
        case '3': return G3;
        case '4': return G4;
        case '5': return G5;
    }
    return nullptr;
}

// Render a short string as 5-row block glyphs, neofetch-style.
Element big_level_glyphs(const std::string& s, Color c) {
    std::vector<std::string> lines(5);
    bool first = true;
    for (char ch : s) {
        auto* g = level_glyph(ch);
        if (!g) continue;
        for (int r = 0; r < 5; ++r) {
            if (!first) lines[r] += ' ';
            for (const char* p = g[r]; *p; ++p)
                lines[r] += (*p == '#') ? "█" : " ";
        }
        first = false;
    }
    std::vector<Element> rows;
    for (auto& l : lines)
        rows.push_back(text(l) | bold | color(c));
    return vbox(std::move(rows));
}

// ------------------------------------------------------------------
// Main tab, left pane: the civilian danger level rendered as a
// prominent standalone panel, neofetch-style.
// ------------------------------------------------------------------
Element render_danger_panel(const ChatApp& app, int scroll,
                            int& total_out) {
    std::vector<Element> all;
    int64_t now = unix_now();

    DangerAssessment a = assess_now(app);
    ChatApp::AiDanger ai;
    {
        std::lock_guard lk(app.ai_mu);
        ai = app.ai_danger;
    }
    double lat = 0, lon = 0, unc = 0;
    bool has_pos = danger_position(app, lat, lon, unc);

    int lvl = ai.have_verdict ? ai.level
                              : (a.computed ? a.level : 0);
    int idx = ai.have_verdict ? ai.index
                              : (a.computed ? a.index : -1);
    Color lc = level_color(lvl > 0 ? lvl : 5);

    auto row = [](Element e) { return hbox({filler(), e, filler()}); };

    if (lvl > 0) {
        // Hero readout: the level itself as large block glyphs,
        // pulsing between the base and a brighter shade.
        Color gc = ((unix_ms() / 450) % 2 == 0) ? lc
                                               : level_color_hot(lvl);
        all.push_back(row(big_level_glyphs(
            "L" + std::to_string(lvl), gc)));
        all.push_back(row(text(level_name(lvl)) | bold | color(lc)));
        if (idx >= 0) {
            all.push_back(row(hbox({
                text("index ") | dim,
                gauge(idx / 100.0f) | size(WIDTH, EQUAL, 20) |
                    color(lc),
                text(" " + std::to_string(idx) + "/100") | bold,
            })));
        }
        std::string meta;
        if (ai.have_verdict) {
            meta = "AI verdict • updated " + format_age(ai.ts);
            if (now - ai.ts > 130) meta += " (stale)";
        } else if (ai.running) {
            meta = "AI assessment in progress...";
        } else if (ai.ts == 0) {
            meta = "AI assessment pending";
        } else {
            meta = "AI unavailable";
        }
        all.push_back(row(text(meta +
                               (ai.model.empty()
                                    ? ""
                                    : " • " + ai.model)) |
                               dim));
        if (!ai.reason.empty())
            all.push_back(row(text(ai.reason) | color(Color::Cyan)));
        if (!ai.error.empty())
            all.push_back(row(text("AI error: " + ai.error) |
                               color(Color::Red)));
    } else {
        bool geo_ready;
        {
            std::lock_guard lk(app.geo_mu);
            geo_ready = app.geo_done;
        }
        if (!geo_ready) {
            // First seconds after launch: position and the danger
            // assessment are still loading — show a loading state
            // instead of a level.
            Color gc = ((unix_ms() / 450) % 2 == 0)
                           ? Color::Cyan
                           : Color::RGB(90, 90, 90);
            all.push_back(row(text("LOADING DATA") | bold |
                                   color(gc)));
            all.push_back(row(text("fetching position…") | dim));
        } else {
            all.push_back(row(text("level unknown — waiting for data") |
                                   color(Color::GrayDark)));
        }
    }
    if (a.computed && !ai.have_verdict) {
        all.push_back(row(text("local model: L" +
                               std::to_string(a.level) + " (" +
                               level_name(a.level) + "), index " +
                               std::to_string(a.index) + "/100") |
                               dim));
    }
    if (has_pos) {
        std::string place, src;
        {
            std::lock_guard lk(app.geo_mu);
            src = app.geo.precise ? "GPS" : "IP geolocation";
            if (!app.geo.city.empty()) {
                place = app.geo.city;
                if (!app.geo.country.empty())
                    place += ", " + app.geo.country;
            } else if (!app.geo.country.empty()) {
                place = app.geo.country;
            }
        }
        char buf[256];
        std::snprintf(buf, sizeof(buf),
                      "position: %.4f, %.4f  ±%.1f km (%s)%s", lat,
                      lon, unc, src.c_str(),
                      place.empty() ? "" : (" — " + place).c_str());
        all.push_back(row(text("  " + std::string(buf)) | dim));
    } else {
        all.push_back(row(text("position unknown") |
                               color(Color::GrayDark)));
    }
    auto evs = dedup_events(app.danger_events);
    if (!a.top.empty())
        all.push_back(row(text("CONTRIBUTING EVENTS") | bold |
                               color(Color::Yellow)));
    int shown = 0;
    for (auto& c : a.top) {
        if (shown++ >= 3) break;
        const auto& e = evs[c.event_index];
        char line[256];
        std::snprintf(
            line, sizeof(line),
            "event #%zu %s %.1fkm (eff %.1fkm), age %.1fh, "
            "contrib %.0f",
            c.event_index, kind_name(e.kind), c.raw_dist_km,
            c.dist_km, std::max(0.0, (now - e.ts) / 3600.0),
            c.contribution);
        all.push_back(row(text(line) | dim));
    }
    if (a.top.empty() && a.computed)
        all.push_back(row(text("no combat events affect this position") |
                               dim));

    // Refresh queue: locations are queried strictly one at a time in
    // refresh_targets() order (own location, then cities). The next-up
    // location is highlighted together with the countdown.
    auto targets = refresh_targets(app);
    size_t next_idx = 0;
    if (!targets.empty()) {
        next_idx = app.refresh_next.load() % targets.size();
        int64_t last = app.refresh_last_query.load();
        bool running = app.refresh_running.load();
        int remain = last > 0 ? 60 - static_cast<int>(now - last) : 60;
        if (remain < 0) remain = 0;
        all.push_back(row(hbox({
            text("next: ") | dim,
            text(targets[next_idx].name) | bold | color(Color::Cyan),
            running ? text(" — querying…") | color(Color::Cyan)
                    : text(" — in " + std::to_string(remain) + "s") |
                          dim,
        })));
        std::string q = "queue: ";
        for (size_t i = 0; i < targets.size(); ++i) {
            if (i) q += " › ";
            std::string nm = targets[i].name;
            if (nm.size() > 22) nm = nm.substr(0, 20) + "..";
            q += (i == next_idx) ? "[" + nm + "]" : nm;
        }
        all.push_back(row(text(q) | dim));
    }

    // Tracked cities: each gets its own danger level computed from
    // the same event set at the city-center coordinates; the AI
    // verdict wins when present. The per-city row also shows when
    // its information was last refreshed and whether it is next up.
    if (!app.cities.empty()) {
        all.push_back(row(text("TRACKED CITIES") | bold |
                               color(Color::Yellow)));
        size_t own_off = targets.empty() || !targets[0].own ? 0 : 1;
        for (size_t i = 0; i < app.cities.size(); ++i) {
            const auto& c = app.cities[i];
            auto ca = assess_tracked_city(c, evs);
            ChatApp::CityVerdict v;
            {
                std::lock_guard lk(app.ai_mu);
                auto it = app.city_ai.find(c.name);
                if (it != app.city_ai.end()) v = it->second;
            }
            int cl = v.have ? v.level
                            : (ca.computed ? ca.level : 0);
            int ci = v.have ? v.index : ca.index;
            bool is_next = !targets.empty() &&
                           own_off + i == next_idx;
            std::vector<Element> row_el = {
                text("  " + c.name) | dim,
                filler(),
                text("L" + std::to_string(cl) + " " +
                     level_name(cl) + "  " +
                     std::to_string(ci) + "/100" +
                     (v.have ? " ai" : "")) |
                    bold | color(level_color(cl)),
            };
            if (v.updated)
                row_el.push_back(text("  upd " +
                                      format_age(v.updated)) |
                                 dim);
            if (is_next)
                row_el.push_back(text("  → next") |
                                 color(Color::Cyan));
            all.push_back(hbox(std::move(row_el)));
            if (v.have && !v.reason.empty())
                all.push_back(text("    " + v.reason) | dim);
            else if (v.running)
                all.push_back(text("    AI assessment in progress...") |
                              dim);
            else if (!v.error.empty())
                all.push_back(text("    AI error: " + v.error) |
                                  color(Color::Red));
            else if (v.ts && !v.have)
                all.push_back(text("    last attempt failed — will "
                                   "retry on its turn") |
                                  color(Color::GrayDark));
        }
    }

    return pane_window(all, scroll, total_out);
}

// ------------------------------------------------------------------
// Main tab, right pane: system state overview.
// ------------------------------------------------------------------
Element render_main_details(const ChatApp& app, int scroll,
                            int& total_out) {
    std::vector<Element> all;

    bool first_head = true;
    auto head = [&all, &first_head](const std::string& s) {
        if (!first_head) all.push_back(text("") | dim);
        first_head = false;
        all.push_back(text(s) | bold | color(Color::Yellow));
    };
    // Key/value row: the label column is padded to a fixed width so all
    // values line up vertically inside the section.
    auto kv = [&all](const std::string& key, Element val) {
        std::string k = "  " + key;
        if (k.size() < 18) k += std::string(18 - k.size(), ' ');
        all.push_back(hbox({text(k) | dim, val}));
    };
    auto kvs = [&kv](const std::string& key, const std::string& val,
                     Decorator dec) {
        kv(key, text(val) | dec);
    };

    head(" SYSTEM ");
    kvs("version", APP_VERSION, dim);
    kvs("name", app.config.name, dim);
    kvs("peer id", peer_id_hex(app.identity), dim);
    kvs("fingerprint",
        crypto::to_hex(app.identity.x25519.pub.data(), 16), dim);
    kvs("data dir", app.data_dir, dim);

    head(" NETWORK ");
    {
        std::string ip = "unknown";
        {
            std::lock_guard lk(app.geo_mu);
            if (app.geo_done && !app.geo.ip.empty()) {
                ip = app.geo.ip;
                if (!app.geo.isp.empty()) ip += "  (" + app.geo.isp + ")";
            }
        }
        kvs("public ip", ip, dim);
    }
    kvs("ports",
        "tcp:" + std::to_string(app.config.port) +
            "   udp:" + std::to_string(app.config.dht_port),
        dim);
    {
        int online = 0;
        for (auto& fv : app.friends)
            if (fv.online) ++online;
        kvs("contacts",
            std::to_string(app.friends.size()) + " (" +
                std::to_string(online) + " online)",
            dim);
    }
    if (app.dht) {
        kvs("dht",
            std::to_string(app.dht->known_nodes()) + " nodes   " +
                std::to_string(app.dht->stored_records()) + " records",
            dim);
    } else {
        kvs("dht", "disabled", dim);
    }

    head(" DATA ");
    kvs("combat events", std::to_string(app.danger_events.size()), dim);
    kvs("tracked cities",
        std::to_string(app.cities.size()) + "   (/city list)", dim);

    head(" UPDATE ");
    {
        std::lock_guard lk(app.update_mu);
        if (app.update_running) {
            kv("update", text("in progress") | color(Color::Yellow));
        } else if (!app.latest_release.tag.empty()) {
            kv("update",
               text("available: " + app.latest_release.tag +
                    " — /update") |
                   color(Color::Yellow));
        } else {
            kvs("update", "up to date", dim);
        }
    }

    all.push_back(text("") | dim);
    all.push_back(text(" Tab: switch view · /help for commands") | dim);

    return pane_window(all, scroll, total_out);
}

// ------------------------------------------------------------------
// Settings tab: read-only view of the effective configuration.
// ------------------------------------------------------------------
Element render_settings_view(const ChatApp& app, int scroll,
                             int& total_out) {
    std::vector<Element> all;
    auto line = [&all](const std::string& s) {
        all.push_back(text(s) | dim);
    };
    auto head = [&all](const std::string& s) {
        all.push_back(text(s) | bold | color(Color::Yellow));
    };

    head(" CONFIG ");
    line("config file: " + app.data_dir + "/config.ini");
    line("name=" + app.config.name + "   port=" +
         std::to_string(app.config.port) + "   dht_port=" +
         std::to_string(app.config.dht_port));
    line("data dir: " + app.data_dir);
    line("bootstraps: " + std::to_string(app.config.bootstraps.size()));
    for (auto& b : app.config.bootstraps) line("  " + b);

    head(" IDENTITY ");
    line("peer id: " + peer_id_hex(app.identity));
    line("fingerprint: " +
         crypto::to_hex(app.identity.x25519.pub.data(), 16));

    head(" AI (danger assessment) ");
    line("endpoint: " + (app.config.ai_base.empty()
                             ? std::string("(default: Pollinations)")
                             : app.config.ai_base));
    line("model: " + (app.config.ai_model.empty()
                          ? std::string("(default)")
                          : app.config.ai_model));
    line("api key: " + (app.config.ai_key.empty()
                            ? std::string("not set")
                            : std::string("set (hidden)")));

    head(" LOCATION ");
    {
        std::lock_guard lk(app.geo_mu);
        if (!app.geo_done) {
            line("status: resolving...");
        } else if (!app.geo.ok) {
            line("status: unavailable");
        } else {
            line(std::string("status: ok (") +
                 (app.geo.precise ? "device GPS" : "IP geolocation") +
                 ")");
            if (app.geo.lat != 0 || app.geo.lon != 0) {
                char buf[96];
                std::snprintf(buf, sizeof(buf), "coords: %.5f, %.5f",
                              app.geo.lat, app.geo.lon);
                line(buf);
            }
            std::string place;
            if (!app.geo.city.empty()) place = app.geo.city;
            if (!app.geo.region.empty() &&
                to_lower(app.geo.region) != to_lower(app.geo.city)) {
                if (!place.empty()) place += ", ";
                place += app.geo.region;
            }
            if (!app.geo.country.empty()) {
                if (!place.empty()) place += ", ";
                place += app.geo.country;
            }
            if (!place.empty()) line("place: " + place);
            if (!app.geo.ip.empty())
                line("public ip: " + app.geo.ip +
                     (app.geo.isp.empty() ? "" : "  (" + app.geo.isp + ")"));
        }
    }

    head(" SOUND NOTIFICATIONS ");
    line(std::string("enabled: ") +
         (app.config.sound_enabled ? "on" : "off"));
    {
        std::string lv = "levels:";
        for (int i = 1; i <= 5; ++i)
            lv += std::string(" L") + std::to_string(i) +
                  (app.config.sound_level[i - 1] ? "[x]" : "[ ]");
        line(lv);
    }
    line("chime when the danger level changes; configure with the");
    line("panel below or /sound on|off|test|levels ...");

    head(" APP ");
    line("version " APP_VERSION "   combat events stored: " +
         std::to_string(app.danger_events.size()));
    {
        std::lock_guard lk(app.update_mu);
        if (app.update_running)
            line("update: in progress");
        else if (!app.latest_release.tag.empty())
            line("update available: " + app.latest_release.tag);
        else
            line("update: up to date");
    }
    all.push_back(text("") | dim);
    line("Edit config.ini and restart to apply changes.");
    line("Slash commands still work from any tab: /add /chat "
         "/event /danger /invite ...");

    return pane_window(all, scroll, total_out);
}

}  // namespace

int main(int argc, char** argv) {
    std::string data_dir_override;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--selftest") return run_selftest();
        if (a == "--data-dir" && i + 1 < argc) {
            data_dir_override = argv[++i];
        } else if (a.rfind("--data-dir=", 0) == 0) {
            data_dir_override = a.substr(11);
        }
    }
    if (const char* env = std::getenv("RADIUS_DATA_DIR"))
        if (data_dir_override.empty()) data_dir_override = env;

    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    const char* home = std::getenv("HOME");
#ifdef _WIN32
    if (!home) home = std::getenv("USERPROFILE");
#endif
    std::string data_dir =
        !data_dir_override.empty()
            ? data_dir_override
            : std::string(home ? home : ".") + "/.radius";
    Config config = load_config(data_dir + "/config.ini");
    if (config.port <= 0 || config.port > 65535) config.port = 5555;
    // UDP and TCP port spaces are separate: by default the DHT shares
    // the chat port number.
    if (config.dht_port <= 0 || config.dht_port > 65535)
        config.dht_port = config.port;

    ChatApp app(data_dir, config);
    try {
        app.identity = load_or_create_identity(data_dir, config.name);
    } catch (const std::exception& e) {
        std::cerr << "identity load failed: " << e.what() << "\n";
        return 1;
    }
    if (!app.db.last_error().empty())
        std::cerr << "database warning: " << app.db.last_error() << "\n";
    reload_friends(app);
    app.danger_events =
        dedup_events(load_events(data_dir + "/danger.txt"));
    app.cities = load_cities(data_dir + "/cities.txt");

    // ---- decentralized layer: Kademlia DHT -------------------------
    std::vector<Endpoint> boot_eps;
    for (auto& b : config.bootstraps) {
        auto eps = resolve_endpoint(b);
        boot_eps.insert(boot_eps.end(), eps.begin(), eps.end());
    }
    app.dht = std::make_unique<Dht>(
        app.identity, app.identity.x25519.pub,
        Endpoint{Endpoint::Family::IPv6, "::",
                 static_cast<uint16_t>(config.dht_port)},
        boot_eps);
    app.dht->start();
    app.dht->publish_self(config.name,
                          static_cast<uint16_t>(config.port));

    auto screen = App::Fullscreen();

    app.net = std::make_unique<Net>(
        app.identity, config.port, app.db,
        [&screen, &app](const std::string& peer_key,
                         const std::string& text) {
            {
                std::lock_guard lk(app.inbox_mu);
                app.inbox.push_back({peer_key, text});
            }
            screen.PostEvent(Event::Custom);
        },
        [&screen, &app](int64_t fid, const std::string& peer_key,
                        bool online, const std::string& name) {
            {
                std::lock_guard lk(app.inbox_mu);
                app.statuses.push_back({fid, peer_key, online, name});
            }
            screen.PostEvent(Event::Custom);
        },
        app.dht.get(),
        [&screen, &app](const std::string& msg) {
            post_notice(app, msg,
                        [&screen] { screen.PostEvent(Event::Custom); });
        });
    app.net->start();

    // Background check for a newer GitHub release.
    std::thread([&app, &screen]() {
        updater::ReleaseInfo rel;
        std::string err;
        if (!updater::fetch_latest(rel, &err)) return;
        if (updater::compare_versions(rel.tag,
                                      updater::current_version()) <= 0)
            return;
        {
            std::lock_guard lk(app.update_mu);
            app.latest_release = rel;
        }
        post_notice(
            app, "update available: " + rel.tag +
                     " — /update to install",
            [&screen] { screen.PostEvent(Event::Custom); });
    }).detach();

    // ---- geolocation ------------------------------------------------
    // Precise device fix (CoreLocation on macOS) + IP geolocation.
    // Slow (GPS acquisition + HTTPS), so it runs in the background and
    // reports through the console once done.
    std::thread([&app, &screen]() {
        GeoInfo g = fetch_geo_info();
        if (g.ip.empty() && app.dht) {
            // ipwho.is did not report the client IP — fall back to the
            // public endpoint observed through the DHT.
            if (auto obs = app.dht->observed_public_endpoint())
                g.ip = obs->addr;
        }
        {
            std::lock_guard lk(app.geo_mu);
            app.geo = g;
            app.geo_done = true;
        }
        auto post = [&](const std::string& m) {
            post_notice(app, m,
                        [&screen] { screen.PostEvent(Event::Custom); });
        };
        if (!g.ok) {
            post("location: unavailable (geo lookup failed)");
            return;
        }
        if (g.precise) {
            char coords[64];
            std::snprintf(coords, sizeof(coords), "%.5f, %.5f",
                          g.lat, g.lon);
            std::string line = "location (device): " +
                               std::string(coords);
            if (g.accuracy_m >= 0)
                line += " ±" + std::to_string(
                            static_cast<int>(g.accuracy_m)) +
                        " m";
            post(line);
        }
        std::string place;
        auto add = [&place](const std::string& s) {
            if (s.empty()) return;
            if (!place.empty()) place += ", ";
            place += s;
        };
        add(g.city);
        // ipwho.is repeats the city name in "region" for municipalities.
        if (!g.region.empty() && to_lower(g.region) != to_lower(g.city))
            add(g.region);
        add(g.country);
        if (!place.empty())
            post("location (approx): " + place +
                 (g.precise ? " (from IP)" : ""));
        if (!g.ip.empty())
            post("public ip: " + g.ip +
                 (g.isp.empty() ? "" : "  (" + g.isp + ")"));
        if (!g.local_ips.empty()) {
            std::string ips;
            for (auto& a : g.local_ips) {
                if (!ips.empty()) ips += ", ";
                ips += a;
            }
            post("local ip: " + ips);
        }
        if (g.precise && place.empty() && g.ip.empty())
            post("location: device fix only, no IP info");

        // Civilian danger assessment for the resolved position.
        auto a = assess_now(app);
        if (a.computed) {
            post("danger level: L" + std::to_string(a.level) + " (" +
                     level_name(a.level) + "), index " +
                     std::to_string(a.index) + "/100 — /danger for "
                     "details");
        } else {
            post("danger: position unknown, cannot assess");
        }
    }).detach();

    // Wake the UI ~5x a second: drives the AI danger refresh, keeps
    // the "updated Xs ago" labels current and animates the level
    // pulse + next-update countdown in the Danger panel.
    std::atomic<bool> ui_running{true};
    std::thread([&screen, &ui_running] {
        while (ui_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            if (ui_running) screen.PostEvent(Event::Custom);
        }
    }).detach();

    // ---- components -------------------------------------------------
    // Tabs: 0 = Main (danger + system), 1 = Logs, 2 = Chats,
    // 3 = Settings. Tab / Shift-Tab switches.
    int tab = 0;
    int main_scroll = 0, friends_scroll = 0, settings_scroll = 0;
    int danger_scroll = 0;
    int main_rows = 0, friends_rows = 0, settings_rows = 0,
        danger_rows = 0;

    std::string input_text;
    std::string input_hint;
    auto handle_input = [&app, &screen, &input_text, &input_hint]() {
        std::string text = input_text;
        input_text.clear();
        input_hint.clear();
        if (text.empty()) return;

        if (!text.empty() && text[0] == '/') {
            execute_command(
                app, text,
                [&screen] { screen.PostEvent(Event::Custom); },
                [&screen] { screen.Post([&screen] { screen.Exit(); }); });
        } else if (app.mode == ChatApp::Mode::Chat) {
            if (auto* fv = app.find_by_id(app.open_friend_id)) {
                bool sent = false;
                if (!fv->peer_key.empty() && app.net)
                    sent = app.net->send(fv->peer_key, text);
                if (!sent && app.net) {
                    app.net->connect_to(fv->f);
                    say(app, "connecting... message not sent");
                } else if (sent) {
                    fv->lines.push_back({true, text});
                    app.db.add_message(fv->f.id, true, text);
                }
            }
        } else {
            say(app, "no chat open — use /chat <name> first");
        }
        screen.PostEvent(Event::Custom);
    };

    InputOption input_opt;
    input_opt.content = &input_text;
    input_opt.placeholder = "command or message (/help)";
    input_opt.multiline = false;  // Enter submits instead of newline
    input_opt.on_enter = handle_input;
    input_opt.on_change = [&app, &screen, &input_text, &input_hint]() {
        input_hint = command_hint(app, input_text);
        screen.PostEvent(Event::Custom);
    };
    auto input = Input(input_opt);
    input |= Renderer([&](Element inner) {
        return hbox({
            text(" ❯ ") | bold | color(Color::Cyan),
            inner | flex,
        });
    });

    auto friends_view = Renderer([&] {
        return window(text(" Contacts ") | bold | color(Color::Yellow),
                      render_friends(app, friends_scroll, friends_rows),
                      ROUNDED) |
               flex;
    });
    auto chat_pane = Renderer([&] {
        FriendView* fv = app.find_by_id(app.open_friend_id);
        if (app.mode == ChatApp::Mode::Chat && fv) {
            bool online = fv->online;
            auto title_el = hbox({
                text(" " + fv->display_name + " ") | bold |
                    color(online ? Color::Green : Color::Magenta),
                text(" " + std::string(online ? "online" : "offline") +
                     " ") |
                    color(Color::GrayDark),
            });
            return window(title_el, render_chat_lines(*fv), ROUNDED) |
                   flex;
        }
        return window(text(" Chat ") | bold | color(Color::Cyan),
                      vbox({filler(),
                            text("no chat open — /chat <name>") | dim,
                            text("contacts are on the left") | dim,
                            filler()}) |
                          flex | borderEmpty,
                      ROUNDED) |
               flex;
    });
    auto chats_view =
        Container::Horizontal({friends_view | size(WIDTH, EQUAL, 34),
                               chat_pane | flex});

    auto tab_main = Renderer([&] {
        int lvl = effective_danger_level(app);
        Color tc = level_color(lvl > 0 ? lvl : 5);
        return hbox({
            window(text(" Danger ") | bold | color(tc),
                   render_danger_panel(app, danger_scroll,
                                       danger_rows),
                   ROUNDED) |
                size(WIDTH, EQUAL, 46),
            window(text(" Main ") | bold | color(Color::Yellow),
                   render_main_details(app, main_scroll, main_rows),
                   ROUNDED) |
                flex,
        }) | flex;
    });
    auto tab_logs = Renderer([&] {
        return window(text(" Logs ") | bold | color(Color::Cyan),
                      render_console(app), ROUNDED) |
               flex;
    });
    // Interactive sound notifications panel pinned under the
    // Settings info pane: master switch, per-level toggles with a
    // ‹ › sound picker each, output device picker, test button.
    auto persist_sound = [&app] { save_sound_config(app); };
    auto sound_cb = [&](const std::string& label, bool* flag) {
        CheckboxOption opt;
        opt.label = label;
        opt.checked = flag;
        opt.on_change = persist_sound;
        return Checkbox(opt);
    };
    // One-row ‹ › cycler for sound/device selection — compact enough
    // that the panel never outgrows the settings tab. Changes land in
    // *index and are synced into app.config by sync_sound_ui.
    auto cycle_picker = [](const std::string& label,
                           const std::vector<std::string>& entries,
                           int* index) {
        return CatchEvent(
            Renderer([label, entries, index](bool focused) {
                int n = static_cast<int>(entries.size());
                int i = n ? std::clamp(*index, 0, n - 1) : 0;
                auto val = text(" " + (n ? entries[i] : "?") + " ") |
                           bold | color(Color::Cyan);
                if (focused) val = val | inverted;
                return hbox({
                    text(" " + label + " ") |
                        (focused ? color(Color::White) : color(Color::GrayDark)),
                    text("‹") | color(Color::Cyan),
                    val,
                    text("›") | color(Color::Cyan),
                });
            }),
            [entries, index](Event e) {
                int n = static_cast<int>(entries.size());
                if (n == 0) return false;
                if (e == Event::ArrowLeft || e == Event::ArrowRight ||
                    e == Event::Character(' ')) {
                    int d = e == Event::ArrowLeft ? -1 : 1;
                    *index = (*index + d % n + n) % n;
                    return true;
                }
                return false;
            });
    };
    // Sound picker entries: index 0 = auto (per-level default).
    auto sound_files = list_sound_files();
    std::vector<std::string> pick_entries = {"auto"};
    for (auto& f : sound_files) pick_entries.push_back(f.name);
    auto pick_index = [&](const std::string& stored) {
        if (stored.empty()) return 0;
        for (size_t i = 1; i < pick_entries.size(); ++i)
            if (to_lower(pick_entries[i]) == to_lower(stored))
                return static_cast<int>(i);
        return 0;
    };
    int pick_idx[5], prev_pick_idx[5];
    for (int i = 0; i < 5; ++i)
        pick_idx[i] = prev_pick_idx[i] =
            pick_index(app.config.sound_pick[i]);
    // Output device entries: index 0 = system default.
    auto sound_devs = list_output_devices();
    std::vector<std::string> dev_entries = {"system default"};
    for (auto& d : sound_devs)
        dev_entries.push_back(d.name.empty() ? d.id : d.name);
    int dev_idx = 0;
    for (size_t i = 0; i < sound_devs.size(); ++i)
        if (sound_devs[i].id == app.config.sound_out)
            dev_idx = static_cast<int>(i) + 1;
    int prev_dev_idx = dev_idx;

    auto sound_master = sound_cb("sound notifications",
                                 &app.config.sound_enabled);
    std::vector<Component> sound_items = {sound_master};
    // Each level gets an enable checkbox followed by its ‹ › sound
    // picker as a direct child of the vertical panel — containers only
    // consume Up/Down for focus, so Left/Right reach the picker.
    for (int i = 1; i <= 5; ++i) {
        sound_items.push_back(sound_cb(
            "L" + std::to_string(i) + " " + level_name(i),
            &app.config.sound_level[i - 1]));
        sound_items.push_back(cycle_picker(
            "L" + std::to_string(i) + " sound", pick_entries,
            &pick_idx[i - 1]));
    }
    sound_items.push_back(
        cycle_picker("output device", dev_entries, &dev_idx));
    // Button only fires on Enter; also trigger on Space so it behaves
    // like the checkboxes above it.
    auto test_sound_fn = [&app, &screen] {
        int lvl = effective_danger_level(app);
        if (lvl < 1 || lvl > 5) lvl = 3;
        test_sound(app, lvl,
                   [&screen] { screen.PostEvent(Event::Custom); });
    };
    sound_items.push_back(CatchEvent(
        Button("test sound", test_sound_fn,
               ButtonOption::Animated()),
        [test_sound_fn](Event e) {
            if (e == Event::Character(' ')) {
                test_sound_fn();
                return true;
            }
            return false;
        }));
    // Mute the repeating danger alert until the level changes.
    auto ack_sound_fn = [&app, &screen] {
        app.sound_alarm_acked = true;
        app.sound_alarm_next_ms = 0;
        say(app, "alert sound silenced until the level changes");
        screen.PostEvent(Event::Custom);
    };
    sound_items.push_back(CatchEvent(
        Button("silence alert", ack_sound_fn,
               ButtonOption::Animated()),
        [ack_sound_fn](Event e) {
            if (e == Event::Character(' ')) {
                ack_sound_fn();
                return true;
            }
            return false;
        }));
    auto sound_panel = Container::Vertical(std::move(sound_items));
    sound_panel |= Renderer([&](Element inner) {
        return window(text(" Sound notifications ") | bold |
                          color(Color::Yellow),
                      inner | borderEmpty, ROUNDED);
    });
    auto settings_info = Renderer([&] {
        return window(text(" Settings ") | bold | color(Color::Yellow),
                      render_settings_view(app, settings_scroll,
                                           settings_rows),
                      ROUNDED) |
               flex;
    });
    auto tab_settings =
        Container::Vertical({settings_info | flex, sound_panel});
    auto content = Container::Tab(
        {tab_main, tab_logs, chats_view, tab_settings}, &tab);

    auto tab_bar = Renderer([&tab] {
        static const char* names[] = {" Main ", " Logs ", " Chats ",
                                      " Settings "};
        std::vector<Element> els;
        for (int i = 0; i < 4; ++i) {
            if (i > 0)
                els.push_back(text(" │ ") | color(Color::GrayDark));
            bool on = i == tab;
            els.push_back(text(names[i]) |
                          (on ? bold | color(Color::Black) |
                                     bgcolor(Color::Cyan)
                              : color(Color::GrayDark)));
        }
        return hbox(std::move(els));
    });

    auto sep = [] {
        return Renderer([] { return separator() | color(Color::GrayDark); });
    };

    auto header = Renderer([&app] {
        std::string fp = crypto::to_hex(app.identity.x25519.pub.data(), 8);
        std::string net_info;
        bool geo_ready = false;
        {
            std::lock_guard lk(app.geo_mu);
            geo_ready = app.geo_done;
            if (app.geo_done) {
                if (!app.geo.ip.empty()) net_info += "ip:" + app.geo.ip;
                std::string loc;
                if (!app.geo.city.empty()) {
                    loc = app.geo.city;
                    if (!app.geo.country.empty())
                        loc += "," + app.geo.country;
                } else if (app.geo.lat != 0 || app.geo.lon != 0) {
                    char coords[48];
                    std::snprintf(coords, sizeof(coords), "%.4f,%.4f",
                                  app.geo.lat, app.geo.lon);
                    loc = coords;
                }
                if (!loc.empty()) {
                    if (!net_info.empty()) net_info += "  ";
                    net_info += "loc:" + loc +
                                (app.geo.precise ? "*" : "");
                }
            }
        }
        // Civilian danger badge (L1 critical .. L5 none detected).
        // Prefers the AI verdict when one is available.
        ChatApp::AiDanger ai;
        {
            std::lock_guard lk(app.ai_mu);
            ai = app.ai_danger;
        }
        int lvl = effective_danger_level(app);
        Element badge = text("");
        if (lvl > 0) {
            Color lc = level_color(lvl);
            badge = hbox({
                text(" L" + std::to_string(lvl)) | bold | color(lc),
                ai.have_verdict ? text(" ai") | dim : text(""),
            });
        } else if (!geo_ready) {
            badge = text(" loading") | color(Color::Cyan);
        }
        return hbox({
            text(" Radius") | bold | color(Color::Cyan),
            text(" v" APP_VERSION) | dim,
            badge,
            filler(),
            text("me:" + app.config.name + "  fp:" + fp +
                 "  tcp:" + std::to_string(app.config.port) +
                 "  udp:" + std::to_string(app.config.dht_port) +
                 (net_info.empty() ? "" : "  " + net_info)) |
                color(Color::GrayDark),
        });
    });

    auto status_line = Renderer([&app, &input_hint] {
        std::string s = input_hint;
        Color c = Color::Yellow;
        if (s.empty()) s = app.notice;
        if (s.empty()) {
            s = app.mode == ChatApp::Mode::Chat
                    ? "Enter: send | /close: back | Tab: switch view"
                    : "Tab: switch view | /help for commands | "
                      "PgUp/PgDn/wheel: scroll";
            c = Color::GrayDark;
        }
        return text(" " + s) | color(c);
    });

    auto root = Container::Vertical(
        {header, sep(), tab_bar, content | flex, input, status_line});
    // FTXUI only dispatches keys to the active child of each container;
    // without this the input never sees keystrokes.
    input->TakeFocus();

    auto scroll_by = [&app, &screen, &tab, &main_scroll, &friends_scroll,
                      &settings_scroll, &danger_scroll, &main_rows,
                      &friends_rows, &settings_rows,
                      &danger_rows](int delta) {
        if (tab == 0) {
            // The Main tab is split into two panes; scroll both.
            danger_scroll = std::clamp(
                danger_scroll + delta, 0, max_scroll(danger_rows));
            main_scroll = std::clamp(main_scroll + delta,
                                     0, max_scroll(main_rows));
            screen.PostEvent(Event::Custom);
            return;
        }
        int mx = 0;
        int* target = nullptr;
        if (tab == 1) {
            mx = max_scroll(app.console.size());
            target = &app.console_scroll;
        } else if (tab == 2) {
            if (app.mode == ChatApp::Mode::Chat) {
                if (auto* fv = app.find_by_id(app.open_friend_id)) {
                    mx = max_scroll(fv->lines.size());
                    target = &fv->chat_scroll;
                }
            }
            if (!target) {
                mx = max_scroll(friends_rows);
                target = &friends_scroll;
            }
        } else {
            mx = max_scroll(settings_rows);
            target = &settings_scroll;
        }
        if (target) *target = std::clamp(*target + delta, 0, mx);
        screen.PostEvent(Event::Custom);
    };

    // Two-way sync between the ‹ › pickers and app.config: picker
    // changes are persisted; config changes made via /sound commands
    // are reflected back into the picker indices.
    auto sync_sound_ui = [&] {
        bool dirty = false;
        for (int i = 0; i < 5; ++i) {
            std::string cur = pick_idx[i] == 0
                                  ? ""
                                  : pick_entries[pick_idx[i]];
            if (cur != app.config.sound_pick[i] &&
                pick_idx[i] == prev_pick_idx[i]) {
                // Config changed externally — follow it.
                pick_idx[i] = pick_index(app.config.sound_pick[i]);
                prev_pick_idx[i] = pick_idx[i];
                continue;
            }
            if (pick_idx[i] == prev_pick_idx[i]) continue;
            prev_pick_idx[i] = pick_idx[i];
            app.config.sound_pick[i] = cur;
            dirty = true;
        }
        std::string cur_dev =
            dev_idx == 0 ? "" : sound_devs[dev_idx - 1].id;
        if (cur_dev != app.config.sound_out &&
            dev_idx == prev_dev_idx) {
            for (size_t i = 0; i < sound_devs.size(); ++i)
                if (sound_devs[i].id == app.config.sound_out)
                    dev_idx = static_cast<int>(i) + 1;
            if (app.config.sound_out.empty()) dev_idx = 0;
            prev_dev_idx = dev_idx;
        } else if (dev_idx != prev_dev_idx) {
            prev_dev_idx = dev_idx;
            app.config.sound_out = cur_dev;
            dirty = true;
        }
        if (dirty) save_sound_config(app);
    };

    auto global = CatchEvent(root, [&](Event event) {
        drain_inbox(app);
        // Sequential AI danger refresh: own location + tracked cities
        // rotate one at a time (self-throttled to ~60 s per attempt).
        kick_location_refresh(app,
                              [&screen] { screen.PostEvent(Event::Custom); });
        check_danger_sound(app);
        sync_sound_ui();
        auto focus_for_tab = [&] {
            if (tab == 3)
                sound_panel->TakeFocus();
            else
                input->TakeFocus();
        };
        if (event == Event::Tab) {
            tab = (tab + 1) % 4;
            focus_for_tab();
            return true;
        }
        if (event == Event::TabReverse) {
            tab = (tab + 3) % 4;
            focus_for_tab();
            return true;
        }
        if (event == Event::PageUp) {
            scroll_by(pane_rows());
            return true;
        }
        if (event == Event::PageDown) {
            scroll_by(-pane_rows());
            return true;
        }
        if (event == Event::ArrowUp) {
            if (tab == 3) return false;  // navigate sound settings
            scroll_by(1);
            return true;
        }
        if (event == Event::ArrowDown) {
            if (tab == 3) return false;  // navigate sound settings
            scroll_by(-1);
            return true;
        }
        if (event.is_mouse()) {
            if (event.mouse().button == Mouse::WheelUp) {
                scroll_by(3);
                return true;
            }
            if (event.mouse().button == Mouse::WheelDown) {
                scroll_by(-3);
                return true;
            }
        }
        return false;  // let the focused input handle keys
    });

    screen.Loop(global);
    ui_running = false;
    app.net->stop();
    if (app.dht) app.dht->stop();
    return 0;
}
