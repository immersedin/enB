// P2P Secure Chat — FTXUI frontend.
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
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <cctype>
#include <cstring>
#include <iterator>
#include <memory>
#include <sstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <sodium.h>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/screen/terminal.hpp>

#include "ai.h"
#include "crypto.h"
#include "danger.h"
#include "db.h"
#include "dht.h"
#include "endpoint.h"
#include "geo.h"
#include "invite.h"
#include "net.h"
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

struct Config {
    int port = 5555;
    int dht_port = 0;  // 0 = same number as port (UDP)
    std::string name = "me";
    std::vector<std::string> bootstraps;  // raw "host:port" DHT endpoints
    std::string openai_key;               // legacy: for /danger ai
    std::string ai_key;                   // AI provider key (Groq etc.)
    std::string ai_base;                  // chat-completions URL (optional)
    std::string ai_model;                 // model name (optional)
};

Config load_config(const std::string& path) {
    Config c;
    std::ifstream f(path);
    std::string line;
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

// Text rows available for the scrollable pane. The fixed chrome around it
// is: header (1) + separator (1) + input (1) + status line (1) +
// window border (2) + inner padding (2).
int pane_rows() {
    return std::max(3, Terminal::Size().dimy - 8);
}

// Copy `text` to the OS clipboard via a platform tool. The payload goes
// through a temp file so no shell escaping of the text is needed.
bool copy_to_clipboard(const std::string& text) {
    fs::path tmp = fs::temp_directory_path() / "p2p-chat-clipboard.txt";
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

    // AI (LLM) danger verdict shown on the Main tab. ai_danger is
    // written by the worker thread under ai_mu; ai_last_query and
    // ai_running implement the 60 s refresh throttle.
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
    std::atomic<bool> ai_running{false};
    int64_t ai_last_query = 0;

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

// Kick off an AI danger assessment in the background. Throttled to
// one request per 60 s unless `force`; the verdict lands in
// app.ai_danger and the raw reply is mirrored into the log.
// Returns false when the location fix is not ready yet.
bool kick_ai_danger(ChatApp& app, bool force,
                    const std::function<void()>& wake) {
    int64_t now = unix_now();
    if (!force && now - app.ai_last_query < 60) return true;
    {
        std::lock_guard lk(app.geo_mu);
        if (!app.geo_done) return false;
    }
    if (app.ai_running.exchange(true)) return true;
    app.ai_last_query = now;

    ai::AiEndpoint ep;
    if (!app.config.ai_base.empty()) ep.base_url = app.config.ai_base;
    if (!app.config.ai_model.empty()) ep.model = app.config.ai_model;
    ep.api_key = app.config.ai_key;
    std::string prompt = build_danger_prompt(app);
    {
        std::lock_guard lk(app.ai_mu);
        app.ai_danger.running = true;
        app.ai_danger.error.clear();
        app.ai_danger.model = ep.model;
    }
    say(app, "querying " + ep.model + " for danger assessment...");
    std::thread([&app, wake, prompt, ep]() {
        std::string err;
        std::string reply = ai::danger_assessment(ep, prompt, &err);
        int level = 0, index = -1;
        bool ok = !reply.empty() && parse_ai_verdict(reply, level, index);
        {
            std::lock_guard lk(app.ai_mu);
            auto& d = app.ai_danger;
            d.running = false;
            d.ts = unix_now();
            if (ok) {
                d.have_verdict = true;
                d.level = level;
                d.index = index;
                d.reason = parse_ai_reason(reply);
                d.error.clear();
            } else {
                d.error = reply.empty()
                              ? ("request failed: " + err)
                              : "could not parse AI reply";
            }
        }
        app.ai_running = false;
        // Mirror the reply into the log tab.
        if (!reply.empty()) {
            std::istringstream rs(reply);
            std::string ln;
            while (std::getline(rs, ln)) {
                if (!ln.empty() && ln.back() == '\r') ln.pop_back();
                if (!ln.empty()) post_notice(app, "  ai| " + ln, wake);
            }
        } else {
            post_notice(app, "AI assessment failed: " + err, wake);
        }
        if (wake) wake();
    }).detach();
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
            app.ai_last_query = 0;
            kick_ai_danger(app, false, wake);
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
            app.ai_last_query = 0;
            kick_ai_danger(app, false, wake);
            say(app, "event removed");
        } else if (sub == "clear") {
            app.danger_events.clear();
            save_danger_events(app);
            app.ai_last_query = 0;
            kick_ai_danger(app, false, wake);
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
            if (kick_ai_danger(app, true, wake))
                say(app, "AI assessment requested "
                         "(auto-refreshes every 60 s)");
            else
                say(app, "AI assessment unavailable — "
                         "waiting for location fix");
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

Element render_console(const ChatApp& app) {
    std::vector<Element> all;
    if (app.console.empty()) {
        all.push_back(text("P2P Secure Chat") | bold |
                      color(Color::Cyan));
        all.push_back(text("type /help for commands") |
                      color(Color::GrayDark));
    } else {
        for (auto& l : app.console) all.push_back(text(l));
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

// ------------------------------------------------------------------
// Main tab: prominent danger level + system state overview.
// ------------------------------------------------------------------
Element render_main_view(const ChatApp& app, int scroll,
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

    // ---- danger headline ----
    all.push_back(text(" DANGER ") | bold | color(Color::Yellow));
    int lvl = ai.have_verdict ? ai.level
                              : (a.computed ? a.level : 0);
    int idx = ai.have_verdict ? ai.index
                              : (a.computed ? a.index : -1);
    if (lvl > 0) {
        Color lc = level_color(lvl);
        all.push_back(text("  L" + std::to_string(lvl) + "  " +
                           std::string(level_name(lvl))) |
                      bold | color(lc));
        if (idx >= 0) {
            all.push_back(hbox({
                text("index ") | dim,
                gauge(idx / 100.0f) | size(WIDTH, EQUAL, 24),
                text(" " + std::to_string(idx) + "/100") | bold,
            }));
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
        all.push_back(text("  " + meta +
                           (ai.model.empty() ? "" : "  •  " + ai.model)) |
                      dim);
        if (!ai.reason.empty())
            all.push_back(text("  " + ai.reason) | color(Color::Cyan));
        if (!ai.error.empty())
            all.push_back(text("  AI error: " + ai.error) |
                          color(Color::Red));
    } else {
        all.push_back(text("  level unknown — waiting for data") |
                      color(Color::GrayDark));
    }
    if (a.computed) {
        all.push_back(text("  local model: L" +
                           std::to_string(a.level) + " (" +
                           level_name(a.level) + "), index " +
                           std::to_string(a.index) + "/100") |
                      dim);
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
        all.push_back(text("  " + std::string(buf)) | dim);
    } else {
        all.push_back(text("  position unknown") |
                      color(Color::GrayDark));
    }
    auto evs = dedup_events(app.danger_events);
    int shown = 0;
    for (auto& c : a.top) {
        if (shown++ >= 5) break;
        const auto& e = evs[c.event_index];
        char line[256];
        std::snprintf(
            line, sizeof(line),
            "  event #%zu %s %.1fkm (eff %.1fkm), age %.1fh, "
            "contrib %.0f",
            c.event_index, kind_name(e.kind), c.raw_dist_km,
            c.dist_km, std::max(0.0, (now - e.ts) / 3600.0),
            c.contribution);
        all.push_back(text(line) | dim);
    }
    if (a.top.empty() && a.computed)
        all.push_back(text("  no combat events affect this position") |
                      dim);

    // ---- system state ----
    all.push_back(separator() | color(Color::GrayDark));
    all.push_back(text(" SYSTEM ") | bold | color(Color::Yellow));
    all.push_back(text("  version " APP_VERSION "   name " +
                       app.config.name) |
                  dim);
    {
        std::string fp =
            crypto::to_hex(app.identity.x25519.pub.data(), 8);
        all.push_back(text("  peer " + peer_id_hex(app.identity)) | dim);
        all.push_back(text("  fingerprint " + fp + "   tcp:" +
                           std::to_string(app.config.port) + "   udp:" +
                           std::to_string(app.config.dht_port)) |
                      dim);
    }
    {
        std::lock_guard lk(app.geo_mu);
        if (app.geo_done && !app.geo.ip.empty()) {
            all.push_back(text("  public ip " + app.geo.ip +
                               (app.geo.isp.empty()
                                    ? ""
                                    : " (" + app.geo.isp + ")")) |
                          dim);
        }
    }
    {
        int online = 0;
        for (auto& fv : app.friends)
            if (fv.online) ++online;
        all.push_back(text("  contacts " +
                           std::to_string(app.friends.size()) + " (" +
                           std::to_string(online) + " online)") |
                      dim);
    }
    if (app.dht) {
        all.push_back(text("  dht nodes " +
                           std::to_string(app.dht->known_nodes()) +
                           "   records " +
                           std::to_string(app.dht->stored_records())) |
                      dim);
    } else {
        all.push_back(text("  dht disabled") | dim);
    }
    all.push_back(text("  combat events " +
                       std::to_string(app.danger_events.size()) +
                       " stored") |
                  dim);
    all.push_back(text("  data dir " + app.data_dir) | dim);
    {
        std::lock_guard lk(app.update_mu);
        if (app.update_running)
            all.push_back(text("  update: in progress") |
                          color(Color::Yellow));
        else if (!app.latest_release.tag.empty())
            all.push_back(text("  update available: " +
                               app.latest_release.tag +
                               " — /update") |
                          color(Color::Yellow));
        else
            all.push_back(text("  update: up to date") | dim);
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
    if (const char* env = std::getenv("P2P_DATA_DIR"))
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
            : std::string(home ? home : ".") + "/.p2p-chat";
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

    // Wake the UI once a minute: drives the AI danger refresh and
    // keeps the "updated Xs ago" labels current.
    std::atomic<bool> ui_running{true};
    std::thread([&screen, &ui_running] {
        while (ui_running) {
            std::this_thread::sleep_for(std::chrono::minutes(1));
            if (ui_running) screen.PostEvent(Event::Custom);
        }
    }).detach();

    // ---- components -------------------------------------------------
    // Tabs: 0 = Main (danger + system), 1 = Logs, 2 = Chats,
    // 3 = Settings. Tab / Shift-Tab switches.
    int tab = 0;
    int main_scroll = 0, friends_scroll = 0, settings_scroll = 0;
    int main_rows = 0, friends_rows = 0, settings_rows = 0;

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
        return window(text(" Main ") | bold | color(Color::Yellow),
                      render_main_view(app, main_scroll, main_rows),
                      ROUNDED) |
               flex;
    });
    auto tab_logs = Renderer([&] {
        return window(text(" Logs ") | bold | color(Color::Cyan),
                      render_console(app), ROUNDED) |
               flex;
    });
    auto tab_settings = Renderer([&] {
        return window(text(" Settings ") | bold | color(Color::Yellow),
                      render_settings_view(app, settings_scroll,
                                           settings_rows),
                      ROUNDED) |
               flex;
    });
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
        {
            std::lock_guard lk(app.geo_mu);
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
        auto da = assess_now(app);
        int lvl = ai.have_verdict ? ai.level
                                  : (da.computed ? da.level : 0);
        Element badge = text("");
        if (lvl > 0) {
            Color lc = level_color(lvl);
            badge = hbox({
                text(" L" + std::to_string(lvl)) | bold | color(lc),
                ai.have_verdict ? text(" ai") | dim : text(""),
            });
        }
        return hbox({
            text(" P2P Secure Chat") | bold | color(Color::Cyan),
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

    auto scroll_by = [&app, &screen, &tab, &main_scroll, &friends_scroll,
                      &settings_scroll, &main_rows, &friends_rows,
                      &settings_rows](int delta) {
        int mx = 0;
        int* target = nullptr;
        if (tab == 0) {
            mx = max_scroll(main_rows);
            target = &main_scroll;
        } else if (tab == 1) {
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

    auto global = CatchEvent(root, [&](Event event) {
        drain_inbox(app);
        // Periodic AI danger refresh (self-throttled to 60 s).
        kick_ai_danger(app, false,
                       [&screen] { screen.PostEvent(Event::Custom); });
        if (event == Event::Tab) {
            tab = (tab + 1) % 4;
            return true;
        }
        if (event == Event::TabReverse) {
            tab = (tab + 3) % 4;
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
            scroll_by(1);
            return true;
        }
        if (event == Event::ArrowDown) {
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
