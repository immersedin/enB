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
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <cctype>
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

#include "crypto.h"
#include "db.h"
#include "dht.h"
#include "endpoint.h"
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
// frame borders (2).
int pane_rows() {
    return std::max(3, Terminal::Size().dimy - 6);
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
    std::mutex update_mu;
    updater::ReleaseInfo latest_release;
    std::atomic<bool> update_running{false};

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
        Endpoint ep;
        if (!parse_endpoint(args[1], ep)) {
            say(app, "bad endpoint — use host:port or [v6]:port");
            return;
        }
        if (app.dht) app.dht->add_bootstrap(ep);
        std::ofstream cfg(app.data_dir + "/config.ini",
                          std::ios::app);
        cfg << "bootstrap=" << ep.str() << "\n";
        say(app, "bootstrap node added: " + ep.str());
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
Element render_friends(const ChatApp& app) {
    std::vector<Element> rows;
    if (app.friends.empty()) {
        rows.push_back(text("  no friends — /add <name> <host> <port>") |
                       color(Color::GrayDark));
    }
    for (auto& fv : app.friends) {
        bool open = fv.f.id == app.open_friend_id;
        std::string where = fv.f.host.empty()
                                ? "dht:" + short_id(fv.f.x25519_pub)
                                : fv.f.host + ":" +
                                      std::to_string(fv.f.port);
        std::string label =
            (open ? ">" : " ") + std::string(" ") +
            (fv.online ? "(*)" : "( )") + " " + fv.display_name + "   " +
            where;
        rows.push_back(text(label) |
                       color(open ? Color::Cyan : Color::White));
    }
    return vbox({text(" Friends ") | bold | color(Color::Yellow),
                 separator(),
                 vbox(std::move(rows)) | flex}) |
           frame | flex;
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

Element render_console(const ChatApp& app) {
    std::vector<Element> rows;
    const size_t total = app.console.size();
    int visible = pane_rows();
    bool overflow = total > static_cast<size_t>(visible);
    if (overflow) --visible;  // room for the scroll indicator
    auto [start, end] =
        scroll_window(total, app.console_scroll, visible);
    if (overflow) {
        rows.push_back(text("  lines " + std::to_string(start + 1) + "-" +
                            std::to_string(end) + " of " +
                            std::to_string(total) +
                            (app.console_scroll > 0
                                 ? "  (scrolled up — PgDn/PgUp)"
                                 : "")) |
                       color(Color::GrayDark));
    }
    if (start == end) {
        rows.push_back(text("P2P Secure Chat") | bold |
                       color(Color::Cyan));
        rows.push_back(text("type /help for commands") |
                       color(Color::GrayDark));
    } else {
        for (size_t i = start; i < end; ++i)
            rows.push_back(text(app.console[i]));
    }
    return vbox(std::move(rows)) | flex | frame;
}

Element render_chat_lines(const FriendView& fv) {
    std::vector<Element> rows;
    const size_t total = fv.lines.size();
    int visible = pane_rows();
    bool overflow = total > static_cast<size_t>(visible);
    if (overflow) --visible;  // room for the scroll indicator
    auto [start, end] = scroll_window(total, fv.chat_scroll, visible);
    if (overflow) {
        rows.push_back(text("  lines " + std::to_string(start + 1) + "-" +
                            std::to_string(end) + " of " +
                            std::to_string(total) +
                            (fv.chat_scroll > 0
                                 ? "  (scrolled up — PgDn/PgUp)"
                                 : "")) |
                       color(Color::GrayDark));
    }
    if (start == end) {
        rows.push_back(text("  no messages yet") |
                       color(Color::GrayDark));
    } else {
        for (size_t i = start; i < end; ++i) {
            const auto& l = fv.lines[i];
            rows.push_back(hbox({
                text(l.outgoing ? "you: " : fv.display_name + ": ") |
                    color(l.outgoing ? Color::Green : Color::Cyan) | bold,
                text(l.text),
            }));
        }
    }
    return vbox(std::move(rows)) | flex | frame;
}

}  // namespace

int main(int argc, char** argv) {
    for (int i = 1; i < argc; ++i)
        if (std::string(argv[i]) == "--selftest") return run_selftest();

    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    const char* home = std::getenv("HOME");
#ifdef _WIN32
    if (!home) home = std::getenv("USERPROFILE");
#endif
    std::string data_dir = std::string(home ? home : ".") + "/.p2p-chat";
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

    // ---- decentralized layer: Kademlia DHT -------------------------
    std::vector<Endpoint> boot_eps;
    for (auto& b : config.bootstraps) {
        Endpoint ep;
        if (parse_endpoint(b, ep)) boot_eps.push_back(ep);
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

    // ---- components -------------------------------------------------
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

    auto friends_view = Renderer([&app] { return render_friends(app); });
    auto main_view = Renderer([&app] {
        if (app.mode == ChatApp::Mode::Chat) {
            FriendView* fv = app.find_by_id(app.open_friend_id);
            std::string title = fv ? fv->display_name : "chat";
            std::string state = (fv && fv->online) ? "online" : "offline";
            auto title_el = hbox(
                {text(" Chat: " + title + " [" + state + "]  ") |
                     bold | color(Color::Magenta),
                 text("/close to exit") | color(Color::GrayDark)});
            static FriendView empty;
            return vbox({title_el, separator(),
                         render_chat_lines(fv ? *fv : empty) | flex});
        }
        return vbox({render_console(app) | flex});
    });

    auto sep = [] { return Renderer([] { return separator(); }); };

    auto header = Renderer([&app] {
        std::string fp = crypto::to_hex(app.identity.x25519.pub.data(), 8);
        return hbox({
            text(" P2P Secure Chat v" APP_VERSION " ") | bold |
                color(Color::Cyan),
            text("  me: " + app.config.name + "  fp:" + fp +
                 "  listen:" + std::to_string(app.config.port) +
                 "  [NoiseXX+DR+SQLCipher]") |
                color(Color::GrayDark),
        });
    });

    auto status_line = Renderer([&app, &input_hint] {
        std::string s = input_hint;
        if (s.empty()) s = app.notice;
        if (s.empty()) {
            s = app.mode == ChatApp::Mode::Chat
                    ? "Enter: send | /close: back"
                    : "/help for commands";
        }
        return text(" " + s) | color(Color::Yellow);
    });

    auto body = Container::Horizontal({friends_view | size(WIDTH, EQUAL, 36),
                                       main_view | flex});
    auto root =
        Container::Vertical({header, sep(), body | flex, input, status_line});

    auto scroll_by = [&app, &screen](int delta) {
        if (app.mode == ChatApp::Mode::Chat) {
            if (auto* fv = app.find_by_id(app.open_friend_id)) {
                int mx = max_scroll(fv->lines.size());
                fv->chat_scroll =
                    std::clamp(fv->chat_scroll + delta, 0, mx);
            }
        } else {
            int mx = max_scroll(app.console.size());
            app.console_scroll =
                std::clamp(app.console_scroll + delta, 0, mx);
        }
        screen.PostEvent(Event::Custom);
    };

    auto global = CatchEvent(root, [&](Event event) {
        drain_inbox(app);
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
    app.net->stop();
    if (app.dht) app.dht->stop();
    return 0;
}
