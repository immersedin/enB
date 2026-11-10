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
// Plain text is sent to the currently open chat.

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <cctype>
#include <memory>
#include <sstream>
#include <mutex>
#include <string>
#include <vector>

#include <sodium.h>

#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>

#include "crypto.h"
#include "db.h"
#include "net.h"

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
};

struct Config {
    int port = 5555;
    std::string name = "me";
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
        } else if (k == "name") {
            c.name = v;
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

    std::vector<FriendView> friends;
    int64_t open_friend_id = -1;

    enum class Mode { Home, Chat };
    Mode mode = Mode::Home;

    std::vector<std::string> console;  // command output on Home screen
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

void drain_inbox(ChatApp& app) {
    std::vector<std::pair<std::string, std::string>> items;
    std::vector<ChatApp::Status> sts;
    {
        std::lock_guard lk(app.inbox_mu);
        items.swap(app.inbox);
        sts.swap(app.statuses);
    }
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
// Slash commands
// ------------------------------------------------------------------
void execute_command(ChatApp& app, const std::string& line) {
    auto args = split_args(line);
    if (args.empty()) return;
    std::string cmd = to_lower(args[0]);

    if (cmd == "/help") {
        say(app, "commands:");
        say(app, "  /friends              list friends");
        say(app, "  /add <name> <host> <port>   add friend & connect");
        say(app, "  /remove <name>        remove friend");
        say(app, "  /chat <name>          open chat (auto-connects)");
        say(app, "  /close                back to console");
        say(app, "  /quit                 exit");
        say(app, "any other text is sent to the open chat");
    } else if (cmd == "/friends") {
        if (app.friends.empty()) {
            say(app, "no friends — use /add <name> <host> <port>");
        }
        for (auto& fv : app.friends) {
            say(app, std::string("  ") + (fv.online ? "(*)" : "( )") + " " +
                       fv.display_name + "  " + fv.f.host + ":" +
                       std::to_string(fv.f.port) +
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
    } else if (cmd == "/quit" || cmd == "/exit") {
        app.net->stop();
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
        std::string label =
            (open ? ">" : " ") + std::string(" ") +
            (fv.online ? "(*)" : "( )") + " " + fv.display_name + "   " +
            fv.f.host + ":" + std::to_string(fv.f.port);
        rows.push_back(text(label) |
                       color(open ? Color::Cyan : Color::White));
    }
    return vbox({text(" Friends ") | bold | color(Color::Yellow),
                 separator(),
                 vbox(std::move(rows)) | flex}) |
           frame | flex;
}

Element render_console(const ChatApp& app) {
    std::vector<Element> rows;
    size_t start = app.console.size() > 200 ? app.console.size() - 200 : 0;
    for (size_t i = start; i < app.console.size(); ++i)
        rows.push_back(text(app.console[i]));
    if (rows.empty()) {
        rows.push_back(text("P2P Secure Chat") | bold |
                       color(Color::Cyan));
        rows.push_back(text("type /help for commands") |
                       color(Color::GrayDark));
    }
    return vbox(std::move(rows)) | flex | frame;
}

Element render_chat_lines(const FriendView& fv) {
    std::vector<Element> rows;
    size_t start = fv.lines.size() > 200 ? fv.lines.size() - 200 : 0;
    for (size_t i = start; i < fv.lines.size(); ++i) {
        const auto& l = fv.lines[i];
        rows.push_back(hbox({
            text(l.outgoing ? "you: " : fv.display_name + ": ") |
                color(l.outgoing ? Color::Green : Color::Cyan) | bold,
            text(l.text),
        }));
    }
    if (rows.empty())
        rows.push_back(text("  no messages yet") | color(Color::GrayDark));
    return vbox(std::move(rows)) | flex | frame;
}

}  // namespace

int main() {
    if (sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    const char* home = std::getenv("HOME");
    std::string data_dir = std::string(home ? home : ".") + "/.p2p-chat";
    Config config = load_config(data_dir + "/config.ini");
    if (config.port <= 0 || config.port > 65535) config.port = 5555;

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
        });
    app.net->start();

    // ---- components -------------------------------------------------
    std::string input_text;
    auto handle_input = [&app, &screen, &input_text]() {
        std::string text = input_text;
        input_text.clear();
        if (text.empty()) return;

        if (!text.empty() && text[0] == '/') {
            execute_command(app, text);
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
            text(" P2P Secure Chat ") | bold | color(Color::Cyan),
            text("  me: " + app.config.name + "  fp:" + fp +
                 "  listen:" + std::to_string(app.config.port) +
                 "  [NoiseXX+DR+SQLCipher]") |
                color(Color::GrayDark),
        });
    });

    auto status_line = Renderer([&app] {
        std::string s = app.notice;
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

    auto global = CatchEvent(root, [&](Event event) {
        drain_inbox(app);
        return false;  // let the focused input handle keys
    });

    screen.Loop(global);
    app.net->stop();
    return 0;
}
