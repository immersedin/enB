#include "db.h"

#include <sqlite3.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace {

std::string read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

void write_file_0600(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f << data;
    f.close();
    chmod(path.c_str(), 0600);
}

std::string random_hex_key() {
    std::string hex;
    hex.reserve(64);
    std::random_device rd;
    for (int i = 0; i < 32; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", rd() & 0xff);
        hex += buf;
    }
    return hex;
}

}  // namespace

struct Database::Impl {
    sqlite3* handle = nullptr;
};

Database::Database(const std::string& data_dir) : impl_(new Impl) {
    std::error_code ec;
    fs::create_directories(data_dir, ec);

    const std::string key_path = data_dir + "/db.key";
    const std::string db_path = data_dir + "/chat.db";

    std::string key;
    if (fs::exists(key_path)) {
        key = read_file(key_path);
        if (key.size() != 64) {
            last_error_ = "corrupt db.key";
            return;
        }
    } else {
        key = random_hex_key();
        write_file_0600(key_path, key);
    }

    if (sqlite3_open_v2(db_path.c_str(), &impl_->handle,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                        nullptr) != SQLITE_OK) {
        last_error_ = "sqlite open failed";
        return;
    }

    // SQLCipher: passphrase as raw key material (hex).
    std::string pragma = "PRAGMA key = \"x'" + key + "'\";";
    char* err = nullptr;
    if (sqlite3_exec(impl_->handle, pragma.c_str(), nullptr, nullptr,
                     &err) != SQLITE_OK) {
        last_error_ = std::string("PRAGMA key failed: ") +
                      (err ? err : "?");
        sqlite3_free(err);
        return;
    }

    const char* schema =
        "CREATE TABLE IF NOT EXISTS friends("
        " id INTEGER PRIMARY KEY,"
        " name TEXT NOT NULL,"
        " host TEXT NOT NULL,"
        " port INTEGER NOT NULL,"
        " x25519_pub TEXT NOT NULL,"
        " ed25519_pub TEXT NOT NULL,"
        " created_at INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS messages("
        " id INTEGER PRIMARY KEY,"
        " friend_id INTEGER NOT NULL,"
        " ts INTEGER NOT NULL,"
        " dir INTEGER NOT NULL,"
        " body TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_msg_friend ON messages(friend_id, id);";
    if (sqlite3_exec(impl_->handle, schema, nullptr, nullptr, &err) !=
        SQLITE_OK) {
        last_error_ = std::string("schema failed: ") +
                      (err ? err : "?");
        sqlite3_free(err);
        return;
    }
}

Database::~Database() {
    if (impl_) {
        if (impl_->handle) sqlite3_close(impl_->handle);
        delete impl_;
    }
}

std::vector<Friend> Database::list_friends() {
    std::vector<Friend> out;
    if (!impl_ || !impl_->handle) return out;
    sqlite3_stmt* st = nullptr;
    const char* sql =
        "SELECT id,name,host,port,x25519_pub,ed25519_pub,created_at "
        "FROM friends ORDER BY name";
    if (sqlite3_prepare_v2(impl_->handle, sql, -1, &st, nullptr) !=
        SQLITE_OK)
        return out;
    while (sqlite3_step(st) == SQLITE_ROW) {
        Friend f;
        f.id = sqlite3_column_int64(st, 0);
        f.name = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        f.host = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
        f.port = sqlite3_column_int(st, 3);
        f.x25519_pub =
            reinterpret_cast<const char*>(sqlite3_column_text(st, 4));
        f.ed25519_pub =
            reinterpret_cast<const char*>(sqlite3_column_text(st, 5));
        f.created_at = sqlite3_column_int64(st, 6);
        out.push_back(f);
    }
    sqlite3_finalize(st);
    return out;
}

std::optional<Friend> Database::find_friend_by_key(
    const std::string& x25519_pub) {
    if (!impl_ || !impl_->handle) return std::nullopt;
    sqlite3_stmt* st = nullptr;
    const char* sql =
        "SELECT id,name,host,port,x25519_pub,ed25519_pub,created_at "
        "FROM friends WHERE x25519_pub=?";
    if (sqlite3_prepare_v2(impl_->handle, sql, -1, &st, nullptr) !=
        SQLITE_OK)
        return std::nullopt;
    sqlite3_bind_text(st, 1, x25519_pub.c_str(), -1, SQLITE_TRANSIENT);
    std::optional<Friend> out;
    if (sqlite3_step(st) == SQLITE_ROW) {
        Friend f;
        f.id = sqlite3_column_int64(st, 0);
        f.name = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        f.host = reinterpret_cast<const char*>(sqlite3_column_text(st, 2));
        f.port = sqlite3_column_int(st, 3);
        f.x25519_pub =
            reinterpret_cast<const char*>(sqlite3_column_text(st, 4));
        f.ed25519_pub =
            reinterpret_cast<const char*>(sqlite3_column_text(st, 5));
        f.created_at = sqlite3_column_int64(st, 6);
        out = f;
    }
    sqlite3_finalize(st);
    return out;
}

int64_t Database::add_friend(const Friend& f) {
    if (!impl_ || !impl_->handle) return -1;
    sqlite3_stmt* st = nullptr;
    const char* sql =
        "INSERT INTO friends(name,host,port,x25519_pub,ed25519_pub,"
        "created_at) VALUES(?,?,?,?,?,?)";
    if (sqlite3_prepare_v2(impl_->handle, sql, -1, &st, nullptr) !=
        SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, f.name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, f.host.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(st, 3, f.port);
    sqlite3_bind_text(st, 4, f.x25519_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 5, f.ed25519_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 6, f.created_at);
    int64_t id = -1;
    if (sqlite3_step(st) == SQLITE_DONE) id = sqlite3_last_insert_rowid(
                                                impl_->handle);
    sqlite3_finalize(st);
    return id;
}

bool Database::remove_friend(int64_t id) {
    if (!impl_ || !impl_->handle) return false;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(impl_->handle,
                           "DELETE FROM friends WHERE id=?", -1, &st,
                           nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(st, 1, id);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

bool Database::set_identity_keys(int64_t id, const std::string& x25519_pub,
                                 const std::string& ed25519_pub) {
    if (!impl_ || !impl_->handle) return false;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(
            impl_->handle,
            "UPDATE friends SET x25519_pub=?, ed25519_pub=? WHERE id=?",
            -1, &st, nullptr) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, x25519_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, ed25519_pub.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(st, 3, id);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

void Database::add_message(int64_t friend_id, bool outgoing,
                           const std::string& body) {
    if (!impl_ || !impl_->handle || friend_id < 0) return;
    sqlite3_stmt* st = nullptr;
    const char* sql =
        "INSERT INTO messages(friend_id,ts,dir,body) VALUES(?,?,?,?)";
    if (sqlite3_prepare_v2(impl_->handle, sql, -1, &st, nullptr) !=
        SQLITE_OK)
        return;
    sqlite3_bind_int64(st, 1, friend_id);
    sqlite3_bind_int64(st, 2,
                       std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now()
                               .time_since_epoch())
                           .count());
    sqlite3_bind_int(st, 3, outgoing ? 1 : 0);
    sqlite3_bind_text(st, 4, body.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

std::vector<StoredMessage> Database::messages_for(int64_t friend_id,
                                                int limit) {
    std::vector<StoredMessage> out;
    if (!impl_ || !impl_->handle) return out;
    sqlite3_stmt* st = nullptr;
    const char* sql =
        "SELECT id,ts,dir,body FROM messages WHERE friend_id=? "
        "ORDER BY id DESC LIMIT ?";
    if (sqlite3_prepare_v2(impl_->handle, sql, -1, &st, nullptr) !=
        SQLITE_OK)
        return out;
    sqlite3_bind_int64(st, 1, friend_id);
    sqlite3_bind_int(st, 2, limit);
    while (sqlite3_step(st) == SQLITE_ROW) {
        StoredMessage m;
        m.id = sqlite3_column_int64(st, 0);
        m.ts = sqlite3_column_int64(st, 1);
        m.outgoing = sqlite3_column_int(st, 2) != 0;
        m.body = reinterpret_cast<const char*>(sqlite3_column_text(st, 3));
        out.push_back(m);
    }
    sqlite3_finalize(st);
    std::reverse(out.begin(), out.end());
    return out;
}
