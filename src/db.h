#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Friend record persisted in the SQLCipher database.
struct Friend {
    int64_t id = -1;
    std::string name;
    std::string host;
    int port = 0;
    std::string x25519_pub;   // hex
    std::string ed25519_pub;  // hex
    int64_t created_at = 0;
};

struct StoredMessage {
    int64_t id = -1;
    int64_t ts = 0;
    bool outgoing = false;
    std::string body;
};

// Encrypted-at-rest storage (SQLCipher) for friends and chat history.
// The database key lives in a separate 0600 file next to the database.
class Database {
public:
    // data_dir e.g. ~/.p2p-chat ; creates dir, key file and schema.
    explicit Database(const std::string& data_dir);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    std::vector<Friend> list_friends();
    std::optional<Friend> find_friend_by_key(const std::string& x25519_pub);
    int64_t add_friend(const Friend& f);
    bool remove_friend(int64_t id);
    // Fill in the identity keys after the first successful handshake.
    bool set_identity_keys(int64_t id, const std::string& x25519_pub,
                           const std::string& ed25519_pub);
    // Remember a working network endpoint for reconnects (host may be
    // empty when the friend is resolved via the DHT).
    bool update_friend_endpoint(int64_t id, const std::string& host,
                                int port);

    void add_message(int64_t friend_id, bool outgoing, const std::string& body);
    std::vector<StoredMessage> messages_for(int64_t friend_id, int limit = 500);

    const std::string& last_error() const { return last_error_; }

private:
    struct Impl;
    Impl* impl_ = nullptr;
    std::string last_error_;
};
