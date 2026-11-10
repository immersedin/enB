#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>

#include "crypto.h"
#include "db.h"

using asio::ip::tcp;

// Local long-term identity: X25519 static key (Noise DH + ratchet base)
// and Ed25519 signing key. Stored as raw 32-byte hex files, mode 0600.
struct Identity {
    crypto::KeyPair x25519;
    crypto::KeyPair ed25519;
    std::string name;
};

Identity load_or_create_identity(const std::string& data_dir,
                                 const std::string& name);

struct PeerInfo {
    std::string x25519_pub;   // hex, unique session key
    std::string ed25519_pub;  // hex
    std::string name;
    std::string host;
    int port = 0;
};

// One established E2EE session (Noise XX + Double Ratchet over TCP).
struct Session {
    tcp::socket sock;
    crypto::NoiseXX noise;
    crypto::DoubleRatchet ratchet;
    PeerInfo peer;
    bool i_am_initiator = false;
    std::mutex tx_mu;
    std::atomic<bool> alive{true};
    std::thread rx_thread;

    Session(tcp::socket&& s, crypto::NoiseXX&& n)
        : sock(std::move(s)), noise(std::move(n)) {}
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    // The receive thread holds a shared_ptr to this session; when the
    // last reference drops inside that very thread, joining is
    // impossible, so detach instead of terminating.
    ~Session() {
        if (rx_thread.joinable()) rx_thread.detach();
    }
};

class Net {
public:
    // on_message(peer_key, text): called from a network thread for every
    // decrypted incoming application message.
    // on_status(friend_id, peer_key, online, name): session up/down
    // notifications. friend_id is -1 when the peer is unknown.
    Net(Identity& identity, int listen_port, Database& db,
        std::function<void(const std::string&, const std::string&)> on_message,
        std::function<void(int64_t, const std::string&, bool,
                           const std::string&)>
            on_status);
    ~Net();

    Net(const Net&) = delete;
    Net& operator=(const Net&) = delete;

    void start();
    void stop();

    // Asynchronous outgoing connection to a friend (host:port).
    void connect_to(const Friend& friend_);

    // Encrypt + send a text message to an established session.
    bool send(const std::string& peer_key, const std::string& text);

    bool has_session(const std::string& peer_key) const;
    std::string peer_name(const std::string& peer_key) const;
    void drop_session(const std::string& peer_key);

private:
    void accept_loop();
    void handle_incoming(tcp::socket sock);
    void handle_outgoing(const Friend& friend_);
    void receive_loop(std::shared_ptr<Session> session);
    void register_session(std::shared_ptr<Session> session);
    void unregister_session(const std::string& peer_key);
    std::shared_ptr<Session> finalize_session(
        tcp::socket&& sock, crypto::NoiseXX&& noise,
        const std::string& peer_name, const crypto::Key32& peer_ed_pub,
        const crypto::Key32& peer_ratchet_pub, crypto::KeyPair&& my_ratchet,
        bool initiator);

    std::shared_ptr<Session> find_session(const std::string& peer_key) const;

    Identity& id_;
    int listen_port_;
    Database& db_;
    std::function<void(const std::string&, const std::string&)> on_message_;
    std::function<void(int64_t, const std::string&, bool,
                       const std::string&)>
        on_status_;

    // Single io_context shared by all sockets. All socket operations are
    // synchronous, so io_context::run() is never called.
    asio::io_context io_;
    std::thread accept_thread_;
    std::atomic<bool> running_{false};

    mutable std::mutex sessions_mu_;
    std::map<std::string, std::shared_ptr<Session>> sessions_;
};
