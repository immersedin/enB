#include "net.h"

#include <sodium.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <system_error>
#ifdef _WIN32
#include <io.h>
#define chmod _chmod
#else
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;

namespace {

constexpr size_t kMaxFrame = 1 << 20;  // 1 MiB

void write_file_0600(const std::string& path, const crypto::Bytes& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    f.close();
    chmod(path.c_str(), 0600);
}

void write_key_file(const std::string& path, const crypto::Key32& k) {
    std::string hex = crypto::to_hex(k.data(), 32) + "\n";
    write_file_0600(path, crypto::Bytes(hex.begin(), hex.end()));
}

crypto::Key32 read_key_file(const std::string& path) {
    std::ifstream f(path);
    std::string hex;
    f >> hex;
    crypto::Key32 k{};
    crypto::Bytes b;
    if (!crypto::from_hex(hex, b) || b.size() != 32)
        throw std::runtime_error("bad key file: " + path);
    std::memcpy(k.data(), b.data(), 32);
    return k;
}

// Framed IO: 4-byte big-endian length + payload.
bool write_frame(tcp::socket& sock, const crypto::Bytes& data) {
    if (data.size() > kMaxFrame) return false;
    uint32_t len = static_cast<uint32_t>(data.size());
    uint8_t hdr[4] = {static_cast<uint8_t>(len >> 24),
                      static_cast<uint8_t>(len >> 16),
                      static_cast<uint8_t>(len >> 8),
                      static_cast<uint8_t>(len)};
    asio::error_code ec;
    asio::write(sock, asio::buffer(hdr, 4), ec);
    if (ec) return false;
    asio::write(sock, asio::buffer(data.data(), data.size()), ec);
    return !ec;
}

bool read_frame(tcp::socket& sock, crypto::Bytes& data) {
    uint8_t hdr[4];
    asio::error_code ec;
    asio::read(sock, asio::buffer(hdr, 4), ec);
    if (ec) return false;
    uint32_t len = (static_cast<uint32_t>(hdr[0]) << 24) |
                   (static_cast<uint32_t>(hdr[1]) << 16) |
                   (static_cast<uint32_t>(hdr[2]) << 8) | hdr[3];
    if (len == 0 || len > kMaxFrame) return false;
    data.resize(len);
    asio::read(sock, asio::buffer(data.data(), len), ec);
    return !ec;
}

// ------------------------------------------------------------------
// Handshake payload (carried inside the Noise-encrypted payload):
//   u16le name_len | name | ed25519_pub(32) | sig(64) | ratchet_pub(32)
//
// sig = Ed25519_sign( "p2p-id-v1" || x25519_pub || ed25519_pub [|| peer_x25519_pub] )
// The initiator includes the responder's X25519 pub (already learned
// from msg2) so the responder can bind the signature to this peer.
// Noise's DH tokens already authenticate both static keys.
// ------------------------------------------------------------------

crypto::Bytes build_sig_message(const crypto::Key32& x_pub,
                                const crypto::Key32& ed_pub,
                                const crypto::Key32* peer_x_pub) {
    crypto::Bytes m;
    const char* domain = "p2p-id-v1";
    m.insert(m.end(), domain, domain + 8);
    m.insert(m.end(), x_pub.begin(), x_pub.end());
    m.insert(m.end(), ed_pub.begin(), ed_pub.end());
    if (peer_x_pub)
        m.insert(m.end(), peer_x_pub->begin(), peer_x_pub->end());
    return m;
}

crypto::Bytes build_handshake_payload(const Identity& id,
                                      const std::string& name,
                                      const crypto::KeyPair& ratchet,
                                      const crypto::Key32* peer_x_pub) {
    crypto::Bytes p;
    uint16_t nl = static_cast<uint16_t>(name.size());
    p.push_back(static_cast<uint8_t>(nl & 0xff));
    p.push_back(static_cast<uint8_t>(nl >> 8));
    p.insert(p.end(), name.begin(), name.end());
    p.insert(p.end(), id.ed25519.pub.begin(), id.ed25519.pub.end());
    crypto::Bytes sig_msg =
        build_sig_message(id.x25519.pub, id.ed25519.pub, peer_x_pub);
    uint8_t sig[64];
    crypto::ed25519_sign(id.ed25519, sig_msg, sig);
    p.insert(p.end(), sig, sig + 64);
    p.insert(p.end(), ratchet.pub.begin(), ratchet.pub.end());
    return p;
}

struct ParsedPayload {
    std::string name;
    crypto::Key32 ed_pub{};
    crypto::Key32 ratchet_pub{};
    crypto::Bytes sig{};
};

bool parse_handshake_payload(const crypto::Bytes& p, ParsedPayload& out) {
    if (p.size() < 2 + 32 + 64 + 32) return false;
    uint16_t nl = static_cast<uint16_t>(p[0]) |
                  (static_cast<uint16_t>(p[1]) << 8);
    size_t off = 2;
    if (off + nl + 32 + 64 + 32 != p.size()) return false;
    out.name.assign(reinterpret_cast<const char*>(p.data() + off), nl);
    off += nl;
    std::memcpy(out.ed_pub.data(), p.data() + off, 32);
    off += 32;
    out.sig.assign(p.begin() + off, p.begin() + off + 64);
    off += 64;
    std::memcpy(out.ratchet_pub.data(), p.data() + off, 32);
    return true;
}

bool verify_identity_sig(const ParsedPayload& parsed,
                         const crypto::Key32& signer_x_pub,
                         const crypto::Key32* expected_peer_x_pub) {
    crypto::Bytes sig_msg =
        build_sig_message(signer_x_pub, parsed.ed_pub,
                          expected_peer_x_pub);
    return crypto::ed25519_verify(parsed.ed_pub, sig_msg, parsed.sig.data());
}

crypto::Key32 derive_ratchet_root(const crypto::NoiseXX& noise) {
    crypto::Key32 root{};
    crypto::hkdf_sha256(noise.handshake_hash().data(), 32,
                        noise.chaining_key().data(), 32, "p2p-dr-root-v1",
                        root.data(), 32);
    return root;
}

}  // namespace

Identity load_or_create_identity(const std::string& data_dir,
                                 const std::string& name) {
    std::error_code ec;
    fs::create_directories(data_dir, ec);

    Identity id;
    id.name = name;

    const std::string x_priv = data_dir + "/x25519.key";
    const std::string x_pub = data_dir + "/x25519.pub";
    const std::string e_priv = data_dir + "/ed25519.key";
    const std::string e_pub = data_dir + "/ed25519.pub";

    if (fs::exists(x_priv)) {
        id.x25519.priv = read_key_file(x_priv);
        if (fs::exists(x_pub)) {
            id.x25519.pub = read_key_file(x_pub);
        } else {
            if (crypto_scalarmult_base(id.x25519.pub.data(),
                                       id.x25519.priv.data()) != 0)
                throw std::runtime_error("x25519 pubkey derivation failed");
        }
    } else {
        id.x25519 = crypto::x25519_generate();
        write_key_file(x_priv, id.x25519.priv);
        write_key_file(x_pub, id.x25519.pub);
    }

    if (fs::exists(e_priv)) {
        // Ed25519 private key file stores the 32-byte seed.
        id.ed25519.priv = read_key_file(e_priv);
        if (fs::exists(e_pub)) {
            id.ed25519.pub = read_key_file(e_pub);
        } else {
            uint8_t pk[32];
            uint8_t sk[64];
            crypto_sign_seed_keypair(pk, sk, id.ed25519.priv.data());
            std::memcpy(id.ed25519.pub.data(), pk, 32);
        }
    } else {
        id.ed25519 = crypto::ed25519_generate();
        write_key_file(e_priv, id.ed25519.priv);
        write_key_file(e_pub, id.ed25519.pub);
    }
    return id;
}

// ------------------------------------------------------------------
// Net
// ------------------------------------------------------------------

Net::Net(Identity& identity, int listen_port, Database& db,
         std::function<void(const std::string&, const std::string&)>
             on_message,
         std::function<void(int64_t, const std::string&, bool,
                            const std::string&)>
             on_status)
    : id_(identity),
      listen_port_(listen_port),
      db_(db),
      on_message_(std::move(on_message)),
      on_status_(std::move(on_status)) {}

Net::~Net() { stop(); }

void Net::start() {
    if (running_.exchange(true)) return;
    accept_thread_ = std::thread([this] { accept_loop(); });
}

void Net::stop() {
    if (!running_.exchange(false)) return;
    {
        std::lock_guard lk(sessions_mu_);
        for (auto& [k, s] : sessions_) {
            s->alive = false;
            asio::error_code ec;
            s->sock.close(ec);
        }
    }
    // Unblock the pending accept() with a loopback connection.
    {
        asio::error_code ec;
        tcp::socket probe(io_);
        probe.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"),
                                    listen_port_),
                      ec);
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    std::vector<std::shared_ptr<Session>> sessions;
    {
        std::lock_guard lk(sessions_mu_);
        for (auto& [k, s] : sessions_) sessions.push_back(s);
    }
    for (auto& s : sessions)
        if (s->rx_thread.joinable()) s->rx_thread.join();
}

void Net::accept_loop() {
    try {
        tcp::acceptor acceptor(io_, tcp::endpoint(tcp::v6(), listen_port_));
        while (running_) {
            tcp::socket sock(io_);
            asio::error_code ec;
            acceptor.accept(sock, ec);
            if (ec || !running_) break;
            std::thread([this, s = std::move(sock)]() mutable {
                handle_incoming(std::move(s));
            }).detach();
        }
    } catch (const std::exception&) {
        // Listener failed (e.g. port already in use).
    }
}

void Net::connect_to(const Friend& friend_) {
    std::thread([this, friend_] { handle_outgoing(friend_); }).detach();
}

// Builds the session object once the Noise handshake has completed.
// Returns nullptr on any verification failure.
std::shared_ptr<Session> Net::finalize_session(
    tcp::socket&& sock, crypto::NoiseXX&& noise, const std::string& peer_name,
    const crypto::Key32& peer_ed_pub, const crypto::Key32& peer_ratchet_pub,
    crypto::KeyPair&& my_ratchet, bool initiator) {
    auto session =
        std::make_shared<Session>(std::move(sock), std::move(noise));
    session->peer.x25519_pub =
        crypto::to_hex(session->noise.remote_static().data(), 32);
    session->peer.ed25519_pub = crypto::to_hex(peer_ed_pub.data(), 32);
    session->peer.name = peer_name.empty() ? "peer" : peer_name;
    session->i_am_initiator = initiator;

    crypto::Key32 root = derive_ratchet_root(session->noise);
    session->ratchet.init(root, initiator, my_ratchet, peer_ratchet_pub);
    session->alive = true;
    return session;
}

void Net::register_session(std::shared_ptr<Session> session) {
    const std::string& key = session->peer.x25519_pub;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(key);
        if (it != sessions_.end()) {
            it->second->alive = false;
            asio::error_code ec;
            it->second->sock.close(ec);
            sessions_.erase(it);
        }
        sessions_[key] = session;
    }
    session->rx_thread = std::thread([this, s = session]() mutable {
        receive_loop(s);
    });
    int64_t fid = -1;
    if (auto f = db_.find_friend_by_key(key)) fid = f->id;
    on_status_(fid, key, true, session->peer.name);
}

void Net::unregister_session(const std::string& peer_key) {
    int64_t fid = -1;
    if (auto f = db_.find_friend_by_key(peer_key)) fid = f->id;
    {
        std::lock_guard lk(sessions_mu_);
        sessions_.erase(peer_key);
    }
    on_status_(fid, peer_key, false, "");
}

void Net::receive_loop(std::shared_ptr<Session> session) {
    try {
    crypto::Bytes frame, transport_pt, app_pt;
    while (session->alive) {
        if (!read_frame(session->sock, frame)) break;
        if (!session->noise.transport_decrypt(frame, transport_pt)) break;
        if (!session->ratchet.decrypt(transport_pt, app_pt)) break;
        on_message_(session->peer.x25519_pub,
                    std::string(app_pt.begin(), app_pt.end()));
    }
    session->alive = false;
    unregister_session(session->peer.x25519_pub);
    } catch (...) {
    }
}

void Net::handle_incoming(tcp::socket sock) {
    try {
        crypto::NoiseXX noise(crypto::NoiseXX::Role::Responder,
                              id_.x25519.priv, id_.x25519.pub);
        crypto::KeyPair my_ratchet = crypto::x25519_generate();

        crypto::Bytes f1, p1;
        if (!read_frame(sock, f1)) return;
        if (!noise.read_msg1(f1, p1)) return;

        crypto::Bytes p2 = build_handshake_payload(
            id_, id_.name, my_ratchet, nullptr);
        crypto::Bytes m2 = noise.write_msg2(p2);
        if (m2.empty() || !write_frame(sock, m2)) return;

        crypto::Bytes f3, p3;
        if (!read_frame(sock, f3)) return;
        if (!noise.read_msg3(f3, p3)) return;

        ParsedPayload parsed3;
        if (!parse_handshake_payload(p3, parsed3)) return;
        // The initiator's signature binds our own X25519 pub.
        if (!verify_identity_sig(parsed3, noise.remote_static(),
                                 &id_.x25519.pub))
            return;

        auto session = finalize_session(
            std::move(sock), std::move(noise), parsed3.name, parsed3.ed_pub,
            parsed3.ratchet_pub, std::move(my_ratchet), false);
        if (!session) return;

        // Learn the peer's endpoint for the friend record.
        asio::error_code ec;
        auto ep = session->sock.remote_endpoint(ec);
        if (!ec) {
            session->peer.host = ep.address().to_string();
            session->peer.port = ep.port();
        }

        // If this key is not a known friend yet, register it so the
        // user can chat with the peer immediately.
        if (!db_.find_friend_by_key(session->peer.x25519_pub)) {
            Friend f;
            f.name = session->peer.name;
            f.host = session->peer.host;
            f.port = session->peer.port;
            f.x25519_pub = session->peer.x25519_pub;
            f.ed25519_pub = session->peer.ed25519_pub;
            f.created_at = std::chrono::duration_cast<
                std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch())
                .count();
            db_.add_friend(f);
        }

        register_session(std::move(session));
    } catch (...) {
    }
}

void Net::handle_outgoing(const Friend& friend_) {
    try {
        tcp::resolver resolver(io_);
        auto endpoints = resolver.resolve(friend_.host,
                                          std::to_string(friend_.port));
        tcp::socket sock(io_);
        asio::error_code ec;
        asio::connect(sock, endpoints, ec);
        if (ec) {
            on_status_(-1, friend_.x25519_pub, false, friend_.name);
            return;
        }

        crypto::NoiseXX noise(crypto::NoiseXX::Role::Initiator,
                              id_.x25519.priv, id_.x25519.pub);
        crypto::KeyPair my_ratchet = crypto::x25519_generate();

        crypto::Bytes m1 = noise.write_msg1({});
        if (!write_frame(sock, m1)) return;

        crypto::Bytes f2, p2;
        if (!read_frame(sock, f2)) return;
        if (!noise.read_msg2(f2, p2)) return;

        ParsedPayload parsed2;
        if (!parse_handshake_payload(p2, parsed2)) return;
        if (!verify_identity_sig(parsed2, noise.remote_static(), nullptr))
            return;

        crypto::Bytes p3 = build_handshake_payload(
            id_, id_.name, my_ratchet, &noise.remote_static());
        crypto::Bytes m3 = noise.write_msg3(p3);
        if (!write_frame(sock, m3)) return;

        auto session = finalize_session(
            std::move(sock), std::move(noise), parsed2.name, parsed2.ed_pub,
            parsed2.ratchet_pub, std::move(my_ratchet), true);
        if (!session) return;
        session->peer.host = friend_.host;
        session->peer.port = friend_.port;
        // Prefer the locally configured friend name.
        session->peer.name = friend_.name;

        // Persist the peer identity keys first so register_session can
        // resolve the friend id for status reporting.
        if (friend_.id >= 0 &&
            (friend_.x25519_pub.empty() ||
             friend_.x25519_pub != session->peer.x25519_pub)) {
            db_.set_identity_keys(friend_.id, session->peer.x25519_pub,
                                  session->peer.ed25519_pub);
        }
        register_session(std::move(session));
    } catch (...) {
        on_status_(-1, friend_.x25519_pub, false, friend_.name);
    }
}

bool Net::send(const std::string& peer_key, const std::string& text) {
    auto session = find_session(peer_key);
    if (!session || !session->alive) return false;

    crypto::Bytes app_pt(text.begin(), text.end());
    crypto::Bytes dr_frame = session->ratchet.encrypt(app_pt);
    crypto::Bytes transport_ct = session->noise.transport_encrypt(dr_frame);
    if (transport_ct.empty()) return false;

    std::lock_guard lk(session->tx_mu);
    return write_frame(session->sock, transport_ct);
}

bool Net::has_session(const std::string& peer_key) const {
    auto s = find_session(peer_key);
    return s && s->alive;
}

std::string Net::peer_name(const std::string& peer_key) const {
    auto s = find_session(peer_key);
    return s ? s->peer.name : std::string();
}

void Net::drop_session(const std::string& peer_key) {
    std::shared_ptr<Session> s;
    {
        std::lock_guard lk(sessions_mu_);
        auto it = sessions_.find(peer_key);
        if (it == sessions_.end()) return;
        s = it->second;
        sessions_.erase(it);
    }
    s->alive = false;
    asio::error_code ec;
    s->sock.close(ec);
    if (s->rx_thread.joinable()) s->rx_thread.join();
    int64_t fid = -1;
    if (auto f = db_.find_friend_by_key(peer_key)) fid = f->id;
    on_status_(fid, peer_key, false, "");
}

std::shared_ptr<Session> Net::find_session(
    const std::string& peer_key) const {
    std::lock_guard lk(sessions_mu_);
    auto it = sessions_.find(peer_key);
    return it == sessions_.end() ? nullptr : it->second;
}
