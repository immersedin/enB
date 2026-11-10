#include "dht.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <memory>
#include <set>
#include <system_error>

#include "net.h"  // Identity

namespace {

// ------------------------------------------------------------------
// Wire helpers (all integers big-endian).
// ------------------------------------------------------------------
void put16(crypto::Bytes& b, uint16_t v) {
    b.push_back(static_cast<uint8_t>(v >> 8));
    b.push_back(static_cast<uint8_t>(v & 0xff));
}
void put32(crypto::Bytes& b, uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put64(crypto::Bytes& b, uint64_t v) {
    for (int i = 7; i >= 0; --i)
        b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
bool get16(const uint8_t*& p, size_t& left, uint16_t& v) {
    if (left < 2) return false;
    v = static_cast<uint16_t>((p[0] << 8) | p[1]);
    p += 2; left -= 2; return true;
}
bool get32(const uint8_t*& p, size_t& left, uint32_t& v) {
    if (left < 4) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | p[i];
    p += 4; left -= 4; return true;
}
void put_key(crypto::Bytes& b, const crypto::Key32& k) {
    b.insert(b.end(), k.begin(), k.end());
}
bool get_key(const uint8_t*& p, size_t& left, crypto::Key32& k) {
    if (left < 32) return false;
    std::memcpy(k.data(), p, 32);
    p += 32; left -= 32; return true;
}

void put_endpoint(crypto::Bytes& b, const Endpoint& ep) {
    endpoint_encode(ep, b);
}
bool get_endpoint(const uint8_t*& p, size_t& left, Endpoint& ep) {
    return endpoint_decode(p, left, ep);
}

// XOR distance between two 256-bit Kademlia IDs.
crypto::Key32 xor_dist(const crypto::Key32& a, const crypto::Key32& b) {
    crypto::Key32 d{};
    for (size_t i = 0; i < 32; ++i) d[i] = a[i] ^ b[i];
    return d;
}
bool closer(const crypto::Key32& a, const crypto::Key32& b,
            const crypto::Key32& target) {
    return xor_dist(a, target) < xor_dist(b, target);
}

// Position of the most significant differing bit, 0 = closest bucket.
int bucket_index(const crypto::Key32& our_id, const crypto::Key32& id) {
    for (int i = 0; i < 32; ++i) {
        uint8_t x = our_id[i] ^ id[i];
        if (x) {
            int bit = 7;
            while (!(x & (1 << bit))) --bit;
            return i * 8 + (7 - bit);
        }
    }
    return 255;  // identical id — shouldn't happen for remote nodes
}

crypto::Key32 sha256_key(const char* domain, const crypto::Key32& id) {
    crypto::Key32 out{};
    crypto::Bytes m(domain, domain + std::strlen(domain));
    m.insert(m.end(), id.begin(), id.end());
    crypto::Bytes digest(32);
    crypto_hash_sha256(digest.data(), m.data(), m.size());
    std::memcpy(out.data(), digest.data(), 32);
    return out;
}

// IPv4-mapped IPv6 helpers (this asio lacks to_v4_mapped/to_v6_mapped).
bool is_v4_mapped_v6(const asio::ip::address_v6& a) {
    auto b = a.to_bytes();
    for (int i = 0; i < 10; ++i)
        if (b[i] != 0) return false;
    return b[10] == 0xff && b[11] == 0xff;
}
asio::ip::address_v4 mapped_to_v4(const asio::ip::address_v6& a) {
    auto b = a.to_bytes();
    asio::ip::address_v4::bytes_type b4{};
    std::copy(b.begin() + 12, b.end(), b4.begin());
    return asio::ip::address_v4(b4);
}
asio::ip::address_v6 mapped_to_v6(const asio::ip::address_v4& a) {
    auto b4 = a.to_bytes();
    asio::ip::address_v6::bytes_type b6{};
    b6[10] = 0xff;
    b6[11] = 0xff;
    std::copy(b4.begin(), b4.end(), b6.begin() + 12);
    return asio::ip::address_v6(b6);
}

Endpoint endpoint_from_asio(const asio::ip::udp::endpoint& ep) {
    Endpoint out;
    out.port = ep.port();
    auto a = ep.address();
    if (a.is_v4()) {
        out.family = Endpoint::Family::IPv4;
        out.addr = a.to_string();
    } else if (is_v4_mapped_v6(a.to_v6())) {
        out.family = Endpoint::Family::IPv4;
        out.addr = mapped_to_v4(a.to_v6()).to_string();
    } else {
        out.family = Endpoint::Family::IPv6;
        out.addr = a.to_string();
    }
    return out;
}
// v4_socket selects the destination encoding: a UDP/IPv4 socket needs a
// plain IPv4 endpoint, a dual-stack UDP/IPv6 socket needs IPv4-mapped
// IPv6 for IPv4 peers.
asio::ip::udp::endpoint endpoint_to_asio(const Endpoint& ep,
                                         bool v4_socket) {
    asio::error_code ec;
    if (ep.family == Endpoint::Family::IPv4) {
        auto a4 = asio::ip::make_address_v4(ep.addr, ec);
        if (ec) return {};
        if (v4_socket) return {a4, ep.port};
        return {mapped_to_v6(a4), ep.port};
    }
    if (v4_socket) return {};  // cannot reach IPv6 from a v4 socket
    auto a6 = asio::ip::make_address_v6(ep.addr, ec);
    if (ec) return {};
    return {a6, ep.port};
}

// ------------------------------------------------------------------
// Peer record blob:
//   magic "P2PREC1" | peer_id(32) | ed_pub(32) | name_len(1) | name |
//   n_endpoints(1) | endpoints... | issued_at(8) | sig(64)
// sig = Ed25519 over everything before sig, key = ed_pub.
// ------------------------------------------------------------------
constexpr char kRecordMagic[] = "P2PREC1";
constexpr size_t kRecordMagicLen = 8;
constexpr size_t kMaxRecordSize = 4096;

crypto::Bytes peer_record_encode_body(const PeerRecord& rec) {
    crypto::Bytes b;
    b.insert(b.end(), kRecordMagic, kRecordMagic + kRecordMagicLen);
    put_key(b, rec.peer_id);
    put_key(b, rec.ed_pub);
    b.push_back(static_cast<uint8_t>(rec.name.size() & 0xff));
    b.insert(b.end(), rec.name.begin(), rec.name.end());
    b.push_back(static_cast<uint8_t>(rec.endpoints.size()));
    for (auto& ep : rec.endpoints) put_endpoint(b, ep);
    put64(b, static_cast<uint64_t>(rec.issued_at));
    return b;
}

struct RecordParts {
    crypto::Key32 peer_id{};
    crypto::Key32 ed_pub{};
    std::string name;
    std::vector<Endpoint> endpoints;
    int64_t issued_at = 0;
    crypto::Bytes sig{};
};

bool peer_record_parse(const crypto::Bytes& blob, RecordParts& out,
                       bool require_sig) {
    if (blob.size() < kRecordMagicLen + 32 + 32 + 1 + 1 + 8 +
                         (require_sig ? 64 : 0) ||
        blob.size() > kMaxRecordSize)
        return false;
    if (std::memcmp(blob.data(), kRecordMagic, kRecordMagicLen) != 0)
        return false;
    const uint8_t* p = blob.data() + kRecordMagicLen;
    size_t left = blob.size() - kRecordMagicLen;
    if (!get_key(p, left, out.peer_id)) return false;
    if (!get_key(p, left, out.ed_pub)) return false;
    if (left < 1) return false;
    uint8_t nl = *p++;
    --left;
    if (left < nl + 1 + 8) return false;
    out.name.assign(reinterpret_cast<const char*>(p), nl);
    p += nl; left -= nl;
    uint8_t ne = *p++;
    --left;
    for (int i = 0; i < ne; ++i) {
        Endpoint ep;
        if (!get_endpoint(p, left, ep)) return false;
        out.endpoints.push_back(ep);
    }
    if (left < 8) return false;
    uint64_t ts = 0;
    for (int i = 0; i < 8; ++i) ts = (ts << 8) | *p++;
    left -= 8;
    out.issued_at = static_cast<int64_t>(ts);
    if (require_sig) {
        if (left != 64) return false;
        out.sig.assign(p, p + 64);
    } else if (left != 0) {
        return false;
    }
    return true;
}

}  // namespace

// ------------------------------------------------------------------
// Public record codec
// ------------------------------------------------------------------

crypto::Bytes peer_record_sign(const PeerRecord& rec, const Identity& id) {
    crypto::Bytes out = peer_record_encode_body(rec);
    uint8_t sig[64];
    crypto::ed25519_sign(id.ed25519, out, sig);
    out.insert(out.end(), sig, sig + 64);
    return out;
}

bool peer_record_decode(const crypto::Bytes& blob, PeerRecord& out) {
    RecordParts r;
    if (!peer_record_parse(blob, r, true)) return false;
    crypto::Bytes body(blob.begin(), blob.end() - 64);
    if (!crypto::ed25519_verify(r.ed_pub, body, r.sig.data()))
        return false;
    out.peer_id = r.peer_id;
    out.ed_pub = r.ed_pub;
    out.name = r.name;
    out.endpoints = r.endpoints;
    out.issued_at = r.issued_at;
    out.valid = true;
    return true;
}

// ==================================================================
// Dht implementation
// ==================================================================
namespace {

// Message types.
constexpr uint8_t kPing = 0x01;
constexpr uint8_t kPong = 0x02;
constexpr uint8_t kFindNode = 0x03;
constexpr uint8_t kNodes = 0x04;
constexpr uint8_t kFindValue = 0x05;
constexpr uint8_t kValue = 0x06;
constexpr uint8_t kStore = 0x07;
constexpr uint8_t kStored = 0x08;

constexpr size_t kBucketSize = 20;
constexpr int kAlpha = 3;
constexpr auto kQueryTimeout = std::chrono::seconds(12);
constexpr auto kNodeFreshness = std::chrono::minutes(30);
constexpr uint32_t kMaxStoreTtl = 7 * 24 * 3600;
constexpr size_t kMaxDatagram = 8192;
constexpr size_t kMaxValueSize = 4096;
constexpr auto kRepublishInterval = std::chrono::minutes(10);

struct RouteNode {
    crypto::Key32 id{};
    Endpoint ep;
    std::chrono::steady_clock::time_point seen{};
};

struct StoredRecord {
    crypto::Bytes value;
    std::chrono::system_clock::time_point expiry{};
};

struct Query {
    uint32_t qid = 0;
    crypto::Key32 target{};   // node id (FIND_NODE) or record key (FIND_VALUE)
    bool want_value = false;
    bool direct_sent = false;
    int outstanding = 0;
    bool done = false;
    std::optional<PeerRecord> record;
    std::set<crypto::Key32> queried;
    std::mutex mu;
    std::condition_variable cv;
};

crypto::Key32 record_key_for(const crypto::Key32& peer_id) {
    return sha256_key("p2p-peer-v1", peer_id);
}

// ------------------------------------------------------------------
// Packet builders / parsers
// ------------------------------------------------------------------
void append_sender(crypto::Bytes& b, const crypto::Key32& id,
                   const Endpoint& ep) {
    put_key(b, id);
    put_endpoint(b, ep);
}

crypto::Bytes pkt_ping(const crypto::Key32& id, const Endpoint& ep) {
    crypto::Bytes b{ kPing };
    append_sender(b, id, ep);
    return b;
}
crypto::Bytes pkt_find_node(uint32_t qid, const crypto::Key32& target,
                            const crypto::Key32& id, const Endpoint& ep) {
    crypto::Bytes b{ kFindNode };
    put32(b, qid);
    put_key(b, target);
    append_sender(b, id, ep);
    return b;
}
crypto::Bytes pkt_find_value(uint32_t qid, const crypto::Key32& key,
                             const crypto::Key32& id, const Endpoint& ep) {
    crypto::Bytes b{ kFindValue };
    put32(b, qid);
    put_key(b, key);
    append_sender(b, id, ep);
    return b;
}
crypto::Bytes pkt_store(uint32_t qid, const crypto::Key32& key,
                        uint32_t ttl, const crypto::Bytes& value,
                        const crypto::Key32& id, const Endpoint& ep) {
    crypto::Bytes b{ kStore };
    put32(b, qid);
    put_key(b, key);
    put32(b, ttl);
    put16(b, static_cast<uint16_t>(value.size()));
    b.insert(b.end(), value.begin(), value.end());
    append_sender(b, id, ep);
    return b;
}

// Reply header shared by PONG/NODES/VALUE/STORED:
//   type | qid(4, absent for PONG) | sender_id(32) | sender_ep | observed_ep
struct ReplyHdr {
    uint32_t qid = 0;
    crypto::Key32 sender_id{};
    Endpoint sender_ep;
    Endpoint observed_ep;
};

void append_reply_hdr(crypto::Bytes& b, uint8_t type, uint32_t qid,
                      const crypto::Key32& id, const Endpoint& my_ep,
                      const Endpoint& observed, bool has_qid) {
    b.push_back(type);
    if (has_qid) put32(b, qid);
    append_sender(b, id, my_ep);
    put_endpoint(b, observed);
}

bool parse_reply_hdr(const crypto::Bytes& pkt, bool has_qid,
                     ReplyHdr& h, const uint8_t*& rest, size_t& left) {
    if (pkt.size() < 1 + (has_qid ? 4 : 0) + 32) return false;
    const uint8_t* p = pkt.data() + 1;
    left = pkt.size() - 1;
    if (has_qid) {
        if (!get32(p, left, h.qid)) return false;
    }
    if (!get_key(p, left, h.sender_id)) return false;
    if (!get_endpoint(p, left, h.sender_ep)) return false;
    if (!get_endpoint(p, left, h.observed_ep)) return false;
    rest = p;
    return true;
}

void append_nodes(crypto::Bytes& b, const std::vector<RouteNode>& nodes) {
    b.push_back(static_cast<uint8_t>(nodes.size()));
    for (auto& n : nodes) {
        put_key(b, n.id);
        put_endpoint(b, n.ep);
    }
}
bool parse_nodes(const uint8_t*& p, size_t& left,
                 std::vector<RouteNode>& out) {
    if (left < 1) return false;
    uint8_t n = *p++;
    --left;
    for (int i = 0; i < n; ++i) {
        RouteNode rn;
        if (!get_key(p, left, rn.id)) return false;
        if (!get_endpoint(p, left, rn.ep)) return false;
        rn.seen = std::chrono::steady_clock::now();
        out.push_back(rn);
    }
    return true;
}

}  // namespace

struct Dht::Impl {
    const Identity& id;
    crypto::Key32 node_id;
    Endpoint udp_ep;
    std::vector<Endpoint> bootstrap;

    asio::io_context io;
    asio::ip::udp::socket sock;
    std::thread io_thread;
    std::atomic<bool> running{false};

    // Routing table: 256 k-buckets indexed by prefix length.
    std::array<std::vector<RouteNode>, 256> buckets;
    // DHT record store: key -> signed value blob + expiry.
    std::map<crypto::Key32, StoredRecord> records;
    // NAT discovery: public endpoint observed by DHT peers (IP only is
    // reused with our chat port when publishing).
    std::optional<Endpoint> observed_public;
    Endpoint last_observed;

    mutable std::mutex mu;

    // Pending iterative queries, keyed by qid. Worker threads wait on
    // the per-query condition variable; the io thread feeds responses.
    std::mutex qmu;
    std::map<uint32_t, std::shared_ptr<Query>> queries;
    uint32_t next_qid = 1;

    std::thread publish_thread;
    asio::ip::udp::endpoint recv_ep_;  // lvalue for async_receive_from
    std::atomic<bool> bound_v4{false};
    // Last publish parameters; the periodic republish reuses them.
    std::string pub_name;
    uint16_t pub_port = 0;
    // Publish loop wakeup + worker lifetime tracking.
    std::mutex pub_mu;
    std::condition_variable pub_cv;
    std::atomic<int> active_workers{0};

    Impl(const Identity& identity, const crypto::Key32& nid,
         const Endpoint& ep, std::vector<Endpoint> boot)
        : id(identity),
          node_id(nid),
          udp_ep(ep),
          bootstrap(std::move(boot)),
          sock(io) {}

    // ---- routing table ------------------------------------------------
    void route_add(const crypto::Key32& nid, const Endpoint& ep) {
        if (nid == node_id || !ep.valid()) return;
        std::lock_guard lk(mu);
        int b = bucket_index(node_id, nid);
        auto& bucket = buckets[b];
        for (auto& n : bucket) {
            if (n.id == nid) {
                n.ep = ep;
                n.seen = std::chrono::steady_clock::now();
                return;
            }
        }
        if (bucket.size() >= kBucketSize) {
            // Evict the least-recently-seen entry only if the bucket is
            // for our own prefix region; otherwise drop. Keeps the table
            // bounded without ping machinery.
            auto oldest = std::min_element(
                bucket.begin(), bucket.end(),
                [](const RouteNode& a, const RouteNode& c) {
                    return a.seen < c.seen;
                });
            if (std::chrono::steady_clock::now() - oldest->seen >
                kNodeFreshness)
                bucket.erase(oldest);
            else
                return;  // bucket full of fresh nodes — drop newcomer
        }
        bucket.push_back({nid, ep, std::chrono::steady_clock::now()});
    }

    // k closest known nodes to target (route table only).
    std::vector<RouteNode> closest(const crypto::Key32& target, size_t k) {
        std::vector<RouteNode> all;
        {
            std::lock_guard lk(mu);
            for (auto& bucket : buckets)
                for (auto& n : bucket) all.push_back(n);
        }
        std::sort(all.begin(), all.end(),
                  [&](const RouteNode& a, const RouteNode& b) {
                      return xor_dist(a.id, target) <
                             xor_dist(b.id, target);
                  });
        if (all.size() > k) all.resize(k);
        return all;
    }

    // ---- transport ----------------------------------------------------
    void send_to(const Endpoint& ep, const crypto::Bytes& pkt) {
        if (!running.load() || !ep.valid()) return;
        auto buf = std::make_shared<crypto::Bytes>(pkt);
        asio::ip::udp::endpoint dst =
            endpoint_to_asio(ep, bound_v4.load());
        if (dst.port() == 0) return;
        sock.async_send_to(
            asio::buffer(*buf), dst,
            [this, buf](asio::error_code, size_t) {});
    }

    void send_request(const Endpoint& ep, const crypto::Bytes& pkt,
                      std::shared_ptr<Query> q) {
        if (q) {
            std::lock_guard lk(q->mu);
            ++q->outstanding;
        }
        send_to(ep, pkt);
    }

    // ---- record store -------------------------------------------------
    void record_put(const crypto::Key32& key, const crypto::Bytes& value,
                    uint32_t ttl) {
        if (value.empty() || value.size() > kMaxValueSize) return;
        uint32_t capped = std::min(ttl, kMaxStoreTtl);
        if (capped == 0) return;
        auto expiry = std::chrono::system_clock::now() +
                      std::chrono::seconds(capped);
        std::lock_guard lk(mu);
        auto it = records.find(key);
        if (it != records.end() &&
            it->second.expiry > std::chrono::system_clock::now()) {
            // First-wins for live records, except peer records where a
            // newer issued_at wins (prevents stale-record pinning while
            // still rejecting arbitrary overwrite of unverifiable data).
            PeerRecord old_r, new_r;
            bool old_ok = peer_record_decode(it->second.value, old_r);
            bool new_ok = peer_record_decode(value, new_r);
            if (old_ok && new_ok) {
                if (new_r.issued_at >= old_r.issued_at) {
                    it->second = {value, expiry};
                }
            }
            // else: keep existing live record
            return;
        }
        records[key] = {value, expiry};
    }

    bool record_get(const crypto::Key32& key, crypto::Bytes& value) {
        std::lock_guard lk(mu);
        auto it = records.find(key);
        if (it == records.end()) return false;
        if (it->second.expiry <= std::chrono::system_clock::now()) {
            records.erase(it);
            return false;
        }
        value = it->second.value;
        return true;
    }

    // ---- query engine -------------------------------------------------
    void register_query(std::shared_ptr<Query> q) {
        std::lock_guard lk(qmu);
        q->qid = next_qid++;
        queries[q->qid] = q;
    }
    void unregister_query(uint32_t qid) {
        std::lock_guard lk(qmu);
        queries.erase(qid);
    }
    std::shared_ptr<Query> find_query(uint32_t qid) {
        std::lock_guard lk(qmu);
        auto it = queries.find(qid);
        return it == queries.end() ? nullptr : it->second;
    }

    // Iterative lookup worker. Runs on its own thread.
    void run_query(crypto::Key32 target, bool want_value,
                   std::function<void(std::shared_ptr<Query>)> done) {
        active_workers++;
        struct Guard {
            std::atomic<int>& c;
            ~Guard() { --c; }
        } guard{active_workers};
        auto q = std::make_shared<Query>();
        q->target = target;
        q->want_value = want_value;
        register_query(q);

        auto deadline = std::chrono::steady_clock::now() + kQueryTimeout;
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard lk(q->mu);
                if (q->done) break;
            }
            // Send the first round to bootstrap endpoints (their node
            // IDs are unknown until they answer).
            if (!q->direct_sent) {
                std::lock_guard lk(q->mu);
                q->direct_sent = true;
                std::vector<Endpoint> boots;
                {
                    std::lock_guard mlk(mu);
                    boots = bootstrap;
                }
                crypto::Bytes pkt = want_value
                    ? pkt_find_value(q->qid, target, node_id, udp_ep)
                    : pkt_find_node(q->qid, target, node_id, udp_ep);
                int sent = 0;
                for (auto& b : boots) {
                    if (sent >= kAlpha) break;
                    if (!b.valid()) continue;
                    ++q->outstanding;
                    send_to(b, pkt);
                    ++sent;
                }
                if (sent == 0 && closest(target, 1).empty()) break;
            }
            // Pick up to alpha closest unqueried nodes and query them.
            for (;;) {
                std::vector<RouteNode> cand;
                {
                    std::lock_guard lk(q->mu);
                    if (q->outstanding >= kAlpha || q->done) break;
                }
                // Recompute candidates each pick: route table grows as
                // responses arrive.
                auto all = closest(target, kBucketSize * 2);
                {
                    std::lock_guard lk(q->mu);
                    for (auto& n : all) {
                        if (q->queried.count(n.id)) continue;
                        cand.push_back(n);
                        if (cand.size() >=
                            static_cast<size_t>(kAlpha - q->outstanding))
                            break;
                    }
                    if (cand.empty()) break;
                    for (auto& n : cand) q->queried.insert(n.id);
                    q->outstanding += static_cast<int>(cand.size());
                }
                crypto::Bytes pkt;
                for (auto& n : cand) {
                    pkt = want_value
                        ? pkt_find_value(q->qid, target, node_id, udp_ep)
                        : pkt_find_node(q->qid, target, node_id, udp_ep);
                    send_to(n.ep, pkt);
                }
            }
            // Wait for responses or timeout slice.
            bool idle = false;
            {
                std::unique_lock lk(q->mu);
                q->cv.wait_for(lk, std::chrono::milliseconds(400),
                               [&] { return q->done || q->outstanding == 0; });
                if (q->done) break;
                idle = (q->outstanding == 0);
            }
            if (idle) {
                // No answers in flight: continue only if the route table
                // still has unqueried candidates closer to the target.
                auto all = closest(target, kBucketSize * 2);
                bool any = false;
                {
                    std::lock_guard qlk(q->mu);
                    for (auto& n : all)
                        if (!q->queried.count(n.id)) { any = true; break; }
                }
                if (!any) break;
            }
        }
        unregister_query(q->qid);
        if (done) done(q);
    }

    // ---- packet handling ----------------------------------------------
    void handle_packet(const crypto::Bytes& pkt,
                       const Endpoint& from) {
        if (pkt.empty()) return;
        uint8_t type = pkt[0];

        // Common tail for requests: sender_id(32) + sender_ep.
        auto parse_sender = [&](const uint8_t*& p, size_t& left,
                                crypto::Key32& id, Endpoint& ep) {
            return get_key(p, left, id) && get_endpoint(p, left, ep);
        };

        switch (type) {
        case kPing: {
            const uint8_t* p = pkt.data() + 1;
            size_t left = pkt.size() - 1;
            crypto::Key32 sid{};
            Endpoint sep;
            if (!parse_sender(p, left, sid, sep)) return;
            route_add(sid, sep);
            crypto::Bytes r;
            append_reply_hdr(r, kPong, 0, node_id, udp_ep, from, false);
            send_to(from, r);
            return;
        }
        case kFindNode:
        case kFindValue: {
            const uint8_t* p = pkt.data() + 1;
            size_t left = pkt.size() - 1;
            uint32_t qid = 0;
            crypto::Key32 target{};
            if (!get32(p, left, qid)) return;
            if (!get_key(p, left, target)) return;
            crypto::Key32 sid{};
            Endpoint sep;
            if (!parse_sender(p, left, sid, sep)) return;
            route_add(sid, sep);

            crypto::Bytes value;
            bool found = false;
            if (type == kFindValue) found = record_get(target, value);

            crypto::Bytes r;
            append_reply_hdr(r, found ? kValue : kNodes, qid, node_id,
                             udp_ep, from, true);
            if (found) {
                r.push_back(1);
                put16(r, static_cast<uint16_t>(value.size()));
                r.insert(r.end(), value.begin(), value.end());
            } else {
                // k closest nodes to target, self first.
                std::vector<RouteNode> nodes;
                {
                    std::lock_guard lk(mu);
                    nodes.push_back({node_id, udp_ep,
                                     std::chrono::steady_clock::now()});
                    for (auto& bucket : buckets)
                        for (auto& n : bucket) nodes.push_back(n);
                }
                std::sort(nodes.begin(), nodes.end(),
                          [&](const RouteNode& a, const RouteNode& b) {
                              return xor_dist(a.id, target) <
                                     xor_dist(b.id, target);
                          });
                if (nodes.size() > kBucketSize) nodes.resize(kBucketSize);
                append_nodes(r, nodes);
            }
            send_to(from, r);
            return;
        }
        case kStore: {
            const uint8_t* p = pkt.data() + 1;
            size_t left = pkt.size() - 1;
            uint32_t qid = 0, ttl = 0;
            crypto::Key32 key{};
            crypto::Key32 sid{};
            Endpoint sep;
            if (!get32(p, left, qid)) return;
            if (!get_key(p, left, key)) return;
            if (!get32(p, left, ttl)) return;
            uint16_t vlen = 0;
            if (!get16(p, left, vlen)) return;
            if (left < vlen) return;
            crypto::Bytes value(p, p + vlen);
            p += vlen; left -= vlen;
            if (!parse_sender(p, left, sid, sep)) return;
            route_add(sid, sep);
            record_put(key, value, ttl);
            crypto::Bytes r;
            append_reply_hdr(r, kStored, qid, node_id, udp_ep, from, true);
            r.push_back(1);
            send_to(from, r);
            return;
        }
        // ---- replies ----------------------------------------------------
        case kPong:
        case kNodes:
        case kValue:
        case kStored: {
            bool has_qid = (type != kPong);
            ReplyHdr h;
            const uint8_t* rest = nullptr;
            size_t left = 0;
            if (!parse_reply_hdr(pkt, has_qid, h, rest, left)) return;
            route_add(h.sender_id, h.sender_ep);
            // NAT discovery: remember the public address peers see.
            {
                std::lock_guard lk(mu);
                last_observed = h.observed_ep;
                if (endpoint_is_public(h.observed_ep))
                    observed_public = h.observed_ep;
            }
            std::shared_ptr<Query> q;
            if (has_qid) q = find_query(h.qid);
            if (!q) return;
            {
                std::lock_guard lk(q->mu);
                if (q->outstanding > 0) --q->outstanding;
            }
            if (type == kNodes) {
                std::vector<RouteNode> nodes;
                if (!parse_nodes(rest, left, nodes)) {
                    q->cv.notify_all();
                    return;
                }
                for (auto& n : nodes) route_add(n.id, n.ep);
            } else if (type == kValue) {
                if (left < 1) { q->cv.notify_all(); return; }
                uint8_t found = *rest++;
                --left;
                if (found) {
                    uint16_t vlen = 0;
                    if (!get16(rest, left, vlen) || left < vlen) {
                        q->cv.notify_all();
                        return;
                    }
                    crypto::Bytes value(rest, rest + vlen);
                    PeerRecord rec;
                    // The DHT key is SHA256("p2p-peer-v1" || peer_id);
                    // the record carries the raw peer id, so accept only
                    // when recomputing the key matches the query target.
                    if (peer_record_decode(value, rec) &&
                        record_key_for(rec.peer_id) == q->target) {
                        std::lock_guard lk(q->mu);
                        q->record = rec;
                        q->done = true;
                    }
                } else {
                    std::vector<RouteNode> nodes;
                    if (parse_nodes(rest, left, nodes))
                        for (auto& n : nodes) route_add(n.id, n.ep);
                }
            }
            q->cv.notify_all();
            return;
        }
        default:
            return;
        }
    }

    void receive_pump() {
        auto buf = std::make_shared<crypto::Bytes>(kMaxDatagram);
        sock.async_receive_from(
            asio::buffer(*buf), recv_ep_,
            [this, buf](asio::error_code ec, size_t n) {
                if (!ec && running.load() && n > 0 && n <= buf->size()) {
                    Endpoint fe = endpoint_from_asio(recv_ep_);
                    crypto::Bytes pkt(buf->begin(), buf->begin() + n);
                    handle_packet(pkt, fe);
                }
                if (running.load()) receive_pump();
            });
    }
};

// Dht public API
Dht::Dht(const Identity& identity, const crypto::Key32& node_id,
         const Endpoint& udp_endpoint, std::vector<Endpoint> bootstrap)
    : impl_(new Impl(identity, node_id, udp_endpoint,
                     std::move(bootstrap))) {}

Dht::~Dht() {
    stop();
    delete impl_;
}

void Dht::start() {
    if (impl_->running.exchange(true)) return;
    impl_->io_thread = std::thread([this] {
        try {
            asio::error_code ec;
            if (impl_->udp_ep.family == Endpoint::Family::IPv4) {
                impl_->sock.open(asio::ip::udp::v4(), ec);
                impl_->bound_v4 = true;
                auto a4 = asio::ip::make_address_v4(impl_->udp_ep.addr, ec);
                impl_->sock.bind({a4, impl_->udp_ep.port}, ec);
            } else {
                impl_->sock.open(asio::ip::udp::v6(), ec);
                impl_->sock.set_option(asio::ip::v6_only(false), ec);
                auto a6 = asio::ip::make_address_v6(impl_->udp_ep.addr, ec);
                impl_->sock.bind({a6, impl_->udp_ep.port}, ec);
            }
            if (ec) {
                impl_->running = false;
                return;
            }
            impl_->receive_pump();
            impl_->io.run();
        } catch (...) {
            impl_->running = false;
        }
    });
    // Periodic self-refresh + republish.
    impl_->publish_thread = std::thread([this] {
        {
            std::unique_lock lk(impl_->pub_mu);
            impl_->pub_cv.wait_for(
                lk, std::chrono::seconds(2),
                [&] { return !impl_->running.load(); });
        }
        while (impl_->running) {
            publish_self("", 0);  // reuses stored name/port
            std::unique_lock lk(impl_->pub_mu);
            impl_->pub_cv.wait_for(
                lk, kRepublishInterval,
                [&] { return !impl_->running.load(); });
        }
    });
}

void Dht::stop() {
    if (!impl_->running.exchange(false)) return;
    {
        std::lock_guard lk(impl_->pub_mu);
    }
    impl_->pub_cv.notify_all();
    asio::error_code ec;
    impl_->sock.close(ec);
    impl_->io.stop();
    if (impl_->io_thread.joinable()) impl_->io_thread.join();
    // Wake any query workers so they exit, then wait for them — Impl
    // must not be deleted while a worker still uses it.
    {
        std::lock_guard lk(impl_->qmu);
        for (auto& [qid, q] : impl_->queries) {
            std::lock_guard qlk(q->mu);
            q->done = true;
            q->cv.notify_all();
        }
    }
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(3);
    while (impl_->active_workers.load() > 0 &&
           std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    if (impl_->publish_thread.joinable()) impl_->publish_thread.join();
}

void Dht::add_bootstrap(const Endpoint& ep) {
    {
        std::lock_guard lk(impl_->mu);
        impl_->bootstrap.push_back(ep);
    }
}

void Dht::publish_self(const std::string& name, uint16_t chat_port) {
    if (!impl_->running) return;
    if (chat_port) {
        impl_->pub_port = chat_port;
        impl_->pub_name = name;
    }
    std::string pname = impl_->pub_name.empty() ? impl_->id.name
                                              : impl_->pub_name;
    if (pname.empty()) pname = "peer";
    if (pname.size() > 255) pname.resize(255);

    PeerRecord rec;
    rec.peer_id = impl_->node_id;
    rec.ed_pub = impl_->id.ed25519.pub;
    rec.name = pname;
    rec.issued_at = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now()
                            .time_since_epoch())
                        .count();
    if (impl_->pub_port) {
        for (auto& ep : local_endpoints(impl_->pub_port))
            rec.endpoints.push_back(ep);
        std::optional<Endpoint> obs;
        {
            std::lock_guard lk(impl_->mu);
            obs = impl_->observed_public;
        }
        if (obs) {
            Endpoint pub{obs->family, obs->addr, impl_->pub_port};
            if (endpoint_is_public(pub) &&
                std::find(rec.endpoints.begin(), rec.endpoints.end(),
                          pub) == rec.endpoints.end())
                rec.endpoints.push_back(pub);
        }
    }
    crypto::Bytes value = peer_record_sign(rec, impl_->id);
    crypto::Key32 key = record_key_for(rec.peer_id);
    // Store locally too so we can answer FIND_VALUE for ourselves.
    impl_->record_put(
        key, value,
        static_cast<uint32_t>(kRepublishInterval.count() * 60 * 3));

    // FIND_NODE + STORE run on a worker thread (blocking iterative
    // lookup must not stall the caller).
    crypto::Key32 target = key;
    std::thread([this, value, target]() {
        impl_->run_query(target, false,
                         [this, value, target](std::shared_ptr<Query> q) {
            auto nodes = impl_->closest(target, kBucketSize);
            nodes.insert(nodes.begin(),
                         RouteNode{impl_->node_id, impl_->udp_ep,
                                   std::chrono::steady_clock::now()});
            uint32_t qid = impl_->next_qid++;
            crypto::Bytes pkt = pkt_store(qid, target, kMaxStoreTtl,
                                          value, impl_->node_id,
                                          impl_->udp_ep);
            for (auto& n : nodes) impl_->send_to(n.ep, pkt);
        });
    }).detach();
}

bool Dht::find_peer(
    const crypto::Key32& peer_id,
    std::function<void(const std::optional<PeerRecord>&)> cb) {
    if (!impl_->running) return false;
    crypto::Key32 key = record_key_for(peer_id);
    std::thread([this, key, cb = std::move(cb)]() mutable {
        impl_->run_query(key, true,
                         [cb = std::move(cb)](std::shared_ptr<Query> q) {
            std::optional<PeerRecord> out;
            {
                std::lock_guard lk(q->mu);
                if (q->record) out = *q->record;
            }
            if (cb) cb(out);
        });
    }).detach();
    return true;
}

size_t Dht::known_nodes() const {
    size_t n = 0;
    std::lock_guard lk(impl_->mu);
    for (auto& b : impl_->buckets) n += b.size();
    return n;
}

size_t Dht::stored_records() const {
    std::lock_guard lk(impl_->mu);
    return impl_->records.size();
}

std::optional<Endpoint> Dht::observed_public_endpoint() const {
    std::lock_guard lk(impl_->mu);
    return impl_->observed_public;
}
