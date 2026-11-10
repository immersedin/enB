#pragma once

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <asio.hpp>

#include "crypto.h"
#include "endpoint.h"

struct Identity;  // defined in net.h — Dht only needs it for signing

// A signed, self-describing peer record stored in the DHT under
// SHA256("p2p-peer-v1" || peer_id). Contains everything needed to reach
// the peer's chat listener; the Ed25519 signature makes the record
// unforgeable, while the Noise handshake later proves possession of the
// matching X25519 static key.
struct PeerRecord {
    bool valid = false;
    crypto::Key32 peer_id{};   // == X25519 public key, hex is the Peer ID
    crypto::Key32 ed_pub{};    // Ed25519 public key used for the signature
    std::string name;
    std::vector<Endpoint> endpoints;  // TCP chat endpoints
    int64_t issued_at = 0;            // unix seconds
};

// Build the signed DHT value blob for a peer record (Ed25519 signature
// over the canonical encoding, appended at the end).
crypto::Bytes peer_record_sign(const PeerRecord& rec, const Identity& id);

// Parse a DHT value blob into a PeerRecord AND verify the Ed25519
// signature. Returns false on malformed input or bad signature; `out`
// is only meaningful when the return is true.
bool peer_record_decode(const crypto::Bytes& blob, PeerRecord& out);

// Kademlia DHT node over UDP. Node ID = our X25519 public key (256-bit,
// same value that authenticates Noise sessions, so a MITM cannot present
// a different identity in the DHT and on the wire).
//
// Wire protocol (single UDP datagram, big-endian integers):
//   request:  type(1) | ... | sender_id(32) | sender_ep
//   reply:    type(1) | qid(4) | sender_id(32) | sender_ep | observed_ep | ...
// observed_ep is the responder's view of the requester's address — used
// for NAT discovery (we learn our public IP without any central server).
class Dht {
public:
    // identity is used to sign published peer records; node_id is the
    // Kademlia/node identity (we pass identity.x25519.pub).
    Dht(const Identity& identity, const crypto::Key32& node_id,
        const Endpoint& udp_endpoint,
        std::vector<Endpoint> bootstrap_nodes);
    ~Dht();

    Dht(const Dht&) = delete;
    Dht& operator=(const Dht&) = delete;

    void start();
    void stop();

    // Add a bootstrap node at runtime (also used for invite hints).
    void add_bootstrap(const Endpoint& ep);

    // Publish/refresh our signed peer record. chat_port is the TCP port
    // peers should connect to; endpoints are enumerated locally and the
    // observed public IP (if any) is added with this port.
    void publish_self(const std::string& name, uint16_t chat_port);

    // Asynchronous peer lookup. cb receives the verified PeerRecord or
    // nullopt. Invoked on a DHT worker thread — callers must marshal to
    // their own threading model. Returns false if DHT is not running.
    bool find_peer(const crypto::Key32& peer_id,
                   std::function<void(const std::optional<PeerRecord>&)>
                       cb);

    // Diagnostics for the UI.
    size_t known_nodes() const;
    size_t stored_records() const;
    std::optional<Endpoint> observed_public_endpoint() const;

private:
    struct Impl;
    Impl* impl_;
};
