// Headless integration self-test. Everything here uses real sockets on
// 127.0.0.1 — Kademlia over UDP, Noise XX + Double Ratchet over TCP.
// No code path is stubbed or simulated.

#include "selftest.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <future>
#include <string>
#include <thread>

#include "crypto.h"
#include "db.h"
#include "dht.h"
#include "endpoint.h"
#include "invite.h"
#include "net.h"

namespace {

int failures = 0;

void check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (!ok) ++failures;
}

template <typename F>
bool wait_for(F&& pred, int timeout_ms = 10000) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

Identity make_identity(const char* name) {
    Identity id;
    id.x25519 = crypto::x25519_generate();
    id.ed25519 = crypto::ed25519_generate();
    id.name = name;
    return id;
}

std::string pid_hex(const Identity& id) {
    return crypto::to_hex(id.x25519.pub.data(), 32);
}

Endpoint loopback(uint16_t port) {
    return {Endpoint::Family::IPv4, "127.0.0.1", port};
}

}  // namespace

int run_selftest() {
    namespace fs = std::filesystem;
    std::printf("== p2p selftest ==\n");

    // Fresh temp dirs for the two chat databases.
    auto base = fs::temp_directory_path() / "p2p-selftest";
    fs::remove_all(base);
    fs::create_directories(base);

    // ------------------------------------------------ identity / invite
    std::printf("-- identity & invitations --\n");
    Identity alice = make_identity("alice");
    Identity bob = make_identity("bob");
    check(!pid_hex(alice).empty() && pid_hex(alice) != pid_hex(bob),
          "distinct peer ids");

    Invitation inv;
    inv.peer_id = alice.x25519.pub;
    inv.ed_pub = alice.ed25519.pub;
    inv.name = "alice";
    inv.dht_hints = {loopback(45678)};
    inv.issued_at = std::chrono::duration_cast<std::chrono::seconds>(
                        std::chrono::system_clock::now()
                            .time_since_epoch())
                        .count();
    inv.ttl = 300;
    crypto::Bytes blob = invitation_encode(inv, alice);
    std::string code = base64url_encode(blob);
    crypto::Bytes decoded;
    check(base64url_decode(code, decoded) && decoded == blob,
          "invite base64url roundtrip");

    Invitation parsed;
    check(invitation_decode(decoded, parsed, inv.issued_at + 10) &&
              parsed.peer_id == inv.peer_id &&
              parsed.name == "alice" &&
              parsed.dht_hints.size() == 1,
          "invite decode + signature verify");
    // Tampered invitation must be rejected.
    crypto::Bytes bad = decoded;
    bad[bad.size() / 2] ^= 0x01;
    Invitation bogus;
    check(!invitation_decode(bad, bogus, inv.issued_at + 10),
          "tampered invite rejected");
    check(!invitation_decode(decoded, bogus, inv.issued_at + 400),
          "expired invite rejected");

    // ------------------------------------------------------- DHT mesh
    std::printf("-- Kademlia DHT (3 nodes, loopback UDP) --\n");
    uint16_t dht_a = 46001, dht_b = 46002, dht_c = 46003;
    Identity carol = make_identity("carol");
    Dht da(alice, alice.x25519.pub, loopback(dht_a), {});
    Dht db_(bob, bob.x25519.pub, loopback(dht_b), {loopback(dht_a)});
    Dht dc(carol, carol.x25519.pub, loopback(dht_c),
           {loopback(dht_b)});

    da.start();
    db_.start();
    dc.start();

    da.publish_self("alice", 47001);
    db_.publish_self("bob", 47002);
    dc.publish_self("carol", 47003);

    // Carol bootstraps through Bob; Alice has no bootstrap at all.
    check(wait_for([&] { return db_.known_nodes() > 0; }),
          "bob learned nodes via bootstrap");
    check(wait_for([&] { return dc.known_nodes() > 0; }),
          "carol learned nodes via bootstrap");
    check(wait_for([&] { return da.known_nodes() > 0; }),
          "alice discovered peers (inbound queries)");

    // Carol resolves Alice purely through the DHT.
    std::promise<std::optional<PeerRecord>> found;
    crypto::Key32 alice_id = alice.x25519.pub;
    check(dc.find_peer(alice_id,
                       [&](const std::optional<PeerRecord>& r) {
                           found.set_value(r);
                       }),
          "carol DHT lookup started");
    auto fut = found.get_future();
    check(wait_for([&] {
              return fut.wait_for(std::chrono::seconds(0)) ==
                     std::future_status::ready;
          },
          15000),
          "carol DHT lookup completed");
    auto rec = fut.get();
    check(rec.has_value() && rec->name == "alice" &&
              rec->peer_id == alice_id,
          "carol resolved alice's signed peer record");
    check(rec.has_value() && !rec->endpoints.empty(),
          "peer record carries chat endpoints");

    // Bob resolves Carol (2-hop path Bob->?->Carol via Alice's table).
    std::promise<std::optional<PeerRecord>> found2;
    crypto::Key32 carol_id = carol.x25519.pub;
    db_.find_peer(carol_id,
                  [&](const std::optional<PeerRecord>& r) {
                      found2.set_value(r);
                  });
    auto fut2 = found2.get_future();
    check(wait_for([&] {
              return fut2.wait_for(std::chrono::seconds(0)) ==
                     std::future_status::ready;
          },
          15000),
          "bob DHT lookup completed");
    check(fut2.get().has_value(), "bob resolved carol's record");

    dc.stop();
    db_.stop();
    da.stop();

    // ------------------------------------------------- real E2EE chat
    std::printf("-- Noise XX + Double Ratchet session --\n");
    Database db_a((base / "a").string());
    Database db_b((base / "b").string());
    std::atomic<bool> got_msg{false};
    std::string got_text;
    Net net_a(alice, 47011, db_a,
              [&](const std::string&, const std::string& text) {
                  got_text = text;
                  got_msg = true;
              },
              [](int64_t, const std::string&, bool, const std::string&) {});
    Net net_b(bob, 47012, db_b,
              [](const std::string&, const std::string&) {},
              [](int64_t, const std::string&, bool,
                 const std::string&) {});
    net_a.start();
    net_b.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    Friend fa;
    fa.name = "alice";
    fa.host = "127.0.0.1";
    fa.port = 47011;
    check(net_b.dial_friend(fa), "bob dialed alice (Noise handshake)");
    check(net_b.has_session(pid_hex(alice)),
          "bob has session keyed by alice's peer id");

    // Message exchange: bob -> alice.
    check(net_b.send(pid_hex(alice), "hello p2p"), "bob sent message");
    check(wait_for([&] { return got_msg.load(); }),
          "alice received decrypted message");
    check(got_text == "hello p2p", "message content intact");

    // Peer-id enforcement: dialing alice while claiming bob's own peer
    // id must fail (remote static key != expected peer id).
    Friend wrong;
    wrong.name = "impostor";
    wrong.host = "127.0.0.1";
    wrong.port = 47011;
    wrong.x25519_pub = pid_hex(bob);  // lie: expect ourselves
    check(!net_b.dial_friend(wrong),
          "peer-id mismatch rejected before msg3");

    // Identity-key change detection: friend record pins alice's ed key;
    // a different ed key must be refused.
    Friend pinned;
    pinned.name = "alice";
    pinned.host = "127.0.0.1";
    pinned.port = 47011;
    pinned.x25519_pub = pid_hex(alice);
    pinned.ed25519_pub = crypto::to_hex(carol.ed25519.pub.data(), 32);
    check(!net_b.dial_friend(pinned),
          "changed ed25519 key rejected with warning");

    net_b.stop();
    net_a.stop();
    fs::remove_all(base);

    std::printf("== %s (%d failure%s) ==\n",
                failures == 0 ? "ALL PASS" : "FAILURES",
                failures, failures == 1 ? "" : "s");
    return failures == 0 ? 0 : 1;
}
