#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "crypto.h"
#include "endpoint.h"

struct Identity;  // defined in net.h

// An invitation carries enough information for a new peer to find and
// authenticate the inviter without any central server:
//   - peer_id / ed_pub: cryptographic identity (Peer ID = x25519 pub hex)
//   - name: display name hint
//   - dht_hints: bootstrap endpoints (the inviter's DHT UDP address) so
//     the recipient can join the DHT and resolve the inviter's signed
//     peer record — the invitation itself never carries the chat
//     endpoints, those come from the DHT record.
//   - issued_at / ttl: validity window
//   - Ed25519 signature over the whole payload: prevents tampering;
//     it does NOT replace the Noise handshake authentication.
struct Invitation {
    bool valid = false;
    crypto::Key32 peer_id{};
    crypto::Key32 ed_pub{};
    std::string name;
    std::vector<Endpoint> dht_hints;
    int64_t issued_at = 0;  // unix seconds
    int64_t ttl = 0;        // seconds
};

// Serialize + sign. Returns empty on failure.
crypto::Bytes invitation_encode(const Invitation& inv, const Identity& id);

// Parse + verify signature + check expiry. Returns false on malformed
// input, bad signature or expired invitation.
bool invitation_decode(const crypto::Bytes& blob, Invitation& out,
                       int64_t now_unix);

// base64url (no padding) codec used for the CLI-friendly invitation code.
std::string base64url_encode(const crypto::Bytes& data);
bool base64url_decode(const std::string& s, crypto::Bytes& out);
