#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace crypto {

// All keys are raw 32-byte values. Curve25519 is used for DH (X25519),
// Ed25519 for identity signatures, ChaCha20-Poly1305 for AEAD and
// SHA-256 for hashing / HKDF, per the Noise spec revision 34 rules.
using Key32 = std::array<uint8_t, 32>;
using Bytes = std::vector<uint8_t>;

struct KeyPair {
    Key32 priv{};
    Key32 pub{};
};

void random_bytes(uint8_t* out, size_t len);
std::string to_hex(const uint8_t* data, size_t len);
std::string to_hex(const Bytes& data);
bool from_hex(const std::string& hex, Bytes& out);
bool from_hex32(const std::string& hex, Key32& out);

KeyPair x25519_generate();
bool x25519_shared(const Key32& priv, const Key32& pub, Key32& out);

KeyPair ed25519_generate();
// Signs msg, writes 64-byte signature into sig.
bool ed25519_sign(const KeyPair& kp, const Bytes& msg, uint8_t sig[64]);
bool ed25519_verify(const Key32& pub, const Bytes& msg, const uint8_t sig[64]);

// ------------------------------------------------------------------
// Noise_XX_25519_ChaChaPoly_SHA256 handshake.
//
// Pattern (Noise revision 34):
//   -> e
//   <- e, ee, s, es
//   -> s, se
//
// The handshake object is single-use and must be driven in order:
// initiator: write_msg1 -> read_msg2 -> write_msg3
// responder: read_msg1  -> write_msg2 -> read_msg3
// After the third message both sides hold a transport CipherState and
// identical handshake hash h / chaining key ck.
// ------------------------------------------------------------------
class NoiseXX {
public:
    enum class Role { Initiator, Responder };

    NoiseXX(Role role, const Key32& static_priv, const Key32& static_pub);

    Bytes write_msg1(const Bytes& payload);
    bool read_msg1(const Bytes& msg, Bytes& payload);

    Bytes write_msg2(const Bytes& payload);
    bool read_msg2(const Bytes& msg, Bytes& payload);

    Bytes write_msg3(const Bytes& payload);
    bool read_msg3(const Bytes& msg, Bytes& payload);

    bool handshake_done() const { return step_ == 3; }

    // Transport encryption (Noise CipherState, continues after handshake).
    Bytes transport_encrypt(const Bytes& plaintext);
    bool transport_decrypt(const Bytes& ciphertext, Bytes& plaintext);

    // Final handshake values, used to derive the ratchet root key.
    const Key32& handshake_hash() const { return h_; }
    const Key32& chaining_key() const { return ck_; }

    // Remote static key learned during the handshake.
    const Key32& remote_static() const { return rs_pub_; }
    bool has_remote_static() const { return has_rs_; }

    // Handshake hash captured just before the payload of the last
    // processed message was mixed in. Used to bind payload signatures
    // to the handshake transcript.
    const Key32& payload_context_hash() const { return h_payload_; }

private:
    void mix_hash(const uint8_t* data, size_t len);
    void mix_key(const Key32& dh);
    Bytes encrypt_and_hash(const Bytes& plaintext);
    bool decrypt_and_hash(const Bytes& ciphertext, Bytes& plaintext);
    Bytes nonce() const;

    Role role_;
    int step_ = 0;  // 0 = nothing exchanged yet

    Key32 h_{};   // handshake hash
    Key32 ck_{};  // chaining key
    bool has_k_ = false;
    Key32 k_{};   // transport cipher key
    uint64_t n_ = 0;

    KeyPair static_kp_;
    std::optional<KeyPair> e_;  // local ephemeral
    std::optional<Key32> re_;   // remote ephemeral
    Key32 rs_pub_{};            // remote static
    bool has_rs_ = false;
    Key32 h_payload_{};         // h before last payload mix_hash
};

// ------------------------------------------------------------------
// Double Ratchet session layer (per Noise connection).
//
// Every message carries a fresh X25519 ephemeral key. Both sides derive
// the same DH output (commutative DH), then evolve a per-direction
// KDF chain: chain = HKDF(chain, dh), key = HKDF(chain, counter).
// This yields per-message forward secrecy in both directions.
// ------------------------------------------------------------------
class DoubleRatchet {
public:
    // initiator_side selects which chain is used for sending.
    void init(const Key32& root, bool initiator_side,
              const KeyPair& my_ratchet, const Key32& their_ratchet_pub);

    // Returns the wire frame: e_pub(32) || counter(u64 LE) || ciphertext.
    Bytes encrypt(const Bytes& plaintext);
    bool decrypt(const Bytes& frame, Bytes& plaintext);

private:
    KeyPair my_ratchet_{};
    Key32 their_ratchet_pub_{};
    Key32 send_chain_{};
    Key32 recv_chain_{};
    uint64_t send_count_ = 0;
    uint64_t recv_count_ = 0;
};

// HKDF-SHA256 (RFC 5869) used by the ratchet.
void hkdf_sha256(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const char* info, uint8_t* out, size_t out_len);

// Noise-style HKDF: HMAC(ck, ikm) -> temp; HMAC(temp,0x01)||HMAC(temp,out1||0x02)
void noise_hkdf(const Key32& ck, const uint8_t* ikm, size_t ikm_len,
                uint8_t out[64]);

}  // namespace crypto
