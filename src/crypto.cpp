#include "crypto.h"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace crypto {

namespace {

constexpr size_t kKeyLen = 32;
constexpr size_t kTagLen = 16;
constexpr size_t kNonceLen = 12;

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    crypto_hash_sha256(out, data, static_cast<unsigned long long>(len));
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* msg, size_t msg_len, uint8_t out[32]) {
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, msg, msg_len);
    crypto_auth_hmacsha256_final(&state, out);
}

void aead_encrypt(const Key32& key, const uint8_t* nonce, const Bytes& ad,
                  const uint8_t* pt, size_t pt_len, Bytes& out) {
    out.resize(pt_len + kTagLen);
    unsigned long long out_len = 0;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        out.data(), &out_len, pt, pt_len, ad.data(), ad.size(),
        nullptr, nonce, key.data());
    out.resize(out_len);
}

bool aead_decrypt(const Key32& key, const uint8_t* nonce, const Bytes& ad,
                  const uint8_t* ct, size_t ct_len, Bytes& out) {
    if (ct_len < kTagLen) return false;
    out.resize(ct_len - kTagLen);
    unsigned long long out_len = 0;
    return crypto_aead_chacha20poly1305_ietf_decrypt(
               out.data(), &out_len, nullptr, ct, ct_len, ad.data(),
               ad.size(), nonce, key.data()) == 0 &&
           (out.resize(out_len), true);
}

}  // namespace

void random_bytes(uint8_t* out, size_t len) {
    randombytes_buf(out, len);
}

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string s;
    s.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        s.push_back(digits[data[i] >> 4]);
        s.push_back(digits[data[i] & 0xf]);
    }
    return s;
}

std::string to_hex(const Bytes& data) { return to_hex(data.data(), data.size()); }

bool from_hex(const std::string& hex, Bytes& out) {
    if (hex.size() % 2 != 0) return false;
    out.resize(hex.size() / 2);
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < out.size(); ++i) {
        int hi = nib(hex[2 * i]), lo = nib(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

bool from_hex32(const std::string& hex, Key32& out) {
    Bytes b;
    if (!from_hex(hex, b) || b.size() != 32) return false;
    std::memcpy(out.data(), b.data(), 32);
    return true;
}

KeyPair x25519_generate() {
    KeyPair kp;
    random_bytes(kp.priv.data(), kp.priv.size());
    if (crypto_scalarmult_base(kp.pub.data(), kp.priv.data()) != 0)
        throw std::runtime_error("x25519 keygen failed");
    return kp;
}

bool x25519_shared(const Key32& priv, const Key32& pub, Key32& out) {
    return crypto_scalarmult(out.data(), priv.data(), pub.data()) == 0;
}

KeyPair ed25519_generate() {
    KeyPair kp;
    random_bytes(kp.priv.data(), kp.priv.size());  // 32-byte seed
    unsigned long long pk_len = 0;
    // libsodium secret key = seed || pubkey (64 bytes)
    uint8_t sk[64];
    std::memcpy(sk, kp.priv.data(), 32);
    if (crypto_sign_seed_keypair(kp.pub.data(), sk, kp.priv.data()) != 0)
        throw std::runtime_error("ed25519 keygen failed");
    std::memcpy(kp.priv.data(), sk, 32);  // keep the seed
    (void)pk_len;
    return kp;
}

bool ed25519_sign(const KeyPair& kp, const Bytes& msg, uint8_t sig[64]) {
    // Rebuild the 64-byte libsodium secret key: seed || pubkey.
    uint8_t sk[64];
    std::memcpy(sk, kp.priv.data(), 32);
    std::memcpy(sk + 32, kp.pub.data(), 32);
    unsigned long long sig_len = 64;
    return crypto_sign_detached(sig, &sig_len, msg.data(), msg.size(),
                                sk) == 0;
}

bool ed25519_verify(const Key32& pub, const Bytes& msg,
                    const uint8_t sig[64]) {
    return crypto_sign_verify_detached(sig, msg.data(), msg.size(),
                                       pub.data()) == 0;
}

// ------------------------------------------------------------------
// HKDF helpers
// ------------------------------------------------------------------

void noise_hkdf(const Key32& ck, const uint8_t* ikm, size_t ikm_len,
                uint8_t out[64]) {
    uint8_t temp[32];
    hmac_sha256(ck.data(), ck.size(), ikm, ikm_len, temp);

    // output1 = HMAC(temp, 0x01)
    const uint8_t one = 0x01;
    hmac_sha256(temp, 32, &one, 1, out);

    // output2 = HMAC(temp, output1 || 0x02)
    uint8_t buf[33];
    std::memcpy(buf, out, 32);
    buf[32] = 0x02;
    hmac_sha256(temp, 32, buf, 33, out + 32);
}

void hkdf_sha256(const uint8_t* salt, size_t salt_len,
                 const uint8_t* ikm, size_t ikm_len,
                 const char* info, uint8_t* out, size_t out_len) {
    // Extract
    uint8_t prk[32];
    if (salt == nullptr || salt_len == 0) {
        uint8_t zeros[32] = {};
        hmac_sha256(zeros, 32, ikm, ikm_len, prk);
    } else {
        hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    }
    // Expand (single or multiple blocks, T(i) chaining; T(0) is empty)
    size_t done = 0;
    Bytes t;
    uint8_t counter = 1;
    size_t info_len = std::strlen(info);
    while (done < out_len) {
        Bytes msg = t;
        msg.insert(msg.end(), info, info + info_len);
        msg.push_back(counter++);
        uint8_t hi[32];
        hmac_sha256(prk, 32, msg.data(), msg.size(), hi);
        size_t take = std::min<size_t>(32, out_len - done);
        std::memcpy(out + done, hi, take);
        t.assign(hi, hi + 32);
        done += take;
    }
}

// ------------------------------------------------------------------
// NoiseXX
// ------------------------------------------------------------------

NoiseXX::NoiseXX(Role role, const Key32& static_priv, const Key32& static_pub)
    : role_(role), static_kp_{static_priv, static_pub} {
    static const char* name = "Noise_XX_25519_ChaChaPoly_SHA256";
    const size_t name_len = std::strlen(name);
    if (name_len <= 32) {
        std::memcpy(h_.data(), name, name_len);
        std::memset(h_.data() + name_len, 0, 32 - name_len);
        ck_ = h_;
    } else {
        uint8_t digest[32];
        sha256(reinterpret_cast<const uint8_t*>(name), name_len, digest);
        std::memcpy(h_.data(), digest, 32);
        ck_ = h_;
    }
    // Empty prologue -> nothing to mix.
}

void NoiseXX::mix_hash(const uint8_t* data, size_t len) {
    Bytes buf(h_.begin(), h_.end());
    buf.insert(buf.end(), data, data + len);
    uint8_t out[32];
    sha256(buf.data(), buf.size(), out);
    std::memcpy(h_.data(), out, 32);
}

void NoiseXX::mix_key(const Key32& dh) {
    uint8_t hkdf_out[64];
    noise_hkdf(ck_, dh.data(), dh.size(), hkdf_out);
    std::memcpy(ck_.data(), hkdf_out, 32);
    std::memcpy(k_.data(), hkdf_out + 32, 32);
    has_k_ = true;
    n_ = 0;
}

Bytes NoiseXX::nonce() const {
    Bytes nonce(kNonceLen, 0);
    for (int i = 0; i < 8; ++i) nonce[i] = static_cast<uint8_t>(n_ >> (8 * i));
    return nonce;
}

Bytes NoiseXX::encrypt_and_hash(const Bytes& plaintext) {
    Bytes ad(h_.begin(), h_.end());
    Bytes ct;
    if (!has_k_) {
        ct = plaintext;
    } else {
        Bytes n = nonce();
        ++n_;
        aead_encrypt(k_, n.data(), ad, plaintext.data(), plaintext.size(), ct);
    }
    mix_hash(ct.data(), ct.size());
    return ct;
}

bool NoiseXX::decrypt_and_hash(const Bytes& ciphertext, Bytes& plaintext) {
    Bytes ad(h_.begin(), h_.end());
    if (!has_k_) {
        plaintext = ciphertext;
    } else {
        Bytes n = nonce();
        ++n_;
        if (!aead_decrypt(k_, n.data(), ad, ciphertext.data(),
                          ciphertext.size(), plaintext))
            return false;
    }
    mix_hash(ciphertext.data(), ciphertext.size());
    return true;
}

static bool read_exact(const Bytes& msg, size_t& off, size_t len, Bytes& out) {
    if (off + len > msg.size()) return false;
    out.assign(msg.begin() + off, msg.begin() + off + len);
    off += len;
    return true;
}

// DH helper: returns true on success.
static bool dh_into(const Key32& priv, const Key32& pub, Key32& out) {
    return crypto_scalarmult(out.data(), priv.data(), pub.data()) == 0;
}

// ---- message 1: initiator -> responder, token: e ----

Bytes NoiseXX::write_msg1(const Bytes& payload) {
    if (role_ != Role::Initiator || step_ != 0)
        throw std::logic_error("bad noise state for msg1");
    e_ = x25519_generate();
    mix_hash(e_->pub.data(), e_->pub.size());
    Bytes out(e_->pub.begin(), e_->pub.end());
    Bytes ct = encrypt_and_hash(payload);
    out.insert(out.end(), ct.begin(), ct.end());
    step_ = 1;
    return out;
}

bool NoiseXX::read_msg1(const Bytes& msg, Bytes& payload) {
    if (role_ != Role::Responder || step_ != 0) return false;
    size_t off = 0;
    Bytes eph;
    if (!read_exact(msg, off, 32, eph)) return false;
    re_.emplace();
    std::memcpy(re_->data(), eph.data(), 32);
    mix_hash(eph.data(), eph.size());
    Bytes rest(msg.begin() + off, msg.end());
    if (!decrypt_and_hash(rest, payload)) return false;
    step_ = 1;
    return true;
}

// ---- message 2: responder -> initiator, tokens: e, ee, s, es ----

Bytes NoiseXX::write_msg2(const Bytes& payload) {
    if (role_ != Role::Responder || step_ != 1 || !re_)
        throw std::logic_error("bad noise state for msg2");
    e_ = x25519_generate();
    mix_hash(e_->pub.data(), e_->pub.size());

    Bytes out(e_->pub.begin(), e_->pub.end());

    // ee: DH(local e, remote e)
    Key32 dh;
    if (!dh_into(e_->priv, *re_, dh)) return {};
    mix_key(dh);

    // s: local static, encrypted
    Bytes s_ct = encrypt_and_hash(Bytes(static_kp_.pub.begin(),
                                        static_kp_.pub.end()));
    out.insert(out.end(), s_ct.begin(), s_ct.end());

    // es: DH(local static priv, remote ephemeral pub)
    if (!dh_into(static_kp_.priv, *re_, dh)) return {};
    mix_key(dh);

    h_payload_ = h_;
    Bytes ct = encrypt_and_hash(payload);
    out.insert(out.end(), ct.begin(), ct.end());
    step_ = 2;
    return out;
}

bool NoiseXX::read_msg2(const Bytes& msg, Bytes& payload) {
    if (role_ != Role::Initiator || step_ != 1 || !e_)
        return false;
    size_t off = 0;
    Bytes eph, s_ct;
    if (!read_exact(msg, off, 32, eph)) return false;
    re_.emplace();
    std::memcpy(re_->data(), eph.data(), 32);
    mix_hash(eph.data(), eph.size());

    // ee
    Key32 dh;
    if (!dh_into(e_->priv, *re_, dh)) return false;
    mix_key(dh);

    // s
    if (!read_exact(msg, off, 48, s_ct)) return false;
    Bytes s_pt;
    if (!decrypt_and_hash(s_ct, s_pt) || s_pt.size() != 32) return false;
    rs_pub_ = {};
    std::memcpy(rs_pub_.data(), s_pt.data(), 32);
    has_rs_ = true;
    step_ = 2;

    // es: DH(local ephemeral priv, remote static pub)
    if (!dh_into(e_->priv, rs_pub_, dh)) return false;
    mix_key(dh);

    h_payload_ = h_;
    Bytes rest(msg.begin() + off, msg.end());
    if (!decrypt_and_hash(rest, payload)) return false;
    return true;
}

// ---- message 3: initiator -> responder, tokens: s, se ----

Bytes NoiseXX::write_msg3(const Bytes& payload) {
    if (role_ != Role::Initiator || step_ != 2 || !re_)
        throw std::logic_error("bad noise state for msg3");
    Bytes out;

    // s: local static, encrypted
    Bytes s_ct = encrypt_and_hash(Bytes(static_kp_.pub.begin(),
                                        static_kp_.pub.end()));
    out.insert(out.end(), s_ct.begin(), s_ct.end());

    // se: DH(local static priv, remote ephemeral pub)
    Key32 dh;
    if (!dh_into(static_kp_.priv, *re_, dh)) return {};
    mix_key(dh);

    h_payload_ = h_;
    Bytes ct = encrypt_and_hash(payload);
    out.insert(out.end(), ct.begin(), ct.end());
    step_ = 3;
    return out;
}

bool NoiseXX::read_msg3(const Bytes& msg, Bytes& payload) {
    if (role_ != Role::Responder || step_ != 2) return false;
    size_t off = 0;
    Bytes s_ct;
    if (!read_exact(msg, off, 48, s_ct)) return false;
    Bytes s_pt;
    if (!decrypt_and_hash(s_ct, s_pt) || s_pt.size() != 32) return false;
    rs_pub_ = {};
    std::memcpy(rs_pub_.data(), s_pt.data(), 32);
    has_rs_ = true;

    // se: DH(local ephemeral priv, remote static pub)
    if (!e_) return false;
    Key32 dh;
    if (!dh_into(e_->priv, rs_pub_, dh)) return false;
    mix_key(dh);

    h_payload_ = h_;
    Bytes rest(msg.begin() + off, msg.end());
    if (!decrypt_and_hash(rest, payload)) return false;
    step_ = 3;
    return true;
}

// ---- transport ----

Bytes NoiseXX::transport_encrypt(const Bytes& plaintext) {
    if (!handshake_done()) throw std::logic_error("handshake not done");
    Bytes ad;  // empty AD for transport
    Bytes n = nonce();
    ++n_;
    Bytes ct;
    aead_encrypt(k_, n.data(), ad, plaintext.data(), plaintext.size(), ct);
    return ct;
}

bool NoiseXX::transport_decrypt(const Bytes& ciphertext, Bytes& plaintext) {
    if (!handshake_done()) return false;
    Bytes ad;
    Bytes n = nonce();
    ++n_;
    return aead_decrypt(k_, n.data(), ad, ciphertext.data(),
                        ciphertext.size(), plaintext);
}

// ------------------------------------------------------------------
// DoubleRatchet
// ------------------------------------------------------------------

namespace {

void ratchet_hkdf(const Key32& salt, const Key32& ikm, const char* info,
                  Key32& out) {
    uint8_t buf[32];
    hkdf_sha256(salt.data(), salt.size(), ikm.data(), ikm.size(), info, buf,
                32);
    std::memcpy(out.data(), buf, 32);
}

}  // namespace

void DoubleRatchet::init(const Key32& root, bool initiator_side,
                         const KeyPair& my_ratchet,
                         const Key32& their_ratchet_pub) {
    my_ratchet_ = my_ratchet;
    their_ratchet_pub_ = their_ratchet_pub;

    Key32 c_ab, c_ba;
    Key32 ikm_a{}, ikm_b{};
    ikm_a[0] = 'a'; ikm_b[0] = 'b';
    ratchet_hkdf(root, ikm_a, "p2p-ratchet-a2b", c_ab);
    ratchet_hkdf(root, ikm_b, "p2p-ratchet-b2a", c_ba);

    if (initiator_side) {
        send_chain_ = c_ab;
        recv_chain_ = c_ba;
    } else {
        send_chain_ = c_ba;
        recv_chain_ = c_ab;
    }
    send_count_ = 0;
    recv_count_ = 0;
}

Bytes DoubleRatchet::encrypt(const Bytes& plaintext) {
    // Fresh ephemeral per message.
    KeyPair eph = x25519_generate();
    Key32 dh;
    if (!x25519_shared(eph.priv, their_ratchet_pub_, dh))
        throw std::runtime_error("ratchet DH failed");

    Key32 new_chain;
    ratchet_hkdf(send_chain_, dh, "p2p-chain", new_chain);
    send_chain_ = new_chain;

    uint64_t counter = send_count_++;
    Key32 ikm{};
    for (int i = 0; i < 8; ++i) ikm[i] = static_cast<uint8_t>(counter >> (8 * i));
    Key32 msg_key;
    ratchet_hkdf(send_chain_, ikm, "p2p-msgkey", msg_key);

    // header = e_pub || counter
    Bytes header(eph.pub.begin(), eph.pub.end());
    for (int i = 0; i < 8; ++i)
        header.push_back(static_cast<uint8_t>(counter >> (8 * i)));

    uint8_t nonce[kNonceLen] = {};
    Bytes ct;
    aead_encrypt(msg_key, nonce, header, plaintext.data(), plaintext.size(),
                 ct);

    Bytes frame = header;
    frame.insert(frame.end(), ct.begin(), ct.end());
    return frame;
}

bool DoubleRatchet::decrypt(const Bytes& frame, Bytes& plaintext) {
    if (frame.size() < 32 + 8 + kTagLen) return false;

    Key32 e_pub;
    std::memcpy(e_pub.data(), frame.data(), 32);
    uint64_t counter = 0;
    for (int i = 0; i < 8; ++i)
        counter |= static_cast<uint64_t>(frame[32 + i]) << (8 * i);

    Key32 dh;
    if (!x25519_shared(my_ratchet_.priv, e_pub, dh)) return false;

    Key32 new_chain;
    ratchet_hkdf(recv_chain_, dh, "p2p-chain", new_chain);
    recv_chain_ = new_chain;

    Key32 ikm{};
    for (int i = 0; i < 8; ++i) ikm[i] = static_cast<uint8_t>(counter >> (8 * i));
    Key32 msg_key;
    ratchet_hkdf(recv_chain_, ikm, "p2p-msgkey", msg_key);

    Bytes header(frame.begin(), frame.begin() + 40);
    uint8_t nonce[kNonceLen] = {};
    return aead_decrypt(msg_key, nonce, header, frame.data() + 40,
                        frame.size() - 40, plaintext);
}

}  // namespace crypto
