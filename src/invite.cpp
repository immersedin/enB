#include "invite.h"

#include <cstring>

#include "net.h"  // Identity

namespace {

constexpr char kInviteMagic[] = "P2PI1";
constexpr size_t kInviteMagicLen = 5;
constexpr size_t kMaxInviteSize = 2048;
constexpr size_t kMaxHints = 8;

void put32(crypto::Bytes& b, uint32_t v) {
    for (int i = 3; i >= 0; --i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put64(crypto::Bytes& b, uint64_t v) {
    for (int i = 7; i >= 0; --i)
        b.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
bool get32(const uint8_t*& p, size_t& left, uint32_t& v) {
    if (left < 4) return false;
    v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | p[i];
    p += 4; left -= 4; return true;
}
bool get64(const uint8_t*& p, size_t& left, uint64_t& v) {
    if (left < 8) return false;
    v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | *p++;
    left -= 8; return true;
}
void put_key(crypto::Bytes& b, const crypto::Key32& k) {
    b.insert(b.end(), k.begin(), k.end());
}
bool get_key(const uint8_t*& p, size_t& left, crypto::Key32& k) {
    if (left < 32) return false;
    std::memcpy(k.data(), p, 32);
    p += 32; left -= 32; return true;
}

int b64val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

}  // namespace

crypto::Bytes invitation_encode(const Invitation& inv,
                                const Identity& id) {
    crypto::Bytes b;
    b.insert(b.end(), kInviteMagic, kInviteMagic + kInviteMagicLen);
    put_key(b, inv.peer_id);
    put_key(b, inv.ed_pub);
    b.push_back(static_cast<uint8_t>(inv.name.size() & 0xff));
    b.insert(b.end(), inv.name.begin(), inv.name.end());
    b.push_back(static_cast<uint8_t>(inv.dht_hints.size()));
    for (auto& ep : inv.dht_hints) endpoint_encode(ep, b);
    put64(b, static_cast<uint64_t>(inv.issued_at));
    put32(b, static_cast<uint32_t>(inv.ttl));
    uint8_t sig[64];
    crypto::ed25519_sign(id.ed25519, b, sig);
    b.insert(b.end(), sig, sig + 64);
    return b;
}

bool invitation_decode(const crypto::Bytes& blob, Invitation& out,
                       int64_t now_unix) {
    if (blob.size() < kInviteMagicLen + 32 + 32 + 1 + 1 + 8 + 4 + 64 ||
        blob.size() > kMaxInviteSize)
        return false;
    if (std::memcmp(blob.data(), kInviteMagic, kInviteMagicLen) != 0)
        return false;
    // Signature is the last 64 bytes, over everything before it.
    crypto::Bytes body(blob.begin(), blob.end() - 64);
    const uint8_t* sig = blob.data() + blob.size() - 64;

    const uint8_t* p = body.data() + kInviteMagicLen;
    size_t left = body.size() - kInviteMagicLen;
    Invitation inv;
    if (!get_key(p, left, inv.peer_id)) return false;
    if (!get_key(p, left, inv.ed_pub)) return false;
    if (left < 1) return false;
    uint8_t nl = *p++;
    --left;
    if (left < nl + 1 + 8 + 4) return false;
    inv.name.assign(reinterpret_cast<const char*>(p), nl);
    p += nl; left -= nl;
    if (left < 1) return false;
    uint8_t nh = *p++;
    --left;
    if (nh > kMaxHints) return false;
    for (int i = 0; i < nh; ++i) {
        Endpoint ep;
        if (!endpoint_decode(p, left, ep)) return false;
        inv.dht_hints.push_back(ep);
    }
    uint64_t ts = 0;
    uint32_t ttl = 0;
    if (!get64(p, left, ts)) return false;
    if (!get32(p, left, ttl)) return false;
    if (left != 0) return false;

    if (!crypto::ed25519_verify(inv.ed_pub, body, sig)) return false;
    inv.issued_at = static_cast<int64_t>(ts);
    inv.ttl = static_cast<int64_t>(ttl);
    if (inv.ttl <= 0 || now_unix < inv.issued_at ||
        now_unix > inv.issued_at + inv.ttl)
        return false;

    inv.valid = true;
    out = inv;
    return true;
}

std::string base64url_encode(const crypto::Bytes& data) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string out;
    out.reserve((data.size() * 4 + 2) / 3);
    size_t i = 0;
    while (i + 3 <= data.size()) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
        out += tbl[v & 63];
        i += 3;
    }
    size_t rem = data.size() - i;
    if (rem == 1) {
        uint32_t v = data[i] << 16;
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
    } else if (rem == 2) {
        uint32_t v = (data[i] << 16) | (data[i + 1] << 8);
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63];
    }
    return out;
}

bool base64url_decode(const std::string& s, crypto::Bytes& out) {
    out.clear();
    std::string t;
    t.reserve(s.size());
    for (char c : s) {
        if (c == '=' ) continue;  // tolerate padding
        if (b64val(c) < 0) return false;
        t += c;
    }
    if (t.size() % 4 == 1) return false;
    size_t i = 0;
    auto val = [&](size_t idx) -> int {
        return idx < t.size() ? b64val(t[idx]) : 0;
    };
    while (i + 4 <= t.size()) {
        uint32_t v = (val(i) << 18) | (val(i + 1) << 12) |
                     (val(i + 2) << 6) | val(i + 3);
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
        out.push_back(static_cast<uint8_t>(v & 0xff));
        i += 4;
    }
    size_t rem = t.size() - i;
    if (rem == 2) {
        uint32_t v = (val(i) << 18) | (val(i + 1) << 12);
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
    } else if (rem == 3) {
        uint32_t v = (val(i) << 18) | (val(i + 1) << 12) |
                     (val(i + 2) << 6);
        out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
        out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
    } else if (rem != 0) {
        return false;
    }
    return !out.empty();
}
