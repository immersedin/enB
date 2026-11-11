#pragma once

#include <cstdint>
#include <string>
#include <vector>

// A network endpoint: IP address family + numeric address + port.
// Used both for TCP (chat transport) and UDP (DHT transport); the
// context decides which protocol applies.
struct Endpoint {
    enum class Family : uint8_t { IPv4 = 4, IPv6 = 6 };

    Family family = Family::IPv4;
    std::string addr;  // numeric, e.g. "192.168.1.10" / "::1" / "fe80::1%en0"
    uint16_t port = 0;

    bool valid() const { return !addr.empty() && port > 0; }
    std::string str() const;
    bool operator==(const Endpoint& o) const {
        return family == o.family && addr == o.addr && port == o.port;
    }
};

// "1.2.3.4:5555" or "[::1]:5555" or bare "::1" (port 0). Returns false on
// parse failure. Scope ids ("fe80::1%en0") are kept in addr but are not
// meaningful off-link; they are preserved for completeness.
bool parse_endpoint(const std::string& s, Endpoint& out);

// Like parse_endpoint, but when the host part is a DNS name it is
// resolved and ALL resulting addresses are returned (a hostname may map
// to several IPs). Returns an empty vector on failure.
std::vector<Endpoint> resolve_endpoint(const std::string& s);

// Wire encoding: family(1) | addr_len(1) | addr bytes | port u16 BE.
// addr_len is 4 for IPv4, 16 for IPv6 (raw bytes, no scope).
// Returns false when the address cannot be parsed to raw bytes.
bool endpoint_encode(const Endpoint& ep, std::vector<uint8_t>& out);
bool endpoint_decode(const uint8_t*& p, size_t& left, Endpoint& out);

// True when the address is globally routable (not loopback, link-local,
// private RFC1918/ULA, multicast or unspecified). Used to decide which
// observed addresses are worth publishing.
bool endpoint_is_public(const Endpoint& ep);

// All local non-loopback TCP endpoints for `port` — used when publishing
// our peer record into the DHT. On failure returns an empty vector.
// The caller should additionally publish the "observed" public endpoint
// learned from DHT replies (NAT-friendly).
std::vector<Endpoint> local_endpoints(uint16_t port);
