#include "endpoint.h"

#include <asio.hpp>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <ifaddrs.h>
#include <netinet/in.h>
#endif

namespace {

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool parse_addr_port(const std::string& host, const std::string& port_s,
                     Endpoint& out) {
    out.addr = trim(host);
    if (out.addr.empty()) return false;
    if (out.addr.front() == '[' && out.addr.back() == ']')
        out.addr = out.addr.substr(1, out.addr.size() - 2);
    char* end = nullptr;
    long p = std::strtol(port_s.c_str(), &end, 10);
    if (!end || *end != '\0' || p <= 0 || p > 65535) return false;
    out.port = static_cast<uint16_t>(p);
    // Family from the address text itself.
    asio::error_code ec;
    auto a4 = asio::ip::make_address_v4(out.addr, ec);
    if (!ec) {
        out.family = Endpoint::Family::IPv4;
        return true;
    }
    auto a6 = asio::ip::make_address_v6(out.addr, ec);
    if (!ec) {
        out.family = Endpoint::Family::IPv6;
        return true;
    }
    return false;
}

}  // namespace

std::string Endpoint::str() const {
    if (family == Family::IPv6) return "[" + addr + "]:" + std::to_string(port);
    return addr + ":" + std::to_string(port);
}

bool parse_endpoint(const std::string& s, Endpoint& out) {
    std::string t = trim(s);
    if (t.empty()) return false;

    // [v6]:port
    if (t.front() == '[') {
        auto close = t.find(']');
        if (close == std::string::npos) return false;
        std::string rest = t.substr(close + 1);
        if (rest.empty() || rest.front() != ':') return false;
        return parse_addr_port(t.substr(1, close - 1), rest.substr(1), out);
    }

    // host:port — split on the LAST colon so bare IPv6 without brackets
    // is rejected (ambiguous) but "::1" alone can still mean port 0? No:
    // we require an explicit port for unbracketed input.
    auto pos = t.rfind(':');
    if (pos == std::string::npos) return false;
    std::string host = t.substr(0, pos);
    std::string port = t.substr(pos + 1);
    if (host.find(':') != std::string::npos) {
        // Unbracketed IPv6 with port is ambiguous — reject.
        // Bare IPv6 without port also rejected above (no colon split).
        // Allow "::1:5555"? ambiguous; require brackets instead.
        // Exception: host part containing only hex/colons and ending in a
        // single numeric tail is still ambiguous — reject uniformly.
        return false;
    }
    return parse_addr_port(host, port, out);
}

std::vector<Endpoint> resolve_endpoint(const std::string& s) {
    Endpoint ep;
    if (parse_endpoint(s, ep)) return {ep};

    // DNS fallback: split host:port ourselves (bracketed IPv6 already
    // handled above; a hostname never contains ':').
    std::string t = trim(s);
    if (t.empty() || t.front() == '[') return {};
    auto pos = t.rfind(':');
    if (pos == std::string::npos) return {};
    std::string host = t.substr(0, pos);
    std::string port_s = t.substr(pos + 1);
    if (host.empty() || host.find(':') != std::string::npos) return {};
    char* end = nullptr;
    long p = std::strtol(port_s.c_str(), &end, 10);
    if (!end || *end != '\0' || p <= 0 || p > 65535) return {};

    asio::io_context ioc;
    asio::ip::udp::resolver resolver(ioc);
    asio::error_code ec;
    auto results = resolver.resolve(host, std::to_string(p), ec);
    if (ec) return {};
    std::vector<Endpoint> out;
    for (auto& r : results) {
        const auto& addr = r.endpoint().address();
        Endpoint e;
        e.family = addr.is_v4() ? Endpoint::Family::IPv4
                                : Endpoint::Family::IPv6;
        e.addr = addr.to_string();
        e.port = static_cast<uint16_t>(p);
        out.push_back(e);
    }
    return out;
}

bool endpoint_encode(const Endpoint& ep, std::vector<uint8_t>& out) {
    asio::ip::address a;
    asio::error_code ec;
    if (ep.family == Endpoint::Family::IPv4) {
        a = asio::ip::make_address(ep.addr, ec);
        if (ec || !a.is_v4()) return false;
    } else {
        a = asio::ip::make_address(ep.addr, ec);
        if (ec || !a.is_v6()) return false;
    }
    out.push_back(static_cast<uint8_t>(ep.family));
    out.push_back(static_cast<uint8_t>(a.is_v4() ? 4 : 16));
    if (a.is_v6()) {
        auto b6 = a.to_v6().to_bytes();
        out.insert(out.end(), b6.begin(), b6.end());
    } else {
        auto bytes = a.to_v4().to_bytes();
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    out.push_back(static_cast<uint8_t>(ep.port >> 8));
    out.push_back(static_cast<uint8_t>(ep.port & 0xff));
    return true;
}

bool endpoint_decode(const uint8_t*& p, size_t& left, Endpoint& out) {
    if (left < 2) return false;
    uint8_t fam = p[0];
    uint8_t len = p[1];
    if (fam != 4 && fam != 6) return false;
    if ((fam == 4 && len != 4) || (fam == 6 && len != 16)) return false;
    if (left < 2 + len + 2) return false;
    asio::ip::address a;
    if (fam == 4) {
        asio::ip::address_v4::bytes_type b{};
        std::memcpy(b.data(), p + 2, 4);
        a = asio::ip::address_v4(b);
    } else {
        asio::ip::address_v6::bytes_type b{};
        std::memcpy(b.data(), p + 2, 16);
        a = asio::ip::address_v6(b);
    }
    out.family = fam == 4 ? Endpoint::Family::IPv4 : Endpoint::Family::IPv6;
    out.addr = a.to_string();
    const uint8_t* portp = p + 2 + len;
    out.port = static_cast<uint16_t>((portp[0] << 8) | portp[1]);
    p += 2 + len + 2;
    left -= 2 + len + 2;
    return out.valid();
}

bool endpoint_is_public(const Endpoint& ep) {
    asio::error_code ec;
    auto a = asio::ip::make_address(ep.addr, ec);
    if (ec) return false;
    if (a.is_loopback() || a.is_multicast() || a.is_unspecified())
        return false;
    if (a.is_v4()) {
        auto b = a.to_v4().to_bytes();
        uint8_t b0 = b[0], b1 = b[1];
        bool priv = b0 == 10 || b0 == 127 ||
                    (b0 == 172 && b1 >= 16 && b1 <= 31) ||
                    (b0 == 192 && b1 == 168) ||
                    (b0 == 169 && b1 == 254) ||
                    (b0 == 100 && b1 >= 64 && b1 <= 127) || b0 >= 224;
        return !priv;
    }
    auto b = a.to_v6().to_bytes();
    // fe80::/10 link-local, fc00::/7 ULA, ff00::/8 multicast.
    if (b[0] == 0xfe && (b[1] & 0xc0) == 0x80) return false;
    if ((b[0] & 0xfe) == 0xfc) return false;
    if (b[0] == 0xff) return false;
    return true;
}

std::vector<Endpoint> local_endpoints(uint16_t port) {
    std::vector<Endpoint> out;
    if (port == 0) return out;
#ifndef _WIN32
    ifaddrs* ifas = nullptr;
    if (getifaddrs(&ifas) != 0) return out;
    for (ifaddrs* it = ifas; it; it = it->ifa_next) {
        if (!it->ifa_addr) continue;
        int fam = it->ifa_addr->sa_family;
        Endpoint ep;
        if (fam == AF_INET) {
            auto* sa = reinterpret_cast<sockaddr_in*>(it->ifa_addr);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
            ep.family = Endpoint::Family::IPv4;
            ep.addr = buf;
        } else if (fam == AF_INET6) {
            auto* sa = reinterpret_cast<sockaddr_in6*>(it->ifa_addr);
            char buf[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf));
            ep.family = Endpoint::Family::IPv6;
            ep.addr = buf;
        } else {
            continue;
        }
        // Skip loopback and link-local (not routable off-link).
        if (ep.addr == "127.0.0.1" || ep.addr == "::1") continue;
        if (ep.addr.rfind("fe80:", 0) == 0 ||
            ep.addr.rfind("169.254.", 0) == 0)
            continue;
        ep.port = port;
        out.push_back(ep);
    }
    freeifaddrs(ifas);
#else
    // Windows: enumerate via getaddrinfo on the hostname.
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        asio::io_context ioc;
        asio::ip::tcp::resolver resolver(ioc);
        asio::error_code ec;
        auto results = resolver.resolve(hostname, "", ec);
        if (ec) return out;
        for (auto& r : results) {
            Endpoint ep;
            const asio::ip::address addr = r.endpoint().address();
            if (addr.is_loopback() || addr.is_unspecified()) continue;
            ep.family = addr.is_v4() ? Endpoint::Family::IPv4
                                      : Endpoint::Family::IPv6;
            ep.addr = addr.to_string();
            ep.port = port;
            if (!ep.addr.empty()) out.push_back(ep);
        }
    }
#endif
    return out;
}
