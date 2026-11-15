#include "news.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#else
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace fs = std::filesystem;

namespace news {
namespace {

std::string own_pid() {
#ifdef _WIN32
    return std::to_string(GetCurrentProcessId());
#else
    return std::to_string(getpid());
#endif
}

// Percent-encode a URL query value (' ' becomes '+').
std::string url_encode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else if (c == ' ') {
            out += '+';
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 15];
        }
    }
    return out;
}

// GET `url` via curl, return the body ("" on failure).
std::string curl_get(const std::string& url, std::string* err) {
    auto fail = [&](const std::string& m) {
        if (err) *err = m;
        return std::string();
    };
    fs::path dir;
    try {
        dir = fs::temp_directory_path();
    } catch (...) {
        return fail("no temp dir");
    }
    std::string tag = own_pid();
    fs::path outf = dir / ("p2p-news-" + tag + ".out");
    fs::path errf = dir / ("p2p-news-" + tag + ".err");
    fs::path codef = dir / ("p2p-news-" + tag + ".code");
    // -L follows redirects; a browser UA avoids some bot filtering.
    std::string cmd =
        std::string("curl -sS -L --connect-timeout 8 --max-time 20 ") +
        "-A \"Mozilla/5.0 (p2p-chat)\" \"" + url + "\" " +
        "-o \"" + outf.string() + "\" " +
        "-w \"%{http_code}\" >\"" + codef.string() + "\" " +
        "2>\"" + errf.string() + "\"";
    int rc = std::system(cmd.c_str());
    std::string code;
    {
        std::ifstream cf(codef);
        cf >> code;
    }
    std::string resp;
    {
        std::ifstream f(outf, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        resp = ss.str();
    }
    if (rc != 0) {
        std::ifstream ef(errf);
        std::stringstream ss;
        ss << ef.rdbuf();
        std::string e = ss.str();
        auto b = e.find_first_not_of(" \t\r\n");
        auto en = e.find_last_not_of(" \t\r\n");
        return fail((b == std::string::npos) ? "news fetch failed"
                                            : e.substr(b, en - b + 1));
    }
    if (code.empty() || code[0] != '2')
        return fail("news fetch failed (HTTP " +
                    (code.empty() ? std::string("?") : code) + ")");
    std::error_code ec;
    fs::remove(outf, ec);
    fs::remove(errf, ec);
    fs::remove(codef, ec);
    return resp;
}

std::string trim(const std::string& s) {
    auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return "";
    auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

void append_utf8(std::string& out, unsigned long cp) {
    if (cp < 0x80) {
        out += static_cast<char>(cp);
    } else if (cp < 0x800) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// Decode XML/HTML entities: named ones plus &#NN; / &#xHH;.
std::string xml_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') {
            out += s[i];
            continue;
        }
        size_t semi = s.find(';', i + 1);
        if (semi == std::string::npos || semi - i > 10) {
            out += s[i];
            continue;
        }
        std::string ent = s.substr(i + 1, semi - i - 1);
        if (ent == "amp") out += '&';
        else if (ent == "lt") out += '<';
        else if (ent == "gt") out += '>';
        else if (ent == "quot") out += '"';
        else if (ent == "apos") out += '\'';
        else if (ent == "nbsp") out += ' ';
        else if (ent.size() > 1 && ent[0] == '#') {
            char* end = nullptr;
            unsigned long cp = std::strtoul(
                ent.c_str() + 1 + (ent[1] == 'x' || ent[1] == 'X' ? 1 : 0),
                &end, ent[1] == 'x' || ent[1] == 'X' ? 16 : 10);
            if (end && *end == '\0' && cp > 0 && cp < 0x110000)
                append_utf8(out, cp);
            else
                out += s.substr(i, semi - i + 1);
        } else {
            out += s.substr(i, semi - i + 1);
        }
        i = semi;
    }
    return out;
}

// Drop residual markup like <b>..</b> or <a href=..>text</a>.
std::string strip_tags(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    bool in_tag = false;
    for (char c : s) {
        if (c == '<') in_tag = true;
        else if (c == '>') in_tag = false;
        else if (!in_tag) out += c;
    }
    return out;
}

// Extract the text of the first <name ..>...</name> element inside
// `blk`, unwrapping CDATA and decoding entities.
bool xml_tag(const std::string& blk, const std::string& name,
             std::string& out) {
    std::string open = "<" + name;
    size_t p = blk.find(open);
    if (p == std::string::npos) return false;
    // The match must be a real tag open, not a prefix of a longer name.
    char c = p + open.size() < blk.size() ? blk[p + open.size()] : '\0';
    if (c != '>' && c != ' ' && c != '\t' && c != '\n' && c != '\r' &&
        c != '/')
        return false;
    size_t gt = blk.find('>', p);
    if (gt == std::string::npos) return false;
    size_t e = blk.find("</" + name, gt);
    if (e == std::string::npos) return false;
    std::string raw = trim(blk.substr(gt + 1, e - gt - 1));
    const std::string cd = "<![CDATA[";
    if (raw.rfind(cd, 0) == 0) {
        size_t close = raw.rfind("]]>");
        if (close != std::string::npos)
            raw = raw.substr(cd.size(), close - cd.size());
    }
    out = trim(xml_unescape(strip_tags(raw)));
    return !out.empty();
}

}  // namespace

std::vector<Item> google_news(const std::string& query, int max_items,
                              std::string* err) {
    std::vector<Item> out;
    if (max_items <= 0 || query.empty()) return out;
    std::string url = "https://news.google.com/rss/search?q=" +
                      url_encode(query) +
                      "&hl=en-US&gl=US&ceid=US:en";
    std::string body = curl_get(url, err);
    if (body.empty()) return out;
    size_t pos = 0;
    while ((pos = body.find("<item>", pos)) != std::string::npos) {
        size_t end = body.find("</item>", pos);
        if (end == std::string::npos) break;
        std::string blk = body.substr(pos, end - pos);
        Item it;
        xml_tag(blk, "title", it.title);
        xml_tag(blk, "pubDate", it.published);
        xml_tag(blk, "source", it.source);
        // Google News titles end with " - <Source>"; the outlet is
        // captured separately, so drop the duplicate suffix.
        if (!it.source.empty() && !it.title.empty()) {
            std::string suf = " - " + it.source;
            if (it.title.size() > suf.size() &&
                it.title.compare(it.title.size() - suf.size(),
                                 suf.size(), suf) == 0)
                it.title.resize(it.title.size() - suf.size());
        }
        if (!it.title.empty()) out.push_back(std::move(it));
        if (static_cast<int>(out.size()) >= max_items) break;
        pos = end + 7;
    }
    if (out.empty() && err) *err = "no news items in feed";
    return out;
}

}  // namespace news
