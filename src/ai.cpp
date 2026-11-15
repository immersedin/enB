#include "ai.h"

#include <cstdio>
#include <cstdlib>
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

namespace ai {
namespace {

std::string own_pid() {
#ifdef _WIN32
    return std::to_string(GetCurrentProcessId());
#else
    return std::to_string(getpid());
#endif
}

// JSON string escaping for the request body.
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// Extract a JSON string value for `key` and unescape it.
bool json_string(const std::string& js, const std::string& key,
                 std::string& out) {
    std::string pat = "\"" + key + "\"";
    size_t p = js.find(pat);
    if (p == std::string::npos) return false;
    p = js.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    p = js.find('"', p + 1);
    if (p == std::string::npos) return false;
    ++p;
    std::string v;
    while (p < js.size()) {
        char c = js[p];
        if (c == '\\' && p + 1 < js.size()) {
            char n = js[p + 1];
            switch (n) {
                case 'n': v += '\n'; break;
                case 't': v += '\t'; break;
                case 'r': v += '\r'; break;
                case '"': v += '"'; break;
                case '\\': v += '\\'; break;
                case '/': v += '/'; break;
                case 'b': v += '\b'; break;
                case 'f': v += '\f'; break;
                default: v += n; break;
            }
            p += 2;
            continue;
        }
        if (c == '"') break;
        v += c;
        ++p;
    }
    out = v;
    return true;
}

// POST `body` to url via curl, return response body ("" on failure).
std::string curl_post(const std::string& url, const std::string& api_key,
                      const std::string& body, std::string* err) {
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
    fs::path bodyf = dir / ("p2p-ai-" + tag + ".json");
    fs::path outf = dir / ("p2p-ai-" + tag + ".out");
    fs::path errf = dir / ("p2p-ai-" + tag + ".err");
    fs::path codef = dir / ("p2p-ai-" + tag + ".code");
    {
        std::ofstream bf(bodyf, std::ios::trunc);
        bf << body;
        if (!bf) return fail("cannot write request body");
    }
    // No -f: we want the JSON error body even on HTTP failures.
    // %{http_code} goes to stdout -> codef.
    std::string cmd =
        std::string("curl -sS --connect-timeout 10 --max-time 60 -X POST ") +
        "\"" + url + "\" " +
        "-H \"Content-Type: application/json\" " +
        (api_key.empty()
             ? std::string()
             : "-H \"Authorization: Bearer " + api_key + "\" ") +
        "--data-binary @\"" + bodyf.string() + "\" " +
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
        fail((b == std::string::npos) ? "request failed"
                                      : e.substr(b, en - b + 1));
    } else if (code.empty() || code[0] != '2') {
        // Surface the API's own error message when present.
        std::string msg;
        if (json_string(resp, "message", msg) && !msg.empty())
            fail("API error " + code + ": " + msg);
        else
            fail("API error " + (code.empty() ? "?" : code));
        resp.clear();
    }
    std::error_code ec;
    fs::remove(bodyf, ec);
    fs::remove(outf, ec);
    fs::remove(errf, ec);
    fs::remove(codef, ec);
    return resp;
}

}  // namespace

std::string chat(const AiEndpoint& ep, const std::string& system,
                 const std::string& user, std::string* err) {
    std::string body =
        "{\"model\":\"" + json_escape(ep.model) + "\","
        "\"messages\":["
        "{\"role\":\"system\",\"content\":\"" +
        json_escape(system) + "\"},"
        "{\"role\":\"user\",\"content\":\"" + json_escape(user) + "\"}],"
        "\"temperature\":0.2,\"max_tokens\":400}";
    std::string resp = curl_post(ep.base_url, ep.api_key, body, err);
    if (resp.empty()) return "";
    // The first "content" string inside choices[0].message is the reply;
    // a top-level scan is safe enough for this payload shape.
    std::string content;
    if (!json_string(resp, "content", content)) {
        if (err) *err = "unexpected API response";
        return "";
    }
    return content;
}

std::string danger_assessment(const AiEndpoint& ep,
                              const std::string& prompt,
                              std::string* err) {
    return chat(ep, kDangerSystemPrompt, prompt, err);
}

}  // namespace ai
