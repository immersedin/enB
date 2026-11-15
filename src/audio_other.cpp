// Non-macOS notification-sound output device backend.
// Linux: PulseAudio/PipeWire sinks via pactl (sink name doubles as the
// paplay --device argument). Windows: no per-device routing.

#include "audio.h"

#include <cctype>
#include <cstdio>
#include <string>
#include <vector>

#if !defined(_WIN32)
namespace {

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(c));
    return s;
}

}  // namespace
#endif

std::vector<AudioDevice> list_output_devices() {
    std::vector<AudioDevice> out;
#if !defined(_WIN32)
    FILE* fp = popen("pactl list sinks", "r");
    if (fp) {
        std::string name, desc;
        char buf[512];
        auto flush = [&] {
            if (!name.empty()) out.push_back({name, desc});
            name.clear();
            desc.clear();
        };
        while (std::fgets(buf, sizeof(buf), fp)) {
            std::string line = buf;
            auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            std::string key = lower(line.substr(0, pos));
            std::string val = line.substr(pos + 1);
            auto b = val.find_first_not_of(" \t\r\n");
            val = b == std::string::npos ? "" : val.substr(b);
            if (!val.empty() && val.back() == '\n') val.pop_back();
            if (key.find("name") != std::string::npos)
                name = val;
            else if (key.find("description") != std::string::npos)
                desc = val;
        }
        flush();
        pclose(fp);
    }
#endif
    return out;
}

std::string default_output_device_id() { return ""; }

bool set_default_output_device(const std::string&) { return false; }
