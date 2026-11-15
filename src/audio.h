#pragma once

#include <string>
#include <vector>

// Output device the notification sound can be routed to.
struct AudioDevice {
    std::string id;    // stable id (CoreAudio UID / PulseAudio sink)
    std::string name;  // human-readable label
};

// Output devices available for notification playback. Empty when the
// platform has no per-device routing (e.g. Windows).
std::vector<AudioDevice> list_output_devices();

// UID/id of the current system default output device ("" if unknown).
std::string default_output_device_id();

// Switch the system default output device; returns false on failure.
bool set_default_output_device(const std::string& uid);

// Human-readable label for a stored device id.
inline std::string output_device_label(const std::string& id) {
    if (id.empty()) return "system default";
    for (auto& d : list_output_devices())
        if (d.id == id) return d.name.empty() ? d.id : d.name;
    return id;
}
