// macOS notification-sound output device backend (CoreAudio HAL).
// Kept in Objective-C++ so the CoreAudio/CoreFoundation headers stay
// out of main.cpp's namespace.

#include "audio.h"

#include <CoreAudio/CoreAudio.h>
#include <CoreFoundation/CoreFoundation.h>

namespace {

std::string cf_to_string(CFStringRef s) {
    if (!s) return "";
    char buf[512];
    if (CFStringGetCString(s, buf, sizeof(buf), kCFStringEncodingUTF8))
        return buf;
    return "";
}

std::string device_uid(AudioDeviceID dev) {
    AudioObjectPropertyAddress a = {
        kAudioDevicePropertyDeviceUID, kAudioObjectPropertyScopeGlobal,
        kAudioObjectPropertyElementMain};
    CFStringRef s = nullptr;
    UInt32 size = sizeof(s);
    if (AudioObjectGetPropertyData(dev, &a, 0, nullptr, &size, &s) !=
        noErr)
        return "";
    std::string r = cf_to_string(s);
    CFRelease(s);
    return r;
}

// kAudioHardwarePropertyDeviceForUID is unreliable on some macOS
// versions, so resolve the UID by scanning the device list instead.
AudioDeviceID device_id_for_uid(const std::string& uid) {
    AudioObjectPropertyAddress a = {
        kAudioHardwarePropertyDevices, kAudioObjectPropertyScopeGlobal,
        kAudioObjectPropertyElementMain};
    UInt32 size = 0;
    if (AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &a, 0,
                                       nullptr, &size) != noErr)
        return kAudioObjectUnknown;
    std::vector<AudioDeviceID> ids(size / sizeof(AudioDeviceID));
    if (AudioObjectGetPropertyData(kAudioObjectSystemObject, &a, 0,
                                   nullptr, &size, ids.data()) != noErr)
        return kAudioObjectUnknown;
    for (AudioDeviceID id : ids)
        if (device_uid(id) == uid) return id;
    return kAudioObjectUnknown;
}

}  // namespace

std::vector<AudioDevice> list_output_devices() {
    std::vector<AudioDevice> out;
    AudioObjectPropertyAddress a = {
        kAudioHardwarePropertyDevices, kAudioObjectPropertyScopeGlobal,
        kAudioObjectPropertyElementMain};
    UInt32 size = 0;
    if (AudioObjectGetPropertyDataSize(kAudioObjectSystemObject, &a, 0,
                                       nullptr, &size) != noErr)
        return out;
    std::vector<AudioDeviceID> ids(size / sizeof(AudioDeviceID));
    if (AudioObjectGetPropertyData(kAudioObjectSystemObject, &a, 0,
                                   nullptr, &size, ids.data()) != noErr)
        return out;
    for (AudioDeviceID id : ids) {
        // Keep only devices with output streams.
        AudioObjectPropertyAddress st = {
            kAudioDevicePropertyStreams, kAudioDevicePropertyScopeOutput,
            kAudioObjectPropertyElementMain};
        UInt32 ss = 0;
        if (AudioObjectGetPropertyDataSize(id, &st, 0, nullptr, &ss) !=
                noErr ||
            ss == 0)
            continue;
        AudioObjectPropertyAddress na = {
            kAudioDevicePropertyDeviceNameCFString,
            kAudioObjectPropertyScopeGlobal,
            kAudioObjectPropertyElementMain};
        CFStringRef name = nullptr;
        UInt32 ns = sizeof(name);
        AudioObjectGetPropertyData(id, &na, 0, nullptr, &ns, &name);
        std::string uid = device_uid(id);
        if (uid.empty()) {
            if (name) CFRelease(name);
            continue;
        }
        out.push_back({uid, cf_to_string(name)});
        if (name) CFRelease(name);
    }
    return out;
}

std::string default_output_device_id() {
    AudioObjectPropertyAddress a = {
        kAudioHardwarePropertyDefaultOutputDevice,
        kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMain};
    AudioDeviceID dev = kAudioObjectUnknown;
    UInt32 size = sizeof(dev);
    if (AudioObjectGetPropertyData(kAudioObjectSystemObject, &a, 0,
                                   nullptr, &size, &dev) != noErr)
        return "";
    return device_uid(dev);
}

bool set_default_output_device(const std::string& uid) {
    AudioDeviceID dev = device_id_for_uid(uid);
    if (dev == kAudioObjectUnknown) return false;
    AudioObjectPropertyAddress a = {
        kAudioHardwarePropertyDefaultOutputDevice,
        kAudioObjectPropertyScopeGlobal, kAudioObjectPropertyElementMain};
    return AudioObjectSetPropertyData(kAudioObjectSystemObject, &a, 0,
                                      nullptr, sizeof(dev),
                                      &dev) == noErr;
}
