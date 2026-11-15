// Precise device geolocation for Linux via GeoClue2
// (org.freedesktop.GeoClue2 on the system D-Bus).
//
// GeoClue2 is the freedesktop location service used by GNOME, KDE and
// most desktop environments; it fuses GPS, Wi-Fi and network positioning.
// If the service is missing, denies access, or no fix arrives within
// ~20 s, nullopt is returned and the caller falls back to IP-based
// geolocation.

#include "geo.h"

#if defined(__linux__)

#include <dbus/dbus.h>

#include <cstdarg>
#include <chrono>
#include <cstring>
#include <optional>

namespace {

struct LocResult {
    bool got = false;
    double lat = 0;
    double lon = 0;
    double acc = -1;
};

// Invoked by libdbus for every incoming message while dispatching.
// Watches for GeoClue2 Client.LocationUpdated and extracts lat/lon.
DBusHandlerResult loc_filter(DBusConnection*, DBusMessage* msg, void* data) {
    LocResult* r = static_cast<LocResult*>(data);
    if (r->got || dbus_message_get_type(msg) != DBUS_MESSAGE_TYPE_SIGNAL)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    const char* iface = dbus_message_get_interface(msg);
    const char* member = dbus_message_get_member(msg);
    if (!iface || !member ||
        std::strcmp(iface, "org.freedesktop.GeoClue2.Client") != 0 ||
        std::strcmp(member, "LocationUpdated") != 0)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    // LocationUpdated(a{sv} location): dict entries {string, variant}.
    DBusMessageIter args, dict, entry, field;
    if (!dbus_message_iter_init(msg, &args)) return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY)
        return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
    dbus_message_iter_recurse(&args, &dict);

    double lat = 0, lon = 0, acc = -1;
    bool have_lat = false, have_lon = false;
    while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
        dbus_message_iter_recurse(&dict, &entry);   // struct {sv}
        dbus_message_iter_recurse(&entry, &field);  // first field: key (s)
        const char* key = nullptr;
        if (dbus_message_iter_get_arg_type(&field) == DBUS_TYPE_STRING)
            dbus_message_iter_get_basic(&field, &key);
        // Advance to the variant value.
        DBusMessageIter next;
        if (!dbus_message_iter_next(&field, &next)) continue;
        if (dbus_message_iter_get_arg_type(&next) != DBUS_TYPE_VARIANT)
            continue;
        DBusMessageIter val;
        dbus_message_iter_recurse(&next, &val);
        if (dbus_message_iter_get_arg_type(&val) != DBUS_TYPE_DOUBLE || !key)
            continue;
        double d = 0;
        dbus_message_iter_get_basic(&val, &d);
        if (std::strcmp(key, "latitude") == 0) {
            lat = d;
            have_lat = true;
        } else if (std::strcmp(key, "longitude") == 0) {
            lon = d;
            have_lon = true;
        } else if (std::strcmp(key, "accuracy") == 0) {
            acc = d;
        }
    }
    if (have_lat && have_lon) {
        r->lat = lat;
        r->lon = lon;
        r->acc = acc;
        r->got = true;
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

// Send a method call and block for the reply (timeout_ms applies to the
// pending call). Returns a new reference to the reply, or nullptr.
DBusMessage* call_method(DBusConnection* conn, const char* dest,
                         const char* path, const char* iface,
                         const char* method, const char* sig,
                         int timeout_ms, ...) {
    DBusMessage* req = dbus_message_new_method_call(dest, path, iface, method);
    if (!req) return nullptr;
    if (sig) {
        va_list ap;
        va_start(ap, timeout_ms);
        if (!dbus_message_append_args_valist(req, sig, ap)) {
            va_end(ap);
            dbus_message_unref(req);
            return nullptr;
        }
        va_end(ap);
    }
    DBusPendingCall* pc = nullptr;
    if (!dbus_connection_send_with_reply(conn, req, &pc, timeout_ms) || !pc) {
        dbus_message_unref(req);
        return nullptr;
    }
    dbus_connection_flush(conn);
    dbus_pending_call_block(pc);
    DBusMessage* reply = dbus_pending_call_steal_reply(pc);
    dbus_pending_call_unref(pc);
    dbus_message_unref(req);
    return reply;
}

// Extract a single string/object-path argument from a reply.
bool reply_string(DBusMessage* reply, const char** out) {
    if (!reply || dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
        return false;
    DBusError err;
    dbus_error_init(&err);
    bool ok = dbus_message_get_args(reply, &err, DBUS_TYPE_OBJECT_PATH, out,
                                    DBUS_TYPE_INVALID);
    dbus_error_free(&err);
    return ok;
}

}  // namespace

std::optional<GeoFix> platform_location() {
    DBusError err;
    dbus_error_init(&err);
    // Shared system-bus connection; GeoClue2 lives there.
    DBusConnection* conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!conn) {
        dbus_error_free(&err);
        return std::nullopt;
    }

    LocResult res;
    dbus_connection_add_filter(conn, loc_filter, &res, nullptr);

    std::optional<GeoFix> result;
    do {
        // Manager.GetClient(desktop_id) -> client object path.
        DBusMessage* r =
            call_method(conn, "org.freedesktop.GeoClue2", "/org/freedesktop/GeoClue2/Manager",
                        "org.freedesktop.GeoClue2.Manager", "GetClient", "s", 5000,
                        "radius");
        const char* client_path = nullptr;
        bool have_client = reply_string(r, &client_path);
        if (r) dbus_message_unref(r);
        if (!have_client || !client_path) break;

        // Subscribe to LocationUpdated, then start the client.
        DBusMessage* m = call_method(conn, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                     "org.freedesktop.DBus", "AddMatch",
                                     "s", 3000,
                                     "type='signal',sender='org.freedesktop.GeoClue2',"
                                     "interface='org.freedesktop.GeoClue2.Client',"
                                     "member='LocationUpdated'");
        if (m) dbus_message_unref(m);

        DBusMessage* st = call_method(conn, "org.freedesktop.GeoClue2", client_path,
                                      "org.freedesktop.GeoClue2.Client", "Start",
                                      nullptr, 5000);
        if (!st || dbus_message_get_type(st) == DBUS_MESSAGE_TYPE_ERROR) {
            if (st) dbus_message_unref(st);
            break;
        }
        dbus_message_unref(st);

        // Pump the connection until the first fix or ~20 s elapse.
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(20);
        while (!res.got) {
            auto now = std::chrono::steady_clock::now();
            if (now >= deadline) break;
            int slice = static_cast<int>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - now)
                    .count());
            if (slice > 500) slice = 500;
            dbus_connection_read_write(conn, slice);
            while (dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS) {
            }
        }

        // Best effort cleanup: stop the client and drop the match.
        DBusMessage* sp = call_method(conn, "org.freedesktop.GeoClue2", client_path,
                                      "org.freedesktop.GeoClue2.Client", "Stop",
                                      nullptr, 1000);
        if (sp) dbus_message_unref(sp);
        DBusMessage* rm = call_method(conn, "org.freedesktop.DBus", "/org/freedesktop/DBus",
                                      "org.freedesktop.DBus", "RemoveMatch",
                                      "s", 1000,
                                      "type='signal',sender='org.freedesktop.GeoClue2',"
                                      "interface='org.freedesktop.GeoClue2.Client',"
                                      "member='LocationUpdated'");
        if (rm) dbus_message_unref(rm);
    } while (false);

    dbus_connection_remove_filter(conn, loc_filter, &res);
    dbus_connection_unref(conn);

    if (res.got) result = GeoFix{res.lat, res.lon, res.acc};
    return result;
}

#endif  // __linux__
