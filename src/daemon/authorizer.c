#include "authorizer.h"

#include <gio/gio.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define MS_POLKIT_ACTION "org.memspy.response.configure"
#define MS_POLKIT_TIMEOUT_MS 120000

struct ms_authorizer {
    GDBusConnection *system_bus;
};

static void
set_error(struct ms_error *error, const char *code, const char *format, ...)
{
    va_list args;
    if (error == NULL)
        return;
    g_strlcpy(error->code, code, sizeof error->code);
    va_start(args, format);
    g_vsnprintf(error->message, sizeof error->message, format, args);
    va_end(args);
}

static bool
read_start_time(pid_t pid, uint64_t *start_time)
{
    g_autofree char *path = g_strdup_printf("/proc/%ld/stat", (long)pid);
    g_autofree char *contents = NULL;
    char *cursor;
    char *save = NULL;
    unsigned int field = 3;

    if (!g_file_get_contents(path, &contents, NULL, NULL))
        return false;
    cursor = strrchr(contents, ')');
    if (cursor == NULL || cursor[1] != ' ')
        return false;
    cursor += 2;
    for (char *token = strtok_r(cursor, " ", &save); token != NULL;
         token = strtok_r(NULL, " ", &save), ++field) {
        if (field == 22) {
            *start_time = g_ascii_strtoull(token, NULL, 10);
            return *start_time != 0;
        }
    }
    return false;
}

bool
ms_peer_identity_read(pid_t pid, uid_t uid, struct ms_peer_identity *identity,
                      struct ms_error *error)
{
    uint64_t start_time;

    if (pid <= 0 || identity == NULL || !read_start_time(pid, &start_time)) {
        set_error(error, "peer_identity", "cannot capture API peer identity");
        return false;
    }
    *identity = (struct ms_peer_identity){
        .pid = pid,
        .uid = uid,
        .start_time = start_time,
    };
    return true;
}

struct ms_authorizer *
ms_authorizer_new(void)
{
    struct ms_authorizer *authorizer = g_new0(struct ms_authorizer, 1);
    authorizer->system_bus = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, NULL);
    return authorizer;
}

static void
map_bus_error(const GError *bus_error, struct ms_error *error)
{
    g_warning("PolicyKit authorization request failed: %s",
              bus_error == NULL ? "unknown D-Bus error" : bus_error->message);
    if (g_error_matches(bus_error, G_IO_ERROR, G_IO_ERROR_TIMED_OUT) ||
        g_error_matches(bus_error, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY) ||
        g_error_matches(bus_error, G_DBUS_ERROR, G_DBUS_ERROR_TIMEOUT) ||
        g_error_matches(bus_error, G_DBUS_ERROR, G_DBUS_ERROR_TIMED_OUT))
        set_error(error, "authorization_timeout", "administrator authorization timed out");
    else if (g_error_matches(bus_error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        set_error(error, "authorization_cancelled", "administrator authorization was cancelled");
    else
        set_error(error, "authorization_unavailable", "administrator authorization is unavailable");
}

bool
ms_authorizer_check(struct ms_authorizer *authorizer,
                    const struct ms_peer_identity *peer, struct ms_error *error)
{
    GVariantBuilder subject_details;
    GVariantBuilder request_details;
    g_autoptr(GVariant) reply = NULL;
    g_autoptr(GVariant) result_details = NULL;
    g_autoptr(GError) bus_error = NULL;
    uint64_t current_start;
    gboolean authorized;
    gboolean challenge;
    const char *dismissed = NULL;

    if (authorizer == NULL || peer == NULL) {
        set_error(error, "authorization_unavailable", "PolicyKit system service is unavailable");
        return false;
    }
    if (!read_start_time(peer->pid, &current_start) || current_start != peer->start_time) {
        set_error(error, "authorization_stale_peer", "API peer identity changed");
        return false;
    }
    if (authorizer->system_bus == NULL) {
        set_error(error, "authorization_unavailable", "PolicyKit system service is unavailable");
        return false;
    }
    g_variant_builder_init(&subject_details, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&subject_details, "{sv}", "pid", g_variant_new_uint32(peer->pid));
    g_variant_builder_add(&subject_details, "{sv}", "start-time",
                          g_variant_new_uint64(peer->start_time));
    g_variant_builder_add(&subject_details, "{sv}", "uid", g_variant_new_int32(peer->uid));
    g_variant_builder_init(&request_details, G_VARIANT_TYPE("a{ss}"));
    reply = g_dbus_connection_call_sync(
        authorizer->system_bus,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
        "CheckAuthorization",
        g_variant_new("((sa{sv})sa{ss}us)", "unix-process", &subject_details,
                      MS_POLKIT_ACTION, &request_details, 1U, ""),
        G_VARIANT_TYPE("(bba{ss})"),
        G_DBUS_CALL_FLAGS_NONE,
        MS_POLKIT_TIMEOUT_MS,
        NULL,
        &bus_error);
    if (reply == NULL) {
        map_bus_error(bus_error, error);
        return false;
    }
    g_variant_get(reply, "(bb@a{ss})", &authorized, &challenge, &result_details);
    if (g_variant_lookup(result_details, "polkit.dismissed", "&s", &dismissed) &&
        g_strcmp0(dismissed, "true") == 0) {
        set_error(error, "authorization_cancelled", "administrator authorization was cancelled");
        return false;
    }
    if (!authorized) {
        set_error(error, "authorization_denied",
                  challenge ? "administrator authorization was not completed" :
                              "administrator authorization was denied");
        return false;
    }
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

void
ms_authorizer_free(struct ms_authorizer *authorizer)
{
    if (authorizer == NULL)
        return;
    g_clear_object(&authorizer->system_bus);
    g_free(authorizer);
}
