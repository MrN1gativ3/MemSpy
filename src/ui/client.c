#include "client.h"

#include <errno.h>
#include <glib.h>
#include <json-c/json.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

struct ms_client {
    int descriptor;
    GThread *subscription_thread;
    void (*on_alert)(const struct ms_alert *, void *);
    void (*on_health)(const struct ms_health *, void *);
    void *userdata;
    gint stopping;
};

static bool decode_health(json_object *object, struct ms_health *health);

static void
set_error(struct ms_error *error, const char *code, const char *format, ...)
{
    va_list args;
    if (error == NULL)
        return;
    snprintf(error->code, sizeof error->code, "%s", code);
    va_start(args, format);
    vsnprintf(error->message, sizeof error->message, format, args);
    va_end(args);
}

static bool
write_line(int descriptor, const char *line)
{
    size_t left = strlen(line);
    while (left > 0) {
        ssize_t count = write(descriptor, line, left);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return false;
        line += count;
        left -= (size_t)count;
    }
    return write(descriptor, "\n", 1) == 1;
}

static json_object *
read_reply(int descriptor, struct ms_error *error)
{
    char *buffer = malloc(MS_MAX_MESSAGE_BYTES + 1U);
    size_t used = 0;
    json_object *reply;
    enum json_tokener_error parse_error;

    if (buffer == NULL)
        return NULL;
    while (used < MS_MAX_MESSAGE_BYTES) {
        ssize_t count = read(descriptor, buffer + used, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            set_error(error, "disconnected", "daemon disconnected");
            free(buffer);
            return NULL;
        }
        if (buffer[used++] == '\n')
            break;
    }
    if (used == MS_MAX_MESSAGE_BYTES && buffer[used - 1] != '\n') {
        set_error(error, "oversized_reply", "daemon reply is too large");
        free(buffer);
        return NULL;
    }
    buffer[used - 1] = '\0';
    reply = json_tokener_parse_verbose(buffer, &parse_error);
    free(buffer);
    if (parse_error != json_tokener_success || reply == NULL) {
        set_error(error, "malformed_reply", "daemon returned malformed JSON");
        return NULL;
    }
    return reply;
}

static bool
reply_ok(json_object *reply, struct ms_error *error)
{
    json_object *field;
    if (!json_object_object_get_ex(reply, "ok", &field) || !json_object_get_boolean(field)) {
        const char *code = "daemon_error";
        if (json_object_object_get_ex(reply, "error", &field))
            code = json_object_get_string(field);
        set_error(error, code, "daemon rejected request");
        return false;
    }
    return true;
}

bool
ms_client_connect_fd(int connected_fd, struct ms_client **out, struct ms_error *error)
{
    struct ms_client *client;
    json_object *reply;

    if (connected_fd < 0 || out == NULL)
        return false;
    client = calloc(1, sizeof *client);
    if (client == NULL) {
        set_error(error, "client_memory", "cannot allocate daemon client");
        close(connected_fd);
        return false;
    }
    client->descriptor = connected_fd;
    if (!write_line(client->descriptor, "{\"v\":2,\"op\":\"hello\"}")) {
        set_error(error, "connect_failed", "%s", strerror(errno));
        ms_client_close(client);
        return false;
    }
    reply = read_reply(client->descriptor, error);
    if (reply == NULL || !reply_ok(reply, error)) {
        if (reply != NULL)
            json_object_put(reply);
        ms_client_close(client);
        return false;
    }
    json_object_put(reply);
    *out = client;
    return true;
}

bool
ms_client_connect(const char *path, struct ms_client **out, struct ms_error *error)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    int descriptor;

    if (path == NULL || out == NULL || strlen(path) >= sizeof address.sun_path)
        return false;
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0)
        return false;
    snprintf(address.sun_path, sizeof address.sun_path, "%s", path);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof address) != 0) {
        set_error(error, "connect_failed", "%s", strerror(errno));
        close(descriptor);
        return false;
    }
    return ms_client_connect_fd(descriptor, out, error);
}

bool
ms_client_get_status(struct ms_client *client, struct ms_health *health, struct ms_error *error)
{
    json_object *reply;
    json_object *object;
    if (!write_line(client->descriptor, "{\"v\":2,\"op\":\"status\"}"))
        return false;
    reply = read_reply(client->descriptor, error);
    if (reply == NULL || !reply_ok(reply, error) ||
        !json_object_object_get_ex(reply, "health", &object) ||
        !decode_health(object, health)) {
        if (reply != NULL)
            json_object_put(reply);
        set_error(error, "malformed_reply", "daemon returned invalid health data");
        return false;
    }
    json_object_put(reply);
    return true;
}

static bool
decode_health(json_object *object, struct ms_health *health)
{
    json_object *field;
    int64_t value;
    if (object == NULL || health == NULL || json_object_get_type(object) != json_type_object)
        return false;
#define HEALTH_VALUE(name, member) do { \
    if (!json_object_object_get_ex(object, name, &field) || json_object_get_type(field) != json_type_int || \
        (value = json_object_get_int64(field)) < 0) return false; \
    health->member = (uint64_t)value; \
} while (0)
    if (!json_object_object_get_ex(object, "state", &field) ||
        json_object_get_type(field) != json_type_int ||
        json_object_get_int(field) < MS_HEALTH_HEALTHY ||
        json_object_get_int(field) > MS_HEALTH_FAILED)
        return false;
    health->state = (enum ms_health_state)json_object_get_int(field);
    HEALTH_VALUE("lost_events", lost_events);
    HEALTH_VALUE("map_pressure", map_pressure);
    HEALTH_VALUE("dropped_alerts", dropped_alerts);
    HEALTH_VALUE("blocked_execs", blocked_execs);
    HEALTH_VALUE("lost_block_events", lost_block_events);
    if (!json_object_object_get_ex(object, "protected", &field) ||
        json_object_get_type(field) != json_type_boolean) return false;
    health->protected = json_object_get_boolean(field);
    if (!json_object_object_get_ex(object, "storage_available", &field) ||
        json_object_get_type(field) != json_type_boolean) return false;
    health->storage_available = json_object_get_boolean(field);
    if (!json_object_object_get_ex(object, "response_supported", &field) ||
        json_object_get_type(field) != json_type_boolean) return false;
    health->response_supported = json_object_get_boolean(field);
    if (!json_object_object_get_ex(object, "response_requested", &field) ||
        json_object_get_type(field) != json_type_boolean) return false;
    health->response_requested = json_object_get_boolean(field);
    if (!json_object_object_get_ex(object, "response_active", &field) ||
        json_object_get_type(field) != json_type_boolean) return false;
    health->response_active = json_object_get_boolean(field);
    if (!json_object_object_get_ex(object, "response_reason", &field) ||
        json_object_get_type(field) != json_type_string ||
        json_object_get_string_len(field) >= (int)sizeof health->response_reason ||
        !g_utf8_validate(json_object_get_string(field), json_object_get_string_len(field), NULL))
        return false;
    g_strlcpy(health->response_reason, json_object_get_string(field),
              sizeof health->response_reason);
    if (!json_object_object_get_ex(object, "message", &field) ||
        json_object_get_type(field) != json_type_string ||
        json_object_get_string_len(field) >= (int)sizeof health->message ||
        !g_utf8_validate(json_object_get_string(field), json_object_get_string_len(field), NULL))
        return false;
    g_strlcpy(health->message, json_object_get_string(field), sizeof health->message);
#undef HEALTH_VALUE
    return true;
}

bool
ms_client_set_response(struct ms_client *client, bool enabled,
                       struct ms_health *confirmed, struct ms_error *error)
{
    const char *request = enabled ?
        "{\"v\":2,\"op\":\"set_response\",\"enabled\":true}" :
        "{\"v\":2,\"op\":\"set_response\",\"enabled\":false}";
    json_object *reply;
    json_object *health;

    if (client == NULL || confirmed == NULL || !write_line(client->descriptor, request))
        return false;
    reply = read_reply(client->descriptor, error);
    if (reply == NULL)
        return false;
    if (!reply_ok(reply, error)) {
        json_object_put(reply);
        return false;
    }
    if (!json_object_object_get_ex(reply, "health", &health) ||
        !decode_health(health, confirmed)) {
        set_error(error, "malformed_reply", "daemon returned invalid confirmed health data");
        json_object_put(reply);
        return false;
    }
    json_object_put(reply);
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

static gpointer
subscription_worker(gpointer data)
{
    struct ms_client *client = data;
    struct ms_error error = {0};
    json_object *message;

    while (!g_atomic_int_get(&client->stopping)) {
        struct pollfd descriptor = {.fd = client->descriptor, .events = POLLIN};
        int ready = poll(&descriptor, 1, 100);
        if (ready < 0 && errno == EINTR)
            continue;
        if (ready <= 0)
            continue;
        if (g_atomic_int_get(&client->stopping))
            break;
        message = read_reply(client->descriptor, &error);
        if (message == NULL)
            break;
        json_object *event;
        json_object *payload;
        if (!json_object_object_get_ex(message, "event", &event)) {
            json_object_put(message);
            continue;
        }
        if (strcmp(json_object_get_string(event), "alert") == 0 && client->on_alert != NULL &&
            json_object_object_get_ex(message, "alert", &payload)) {
            struct ms_alert alert = {0};
            if (ms_alert_from_json(payload, &alert, NULL))
                client->on_alert(&alert, client->userdata);
        } else if (strcmp(json_object_get_string(event), "health") == 0 && client->on_health != NULL &&
                   json_object_object_get_ex(message, "health", &payload)) {
            struct ms_health health = {0};
            if (decode_health(payload, &health))
                client->on_health(&health, client->userdata);
        }
        json_object_put(message);
    }
    return NULL;
}

bool
ms_client_list_alerts(struct ms_client *client, int64_t before_id, enum ms_severity minimum,
                      size_t limit, struct ms_alert_page *page, struct ms_error *error)
{
    char request[256];
    json_object *reply;
    json_object *items;
    json_object *field;
    size_t length;

    snprintf(request, sizeof request,
             "{\"v\":2,\"op\":\"alerts\",\"before_id\":%lld,\"minimum\":%d,\"limit\":%zu}",
             (long long)before_id, minimum, limit);
    if (!write_line(client->descriptor, request))
        return false;
    reply = read_reply(client->descriptor, error);
    if (reply == NULL || !reply_ok(reply, error) ||
        !json_object_object_get_ex(reply, "alerts", &items) ||
        json_object_get_type(items) != json_type_array) {
        if (reply != NULL)
            json_object_put(reply);
        return false;
    }
    length = json_object_array_length(items);
    if (length > 200) {
        set_error(error, "malformed_reply", "daemon returned too many alerts");
        json_object_put(reply);
        return false;
    }
    struct ms_alert_page result = {.items = calloc(length == 0 ? 1 : length, sizeof(struct ms_alert)), .length = length};
    if (result.items == NULL) {
        set_error(error, "client_memory", "cannot allocate alert history");
        json_object_put(reply);
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        if (!ms_alert_from_json(json_object_array_get_idx(items, index), &result.items[index], error)) {
            ms_alert_page_clear(&result);
            json_object_put(reply);
            return false;
        }
    }
    if (json_object_object_get_ex(reply, "next_before_id", &field))
        result.next_before_id = json_object_get_int64(field);
    ms_alert_page_clear(page);
    *page = result;
    json_object_put(reply);
    return true;
}

bool
ms_client_subscribe(struct ms_client *client,
                    void (*on_alert)(const struct ms_alert *, void *),
                    void (*on_health)(const struct ms_health *, void *),
                    void *userdata, struct ms_error *error)
{
    json_object *reply;
    if (client == NULL || client->subscription_thread != NULL ||
        !write_line(client->descriptor, "{\"v\":2,\"op\":\"subscribe\"}"))
        return false;
    reply = read_reply(client->descriptor, error);
    if (reply == NULL || !reply_ok(reply, error)) {
        if (reply != NULL)
            json_object_put(reply);
        return false;
    }
    json_object_put(reply);
    client->on_alert = on_alert;
    client->on_health = on_health;
    client->userdata = userdata;
    client->subscription_thread = g_thread_new("memspy-client-subscription", subscription_worker, client);
    return true;
}

void
ms_client_interrupt(struct ms_client *client)
{
    if (client == NULL)
        return;
    g_atomic_int_set(&client->stopping, true);
    shutdown(client->descriptor, SHUT_RDWR);
}

void
ms_client_wait(struct ms_client *client)
{
    if (client != NULL && client->subscription_thread != NULL) {
        g_thread_join(client->subscription_thread);
        client->subscription_thread = NULL;
    }
}

void
ms_client_close(struct ms_client *client)
{
    if (client == NULL)
        return;
    ms_client_interrupt(client);
    ms_client_wait(client);
    close(client->descriptor);
    free(client);
}
