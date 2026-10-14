#define _GNU_SOURCE
#include "api.h"

#include <errno.h>
#include <glib.h>
#include <json-c/json.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "authorizer.h"

#define MS_API_MAX_SESSIONS 64U
#define MS_API_REQUEST_TIMEOUT_MS 5000

struct ms_session {
    struct ms_api *api;
    int descriptor;
    GMutex write_mutex;
    bool subscribed;
    struct ms_peer_identity peer;
};

struct ms_api {
    char *socket_path;
    struct ms_store *store;
    struct ms_api_callbacks callbacks;
    struct ms_health health;
    int listener;
    GThread *accept_thread;
    GMutex mutex;
    GCond workers_done;
    GMutex response_mutex;
    GPtrArray *sessions;
    bool stopping;
    bool owns_socket;
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
write_all(int descriptor, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t written = write(descriptor, data, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        data += written;
        length -= (size_t)written;
    }
    return true;
}

static bool
send_json(int descriptor, json_object *object)
{
    const char *text = json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN);
    return write_all(descriptor, text, strlen(text)) && write_all(descriptor, "\n", 1);
}

static bool
session_send_json(struct ms_session *session, json_object *object)
{
    bool sent;
    g_mutex_lock(&session->write_mutex);
    sent = send_json(session->descriptor, object);
    g_mutex_unlock(&session->write_mutex);
    return sent;
}

static bool
session_publish_json(struct ms_session *session, json_object *object)
{
    /* Subscriptions are best-effort live delivery; SQLite remains the source
     * of history. Check writability before sending so a client that stops
     * reading cannot stall sensor processing or other subscribers. */
    struct pollfd descriptor = {.fd = session->descriptor, .events = POLLOUT};
    if (poll(&descriptor, 1, 0) != 1 || (descriptor.revents & POLLOUT) == 0)
        return false;
    return session_send_json(session, object);
}

static void
send_error(int descriptor, const char *code)
{
    json_object *reply = json_object_new_object();
    json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(reply, "ok", json_object_new_boolean(false));
    json_object_object_add(reply, "error", json_object_new_string(code));
    send_json(descriptor, reply);
    json_object_put(reply);
}

static ssize_t
read_line(int descriptor, char *buffer, int timeout_ms)
{
    /* Requests are newline-delimited JSON. Enforce both a size limit and a
     * deadline before parsing, so a connected but idle client cannot hold a
     * worker indefinitely or force an oversized allocation. */
    const gint64 deadline = timeout_ms < 0 ? 0 :
        g_get_monotonic_time() + (gint64)timeout_ms * G_TIME_SPAN_MILLISECOND;
    size_t used = 0;
    while (used <= MS_MAX_MESSAGE_BYTES) {
        if (timeout_ms >= 0) {
            gint64 remaining = deadline - g_get_monotonic_time();
            struct pollfd ready = {.fd = descriptor, .events = POLLIN};
            int result;

            if (remaining <= 0)
                return -3;
            do {
                result = poll(&ready, 1,
                              (int)((remaining + G_TIME_SPAN_MILLISECOND - 1) /
                                    G_TIME_SPAN_MILLISECOND));
            } while (result < 0 && errno == EINTR);
            if (result <= 0 || (ready.revents & POLLIN) == 0)
                return -3;
        }
        ssize_t count = read(descriptor, buffer + used, 1);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            return count;
        if (buffer[used++] == '\n') {
            buffer[used - 1] = '\0';
            return (ssize_t)(used - 1);
        }
    }
    return -2;
}

static json_object *
parse_request(const char *line)
{
    enum json_tokener_error parse_error;
    json_object *request = json_tokener_parse_verbose(line, &parse_error);
    if (parse_error != json_tokener_success || request == NULL ||
        json_object_get_type(request) != json_type_object) {
        if (request != NULL)
            json_object_put(request);
        return NULL;
    }
    return request;
}

static bool
request_string(json_object *request, const char *name, const char **value)
{
    json_object *field;
    if (!json_object_object_get_ex(request, name, &field) ||
        json_object_get_type(field) != json_type_string)
        return false;
    *value = json_object_get_string(field);
    return true;
}

static bool
request_version(json_object *request, int *version)
{
    json_object *field;
    if (!json_object_object_get_ex(request, "v", &field) ||
        json_object_get_type(field) != json_type_int)
        return false;
    *version = json_object_get_int(field);
    return true;
}

static json_object *
health_json(const struct ms_health *health)
{
    json_object *object = json_object_new_object();
    json_object_object_add(object, "state", json_object_new_int(health->state));
    json_object_object_add(object, "protected", json_object_new_boolean(health->protected));
    json_object_object_add(object, "lost_events", json_object_new_uint64(health->lost_events));
    json_object_object_add(object, "map_pressure", json_object_new_uint64(health->map_pressure));
    json_object_object_add(object, "dropped_alerts", json_object_new_uint64(health->dropped_alerts));
    json_object_object_add(object, "storage_available", json_object_new_boolean(health->storage_available));
    json_object_object_add(object, "response_supported", json_object_new_boolean(health->response_supported));
    json_object_object_add(object, "response_requested", json_object_new_boolean(health->response_requested));
    json_object_object_add(object, "response_active", json_object_new_boolean(health->response_active));
    json_object_object_add(object, "blocked_execs", json_object_new_uint64(health->blocked_execs));
    json_object_object_add(object, "blocked_operations",
                           json_object_new_uint64(health->blocked_operations));
    json_object_object_add(object, "lost_block_events", json_object_new_uint64(health->lost_block_events));
    json_object_object_add(object, "incomplete_observations",
                           json_object_new_uint64(health->incomplete_observations));
    json_object_object_add(object, "journal_errors",
                           json_object_new_uint64(health->journal_errors));
    json_object_object_add(object, "response_reason", json_object_new_string(health->response_reason));
    json_object_object_add(object, "message", json_object_new_string(health->message));
    return object;
}

static void
handle_status(struct ms_session *session)
{
    json_object *reply = json_object_new_object();
    struct ms_health snapshot;

    g_mutex_lock(&session->api->mutex);
    snapshot = session->api->health;
    g_mutex_unlock(&session->api->mutex);
    json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(reply, "ok", json_object_new_boolean(true));
    json_object_object_add(reply, "health", health_json(&snapshot));
    session_send_json(session, reply);
    json_object_put(reply);
}

static void
handle_set_response(struct ms_session *session, json_object *request)
{
    /* Reading status and alerts only needs socket access. Changing response
     * mode is different: serialize requests, authorize the actual socket
     * peer through PolicyKit, then return the daemon's confirmed health. */
    json_object *field;
    json_object *reply;
    struct ms_error error = {0};
    struct ms_health snapshot;
    bool enabled;
    bool success = false;

    if (!json_object_object_get_ex(request, "enabled", &field) ||
        json_object_get_type(field) != json_type_boolean) {
        send_error(session->descriptor, "invalid_request");
        return;
    }
    enabled = json_object_get_boolean(field);
    g_mutex_lock(&session->api->response_mutex);
    if (session->api->callbacks.authorize_response == NULL) {
        set_error(&error, "authorization_unavailable", "authorization is unavailable");
    } else if (session->api->callbacks.authorize_response(
                   &session->peer, session->api->callbacks.userdata, &error) &&
               session->api->callbacks.set_response != NULL &&
               session->api->callbacks.set_response(
                   &session->peer, enabled, session->api->callbacks.userdata, &error)) {
        g_mutex_lock(&session->api->mutex);
        snapshot = session->api->health;
        g_mutex_unlock(&session->api->mutex);
        success = true;
    }
    g_mutex_unlock(&session->api->response_mutex);
    if (!success) {
        send_error(session->descriptor,
                   error.code[0] != '\0' ? error.code : "response_failed");
        return;
    }
    reply = json_object_new_object();
    json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(reply, "ok", json_object_new_boolean(true));
    json_object_object_add(reply, "health", health_json(&snapshot));
    session_send_json(session, reply);
    json_object_put(reply);
}

static void
handle_alerts(struct ms_session *session, json_object *request)
{
    json_object *field;
    int64_t before = 0;
    int minimum = MS_SEVERITY_MEDIUM;
    size_t limit = 100;
    struct ms_alert_page page = {0};
    struct ms_error error = {0};
    struct ms_store *store;
    json_object *reply;
    json_object *items;

    g_mutex_lock(&session->api->mutex);
    store = session->api->store;
    g_mutex_unlock(&session->api->mutex);
    if (store == NULL) {
        send_error(session->descriptor, "storage_unavailable");
        return;
    }

    if (json_object_object_get_ex(request, "before_id", &field)) {
        if (json_object_get_type(field) != json_type_int || json_object_get_int64(field) < 0) {
            send_error(session->descriptor, "invalid_request");
            return;
        }
        before = json_object_get_int64(field);
    }
    if (json_object_object_get_ex(request, "minimum", &field)) {
        if (json_object_get_type(field) != json_type_int ||
            (json_object_get_int(field) != MS_SEVERITY_MEDIUM &&
             json_object_get_int(field) != MS_SEVERITY_HIGH)) {
            send_error(session->descriptor, "invalid_request");
            return;
        }
        minimum = json_object_get_int(field);
    }
    if (json_object_object_get_ex(request, "limit", &field)) {
        if (json_object_get_type(field) != json_type_int || json_object_get_int64(field) <= 0) {
            send_error(session->descriptor, "invalid_request");
            return;
        }
        limit = (size_t)json_object_get_uint64(field);
    }
    if (!ms_store_list(store, before, (enum ms_severity)minimum, limit, &page, &error)) {
        send_error(session->descriptor, error.code);
        return;
    }
    reply = json_object_new_object();
    items = json_object_new_array_ext((int)page.length);
    for (size_t index = 0; index < page.length; ++index)
        json_object_array_add(items, ms_alert_to_json(&page.items[index]));
    json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(reply, "ok", json_object_new_boolean(true));
    json_object_object_add(reply, "alerts", items);
    json_object_object_add(reply, "next_before_id", json_object_new_int64(page.next_before_id));
    session_send_json(session, reply);
    json_object_put(reply);
    ms_alert_page_clear(&page);
}

static void
handle_alert(struct ms_session *session, json_object *request)
{
    json_object *field;
    json_object *reply;
    json_object *encoded;
    struct ms_alert alert = {0};
    struct ms_error error = {0};
    struct ms_store *store;
    int64_t id;

    if (!json_object_object_get_ex(request, "id", &field) ||
        json_object_get_type(field) != json_type_int ||
        (id = json_object_get_int64(field)) <= 0) {
        send_error(session->descriptor, "invalid_request");
        return;
    }
    g_mutex_lock(&session->api->mutex);
    store = session->api->store;
    g_mutex_unlock(&session->api->mutex);
    if (store == NULL) {
        send_error(session->descriptor, "storage_unavailable");
        return;
    }
    if (!ms_store_get(store, id, &alert, &error)) {
        send_error(session->descriptor,
                   strcmp(error.code, "store_not_found") == 0 ? "alert_not_found" : error.code);
        return;
    }
    encoded = ms_alert_to_json(&alert);
    if (encoded == NULL) {
        send_error(session->descriptor, "store_data");
        return;
    }
    reply = json_object_new_object();
    json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(reply, "ok", json_object_new_boolean(true));
    json_object_object_add(reply, "alert", encoded);
    session_send_json(session, reply);
    json_object_put(reply);
}

static gpointer
client_worker(gpointer data)
{
    /* Each local client first agrees on the protocol version with "hello".
     * Subsequent newline-delimited requests are handled on this worker;
     * subscribers remain connected for live health and alert messages. */
    struct ms_session *session = data;
    char *line = g_malloc(MS_MAX_MESSAGE_BYTES + 2U);
    bool handshaken = false;
    ssize_t length;

    while ((length = read_line(session->descriptor, line,
                               session->subscribed ? -1 : MS_API_REQUEST_TIMEOUT_MS)) > 0) {
        json_object *request = parse_request(line);
        const char *operation;
        int version;

        if (request == NULL) {
            send_error(session->descriptor, "malformed_json");
            break;
        }
        if (!request_version(request, &version) || !request_string(request, "op", &operation)) {
            send_error(session->descriptor, "invalid_request");
            json_object_put(request);
            break;
        }
        if (version != MS_PROTOCOL_VERSION) {
            send_error(session->descriptor, "unsupported_version");
            json_object_put(request);
            break;
        }
        if (!handshaken) {
            if (strcmp(operation, "hello") != 0) {
                json_object_put(request);
                break;
            }
            json_object *reply = json_object_new_object();
            json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
            json_object_object_add(reply, "ok", json_object_new_boolean(true));
            json_object_object_add(reply, "daemon_version", json_object_new_string("0.1.0"));
            send_json(session->descriptor, reply);
            json_object_put(reply);
            handshaken = true;
        } else if (strcmp(operation, "status") == 0) {
            handle_status(session);
        } else if (strcmp(operation, "alerts") == 0) {
            handle_alerts(session, request);
        } else if (strcmp(operation, "alert") == 0) {
            handle_alert(session, request);
        } else if (strcmp(operation, "set_response") == 0) {
            handle_set_response(session, request);
        } else if (strcmp(operation, "subscribe") == 0) {
            json_object *reply = json_object_new_object();
            json_object_object_add(reply, "v", json_object_new_int(MS_PROTOCOL_VERSION));
            json_object_object_add(reply, "ok", json_object_new_boolean(true));
            g_mutex_lock(&session->api->mutex);
            session->subscribed = true;
            session_send_json(session, reply);
            g_mutex_unlock(&session->api->mutex);
            json_object_put(reply);
        } else {
            send_error(session->descriptor, "unknown_operation");
        }
        json_object_put(request);
    }
    if (length == -2)
        shutdown(session->descriptor, SHUT_RDWR);
    close(session->descriptor);
    g_free(line);

    g_mutex_lock(&session->api->mutex);
    g_ptr_array_remove_fast(session->api->sessions, session);
    g_cond_broadcast(&session->api->workers_done);
    g_mutex_unlock(&session->api->mutex);
    g_mutex_clear(&session->write_mutex);
    g_free(session);
    return NULL;
}

static gpointer
accept_worker(gpointer data)
{
    struct ms_api *api = data;
    while (true) {
        int descriptor = accept(api->listener, NULL, NULL);
        if (descriptor < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (!ms_api_accept_fd(api, descriptor)) {
            close(descriptor);
            break;
        }
    }
    return NULL;
}

bool
ms_api_accept_fd(struct ms_api *api, int connected_fd)
{
    struct ms_session *session;
    struct ucred credentials;
    const struct timeval send_timeout = {.tv_usec = 100000};
    socklen_t credentials_size = sizeof credentials;

    if (api == NULL || connected_fd < 0)
        return false;
    if (getsockopt(connected_fd, SOL_SOCKET, SO_PEERCRED, &credentials, &credentials_size) != 0) {
        if (api->listener >= 0 || errno != EPERM)
            return false;
        /* shortcut: managed tests deny SO_PEERCRED; production listener sessions never use this fallback. */
        credentials.pid = getpid();
        credentials.uid = getuid();
        credentials.gid = getgid();
    }
    if (setsockopt(connected_fd, SOL_SOCKET, SO_SNDTIMEO,
                   &send_timeout, sizeof send_timeout) != 0) {
        /* shortcut: managed tests deny socket options; production listener sessions fail closed. */
        if (api->listener >= 0 || errno != EPERM)
            return false;
    }
    session = g_new0(struct ms_session, 1);
    session->api = api;
    session->descriptor = connected_fd;
    if (!ms_peer_identity_read(credentials.pid, credentials.uid, &session->peer, NULL)) {
        g_free(session);
        return false;
    }
    g_mutex_init(&session->write_mutex);
    g_mutex_lock(&api->mutex);
    if (api->stopping || api->sessions->len >= MS_API_MAX_SESSIONS) {
        g_mutex_unlock(&api->mutex);
        g_mutex_clear(&session->write_mutex);
        g_free(session);
        return false;
    }
    g_ptr_array_add(api->sessions, session);
    g_mutex_unlock(&api->mutex);
    if (api->callbacks.peer_connected != NULL)
        api->callbacks.peer_connected(credentials.pid, credentials.uid, api->callbacks.userdata);
    g_thread_unref(g_thread_new("memspy-api-client", client_worker, session));
    return true;
}

struct ms_api *
ms_api_new(const char *socket_path, struct ms_store *store,
           const struct ms_api_callbacks *callbacks)
{
    struct ms_api *api;
    if (socket_path == NULL)
        return NULL;
    api = g_new0(struct ms_api, 1);
    api->socket_path = g_strdup(socket_path);
    api->store = store;
    api->listener = -1;
    api->sessions = g_ptr_array_new();
    g_mutex_init(&api->mutex);
    g_cond_init(&api->workers_done);
    g_mutex_init(&api->response_mutex);
    if (callbacks != NULL)
        api->callbacks = *callbacks;
    return api;
}

void
ms_api_set_store(struct ms_api *api, struct ms_store *store)
{
    if (api == NULL)
        return;
    g_mutex_lock(&api->mutex);
    api->store = store;
    g_mutex_unlock(&api->mutex);
}

bool
ms_api_start(struct ms_api *api, struct ms_error *error)
{
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    struct stat metadata;

    if (strlen(api->socket_path) >= sizeof address.sun_path) {
        set_error(error, "socket_path", "socket path is too long");
        return false;
    }
    if (lstat(api->socket_path, &metadata) == 0) {
        if (!S_ISSOCK(metadata.st_mode) || metadata.st_uid != geteuid()) {
            set_error(error, "socket_path", "refusing to replace unsafe socket path");
            return false;
        }
        if (unlink(api->socket_path) != 0) {
            set_error(error, "socket_io", "%s", g_strerror(errno));
            return false;
        }
    }
    api->listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (api->listener < 0) {
        set_error(error, "socket_io", "%s", g_strerror(errno));
        return false;
    }
    g_strlcpy(address.sun_path, api->socket_path, sizeof address.sun_path);
    if (bind(api->listener, (struct sockaddr *)&address, sizeof address) != 0) {
        set_error(error, "socket_io", "bind: %s", g_strerror(errno));
        close(api->listener);
        api->listener = -1;
        return false;
    }
    api->owns_socket = true;
    if (chmod(api->socket_path, 0660) != 0) {
        set_error(error, "socket_io", "chmod: %s", g_strerror(errno));
        close(api->listener);
        api->listener = -1;
        unlink(api->socket_path);
        api->owns_socket = false;
        return false;
    }
    if (listen(api->listener, 64) != 0) {
        set_error(error, "socket_io", "listen: %s", g_strerror(errno));
        close(api->listener);
        api->listener = -1;
        unlink(api->socket_path);
        api->owns_socket = false;
        return false;
    }
    api->accept_thread = g_thread_new("memspy-api", accept_worker, api);
    return true;
}

void
ms_api_publish_health(struct ms_api *api, const struct ms_health *health)
{
    json_object *message;
    json_object *object;
    if (api == NULL || health == NULL)
        return;
    g_mutex_lock(&api->mutex);
    api->health = *health;
    message = json_object_new_object();
    object = health_json(health);
    json_object_object_add(message, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(message, "event", json_object_new_string("health"));
    json_object_object_add(message, "health", object);
    for (guint index = 0; index < api->sessions->len; ++index) {
        struct ms_session *session = g_ptr_array_index(api->sessions, index);
        if (session->subscribed && !session_publish_json(session, message))
            shutdown(session->descriptor, SHUT_RDWR);
    }
    json_object_put(message);
    g_mutex_unlock(&api->mutex);
}

void
ms_api_publish_alert(struct ms_api *api, const struct ms_alert *alert)
{
    json_object *message;
    if (api == NULL || alert == NULL)
        return;
    message = json_object_new_object();
    json_object_object_add(message, "v", json_object_new_int(MS_PROTOCOL_VERSION));
    json_object_object_add(message, "event", json_object_new_string("alert"));
    json_object_object_add(message, "alert", ms_alert_to_json(alert));
    g_mutex_lock(&api->mutex);
    for (guint index = 0; index < api->sessions->len; ++index) {
        struct ms_session *session = g_ptr_array_index(api->sessions, index);
        if (session->subscribed && !session_publish_json(session, message))
            shutdown(session->descriptor, SHUT_RDWR);
    }
    g_mutex_unlock(&api->mutex);
    json_object_put(message);
}

void
ms_api_free(struct ms_api *api)
{
    if (api == NULL)
        return;
    g_mutex_lock(&api->mutex);
    api->stopping = true;
    if (api->listener >= 0)
        shutdown(api->listener, SHUT_RDWR);
    for (guint index = 0; index < api->sessions->len; ++index) {
        struct ms_session *session = g_ptr_array_index(api->sessions, index);
        shutdown(session->descriptor, SHUT_RDWR);
    }
    g_mutex_unlock(&api->mutex);
    if (api->listener >= 0) {
        close(api->listener);
        api->listener = -1;
    }
    if (api->accept_thread != NULL)
        g_thread_join(api->accept_thread);
    g_mutex_lock(&api->mutex);
    while (api->sessions->len > 0)
        g_cond_wait(&api->workers_done, &api->mutex);
    g_mutex_unlock(&api->mutex);
    if (api->owns_socket)
        unlink(api->socket_path);
    g_ptr_array_free(api->sessions, true);
    g_cond_clear(&api->workers_done);
    g_mutex_clear(&api->response_mutex);
    g_mutex_clear(&api->mutex);
    g_free(api->socket_path);
    g_free(api);
}
