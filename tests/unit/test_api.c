#include <glib.h>
#include <glib/gstdio.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "client.h"

struct api_fixture {
    char *directory;
    char *database_path;
    char *socket_path;
    struct ms_store *store;
    struct ms_api *api;
    pid_t peer_pid;
    uid_t peer_uid;
    gint peer_count;
};

static void
peer_connected(pid_t pid, uid_t uid, void *userdata)
{
    struct api_fixture *fixture = userdata;
    fixture->peer_pid = pid;
    fixture->peer_uid = uid;
    g_atomic_int_inc(&fixture->peer_count);
}

static void
fixture_setup(struct api_fixture *fixture, gconstpointer user_data)
{
    struct ms_error error = {0};
    struct ms_health health = {
        .state = MS_HEALTH_HEALTHY,
        .protected = true,
        .storage_available = true,
    };
    struct ms_api_callbacks callbacks = {.peer_connected = peer_connected, .userdata = fixture};

    (void)user_data;
    fixture->directory = g_dir_make_tmp("memspy-api-XXXXXX", NULL);
    fixture->database_path = g_build_filename(fixture->directory, "alerts.db", NULL);
    fixture->socket_path = g_build_filename(fixture->directory, "memspyd.sock", NULL);
    g_assert_true(ms_store_open(fixture->database_path, &fixture->store, &error));
    fixture->api = ms_api_new(fixture->socket_path, fixture->store, &callbacks);
    g_assert_nonnull(fixture->api);
    ms_api_publish_health(fixture->api, &health);
}

static void
fixture_teardown(struct api_fixture *fixture, gconstpointer user_data)
{
    g_autofree char *wal = g_strconcat(fixture->database_path, "-wal", NULL);
    g_autofree char *shm = g_strconcat(fixture->database_path, "-shm", NULL);

    (void)user_data;
    ms_api_free(fixture->api);
    ms_store_close(fixture->store);
    g_unlink(wal);
    g_unlink(shm);
    g_unlink(fixture->database_path);
    g_rmdir(fixture->directory);
    g_free(fixture->socket_path);
    g_free(fixture->database_path);
    g_free(fixture->directory);
}

static struct ms_alert
sample_alert(enum ms_severity severity, const char *rule)
{
    struct ms_alert alert = {
        .timestamp_utc = 1791676800,
        .observed_boottime_ns = 100,
        .severity = severity,
        .pid = 12,
        .ppid = 1,
        .uid = 1000,
    };

    g_strlcpy(alert.rule_id, rule, sizeof alert.rule_id);
    g_strlcpy(alert.explanation, "fixture", sizeof alert.explanation);
    g_strlcpy(alert.comm, "fixture", sizeof alert.comm);
    g_strlcpy(alert.exe, "/usr/bin/fixture", sizeof alert.exe);
    return alert;
}

static void
test_api_handshake_status_and_history(struct api_fixture *fixture, gconstpointer user_data)
{
    struct ms_client *client = NULL;
    struct ms_error error = {0};
    struct ms_health health = {0};
    struct ms_alert medium = sample_alert(MS_SEVERITY_MEDIUM, "DELETED_EXEC");
    struct ms_alert high = sample_alert(MS_SEVERITY_HIGH, "MEMFD_EXEC");
    struct ms_alert_page page = {0};

    (void)user_data;
    g_assert_true(ms_store_insert(fixture->store, &medium, &error));
    g_assert_true(ms_store_insert(fixture->store, &high, &error));
    int pair[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), ==, 0);
    g_assert_true(ms_api_accept_fd(fixture->api, pair[0]));
    if (!ms_client_connect_fd(pair[1], &client, &error))
        g_test_message("client connect failed: %s: %s", error.code, error.message);
    g_assert_nonnull(client);
    for (unsigned int attempt = 0; attempt < 100U && g_atomic_int_get(&fixture->peer_count) == 0; ++attempt)
        g_usleep(1000);
    g_assert_cmpint(g_atomic_int_get(&fixture->peer_count), >, 0);
    g_assert_cmpint(fixture->peer_pid, ==, getpid());
    g_assert_cmpuint(fixture->peer_uid, ==, getuid());
    g_assert_true(ms_client_get_status(client, &health, &error));
    g_assert_cmpint(health.state, ==, MS_HEALTH_HEALTHY);
    g_assert_true(health.protected);
    g_assert_true(ms_client_list_alerts(client, 0, MS_SEVERITY_HIGH, 1000, &page, &error));
    g_assert_cmpuint(page.length, ==, 1);
    g_assert_cmpint(page.items[0].id, ==, high.id);
    ms_alert_page_clear(&page);
    ms_client_close(client);
}

static int
raw_connect(struct ms_api *api)
{
    int pair[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), ==, 0);
    g_assert_true(ms_api_accept_fd(api, pair[0]));
    return pair[1];
}

static char *
read_line(int descriptor)
{
    GString *line = g_string_new(NULL);
    char byte;

    while (read(descriptor, &byte, 1) == 1 && byte != '\n')
        g_string_append_c(line, byte);
    return g_string_free(line, false);
}

static void
test_api_rejects_hostile_clients(struct api_fixture *fixture, gconstpointer user_data)
{
    int descriptor;
    g_autofree char *line = NULL;
    g_autofree char *oversized = g_strnfill(MS_MAX_MESSAGE_BYTES + 1U, 'x');

    (void)user_data;
    descriptor = raw_connect(fixture->api);
    g_assert_cmpint(write(descriptor, "{not-json}\n", 11), ==, 11);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "malformed_json"));
    close(descriptor);

    descriptor = raw_connect(fixture->api);
    static const char status_before_hello[] = "{\"v\":1,\"op\":\"status\"}\n";
    g_assert_cmpint(write(descriptor, status_before_hello, sizeof status_before_hello - 1U), ==,
                    (ssize_t)(sizeof status_before_hello - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_cmpstr(line, ==, "");
    close(descriptor);

    descriptor = raw_connect(fixture->api);
    static const char hello[] = "{\"v\":1,\"op\":\"hello\"}\n";
    static const char unknown[] = "{\"v\":1,\"op\":\"delete\"}\n";
    g_assert_cmpint(write(descriptor, hello, sizeof hello - 1U), ==, (ssize_t)(sizeof hello - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "\"ok\":true"));
    g_assert_cmpint(write(descriptor, unknown, sizeof unknown - 1U), ==, (ssize_t)(sizeof unknown - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "unknown_operation"));
    close(descriptor);

    descriptor = raw_connect(fixture->api);
    static const char invalid_alerts[] =
        "{\"v\":1,\"op\":\"alerts\",\"before_id\":-1,\"minimum\":0,\"limit\":\"many\"}\n";
    g_assert_cmpint(write(descriptor, hello, sizeof hello - 1U), ==, (ssize_t)(sizeof hello - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "\"ok\":true"));
    g_assert_cmpint(write(descriptor, invalid_alerts, sizeof invalid_alerts - 1U), ==,
                    (ssize_t)(sizeof invalid_alerts - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "invalid_request"));
    close(descriptor);

    descriptor = raw_connect(fixture->api);
    static const char unsupported[] = "{\"v\":99,\"op\":\"hello\"}\n";
    g_assert_cmpint(write(descriptor, unsupported, sizeof unsupported - 1U), ==,
                    (ssize_t)(sizeof unsupported - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "unsupported_version"));
    close(descriptor);

    descriptor = raw_connect(fixture->api);
    g_assert_cmpint(write(descriptor, oversized, MS_MAX_MESSAGE_BYTES + 1U), ==,
                    MS_MAX_MESSAGE_BYTES + 1U);
    g_assert_cmpint(read(descriptor, &(char){0}, 1), ==, 0);
    close(descriptor);
}

static void
test_api_preserves_unowned_socket_path(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-api-owner-XXXXXX", NULL);
    g_autofree char *database_path = g_build_filename(directory, "alerts.db", NULL);
    g_autofree char *socket_path = g_build_filename(directory, "memspyd.sock", NULL);
    g_autofree char *wal = g_strconcat(database_path, "-wal", NULL);
    g_autofree char *shm = g_strconcat(database_path, "-shm", NULL);
    g_autofree char *contents = NULL;
    struct ms_store *store = NULL;
    struct ms_api *api;
    struct ms_error error = {0};

    g_assert_true(ms_store_open(database_path, &store, &error));
    g_assert_true(g_file_set_contents(socket_path, "operator file", -1, NULL));
    api = ms_api_new(socket_path, store, NULL);
    g_assert_nonnull(api);
    g_assert_false(ms_api_start(api, &error));
    ms_api_free(api);
    g_assert_true(g_file_get_contents(socket_path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "operator file");
    ms_store_close(store);
    g_unlink(socket_path);
    g_unlink(database_path);
    g_unlink(wal);
    g_unlink(shm);
    g_rmdir(directory);
}

static void
test_api_reports_unavailable_history(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-api-recovery-XXXXXX", NULL);
    g_autofree char *database = g_build_filename(directory, "alerts.db", NULL);
    g_autofree char *wal = g_strconcat(database, "-wal", NULL);
    g_autofree char *shm = g_strconcat(database, "-shm", NULL);
    struct ms_api *api = ms_api_new("/unused", NULL, NULL);
    struct ms_store *store = NULL;
    struct ms_error error = {0};
    g_autofree char *line = NULL;
    static const char hello[] = "{\"v\":1,\"op\":\"hello\"}\n";
    static const char alerts[] = "{\"v\":1,\"op\":\"alerts\"}\n";
    int descriptor;

    g_assert_nonnull(api);
    descriptor = raw_connect(api);
    g_assert_cmpint(write(descriptor, hello, sizeof hello - 1U), ==,
                    (ssize_t)(sizeof hello - 1U));
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "\"ok\":true"));
    g_assert_cmpint(write(descriptor, alerts, sizeof alerts - 1U), ==,
                    (ssize_t)(sizeof alerts - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "storage_unavailable"));

    g_assert_true(ms_store_open(database, &store, &error));
    ms_api_set_store(api, store);
    g_assert_cmpint(write(descriptor, alerts, sizeof alerts - 1U), ==,
                    (ssize_t)(sizeof alerts - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "\"ok\":true"));
    close(descriptor);
    ms_api_free(api);
    ms_store_close(store);
    g_unlink(wal);
    g_unlink(shm);
    g_unlink(database);
    g_rmdir(directory);
}

static void
test_api_bounds_connected_clients(void)
{
    struct ms_api *api = ms_api_new("/unused", NULL, NULL);
    int clients[64];
    int rejected[2];

    g_assert_nonnull(api);
    for (size_t index = 0; index < G_N_ELEMENTS(clients); ++index) {
        int pair[2];
        g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), ==, 0);
        g_assert_true(ms_api_accept_fd(api, pair[0]));
        clients[index] = pair[1];
    }
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, rejected), ==, 0);
    g_assert_false(ms_api_accept_fd(api, rejected[0]));
    close(rejected[0]);
    close(rejected[1]);
    for (size_t index = 0; index < G_N_ELEMENTS(clients); ++index)
        close(clients[index]);
    ms_api_free(api);
}

static void
test_api_disconnects_stalled_handshake(void)
{
    struct ms_api *api = ms_api_new("/unused", NULL, NULL);
    struct pollfd stalled;

    g_assert_nonnull(api);
    stalled = (struct pollfd){.fd = raw_connect(api), .events = POLLIN | POLLHUP};
    g_assert_cmpint(poll(&stalled, 1, 7000), ==, 1);
    g_assert_cmpint(read(stalled.fd, &(char){0}, 1), ==, 0);
    close(stalled.fd);
    ms_api_free(api);
}

static void
test_api_disconnects_stalled_subscriber_without_blocking(struct api_fixture *fixture,
                                                          gconstpointer user_data)
{
    static const char hello[] = "{\"v\":1,\"op\":\"hello\"}\n";
    static const char subscribe[] = "{\"v\":1,\"op\":\"subscribe\"}\n";
    struct ms_alert alert = sample_alert(MS_SEVERITY_HIGH, "MEMFD_EXEC");
    g_autofree char *line = NULL;
    int descriptor = raw_connect(fixture->api);
    int receive_buffer = 1024;

    (void)user_data;
    setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &receive_buffer, sizeof receive_buffer);
    g_assert_cmpint(write(descriptor, hello, sizeof hello - 1U), ==, (ssize_t)(sizeof hello - 1U));
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "\"ok\":true"));
    g_assert_cmpint(write(descriptor, subscribe, sizeof subscribe - 1U), ==,
                    (ssize_t)(sizeof subscribe - 1U));
    g_clear_pointer(&line, g_free);
    line = read_line(descriptor);
    g_assert_nonnull(strstr(line, "\"ok\":true"));
    memset(alert.cmdline, 'x', MS_MAX_CMDLINE_BYTES);
    alert.cmdline[MS_MAX_CMDLINE_BYTES] = '\0';

    gint64 started = g_get_monotonic_time();
    for (unsigned int index = 0; index < 300U; ++index)
        ms_api_publish_alert(fixture->api, &alert);
    g_assert_cmpint(g_get_monotonic_time() - started, <, G_TIME_SPAN_SECOND);
    close(descriptor);
}

struct subscription_result {
    GMutex mutex;
    GCond changed;
    unsigned int alerts;
    unsigned int health_changes;
};

static void
on_alert(const struct ms_alert *alert, void *userdata)
{
    struct subscription_result *result = userdata;
    g_assert_cmpstr(alert->rule_id, ==, "MEMFD_EXEC");
    g_mutex_lock(&result->mutex);
    ++result->alerts;
    g_cond_broadcast(&result->changed);
    g_mutex_unlock(&result->mutex);
}

static void
on_health(const struct ms_health *health, void *userdata)
{
    struct subscription_result *result = userdata;
    g_assert_cmpint(health->state, ==, MS_HEALTH_DEGRADED);
    g_mutex_lock(&result->mutex);
    ++result->health_changes;
    g_cond_broadcast(&result->changed);
    g_mutex_unlock(&result->mutex);
}

static void
test_api_streams_alerts_and_health(struct api_fixture *fixture, gconstpointer user_data)
{
    struct ms_client *client = NULL;
    struct ms_error error = {0};
    struct ms_alert alert = sample_alert(MS_SEVERITY_HIGH, "MEMFD_EXEC");
    struct ms_health health = {.state = MS_HEALTH_DEGRADED, .storage_available = false};
    struct subscription_result result = {0};
    int pair[2];

    (void)user_data;
    g_mutex_init(&result.mutex);
    g_cond_init(&result.changed);
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_STREAM, 0, pair), ==, 0);
    g_assert_true(ms_api_accept_fd(fixture->api, pair[0]));
    g_assert_true(ms_client_connect_fd(pair[1], &client, &error));
    g_assert_true(ms_client_subscribe(client, on_alert, on_health, &result, &error));
    ms_api_publish_alert(fixture->api, &alert);
    ms_api_publish_health(fixture->api, &health);

    g_mutex_lock(&result.mutex);
    gint64 deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    while ((result.alerts == 0 || result.health_changes == 0) &&
           g_cond_wait_until(&result.changed, &result.mutex, deadline)) {}
    g_assert_cmpuint(result.alerts, ==, 1);
    g_assert_cmpuint(result.health_changes, ==, 1);
    g_mutex_unlock(&result.mutex);
    ms_client_close(client);
    g_cond_clear(&result.changed);
    g_mutex_clear(&result.mutex);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add("/api/handshake-status-history", struct api_fixture, NULL, fixture_setup,
               test_api_handshake_status_and_history, fixture_teardown);
    g_test_add("/api/hostile-clients", struct api_fixture, NULL, fixture_setup,
               test_api_rejects_hostile_clients, fixture_teardown);
    g_test_add("/api/subscription", struct api_fixture, NULL, fixture_setup,
               test_api_streams_alerts_and_health, fixture_teardown);
    g_test_add("/api/stalled-subscriber", struct api_fixture, NULL, fixture_setup,
               test_api_disconnects_stalled_subscriber_without_blocking, fixture_teardown);
    g_test_add_func("/api/preserve-unowned-socket", test_api_preserves_unowned_socket_path);
    g_test_add_func("/api/unavailable-history", test_api_reports_unavailable_history);
    g_test_add_func("/api/bounded-clients", test_api_bounds_connected_clients);
    g_test_add_func("/api/stalled-handshake", test_api_disconnects_stalled_handshake);
    return g_test_run();
}
