#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "app.h"
#include "enforcer.h"
#include "health.h"

struct fake_io {
    GString *order;
    bool fail_store;
    size_t stored;
    size_t published;
    size_t health_updates;
    int64_t prune_cutoff;
    bool state_valid;
    bool persisted_enabled;
    bool response_supported;
    bool response_active;
    bool fail_state_store;
    size_t rejected_launchers;
    uint64_t blocked_execs;
    uint64_t blocked_operations;
    uint64_t lost_block_events;
    bool fail_journal;
    size_t journaled;
    GArray *response_changes;
};

static bool
fake_insert(void *userdata, struct ms_alert *alert, struct ms_error *error)
{
    struct fake_io *io = userdata;
    g_string_append_c(io->order, 'S');
    if (io->fail_store) {
        g_strlcpy(error->code, "store_error", sizeof error->code);
        return false;
    }
    alert->id = (int64_t)++io->stored;
    return true;
}

static size_t
fake_prune(void *userdata, int64_t cutoff, size_t batch, struct ms_error *error)
{
    struct fake_io *io = userdata;
    (void)batch;
    (void)error;
    io->prune_cutoff = cutoff;
    return 0;
}

static void
fake_publish_alert(void *userdata, const struct ms_alert *alert)
{
    struct fake_io *io = userdata;
    (void)alert;
    g_string_append_c(io->order, 'P');
    ++io->published;
}

static void
fake_publish_health(void *userdata, const struct ms_health *health)
{
    struct fake_io *io = userdata;
    (void)health;
    ++io->health_updates;
}

static bool
fake_journal_alert(void *userdata, const struct ms_alert *alert, struct ms_error *error)
{
    struct fake_io *io = userdata;
    g_assert_cmpint(alert->id, >, 0);
    g_string_append_c(io->order, 'J');
    ++io->journaled;
    if (!io->fail_journal)
        return true;
    g_strlcpy(error->code, "journal_error", sizeof error->code);
    g_strlcpy(error->message, "fixture journal failure", sizeof error->message);
    return false;
}

static bool
fake_response_state_load(void *userdata, const char *path, bool *enabled,
                         struct ms_error *error)
{
    struct fake_io *io = userdata;
    (void)path;
    if (!io->state_valid) {
        g_strlcpy(error->code, "response_state_invalid", sizeof error->code);
        g_strlcpy(error->message, "invalid response state", sizeof error->message);
        return false;
    }
    *enabled = io->persisted_enabled;
    return true;
}

static bool
fake_response_state_store(void *userdata, const char *path, bool enabled,
                          struct ms_error *error)
{
    struct fake_io *io = userdata;
    (void)path;
    if (io->fail_state_store) {
        g_strlcpy(error->code, "response_state_io", sizeof error->code);
        g_strlcpy(error->message, "cannot persist response state", sizeof error->message);
        return false;
    }
    io->persisted_enabled = enabled;
    return true;
}

static bool
fake_response_allowlist(void *userdata, const char *path, GArray **keys,
                        size_t *rejected, struct ms_error *warning)
{
    struct fake_io *io = userdata;
    (void)path;
    *keys = g_array_new(false, false, sizeof(struct ms_allowlist_key));
    *rejected = io->rejected_launchers;
    if (*rejected > 0)
        g_strlcpy(warning->message, "unsafe launcher entry ignored", sizeof warning->message);
    return true;
}

static bool
fake_response_attach(void *userdata, const GArray *keys, bool requested,
                     struct ms_enforcer_status *status, struct ms_error *error)
{
    struct fake_io *io = userdata;
    (void)keys;
    (void)error;
    io->response_active = io->response_supported && requested;
    *status = (struct ms_enforcer_status){
        .supported = io->response_supported,
        .enabled = io->response_active,
    };
    if (!status->supported)
        g_strlcpy(status->reason, "BPF LSM unavailable", sizeof status->reason);
    return true;
}

static bool
fake_response_set(void *userdata, bool enabled, struct ms_error *error)
{
    struct fake_io *io = userdata;
    (void)error;
    g_array_append_val(io->response_changes, enabled);
    io->response_active = enabled;
    return true;
}

static int
fake_response_poll(void *userdata, int timeout_ms, struct ms_enforcer_status *status,
                   struct ms_error *error)
{
    struct fake_io *io = userdata;
    (void)timeout_ms;
    (void)error;
    *status = (struct ms_enforcer_status){
        .supported = io->response_supported,
        .enabled = io->response_active,
        .denied = io->blocked_execs,
        .denied_execs = io->blocked_operations,
        .lost_events = io->lost_block_events,
    };
    return 0;
}

static struct ms_observation
memfd_observation(pid_t pid)
{
    struct ms_observation observation = {
        .kind = MS_OBSERVATION_EXEC,
        .process = {.pid = pid, .start_boottime_ns = 100},
        .observed_boottime_ns = 200,
        .timestamp_utc = 2000,
        .uid = 1000,
        .flags = MS_OBSERVATION_MEMFD,
    };
    g_strlcpy(observation.comm, "fixture", sizeof observation.comm);
    g_strlcpy(observation.exe, "/tmp/fixture", sizeof observation.exe);
    g_strlcpy(observation.cmdline, "fixture", sizeof observation.cmdline);
    return observation;
}

static struct ms_app *
new_test_app(struct fake_io *io, const char *allowlist_path)
{
    struct ms_app_config config = {.allowlist_path = allowlist_path};
    struct ms_app_dependencies dependencies = {
        .store_insert = fake_insert,
        .store_prune = fake_prune,
        .publish_alert = fake_publish_alert,
        .publish_health = fake_publish_health,
        .journal_alert = fake_journal_alert,
        .userdata = io,
    };
    struct ms_error error = {0};
    struct ms_app *app = ms_app_new(&config, &dependencies, &error);
    g_assert_nonnull(app);
    return app;
}

static struct ms_app *
new_response_app(struct fake_io *io, const char *allowlist_path)
{
    struct ms_app_config config = {
        .allowlist_path = allowlist_path,
        .response_state_path = "/var/lib/memspy/response-mode",
        .response_allowlist_path = "/etc/memspy/response-allowlist.conf",
        .response_pin_dir = "/sys/fs/bpf/memspy",
    };
    struct ms_app_dependencies dependencies = {
        .store_insert = fake_insert,
        .store_prune = fake_prune,
        .publish_alert = fake_publish_alert,
        .publish_health = fake_publish_health,
        .response_state_load = fake_response_state_load,
        .response_state_store = fake_response_state_store,
        .response_allowlist_load = fake_response_allowlist,
        .response_attach = fake_response_attach,
        .response_set_enabled = fake_response_set,
        .response_poll = fake_response_poll,
        .userdata = io,
    };
    struct ms_error error = {0};
    struct ms_app *app = ms_app_new(&config, &dependencies, &error);
    g_assert_nonnull(app);
    return app;
}

static void
test_health_reducer(void)
{
    struct ms_health health = {
        .state = MS_HEALTH_HEALTHY,
        .protected = true,
        .storage_available = true,
    };

    ms_health_apply(&health, MS_HEALTH_EVENT_LOST, 2);
    g_assert_cmpint(health.state, ==, MS_HEALTH_DEGRADED);
    g_assert_false(health.protected);
    g_assert_cmpuint(health.lost_events, ==, 2);
    ms_health_apply(&health, MS_HEALTH_REQUIRED_PROBE_FAILED, 1);
    g_assert_cmpint(health.state, ==, MS_HEALTH_FAILED);
    g_assert_false(health.protected);
}

static void
test_pipeline_store_then_publish_and_recovery(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-app-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL)};
    struct ms_app *app;
    struct ms_observation first = memfd_observation(41);
    struct ms_observation second = memfd_observation(42);

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    ms_app_observe(app, &first);
    g_assert_cmpstr(io.order->str, ==, "SJP");
    io.fail_store = true;
    ms_app_observe(app, &second);
    g_assert_cmpstr(io.order->str, ==, "SJPSP");
    g_assert_cmpuint(io.published, ==, 2);
    g_assert_false(ms_app_health(app)->storage_available);

    io.fail_store = false;
    ms_app_maintain(app, 31 * 86400);
    g_assert_cmpuint(io.stored, ==, 2);
    g_assert_true(ms_app_health(app)->storage_available);
    g_assert_cmpint(io.prune_cutoff, ==, 86400);
    ms_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_journal_failure_does_not_block_alerts(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-journal-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL), .fail_journal = true};
    struct ms_app *app;
    struct ms_observation first = memfd_observation(61);
    struct ms_observation second = memfd_observation(62);

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*structured journal output failed*");
    ms_app_observe(app, &first);
    g_test_assert_expected_messages();
    ms_app_observe(app, &second);
    g_assert_cmpuint(io.stored, ==, 2);
    g_assert_cmpuint(io.published, ==, 2);
    g_assert_cmpuint(io.journaled, ==, 2);
    g_assert_cmpuint(ms_app_health(app)->journal_errors, ==, 2);
    g_assert_cmpint(ms_app_health(app)->state, ==, MS_HEALTH_DEGRADED);
    ms_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_allowlist_and_incomplete_alert(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-app-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL)};
    struct ms_app *app;
    struct ms_observation observation = memfd_observation(51);

    g_assert_true(g_file_set_contents(allowlist, "MEMFD_EXEC /tmp/fixture\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    ms_app_observe(app, &observation);
    g_assert_cmpuint(io.published, ==, 0);
    ms_app_free(app);

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    observation.enrichment_incomplete = true;
    observation.exe[0] = '\0';
    ms_app_observe(app, &observation);
    g_assert_cmpuint(io.published, ==, 1);
    ms_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_storage_queue_is_bounded(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-app-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL), .fail_store = true};
    struct ms_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    for (unsigned int index = 0; index < MS_APP_QUEUE_CAPACITY + 1U; ++index) {
        struct ms_observation observation = memfd_observation((pid_t)(100 + index));
        ms_app_observe(app, &observation);
    }
    g_assert_cmpuint(io.published, ==, MS_APP_QUEUE_CAPACITY + 1U);
    g_assert_cmpuint(ms_app_health(app)->dropped_alerts, ==, 1);
    ms_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_startup_continues_without_corrupt_store(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-app-store-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    g_autofree char *database = g_build_filename(directory, "alerts.db", NULL);
    g_autofree char *socket = g_build_filename(directory, "memspyd.sock", NULL);
    struct ms_app_config config = {
        .allowlist_path = allowlist,
        .database_path = database,
        .socket_path = socket,
    };
    struct ms_error error = {0};
    struct ms_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    g_assert_true(g_file_set_contents(database, "not a sqlite database", -1, NULL));
    g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*storage unavailable at startup*");
    app = ms_app_new(&config, NULL, &error);
    g_test_assert_expected_messages();
    g_assert_nonnull(app);
    g_assert_false(ms_app_health(app)->storage_available);
    g_assert_cmpint(ms_app_health(app)->state, ==, MS_HEALTH_DEGRADED);
    g_assert_cmpint(g_unlink(database), ==, 0);
    ms_app_maintain(app, 1);
    g_assert_true(ms_app_health(app)->storage_available);
    g_assert_cmpint(ms_app_health(app)->state, ==, MS_HEALTH_HEALTHY);
    ms_app_free(app);
    g_unlink(database);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_response_startup_states(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-response-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {
        .order = g_string_new(NULL),
        .state_valid = true,
        .persisted_enabled = true,
        .response_changes = g_array_new(false, false, sizeof(bool)),
    };
    struct ms_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_response_app(&io, allowlist);
    g_assert_true(ms_app_health(app)->response_requested);
    g_assert_false(ms_app_health(app)->response_supported);
    g_assert_false(ms_app_health(app)->response_active);
    g_assert_cmpstr(ms_app_health(app)->response_reason, ==, "BPF LSM unavailable");
    ms_app_free(app);

    io.response_supported = true;
    io.persisted_enabled = false;
    app = new_response_app(&io, allowlist);
    g_assert_true(ms_app_health(app)->response_supported);
    g_assert_false(ms_app_health(app)->response_active);
    ms_app_free(app);

    io.persisted_enabled = true;
    app = new_response_app(&io, allowlist);
    g_assert_true(ms_app_health(app)->response_active);
    ms_app_free(app);

    io.state_valid = false;
    app = new_response_app(&io, allowlist);
    g_assert_false(ms_app_health(app)->response_requested);
    g_assert_false(ms_app_health(app)->response_active);
    g_assert_cmpint(ms_app_health(app)->state, ==, MS_HEALTH_DEGRADED);
    ms_app_free(app);

    io.state_valid = true;
    io.persisted_enabled = false;
    io.rejected_launchers = 1;
    app = new_response_app(&io, allowlist);
    g_assert_cmpint(ms_app_health(app)->state, ==, MS_HEALTH_DEGRADED);
    g_assert_nonnull(strstr(ms_app_health(app)->response_reason, "unsafe launcher"));
    ms_app_free(app);
    g_array_free(io.response_changes, true);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_response_transition_rolls_back_on_persistence_failure(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-response-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {
        .order = g_string_new(NULL),
        .state_valid = true,
        .response_supported = true,
        .fail_state_store = true,
        .response_changes = g_array_new(false, false, sizeof(bool)),
    };
    struct ms_error error = {0};
    struct ms_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_response_app(&io, allowlist);
    g_assert_false(ms_app_set_response(app, true, &error));
    g_assert_false(io.response_active);
    g_assert_false(ms_app_health(app)->response_requested);
    g_assert_false(ms_app_health(app)->response_active);
    g_assert_cmpuint(io.response_changes->len, ==, 2);
    g_assert_true(g_array_index(io.response_changes, bool, 0));
    g_assert_false(g_array_index(io.response_changes, bool, 1));
    ms_app_free(app);

    g_array_set_size(io.response_changes, 0);
    io.persisted_enabled = true;
    io.response_active = false;
    app = new_response_app(&io, allowlist);
    g_array_set_size(io.response_changes, 0);
    g_assert_false(ms_app_set_response(app, false, &error));
    g_assert_true(io.response_active);
    g_assert_true(ms_app_health(app)->response_requested);
    g_assert_true(ms_app_health(app)->response_active);
    g_assert_false(g_array_index(io.response_changes, bool, 0));
    g_assert_true(g_array_index(io.response_changes, bool, 1));
    ms_app_free(app);
    g_array_free(io.response_changes, true);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_blocked_alert_and_response_counters(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-response-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {
        .order = g_string_new(NULL),
        .state_valid = true,
        .persisted_enabled = true,
        .response_supported = true,
        .response_changes = g_array_new(false, false, sizeof(bool)),
    };
    struct ms_alert alert = {
        .action = MS_ALERT_BLOCKED,
        .severity = MS_SEVERITY_HIGH,
        .pid = 123,
    };
    struct ms_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_response_app(&io, allowlist);
    ms_app_blocked(app, &alert);
    g_assert_cmpuint(io.stored, ==, 1);
    g_assert_cmpuint(io.published, ==, 1);

    io.fail_store = true;
    ms_app_blocked(app, &alert);
    g_assert_false(ms_app_health(app)->storage_available);
    g_assert_true(ms_app_health(app)->response_active);
    io.blocked_execs = 9;
    io.blocked_operations = 2;
    io.lost_block_events = 2;
    ms_app_maintain(app, 0);
    g_assert_cmpuint(ms_app_health(app)->blocked_execs, ==, 2);
    g_assert_cmpuint(ms_app_health(app)->blocked_operations, ==, 9);
    g_assert_cmpuint(ms_app_health(app)->lost_block_events, ==, 2);
    g_assert_true(ms_app_health(app)->response_active);
    ms_app_free(app);
    g_array_free(io.response_changes, true);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/daemon/health", test_health_reducer);
    g_test_add_func("/daemon/pipeline-recovery", test_pipeline_store_then_publish_and_recovery);
    g_test_add_func("/daemon/journal-failure", test_journal_failure_does_not_block_alerts);
    g_test_add_func("/daemon/allowlist-incomplete", test_allowlist_and_incomplete_alert);
    g_test_add_func("/daemon/bounded-queue", test_storage_queue_is_bounded);
    g_test_add_func("/daemon/startup-with-corrupt-store", test_startup_continues_without_corrupt_store);
    g_test_add_func("/daemon/response-startup", test_response_startup_states);
    g_test_add_func("/daemon/response-rollback", test_response_transition_rolls_back_on_persistence_failure);
    g_test_add_func("/daemon/blocked-response-health", test_blocked_alert_and_response_counters);
    return g_test_run();
}
