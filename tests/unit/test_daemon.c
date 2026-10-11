#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "app.h"
#include "health.h"

struct fake_io {
    GString *order;
    bool fail_store;
    size_t stored;
    size_t published;
    size_t health_updates;
    int64_t prune_cutoff;
};

static bool
fake_insert(void *userdata, struct fl_alert *alert, struct fl_error *error)
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
fake_prune(void *userdata, int64_t cutoff, size_t batch, struct fl_error *error)
{
    struct fake_io *io = userdata;
    (void)batch;
    (void)error;
    io->prune_cutoff = cutoff;
    return 0;
}

static void
fake_publish_alert(void *userdata, const struct fl_alert *alert)
{
    struct fake_io *io = userdata;
    (void)alert;
    g_string_append_c(io->order, 'P');
    ++io->published;
}

static void
fake_publish_health(void *userdata, const struct fl_health *health)
{
    struct fake_io *io = userdata;
    (void)health;
    ++io->health_updates;
}

static struct fl_observation
memfd_observation(pid_t pid)
{
    struct fl_observation observation = {
        .kind = FL_OBSERVATION_EXEC,
        .process = {.pid = pid, .start_boottime_ns = 100},
        .observed_boottime_ns = 200,
        .timestamp_utc = 2000,
        .uid = 1000,
        .flags = FL_OBSERVATION_MEMFD,
    };
    g_strlcpy(observation.comm, "fixture", sizeof observation.comm);
    g_strlcpy(observation.exe, "/tmp/fixture", sizeof observation.exe);
    g_strlcpy(observation.cmdline, "fixture", sizeof observation.cmdline);
    return observation;
}

static struct fl_app *
new_test_app(struct fake_io *io, const char *allowlist_path)
{
    struct fl_app_config config = {.allowlist_path = allowlist_path};
    struct fl_app_dependencies dependencies = {
        .store_insert = fake_insert,
        .store_prune = fake_prune,
        .publish_alert = fake_publish_alert,
        .publish_health = fake_publish_health,
        .userdata = io,
    };
    struct fl_error error = {0};
    struct fl_app *app = fl_app_new(&config, &dependencies, &error);
    g_assert_nonnull(app);
    return app;
}

static void
test_health_reducer(void)
{
    struct fl_health health = {
        .state = FL_HEALTH_HEALTHY,
        .protected = true,
        .storage_available = true,
    };

    fl_health_apply(&health, FL_HEALTH_EVENT_LOST, 2);
    g_assert_cmpint(health.state, ==, FL_HEALTH_DEGRADED);
    g_assert_false(health.protected);
    g_assert_cmpuint(health.lost_events, ==, 2);
    fl_health_apply(&health, FL_HEALTH_REQUIRED_PROBE_FAILED, 1);
    g_assert_cmpint(health.state, ==, FL_HEALTH_FAILED);
    g_assert_false(health.protected);
}

static void
test_pipeline_store_then_publish_and_recovery(void)
{
    g_autofree char *directory = g_dir_make_tmp("fileless-app-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL)};
    struct fl_app *app;
    struct fl_observation first = memfd_observation(41);
    struct fl_observation second = memfd_observation(42);

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    fl_app_observe(app, &first);
    g_assert_cmpstr(io.order->str, ==, "SP");
    io.fail_store = true;
    fl_app_observe(app, &second);
    g_assert_cmpstr(io.order->str, ==, "SPSP");
    g_assert_cmpuint(io.published, ==, 2);
    g_assert_false(fl_app_health(app)->storage_available);

    io.fail_store = false;
    fl_app_maintain(app, 31 * 86400);
    g_assert_cmpuint(io.stored, ==, 2);
    g_assert_true(fl_app_health(app)->storage_available);
    g_assert_cmpint(io.prune_cutoff, ==, 86400);
    fl_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_allowlist_and_incomplete_alert(void)
{
    g_autofree char *directory = g_dir_make_tmp("fileless-app-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL)};
    struct fl_app *app;
    struct fl_observation observation = memfd_observation(51);

    g_assert_true(g_file_set_contents(allowlist, "FL-MEMFD-EXEC /tmp/fixture\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    fl_app_observe(app, &observation);
    g_assert_cmpuint(io.published, ==, 0);
    fl_app_free(app);

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    observation.enrichment_incomplete = true;
    observation.exe[0] = '\0';
    fl_app_observe(app, &observation);
    g_assert_cmpuint(io.published, ==, 1);
    fl_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_storage_queue_is_bounded(void)
{
    g_autofree char *directory = g_dir_make_tmp("fileless-app-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    struct fake_io io = {.order = g_string_new(NULL), .fail_store = true};
    struct fl_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    app = new_test_app(&io, allowlist);
    for (unsigned int index = 0; index < FL_APP_QUEUE_CAPACITY + 1U; ++index) {
        struct fl_observation observation = memfd_observation((pid_t)(100 + index));
        fl_app_observe(app, &observation);
    }
    g_assert_cmpuint(io.published, ==, FL_APP_QUEUE_CAPACITY + 1U);
    g_assert_cmpuint(fl_app_health(app)->dropped_alerts, ==, 1);
    fl_app_free(app);
    g_string_free(io.order, true);
    g_unlink(allowlist);
    g_rmdir(directory);
}

static void
test_startup_continues_without_corrupt_store(void)
{
    g_autofree char *directory = g_dir_make_tmp("fileless-app-store-XXXXXX", NULL);
    g_autofree char *allowlist = g_build_filename(directory, "allowlist.conf", NULL);
    g_autofree char *database = g_build_filename(directory, "alerts.db", NULL);
    g_autofree char *socket = g_build_filename(directory, "filelessd.sock", NULL);
    struct fl_app_config config = {
        .allowlist_path = allowlist,
        .database_path = database,
        .socket_path = socket,
    };
    struct fl_error error = {0};
    struct fl_app *app;

    g_assert_true(g_file_set_contents(allowlist, "# empty\n", -1, NULL));
    g_assert_true(g_file_set_contents(database, "not a sqlite database", -1, NULL));
    g_test_expect_message(NULL, G_LOG_LEVEL_WARNING, "*storage unavailable at startup*");
    app = fl_app_new(&config, NULL, &error);
    g_test_assert_expected_messages();
    g_assert_nonnull(app);
    g_assert_false(fl_app_health(app)->storage_available);
    g_assert_cmpint(fl_app_health(app)->state, ==, FL_HEALTH_DEGRADED);
    g_assert_cmpint(g_unlink(database), ==, 0);
    fl_app_maintain(app, 1);
    g_assert_true(fl_app_health(app)->storage_available);
    g_assert_cmpint(fl_app_health(app)->state, ==, FL_HEALTH_HEALTHY);
    fl_app_free(app);
    g_unlink(database);
    g_unlink(allowlist);
    g_rmdir(directory);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/daemon/health", test_health_reducer);
    g_test_add_func("/daemon/pipeline-recovery", test_pipeline_store_then_publish_and_recovery);
    g_test_add_func("/daemon/allowlist-incomplete", test_allowlist_and_incomplete_alert);
    g_test_add_func("/daemon/bounded-queue", test_storage_queue_is_bounded);
    g_test_add_func("/daemon/startup-with-corrupt-store", test_startup_continues_without_corrupt_store);
    return g_test_run();
}
