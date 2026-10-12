#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>

#include "state.h"

static struct ms_alert
alert(int64_t id, enum ms_severity severity)
{
    struct ms_alert value = {.id = id, .severity = severity};
    g_strlcpy(value.rule_id, severity == MS_SEVERITY_HIGH ? "MEMFD_EXEC" : "DELETED_EXEC",
              sizeof value.rule_id);
    return value;
}

static void
test_indicator_and_notification_rules(void)
{
    struct ms_ui_state state;
    struct ms_health healthy = {
        .state = MS_HEALTH_HEALTHY,
        .protected = true,
        .storage_available = true,
    };
    struct ms_health degraded = {.state = MS_HEALTH_DEGRADED};
    struct ms_alert medium = alert(1, MS_SEVERITY_MEDIUM);
    struct ms_alert high = alert(2, MS_SEVERITY_HIGH);

    ms_ui_state_init(&state);
    g_assert_cmpint(ms_ui_state_indicator(&state), ==, MS_INDICATOR_OFFLINE);
    ms_ui_state_apply_health(&state, &healthy);
    g_assert_cmpint(ms_ui_state_indicator(&state), ==, MS_INDICATOR_HEALTHY);
    g_assert_true(ms_ui_state_apply_alert(&state, &medium));
    g_assert_false(ms_ui_state_should_notify(&state, &medium));
    g_assert_cmpint(ms_ui_state_indicator(&state), ==, MS_INDICATOR_MEDIUM);
    g_assert_true(ms_ui_state_apply_alert(&state, &high));
    g_assert_true(ms_ui_state_should_notify(&state, &high));
    ms_ui_state_mark_notified(&state, high.id);
    g_assert_false(ms_ui_state_should_notify(&state, &high));
    ms_ui_state_apply_health(&state, &degraded);
    g_assert_cmpint(ms_ui_state_indicator(&state), ==, MS_INDICATOR_OFFLINE);
}

static void
test_read_filter_disconnect_and_duplicates(void)
{
    struct ms_ui_state state;
    struct ms_health healthy = {.state = MS_HEALTH_HEALTHY, .protected = true};
    struct ms_alert high = alert(8, MS_SEVERITY_HIGH);

    ms_ui_state_init(&state);
    ms_ui_state_apply_health(&state, &healthy);
    g_assert_true(ms_ui_state_apply_alert(&state, &high));
    g_assert_false(ms_ui_state_apply_alert(&state, &high));
    ms_ui_state_set_filter(&state, MS_UI_FILTER_HIGH);
    g_assert_true(ms_ui_state_visible(&state, &high));
    g_assert_false(ms_ui_state_visible(&state, &(struct ms_alert){.severity = MS_SEVERITY_MEDIUM}));
    ms_ui_state_mark_visible_read(&state);
    g_assert_cmpint(ms_ui_state_indicator(&state), ==, MS_INDICATOR_HEALTHY);
    ms_ui_state_disconnect(&state);
    g_assert_cmpint(ms_ui_state_indicator(&state), ==, MS_INDICATOR_OFFLINE);
}

static void
test_state_persistence(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-ui-state-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(directory, "state", NULL);
    struct ms_ui_state state;
    struct ms_ui_state loaded;
    struct ms_error error = {0};
    struct stat metadata;

    ms_ui_state_init(&state);
    state.last_seen_id = 12;
    state.last_notified_id = 15;
    state.last_alert_id = 18;
    state.last_notified_boottime_ns = 900;
    g_assert_true(ms_ui_state_save(&state, path, &error));
    g_assert_cmpint(g_stat(path, &metadata), ==, 0);
    g_assert_cmpuint(metadata.st_mode & 0777U, ==, 0600U);
    ms_ui_state_init(&loaded);
    g_assert_true(ms_ui_state_load(&loaded, path, &error));
    g_assert_cmpint(loaded.last_seen_id, ==, 12);
    g_assert_cmpint(loaded.last_notified_id, ==, 15);
    g_assert_cmpint(loaded.last_alert_id, ==, 18);
    g_assert_cmpuint(loaded.last_notified_boottime_ns, ==, 900);
    g_unlink(path);
    g_rmdir(directory);
}

static void
test_transient_live_alert(void)
{
    struct ms_ui_state state;
    struct ms_health healthy = {.state = MS_HEALTH_HEALTHY, .protected = true};
    struct ms_alert high = alert(0, MS_SEVERITY_HIGH);

    high.observed_boottime_ns = 1234;
    high.pid = 77;
    ms_ui_state_init(&state);
    ms_ui_state_apply_health(&state, &healthy);
    g_assert_true(ms_ui_state_apply_alert(&state, &high));
    g_assert_true(ms_ui_state_should_notify(&state, &high));
    ms_ui_state_mark_alert_notified(&state, &high);
    g_assert_false(ms_ui_state_should_notify(&state, &high));
}

static void
test_response_health_is_confirmed_state(void)
{
    struct ms_ui_state state;
    struct ms_health health = {
        .state = MS_HEALTH_HEALTHY,
        .protected = true,
        .response_supported = true,
        .response_requested = true,
        .response_active = true,
        .blocked_execs = 7,
    };

    ms_ui_state_init(&state);
    ms_ui_state_apply_health(&state, &health);
    g_assert_true(state.connected);
    g_assert_true(state.health.response_supported);
    g_assert_true(state.health.response_requested);
    g_assert_true(state.health.response_active);
    g_assert_cmpuint(state.health.blocked_execs, ==, 7);
    ms_ui_state_disconnect(&state);
    g_assert_false(state.connected);
    g_assert_true(state.health.response_active);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ui-state/indicator-notification", test_indicator_and_notification_rules);
    g_test_add_func("/ui-state/filter-disconnect", test_read_filter_disconnect_and_duplicates);
    g_test_add_func("/ui-state/persistence", test_state_persistence);
    g_test_add_func("/ui-state/transient-live-alert", test_transient_live_alert);
    g_test_add_func("/ui-state/response-confirmed-health", test_response_health_is_confirmed_state);
    return g_test_run();
}
