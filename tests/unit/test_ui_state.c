#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>

#include "state.h"

static struct fl_alert
alert(int64_t id, enum fl_severity severity)
{
    struct fl_alert value = {.id = id, .severity = severity};
    g_strlcpy(value.rule_id, severity == FL_SEVERITY_HIGH ? "FL-MEMFD-EXEC" : "FL-DELETED-EXEC",
              sizeof value.rule_id);
    return value;
}

static void
test_indicator_and_notification_rules(void)
{
    struct fl_ui_state state;
    struct fl_health healthy = {
        .state = FL_HEALTH_HEALTHY,
        .protected = true,
        .storage_available = true,
    };
    struct fl_health degraded = {.state = FL_HEALTH_DEGRADED};
    struct fl_alert medium = alert(1, FL_SEVERITY_MEDIUM);
    struct fl_alert high = alert(2, FL_SEVERITY_HIGH);

    fl_ui_state_init(&state);
    g_assert_cmpint(fl_ui_state_indicator(&state), ==, FL_INDICATOR_OFFLINE);
    fl_ui_state_apply_health(&state, &healthy);
    g_assert_cmpint(fl_ui_state_indicator(&state), ==, FL_INDICATOR_HEALTHY);
    g_assert_true(fl_ui_state_apply_alert(&state, &medium));
    g_assert_false(fl_ui_state_should_notify(&state, &medium));
    g_assert_cmpint(fl_ui_state_indicator(&state), ==, FL_INDICATOR_MEDIUM);
    g_assert_true(fl_ui_state_apply_alert(&state, &high));
    g_assert_true(fl_ui_state_should_notify(&state, &high));
    fl_ui_state_mark_notified(&state, high.id);
    g_assert_false(fl_ui_state_should_notify(&state, &high));
    fl_ui_state_apply_health(&state, &degraded);
    g_assert_cmpint(fl_ui_state_indicator(&state), ==, FL_INDICATOR_OFFLINE);
}

static void
test_read_filter_disconnect_and_duplicates(void)
{
    struct fl_ui_state state;
    struct fl_health healthy = {.state = FL_HEALTH_HEALTHY, .protected = true};
    struct fl_alert high = alert(8, FL_SEVERITY_HIGH);

    fl_ui_state_init(&state);
    fl_ui_state_apply_health(&state, &healthy);
    g_assert_true(fl_ui_state_apply_alert(&state, &high));
    g_assert_false(fl_ui_state_apply_alert(&state, &high));
    fl_ui_state_set_filter(&state, FL_UI_FILTER_HIGH);
    g_assert_true(fl_ui_state_visible(&state, &high));
    g_assert_false(fl_ui_state_visible(&state, &(struct fl_alert){.severity = FL_SEVERITY_MEDIUM}));
    fl_ui_state_mark_visible_read(&state);
    g_assert_cmpint(fl_ui_state_indicator(&state), ==, FL_INDICATOR_HEALTHY);
    fl_ui_state_disconnect(&state);
    g_assert_cmpint(fl_ui_state_indicator(&state), ==, FL_INDICATOR_OFFLINE);
}

static void
test_state_persistence(void)
{
    g_autofree char *directory = g_dir_make_tmp("fileless-ui-state-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(directory, "state", NULL);
    struct fl_ui_state state;
    struct fl_ui_state loaded;
    struct fl_error error = {0};
    struct stat metadata;

    fl_ui_state_init(&state);
    state.last_seen_id = 12;
    state.last_notified_id = 15;
    state.last_alert_id = 18;
    state.last_notified_boottime_ns = 900;
    g_assert_true(fl_ui_state_save(&state, path, &error));
    g_assert_cmpint(g_stat(path, &metadata), ==, 0);
    g_assert_cmpuint(metadata.st_mode & 0777U, ==, 0600U);
    fl_ui_state_init(&loaded);
    g_assert_true(fl_ui_state_load(&loaded, path, &error));
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
    struct fl_ui_state state;
    struct fl_health healthy = {.state = FL_HEALTH_HEALTHY, .protected = true};
    struct fl_alert high = alert(0, FL_SEVERITY_HIGH);

    high.observed_boottime_ns = 1234;
    high.pid = 77;
    fl_ui_state_init(&state);
    fl_ui_state_apply_health(&state, &healthy);
    g_assert_true(fl_ui_state_apply_alert(&state, &high));
    g_assert_true(fl_ui_state_should_notify(&state, &high));
    fl_ui_state_mark_alert_notified(&state, &high);
    g_assert_false(fl_ui_state_should_notify(&state, &high));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ui-state/indicator-notification", test_indicator_and_notification_rules);
    g_test_add_func("/ui-state/filter-disconnect", test_read_filter_disconnect_and_duplicates);
    g_test_add_func("/ui-state/persistence", test_state_persistence);
    g_test_add_func("/ui-state/transient-live-alert", test_transient_live_alert);
    return g_test_run();
}
