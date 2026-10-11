#include <atk/atk.h>
#include <gtk/gtk.h>

#include "indicator.h"
#include "window.h"

static void
noop(void *userdata)
{
    (void)userdata;
}

static void
test_indicator_constructs(void)
{
    struct ms_indicator *indicator = ms_indicator_new(noop, noop, NULL);

    g_assert_nonnull(indicator);
    ms_indicator_free(indicator);
}

static struct ms_alert
fixture_alert(int64_t id, enum ms_severity severity, const char *cmdline)
{
    struct ms_alert alert = {
        .id = id,
        .timestamp_utc = 1700000000,
        .severity = severity,
        .pid = 4321,
        .uid = 1000,
    };
    g_strlcpy(alert.rule_id, severity == MS_SEVERITY_HIGH ? "MEMFD_EXEC" : "DELETED_EXEC",
              sizeof alert.rule_id);
    g_strlcpy(alert.explanation, "A suspicious executable image was observed", sizeof alert.explanation);
    g_strlcpy(alert.comm, "fixture", sizeof alert.comm);
    g_strlcpy(alert.exe, "/memfd:fixture (deleted)", sizeof alert.exe);
    g_strlcpy(alert.cmdline, cmdline, sizeof alert.cmdline);
    g_strlcpy(alert.evidence, "memfd-backed executable image", sizeof alert.evidence);
    return alert;
}

static void
test_window_states_filters_and_accessibility(void)
{
    struct ms_window *window = ms_window_new(NULL);
    struct ms_health degraded = {
        .state = MS_HEALTH_DEGRADED,
        .protected = false,
        .storage_available = false,
    };
    struct ms_alert high = fixture_alert(2, MS_SEVERITY_HIGH,
        "fixture --a-very-long-command-line-that-must-wrap-without-hiding-evidence");
    struct ms_alert medium = fixture_alert(1, MS_SEVERITY_MEDIUM, "fixture --medium");
    AtkObject *accessible = gtk_widget_get_accessible(GTK_WIDGET(ms_window_widget(window)));

    g_assert_cmpstr(atk_object_get_name(accessible), ==, "Fileless malware alerts");
    ms_window_set_loading(window);
    g_assert_cmpstr(ms_window_status_text(window), ==, "Connecting to detector…");
    ms_window_set_health(window, &degraded);
    g_assert_cmpstr(ms_window_status_text(window), ==, "Monitoring degraded");
    g_assert_true(ms_window_add_alert(window, &medium));
    g_assert_true(ms_window_add_alert(window, &high));
    g_assert_false(ms_window_add_alert(window, &high));
    g_assert_cmpuint(ms_window_visible_count(window), ==, 2);
    ms_window_set_filter(window, MS_UI_FILTER_HIGH);
    g_assert_cmpuint(ms_window_visible_count(window), ==, 1);
    g_assert_true(ms_window_select_alert(window, 2));
    ms_window_set_filter(window, MS_UI_FILTER_MEDIUM);
    g_assert_cmpuint(ms_window_visible_count(window), ==, 1);
    ms_window_set_offline(window, "Detector unavailable");
    g_assert_cmpstr(ms_window_status_text(window), ==, "Detector unavailable");
    ms_window_free(window);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    if (!gtk_init_check(&argc, &argv)) {
        g_test_message("GTK display unavailable");
        return 77;
    }
    g_test_add_func("/ui/indicator-constructs", test_indicator_constructs);
    g_test_add_func("/ui/window-states-filters-accessibility",
                    test_window_states_filters_and_accessibility);
    return g_test_run();
}
