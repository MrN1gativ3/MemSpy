#include <atk/atk.h>
#include <gtk/gtk.h>

#include "window.h"

static struct fl_alert
fixture_alert(int64_t id, enum fl_severity severity, const char *cmdline)
{
    struct fl_alert alert = {
        .id = id,
        .timestamp_utc = 1700000000,
        .severity = severity,
        .pid = 4321,
        .uid = 1000,
    };
    g_strlcpy(alert.rule_id, severity == FL_SEVERITY_HIGH ? "FL-MEMFD-EXEC" : "FL-DELETED-EXEC",
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
    struct fl_window *window = fl_window_new(NULL);
    struct fl_health degraded = {
        .state = FL_HEALTH_DEGRADED,
        .protected = false,
        .storage_available = false,
    };
    struct fl_alert high = fixture_alert(2, FL_SEVERITY_HIGH,
        "fixture --a-very-long-command-line-that-must-wrap-without-hiding-evidence");
    struct fl_alert medium = fixture_alert(1, FL_SEVERITY_MEDIUM, "fixture --medium");
    AtkObject *accessible = gtk_widget_get_accessible(GTK_WIDGET(fl_window_widget(window)));

    g_assert_cmpstr(atk_object_get_name(accessible), ==, "Fileless malware alerts");
    fl_window_set_loading(window);
    g_assert_cmpstr(fl_window_status_text(window), ==, "Connecting to detector…");
    fl_window_set_health(window, &degraded);
    g_assert_cmpstr(fl_window_status_text(window), ==, "Monitoring degraded");
    g_assert_true(fl_window_add_alert(window, &medium));
    g_assert_true(fl_window_add_alert(window, &high));
    g_assert_false(fl_window_add_alert(window, &high));
    g_assert_cmpuint(fl_window_visible_count(window), ==, 2);
    fl_window_set_filter(window, FL_UI_FILTER_HIGH);
    g_assert_cmpuint(fl_window_visible_count(window), ==, 1);
    g_assert_true(fl_window_select_alert(window, 2));
    fl_window_set_filter(window, FL_UI_FILTER_MEDIUM);
    g_assert_cmpuint(fl_window_visible_count(window), ==, 1);
    fl_window_set_offline(window, "Detector unavailable");
    g_assert_cmpstr(fl_window_status_text(window), ==, "Detector unavailable");
    fl_window_free(window);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    if (!gtk_init_check(&argc, &argv)) {
        g_test_message("GTK display unavailable");
        return 77;
    }
    g_test_add_func("/ui/window-states-filters-accessibility",
                    test_window_states_filters_and_accessibility);
    return g_test_run();
}
