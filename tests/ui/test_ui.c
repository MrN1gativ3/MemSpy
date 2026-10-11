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

static bool
has_button_label(GtkWidget *widget, const char *text)
{
    GList *children;
    GList *item;

    if (GTK_IS_BUTTON(widget) && g_strcmp0(gtk_button_get_label(GTK_BUTTON(widget)), text) == 0)
        return true;
    if (!GTK_IS_CONTAINER(widget))
        return false;
    children = gtk_container_get_children(GTK_CONTAINER(widget));
    for (item = children; item != NULL; item = item->next) {
        if (has_button_label(GTK_WIDGET(item->data), text)) {
            g_list_free(children);
            return true;
        }
    }
    g_list_free(children);
    return false;
}

static bool
has_label_text(GtkWidget *widget, const char *text)
{
    GList *children;
    GList *item;

    if (GTK_IS_LABEL(widget) && g_strcmp0(gtk_label_get_text(GTK_LABEL(widget)), text) == 0)
        return true;
    if (!GTK_IS_CONTAINER(widget))
        return false;
    children = gtk_container_get_children(GTK_CONTAINER(widget));
    for (item = children; item != NULL; item = item->next) {
        if (has_label_text(GTK_WIDGET(item->data), text)) {
            g_list_free(children);
            return true;
        }
    }
    g_list_free(children);
    return false;
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
    GtkWidget *titlebar = gtk_window_get_titlebar(ms_window_widget(window));

    g_assert_cmpstr(atk_object_get_name(accessible), ==, "Fileless malware alerts");
    g_assert_cmpstr(gtk_header_bar_get_subtitle(GTK_HEADER_BAR(titlebar)), ==,
                    "Fileless activity monitor");
    g_assert_true(has_button_label(GTK_WIDGET(ms_window_widget(window)), "All 0"));
    ms_window_set_loading(window);
    g_assert_cmpstr(ms_window_status_text(window), ==, "Connecting to detector…");
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)),
                                 "Showing available alert history"));
    ms_window_set_health(window, &degraded);
    g_assert_cmpstr(ms_window_status_text(window), ==, "Monitoring degraded");
    g_assert_true(ms_window_add_alert(window, &medium));
    ms_window_set_filter(window, MS_UI_FILTER_HIGH);
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)),
                                 "No high-severity alerts"));
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)),
                                 "Monitoring the last 30 days"));
    g_assert_true(ms_window_add_alert(window, &high));
    g_assert_false(ms_window_add_alert(window, &high));
    g_assert_true(has_button_label(GTK_WIDGET(ms_window_widget(window)), "All 2"));
    g_assert_true(has_button_label(GTK_WIDGET(ms_window_widget(window)), "High 1"));
    g_assert_true(has_button_label(GTK_WIDGET(ms_window_widget(window)), "Medium 1"));
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)), "Executable"));
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)), "Detection signal"));
    ms_window_set_filter(window, MS_UI_FILTER_ALL);
    g_assert_cmpuint(ms_window_visible_count(window), ==, 2);
    ms_window_set_filter(window, MS_UI_FILTER_HIGH);
    g_assert_cmpuint(ms_window_visible_count(window), ==, 1);
    g_assert_true(ms_window_select_alert(window, 2));
    ms_window_set_filter(window, MS_UI_FILTER_MEDIUM);
    g_assert_cmpuint(ms_window_visible_count(window), ==, 1);
    ms_window_set_offline(window, "Detector unavailable",
                          "MemSpy will reconnect automatically");
    g_assert_cmpstr(ms_window_status_text(window), ==, "Detector unavailable");
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)),
                                 "MemSpy will reconnect automatically"));
    g_assert_true(has_label_text(GTK_WIDGET(ms_window_widget(window)),
                                 "Showing available alert history"));
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
