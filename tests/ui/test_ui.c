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
    g_strlcpy(alert.username, "analyst", sizeof alert.username);
    g_strlcpy(alert.exe, "/memfd:fixture (deleted)", sizeof alert.exe);
    g_strlcpy(alert.cmdline, cmdline, sizeof alert.cmdline);
    g_strlcpy(alert.parent_exe, "/usr/bin/terminal", sizeof alert.parent_exe);
    g_strlcpy(alert.parent_comm, "terminal", sizeof alert.parent_comm);
    g_strlcpy(alert.parent_sha256,
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              sizeof alert.parent_sha256);
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

struct label_search {
    const char *text;
    bool found;
};

static void
find_label_text(GtkWidget *widget, gpointer userdata)
{
    struct label_search *search = userdata;

    if (search->found)
        return;
    if (GTK_IS_LABEL(widget) &&
        g_strcmp0(gtk_label_get_text(GTK_LABEL(widget)), search->text) == 0)
        search->found = true;
    else if (GTK_IS_CONTAINER(widget))
        gtk_container_forall(GTK_CONTAINER(widget), find_label_text, search);
}

static bool
has_label_text(GtkWidget *widget, const char *text)
{
    struct label_search search = {.text = text};

    find_label_text(widget, &search);
    return search.found;
}

struct label_count {
    const char *text;
    unsigned int count;
};

static void
count_label_text(GtkWidget *widget, gpointer userdata)
{
    struct label_count *search = userdata;

    if (GTK_IS_LABEL(widget) &&
        g_strcmp0(gtk_label_get_text(GTK_LABEL(widget)), search->text) == 0)
        ++search->count;
    if (GTK_IS_CONTAINER(widget))
        gtk_container_forall(GTK_CONTAINER(widget), count_label_text, search);
}

static unsigned int
label_text_count(GtkWidget *widget, const char *text)
{
    struct label_count search = {.text = text};

    count_label_text(widget, &search);
    return search.count;
}

struct class_search {
    const char *name;
    unsigned int count;
};

static void
count_style_class(GtkWidget *widget, gpointer userdata)
{
    struct class_search *search = userdata;

    if (gtk_style_context_has_class(gtk_widget_get_style_context(widget), search->name))
        ++search->count;
    if (GTK_IS_CONTAINER(widget))
        gtk_container_forall(GTK_CONTAINER(widget), count_style_class, search);
}

static unsigned int
style_class_count(GtkWidget *widget, const char *name)
{
    struct class_search search = {.name = name};

    count_style_class(widget, &search);
    return search.count;
}

static GtkWidget *
find_switch(GtkWidget *widget)
{
    GList *children;
    GList *item;

    if (GTK_IS_SWITCH(widget))
        return widget;
    if (!GTK_IS_CONTAINER(widget))
        return NULL;
    children = gtk_container_get_children(GTK_CONTAINER(widget));
    for (item = children; item != NULL; item = item->next) {
        GtkWidget *result = find_switch(GTK_WIDGET(item->data));
        if (result != NULL) {
            g_list_free(children);
            return result;
        }
    }
    g_list_free(children);
    return NULL;
}

static GtkWidget *
find_style_class(GtkWidget *widget, const char *name)
{
    GList *children;
    GList *item;

    if (gtk_style_context_has_class(gtk_widget_get_style_context(widget), name))
        return widget;
    if (!GTK_IS_CONTAINER(widget))
        return NULL;
    children = gtk_container_get_children(GTK_CONTAINER(widget));
    for (item = children; item != NULL; item = item->next) {
        GtkWidget *result = find_style_class(GTK_WIDGET(item->data), name);
        if (result != NULL) {
            g_list_free(children);
            return result;
        }
    }
    g_list_free(children);
    return NULL;
}

struct response_calls {
    unsigned int count;
    bool enabled;
};

static void
response_changed(bool enabled, void *userdata)
{
    struct response_calls *calls = userdata;
    ++calls->count;
    calls->enabled = enabled;
}

static void
test_response_switch_states_and_accessibility(void)
{
    struct ms_window *window = ms_window_new(NULL);
    struct response_calls calls = {0};
    struct ms_health health = {
        .state = MS_HEALTH_HEALTHY,
        .protected = true,
        .storage_available = true,
        .response_supported = true,
    };
    GtkWidget *widget = GTK_WIDGET(ms_window_widget(window));
    GtkWidget *control = find_switch(widget);
    AtkObject *accessible;

    g_assert_nonnull(control);
    g_assert_cmpint(gtk_widget_get_valign(control), ==, GTK_ALIGN_CENTER);
    accessible = gtk_widget_get_accessible(control);
    ms_window_set_response_handler(window, response_changed, &calls);

    ms_window_set_health(window, &health);
    g_assert_true(has_label_text(widget, "Off — Detection only"));
    g_assert_false(gtk_switch_get_active(GTK_SWITCH(control)));
    g_assert_true(gtk_widget_get_sensitive(control));
    g_assert_cmpstr(atk_object_get_name(accessible), ==, "Response mode: Off — Detection only");
    AtkStateSet *states = atk_object_ref_state_set(accessible);
    g_assert_false(atk_state_set_contains_state(states, ATK_STATE_CHECKED));
    g_object_unref(states);

    health.response_requested = true;
    health.response_active = true;
    ms_window_set_health(window, &health);
    g_assert_true(has_label_text(widget, "On — Blocking memfd execution"));
    g_assert_true(gtk_switch_get_active(GTK_SWITCH(control)));
    g_assert_cmpuint(calls.count, ==, 0);
    states = atk_object_ref_state_set(accessible);
    g_assert_true(atk_state_set_contains_state(states, ATK_STATE_CHECKED));
    g_object_unref(states);

    ms_window_set_response_pending(window, true);
    g_assert_true(has_label_text(widget, "Pending — Waiting for administrator authentication"));
    g_assert_false(gtk_widget_get_sensitive(control));

    ms_window_set_response_pending(window, false);
    g_assert_true(has_label_text(widget, "On — Blocking memfd execution"));
    g_assert_true(gtk_widget_get_sensitive(control));
    ms_window_set_response_error(window, "Administrator authentication was cancelled");
    g_assert_true(has_label_text(widget, "On — Blocking memfd execution"));
    g_assert_true(has_label_text(widget, "Administrator authentication was cancelled"));
    g_assert_true(gtk_switch_get_active(GTK_SWITCH(control)));

    health.response_supported = false;
    health.response_requested = false;
    health.response_active = false;
    g_strlcpy(health.response_reason, "BPF LSM is not active", sizeof health.response_reason);
    ms_window_set_health(window, &health);
    g_assert_true(has_label_text(widget, "Unavailable — BPF LSM is not active"));
    g_assert_false(gtk_widget_get_sensitive(control));
    g_assert_cmpstr(atk_object_get_name(accessible), ==,
                    "Response mode: Unavailable — BPF LSM is not active");

    health.response_supported = true;
    health.response_reason[0] = '\0';
    ms_window_set_health(window, &health);
    gtk_switch_set_active(GTK_SWITCH(control), true);
    g_assert_cmpuint(calls.count, ==, 1);
    g_assert_true(calls.enabled);
    ms_window_set_response_pending(window, true);
    ms_window_set_response_error(window, "Response mode could not be changed");
    g_assert_true(has_label_text(widget, "Response mode could not be changed"));
    g_assert_false(gtk_switch_get_active(GTK_SWITCH(control)));
    g_assert_cmpuint(calls.count, ==, 1);

    ms_window_free(window);
}

static void
test_wide_window_keeps_dashboard_readable(void)
{
    struct ms_window *window = ms_window_new(NULL);
    GtkWidget *widget = GTK_WIDGET(ms_window_widget(window));
    GtkWidget *content = find_style_class(widget, "memspy-content");
    GtkAllocation allocation;

    g_assert_nonnull(content);
    gtk_widget_show(widget);
    gtk_window_resize(GTK_WINDOW(widget), 1400, 700);
    while (gtk_events_pending())
        gtk_main_iteration();
    gtk_widget_get_allocation(content, &allocation);
    g_assert_cmpint(allocation.width, <=, 960);
    g_assert_cmpint(allocation.width, >=, 400);

    ms_window_free(window);
}

static void
test_alert_outcomes_and_grouped_process_details(void)
{
    struct ms_window *window = ms_window_new(NULL);
    struct ms_alert detected = fixture_alert(1, MS_SEVERITY_MEDIUM, "fixture --detected");
    struct ms_alert blocked = fixture_alert(2, MS_SEVERITY_HIGH,
        "fixture --blocked 'argument with spaces'");
    GtkWidget *widget = GTK_WIDGET(ms_window_widget(window));

    detected.action = MS_ALERT_DETECTED;
    blocked.action = MS_ALERT_BLOCKED;
    blocked.ppid = 99;
    blocked.target_pid = 7331;
    blocked.target_namespace_pid = 31;
    blocked.bytes_written = 64;
    blocked.grandparent_pid = 2;
    blocked.ssh_origin = true;
    blocked.pid_namespace = 101;
    blocked.mount_namespace = 202;
    blocked.arguments_truncated = true;
    g_strlcpy(blocked.launcher_exe, "/usr/bin/loader", sizeof blocked.launcher_exe);
    g_strlcpy(blocked.target_exe, "/memfd:payload", sizeof blocked.target_exe);
    g_strlcpy(blocked.grandparent_comm, "sshd", sizeof blocked.grandparent_comm);
    g_strlcpy(blocked.grandparent_exe, "/usr/sbin/sshd", sizeof blocked.grandparent_exe);
    g_strlcpy(blocked.systemd_unit, "fixture.service", sizeof blocked.systemd_unit);
    g_strlcpy(blocked.cgroup_path, "/system.slice/fixture.service", sizeof blocked.cgroup_path);

    g_assert_true(ms_window_add_alert(window, &detected));
    g_assert_true(ms_window_add_alert(window, &blocked));
    g_assert_true(has_label_text(widget, "Detected"));
    g_assert_true(has_label_text(widget, "Blocked"));
    g_assert_true(has_label_text(widget, "Process details"));
    g_assert_true(has_label_text(widget, "Identity"));
    g_assert_true(has_label_text(widget, "Execution"));
    g_assert_true(has_label_text(widget, "Workload"));
    g_assert_true(has_label_text(widget, "Target"));
    g_assert_true(has_label_text(widget, "Detection"));
    g_assert_true(has_label_text(widget, "User"));
    g_assert_true(has_label_text(widget, "Process"));
    g_assert_true(has_label_text(widget, "Parent process name"));
    g_assert_true(has_label_text(widget, "Parent PID"));
    g_assert_true(has_label_text(widget, "Parent executable"));
    g_assert_true(has_label_text(widget, "Parent SHA-256"));
    g_assert_true(has_label_text(widget, "Grandparent process name"));
    g_assert_true(has_label_text(widget, "SSH origin"));
    g_assert_true(has_label_text(widget, "Systemd unit"));
    g_assert_true(has_label_text(widget, "Cgroup"));
    g_assert_true(has_label_text(widget, "Namespaces"));
    g_assert_true(has_label_text(widget,
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    g_assert_true(has_label_text(widget, "Attempted executable"));
    g_assert_true(has_label_text(widget, "Command line"));
    g_assert_true(has_label_text(widget, "Launcher executable"));
    g_assert_true(has_label_text(widget, "Target PID"));
    g_assert_true(has_label_text(widget, "Target executable"));
    g_assert_true(has_label_text(widget, "Target namespace PID"));
    g_assert_true(has_label_text(widget, "Bytes written"));
    g_assert_true(has_label_text(widget, "Outcome"));
    g_assert_true(has_label_text(widget, "Rule"));
    g_assert_true(has_label_text(widget, "Detection signal"));
    g_assert_true(has_label_text(widget, "Arguments truncated"));
    g_assert_cmpuint(label_text_count(widget, "Target"), ==, 1);
    g_assert_cmpuint(label_text_count(widget, "Launcher executable"), ==, 1);
    g_assert_cmpuint(label_text_count(widget, "Arguments truncated"), ==, 1);
    g_assert_cmpuint(style_class_count(widget, "memspy-outcome-blocked"), ==, 1);
    g_assert_cmpuint(style_class_count(widget, "memspy-outcome-detected"), ==, 1);

    ms_window_free(window);
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
    g_assert_cmpuint(style_class_count(GTK_WIDGET(ms_window_widget(window)),
                                       "memspy-state-icon"), ==, 1);
    g_assert_cmpuint(style_class_count(GTK_WIDGET(ms_window_widget(window)),
                                       "memspy-empty-icon"), ==, 1);
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
    g_assert_cmpuint(style_class_count(GTK_WIDGET(ms_window_widget(window)),
                                       "memspy-alert-icon"), ==, 2);
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
    g_test_add_func("/ui/response-switch-states-accessibility",
                    test_response_switch_states_and_accessibility);
    g_test_add_func("/ui/wide-window-readable-width",
                    test_wide_window_keeps_dashboard_readable);
    g_test_add_func("/ui/alert-outcomes-grouped-process-details",
                    test_alert_outcomes_and_grouped_process_details);
    return g_test_run();
}
