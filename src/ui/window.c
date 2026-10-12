#include "window.h"

#include <stdio.h>
#include <string.h>

#define MS_UI_MAX_CONTENT_WIDTH 960

struct alert_view {
    struct ms_alert alert;
    GtkWidget *row;
};

struct ms_window {
    GtkWidget *window;
    GtkWidget *status_box;
    GtkWidget *status_icon;
    GtkWidget *status_label;
    GtkWidget *status_detail;
    GtkWidget *spinner;
    GtkWidget *response_switch;
    GtkWidget *response_label;
    GtkWidget *response_error;
    GtkWidget *list;
    GtkWidget *empty_box;
    GtkWidget *empty_title;
    GtkWidget *empty_detail;
    GtkWidget *filter_buttons[3];
    GPtrArray *alerts;
    enum ms_ui_filter filter;
    bool monitoring;
    bool response_connected;
    bool response_supported;
    bool response_active;
    bool response_pending;
    bool setting_response;
    char response_reason[256];
    void (*response_handler)(bool enabled, void *userdata);
    void *response_userdata;
};

static void
add_class(GtkWidget *widget, const char *name)
{
    gtk_style_context_add_class(gtk_widget_get_style_context(widget), name);
}

static void
constrain_content_width(GtkWidget *widget, GtkAllocation *allocation, gpointer userdata)
{
    GtkWidget *content = userdata;
    int margin = MAX((allocation->width - MS_UI_MAX_CONTENT_WIDTH) / 2, 0);

    (void)widget;
    if (gtk_widget_get_margin_start(content) != margin) {
        gtk_widget_set_margin_start(content, margin);
        gtk_widget_set_margin_end(content, margin);
    }
}

static gboolean
filter_row(GtkListBoxRow *row, gpointer userdata)
{
    struct ms_window *window = userdata;
    const struct alert_view *view = g_object_get_data(G_OBJECT(row), "memspy-alert");
    if (window->filter == MS_UI_FILTER_ALL)
        return true;
    if (window->filter == MS_UI_FILTER_HIGH)
        return view->alert.severity == MS_SEVERITY_HIGH;
    return view->alert.severity == MS_SEVERITY_MEDIUM;
}

static gint
sort_rows(GtkListBoxRow *left, GtkListBoxRow *right, gpointer userdata)
{
    const struct alert_view *a = g_object_get_data(G_OBJECT(left), "memspy-alert");
    const struct alert_view *b = g_object_get_data(G_OBJECT(right), "memspy-alert");
    (void)userdata;
    return a->alert.id < b->alert.id ? 1 : a->alert.id > b->alert.id ? -1 : 0;
}

static void
update_empty_state(struct ms_window *window)
{
    static const char *titles[] = {
        "No alerts detected",
        "No high-severity alerts",
        "No medium-severity alerts",
    };
    const char *title = titles[window->filter];

    gtk_label_set_text(GTK_LABEL(window->empty_title), title);
    gtk_label_set_text(GTK_LABEL(window->empty_detail), window->monitoring ?
                       "Monitoring the last 30 days" : "Showing available alert history");
    atk_object_set_name(gtk_widget_get_accessible(window->empty_box), title);
}

static void
filter_toggled(GtkToggleButton *button, gpointer userdata)
{
    struct ms_window *window = userdata;
    if (!gtk_toggle_button_get_active(button))
        return;
    window->filter = (enum ms_ui_filter)GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(button), "memspy-filter"));
    if (window->list != NULL)
        gtk_list_box_invalidate_filter(GTK_LIST_BOX(window->list));
    update_empty_state(window);
}

static GtkWidget *
new_wrapping_label(const char *text)
{
    GtkWidget *label = gtk_label_new(text);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0F);
    gtk_label_set_line_wrap(GTK_LABEL(label), true);
    gtk_label_set_line_wrap_mode(GTK_LABEL(label), PANGO_WRAP_WORD_CHAR);
    return label;
}

static GtkWidget *
new_detail_field(const char *title, const char *value, bool technical)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *heading = new_wrapping_label(title);
    GtkWidget *content = new_wrapping_label(value);

    add_class(heading, "memspy-detail-label");
    add_class(content, "memspy-detail-value");
    if (technical)
        add_class(content, "memspy-rule-id");
    gtk_label_set_selectable(GTK_LABEL(content), true);
    gtk_box_pack_start(GTK_BOX(box), heading, false, false, 0);
    gtk_box_pack_start(GTK_BOX(box), content, false, false, 0);
    return box;
}

static void
add_detail_field(GtkWidget *box, const char *title, const char *value, bool technical)
{
    if (value != NULL && value[0] != '\0')
        gtk_box_pack_start(GTK_BOX(box), new_detail_field(title, value, technical),
                           false, false, 0);
}

static GtkWidget *
new_detail_section(const char *title)
{
    GtkWidget *label = new_wrapping_label(title);

    add_class(label, "memspy-detail-section");
    return label;
}

static void
update_filter_labels(struct ms_window *window)
{
    size_t high = 0;
    size_t medium = 0;
    char label[32];

    for (guint index = 0; index < window->alerts->len; ++index) {
        const struct alert_view *view = g_ptr_array_index(window->alerts, index);
        if (view->alert.severity == MS_SEVERITY_HIGH)
            ++high;
        else
            ++medium;
    }
    snprintf(label, sizeof label, "All %u", window->alerts->len);
    gtk_button_set_label(GTK_BUTTON(window->filter_buttons[0]), label);
    snprintf(label, sizeof label, "High %zu", high);
    gtk_button_set_label(GTK_BUTTON(window->filter_buttons[1]), label);
    snprintf(label, sizeof label, "Medium %zu", medium);
    gtk_button_set_label(GTK_BUTTON(window->filter_buttons[2]), label);
}

static GtkWidget *
create_alert_row(struct alert_view *view)
{
    const char *severity = view->alert.severity == MS_SEVERITY_HIGH ? "High" : "Medium";
    const bool blocked = view->alert.action == MS_ALERT_BLOCKED;
    const char *outcome = blocked ? "Blocked" : "Detected";
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *heading = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *severity_icon = gtk_image_new_from_icon_name(
        view->alert.severity == MS_SEVERITY_HIGH ?
        "memspy-high-symbolic" : "memspy-medium-symbolic", GTK_ICON_SIZE_BUTTON);
    GtkWidget *severity_label = gtk_label_new(severity);
    GtkWidget *outcome_label = gtk_label_new(outcome);
    GtkWidget *rule_label = gtk_label_new(view->alert.rule_id);
    GtkWidget *timestamp;
    GtkWidget *explanation = new_wrapping_label(view->alert.explanation);
    GtkWidget *process;
    GtkWidget *expander = gtk_expander_new("Process details");
    GtkWidget *details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GDateTime *date = g_date_time_new_from_unix_local(view->alert.timestamp_utc);
    char *time_text = date == NULL ? g_strdup("Time unavailable") :
        g_date_time_format(date, "%x · %X");
    char process_text[256];
    char user_text[MS_USERNAME_BYTES + 64U];
    char parent_pid[32];
    char grandparent_pid[32];
    char target_pid[32];
    char target_namespace_pid[32];
    char namespace_text[96];
    char bytes_written[32];
    char accessible_name[256];

    snprintf(process_text, sizeof process_text, "%s · PID %d", view->alert.comm, view->alert.pid);
    process = new_wrapping_label(process_text);
    timestamp = gtk_label_new(time_text);
    gtk_label_set_xalign(GTK_LABEL(timestamp), 1.0F);
    add_class(timestamp, "memspy-timestamp");
    if (date != NULL)
        g_date_time_unref(date);
    g_free(time_text);
    add_class(severity_icon, "memspy-alert-icon");
    atk_object_set_role(gtk_widget_get_accessible(severity_icon), ATK_ROLE_REDUNDANT_OBJECT);
    add_class(severity_label, "memspy-severity");
    add_class(outcome_label, "memspy-outcome");
    add_class(outcome_label, blocked ? "memspy-outcome-blocked" : "memspy-outcome-detected");
    add_class(rule_label, "memspy-rule-id");
    gtk_label_set_xalign(GTK_LABEL(severity_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(outcome_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(rule_label), 0.0F);
    gtk_box_pack_start(GTK_BOX(heading), severity_icon, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), severity_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), outcome_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), rule_label, true, true, 0);
    gtk_box_pack_end(GTK_BOX(heading), timestamp, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), heading, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), explanation, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), process, false, false, 0);

    gtk_box_pack_start(GTK_BOX(details), new_detail_section("Identity"), false, false, 0);
    if (view->alert.username[0] != '\0')
        snprintf(user_text, sizeof user_text, "%s · UID %u", view->alert.username,
                 (unsigned int)view->alert.uid);
    else
        snprintf(user_text, sizeof user_text, "UID %u", (unsigned int)view->alert.uid);
    add_detail_field(details, "User", user_text, false);
    add_detail_field(details, "Process", process_text, true);
    add_detail_field(details, "Parent process name", view->alert.parent_comm, true);
    if (view->alert.ppid > 0) {
        snprintf(parent_pid, sizeof parent_pid, "%d", view->alert.ppid);
        add_detail_field(details, "Parent PID", parent_pid, true);
    }
    add_detail_field(details, "Parent executable", view->alert.parent_exe, true);
    add_detail_field(details, "Parent SHA-256", view->alert.parent_sha256, true);
    add_detail_field(details, "Grandparent process name", view->alert.grandparent_comm, true);
    if (view->alert.grandparent_pid > 0) {
        snprintf(grandparent_pid, sizeof grandparent_pid, "%d", view->alert.grandparent_pid);
        add_detail_field(details, "Grandparent PID", grandparent_pid, true);
    }
    add_detail_field(details, "Grandparent executable", view->alert.grandparent_exe, true);
    add_detail_field(details, "TTY", view->alert.tty, true);
    if (view->alert.ssh_origin)
        add_detail_field(details, "SSH origin", "Yes", false);

    gtk_box_pack_start(GTK_BOX(details), new_detail_section("Execution"), false, false, 0);
    add_detail_field(details, blocked ? "Attempted executable" : "Executable",
                     view->alert.exe, true);
    add_detail_field(details, "Command line", view->alert.cmdline, true);
    if (blocked)
        add_detail_field(details, "Launcher executable", view->alert.launcher_exe, true);

    if (view->alert.systemd_unit[0] != '\0' || view->alert.cgroup_path[0] != '\0' ||
        view->alert.container_id[0] != '\0' || view->alert.pid_namespace != 0 ||
        view->alert.mount_namespace != 0) {
        gtk_box_pack_start(GTK_BOX(details), new_detail_section("Workload"), false, false, 0);
        add_detail_field(details, "Systemd unit", view->alert.systemd_unit, true);
        if (view->alert.container_id[0] != '\0') {
            char container[MS_CONTAINER_ID_BYTES + MS_CONTAINER_RUNTIME_BYTES + 8U];
            snprintf(container, sizeof container, "%s%s%s", view->alert.container_id,
                     view->alert.container_runtime[0] == '\0' ? "" : " · ",
                     view->alert.container_runtime);
            add_detail_field(details, "Container", container, true);
        }
        add_detail_field(details, "Cgroup", view->alert.cgroup_path, true);
        snprintf(namespace_text, sizeof namespace_text, "PID %llu · mount %llu",
                 (unsigned long long)view->alert.pid_namespace,
                 (unsigned long long)view->alert.mount_namespace);
        add_detail_field(details, "Namespaces", namespace_text, true);
    }

    if (view->alert.target_pid > 0 || view->alert.target_namespace_pid > 0 ||
        view->alert.target_exe[0] != '\0' || view->alert.bytes_written > 0) {
        gtk_box_pack_start(GTK_BOX(details), new_detail_section("Target"), false, false, 0);
        if (view->alert.target_pid > 0) {
            snprintf(target_pid, sizeof target_pid, "%d", view->alert.target_pid);
            add_detail_field(details, "Target PID", target_pid, true);
        }
        if (view->alert.target_namespace_pid > 0) {
            snprintf(target_namespace_pid, sizeof target_namespace_pid, "%d",
                     view->alert.target_namespace_pid);
            add_detail_field(details, "Target namespace PID", target_namespace_pid, true);
        }
        add_detail_field(details, "Target executable", view->alert.target_exe, true);
        if (view->alert.bytes_written > 0) {
            snprintf(bytes_written, sizeof bytes_written, "%llu",
                     (unsigned long long)view->alert.bytes_written);
            add_detail_field(details, "Bytes written", bytes_written, true);
        }
    }

    gtk_box_pack_start(GTK_BOX(details), new_detail_section("Detection"), false, false, 0);
    add_detail_field(details, "Outcome", outcome, false);
    add_detail_field(details, "Rule", view->alert.rule_id, true);
    add_detail_field(details, "Detection signal", view->alert.evidence, false);
    if (view->alert.arguments_truncated)
        add_detail_field(details, "Arguments truncated",
                         "Yes — captured command line is incomplete", false);
    if (view->alert.enrichment_incomplete)
        add_detail_field(details, "Evidence completeness",
                         "Some process details were unavailable", false);
    gtk_container_add(GTK_CONTAINER(expander), details);
    gtk_box_pack_start(GTK_BOX(content), expander, false, false, 0);
    gtk_container_add(GTK_CONTAINER(row), content);
    add_class(row, "memspy-alert-row");
    add_class(row, view->alert.severity == MS_SEVERITY_HIGH ?
              "memspy-health-high" : "memspy-health-medium");
    snprintf(accessible_name, sizeof accessible_name, "%s %s alert, %s, process %s",
             outcome, severity, view->alert.rule_id, view->alert.comm);
    atk_object_set_name(gtk_widget_get_accessible(row), accessible_name);
    return row;
}

static void
update_response_control(struct ms_window *window)
{
    char text[384];
    char accessible_name[416];
    const char *name;

    if (window->response_pending)
        name = "Pending — Waiting for administrator authentication";
    else if (!window->response_connected)
        name = "Unavailable — Detector is disconnected";
    else if (!window->response_supported) {
        snprintf(text, sizeof text, "Unavailable — %s",
                 window->response_reason[0] == '\0' ?
                 "Response mode is not supported" : window->response_reason);
        name = text;
    } else if (window->response_active)
        name = "On — Blocking memfd execution";
    else
        name = "Off — Detection only";

    gtk_label_set_text(GTK_LABEL(window->response_label), name);
    window->setting_response = true;
    gtk_switch_set_active(GTK_SWITCH(window->response_switch), window->response_active);
    window->setting_response = false;
    gtk_widget_set_sensitive(window->response_switch,
                             window->response_connected && window->response_supported &&
                             !window->response_pending);
    snprintf(accessible_name, sizeof accessible_name, "Response mode: %s", name);
    atk_object_set_name(gtk_widget_get_accessible(window->response_switch), accessible_name);
}

static void
response_toggled(GObject *object, GParamSpec *parameter, gpointer userdata)
{
    struct ms_window *window = userdata;

    (void)parameter;
    if (!window->setting_response && window->response_handler != NULL)
        window->response_handler(gtk_switch_get_active(GTK_SWITCH(object)),
                                 window->response_userdata);
}

static GtkWidget *
create_filters(struct ms_window *window)
{
    static const char *labels[] = {"All", "High", "Medium"};
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GSList *group = NULL;
    for (unsigned int index = 0; index < 3; ++index) {
        GtkWidget *button = gtk_radio_button_new_with_label(group, labels[index]);
        group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(button));
        g_object_set_data(G_OBJECT(button), "memspy-filter", GINT_TO_POINTER(index));
        g_signal_connect(button, "toggled", G_CALLBACK(filter_toggled), window);
        gtk_toggle_button_set_mode(GTK_TOGGLE_BUTTON(button), false);
        add_class(button, "memspy-filter-button");
        gtk_box_pack_start(GTK_BOX(box), button, false, false, 0);
        window->filter_buttons[index] = button;
    }
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(window->filter_buttons[0]), true);
    add_class(box, "memspy-filters");
    update_filter_labels(window);
    atk_object_set_name(gtk_widget_get_accessible(box), "Alert severity filter");
    return box;
}

struct ms_window *
ms_window_new(GtkApplication *application)
{
    struct ms_window *window = g_new0(struct ms_window, 1);
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *filters;
    GtkWidget *scroller = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *placeholder_icon = gtk_image_new_from_icon_name("security-high-symbolic",
                                                               GTK_ICON_SIZE_DIALOG);
    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *detector_row;
    GtkWidget *response_row;
    GtkWidget *response_box;

    window->window = application == NULL ? gtk_window_new(GTK_WINDOW_TOPLEVEL) :
        gtk_application_window_new(application);
    window->alerts = g_ptr_array_new_with_free_func(g_free);
    window->filter = MS_UI_FILTER_ALL;
    window->empty_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    window->empty_title = gtk_label_new("");
    window->empty_detail = gtk_label_new("");
    gtk_window_set_title(GTK_WINDOW(window->window), "MemSpy");
    gtk_window_set_default_size(GTK_WINDOW(window->window), 440, 560);
    gtk_window_set_titlebar(GTK_WINDOW(window->window), header);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "MemSpy");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "Fileless activity monitor");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), true);
    atk_object_set_name(gtk_widget_get_accessible(window->window), "Fileless malware alerts");
    add_class(window->window, "memspy-window");

    window->status_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    detector_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    response_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    window->status_icon = gtk_image_new_from_icon_name("memspy-offline-symbolic",
                                                       GTK_ICON_SIZE_BUTTON);
    add_class(window->status_icon, "memspy-state-icon");
    window->spinner = gtk_spinner_new();
    GtkWidget *status_copy = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    window->status_label = gtk_label_new("");
    window->status_detail = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(window->status_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(window->status_detail), 0.0F);
    gtk_label_set_line_wrap(GTK_LABEL(window->status_detail), true);
    add_class(window->status_label, "memspy-status-title");
    add_class(window->status_detail, "memspy-status-detail");
    gtk_box_pack_start(GTK_BOX(status_copy), window->status_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(status_copy), window->status_detail, false, false, 0);
    gtk_box_pack_start(GTK_BOX(detector_row), window->status_icon, false, false, 0);
    gtk_box_pack_start(GTK_BOX(detector_row), window->spinner, false, false, 0);
    gtk_box_pack_start(GTK_BOX(detector_row), status_copy, true, true, 0);
    response_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *response_title = gtk_label_new("Response mode");
    window->response_label = gtk_label_new("");
    window->response_error = gtk_label_new("");
    window->response_switch = gtk_switch_new();
    gtk_widget_set_valign(window->response_switch, GTK_ALIGN_CENTER);
    gtk_label_set_xalign(GTK_LABEL(response_title), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(window->response_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(window->response_error), 0.0F);
    gtk_label_set_line_wrap(GTK_LABEL(window->response_label), true);
    gtk_label_set_line_wrap(GTK_LABEL(window->response_error), true);
    gtk_widget_set_size_request(window->response_error, -1, 34);
    add_class(response_title, "memspy-response-title");
    add_class(window->response_label, "memspy-response-state");
    add_class(window->response_error, "memspy-response-error");
    gtk_box_pack_start(GTK_BOX(response_box), response_title, false, false, 0);
    gtk_box_pack_start(GTK_BOX(response_box), window->response_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(response_box), window->response_error, false, false, 0);
    gtk_box_pack_start(GTK_BOX(response_row), response_box, true, true, 0);
    gtk_box_pack_end(GTK_BOX(response_row), window->response_switch, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), detector_row, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), response_row, false, false, 0);
    g_signal_connect(window->response_switch, "notify::active",
                     G_CALLBACK(response_toggled), window);
    add_class(window->status_box, "memspy-status-banner");
    atk_object_set_name(gtk_widget_get_accessible(window->status_box), "Detector status");

    filters = create_filters(window);
    add_class(root, "memspy-content");
    add_class(placeholder_icon, "memspy-empty-icon");
    add_class(window->empty_title, "memspy-empty-title");
    add_class(window->empty_detail, "memspy-empty-detail");
    gtk_box_pack_start(GTK_BOX(window->empty_box), placeholder_icon, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->empty_box), window->empty_title, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->empty_box), window->empty_detail, false, false, 0);
    window->list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(window->list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_filter_func(GTK_LIST_BOX(window->list), filter_row, window, NULL);
    gtk_list_box_set_sort_func(GTK_LIST_BOX(window->list), sort_rows, window, NULL);
    gtk_list_box_set_placeholder(GTK_LIST_BOX(window->list), window->empty_box);
    atk_object_set_name(gtk_widget_get_accessible(window->list), "Detected alerts");
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroller),
                                   GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_overlay_scrolling(GTK_SCROLLED_WINDOW(scroller), false);
    gtk_container_add(GTK_CONTAINER(scroller), window->list);
    gtk_box_pack_start(GTK_BOX(root), window->status_box, false, false, 0);
    gtk_box_pack_start(GTK_BOX(root), filters, false, false, 0);
    gtk_box_pack_start(GTK_BOX(root), scroller, true, true, 0);
    gtk_container_set_border_width(GTK_CONTAINER(root), 12);
    gtk_container_add(GTK_CONTAINER(window->window), root);
    g_signal_connect(window->window, "size-allocate",
                     G_CALLBACK(constrain_content_width), root);
    ms_window_set_loading(window);
    update_empty_state(window);
    gtk_widget_show_all(root);
    return window;
}

GtkWindow *
ms_window_widget(struct ms_window *window)
{
    return window == NULL ? NULL : GTK_WINDOW(window->window);
}

void
ms_window_set_loading(struct ms_window *window)
{
    if (window == NULL)
        return;
    window->monitoring = false;
    window->response_connected = false;
    gtk_label_set_text(GTK_LABEL(window->status_label), "Connecting to detector…");
    gtk_label_set_text(GTK_LABEL(window->status_detail),
                       "Establishing a secure local connection");
    gtk_image_set_from_icon_name(GTK_IMAGE(window->status_icon), "memspy-offline-symbolic",
                                 GTK_ICON_SIZE_BUTTON);
    gtk_spinner_start(GTK_SPINNER(window->spinner));
    add_class(window->status_box, "memspy-health-offline");
    gtk_label_set_text(GTK_LABEL(window->response_error), "");
    update_response_control(window);
    update_empty_state(window);
}

static void
set_status(struct ms_window *window, const char *text, const char *detail,
           const char *icon, const char *style)
{
    GtkStyleContext *context = gtk_widget_get_style_context(window->status_box);
    static const char *classes[] = {
        "memspy-health-healthy", "memspy-health-medium",
        "memspy-health-high", "memspy-health-offline",
    };
    for (unsigned int index = 0; index < G_N_ELEMENTS(classes); ++index)
        gtk_style_context_remove_class(context, classes[index]);
    gtk_style_context_add_class(context, style);
    gtk_spinner_stop(GTK_SPINNER(window->spinner));
    gtk_label_set_text(GTK_LABEL(window->status_label), text);
    gtk_label_set_text(GTK_LABEL(window->status_detail), detail);
    gtk_image_set_from_icon_name(GTK_IMAGE(window->status_icon), icon, GTK_ICON_SIZE_BUTTON);
}

void
ms_window_set_health(struct ms_window *window, const struct ms_health *health)
{
    if (window == NULL || health == NULL)
        return;
    window->monitoring = health->state != MS_HEALTH_FAILED;
    window->response_connected = true;
    window->response_supported = health->response_supported;
    window->response_active = health->response_active;
    g_strlcpy(window->response_reason, health->response_reason,
              sizeof window->response_reason);
    gtk_label_set_text(GTK_LABEL(window->response_error), "");
    if (health->state == MS_HEALTH_HEALTHY && health->protected)
        set_status(window, "Monitoring active", "Kernel probes and alert storage are healthy",
                   "memspy-healthy-symbolic", "memspy-health-healthy");
    else if (health->state == MS_HEALTH_FAILED)
        set_status(window, "Monitoring failed", "Detection is currently unavailable",
                   "memspy-offline-symbolic", "memspy-health-offline");
    else
        set_status(window, "Monitoring degraded", "Detection continues with reduced coverage",
                   "memspy-medium-symbolic", "memspy-health-medium");
    update_response_control(window);
    update_empty_state(window);
}

void
ms_window_set_offline(struct ms_window *window, const char *message, const char *detail)
{
    if (window == NULL)
        return;
    window->monitoring = false;
    window->response_connected = false;
    set_status(window, message == NULL ? "Detector unavailable" : message,
               detail == NULL ? "Detection is currently unavailable" : detail,
               "memspy-offline-symbolic", "memspy-health-offline");
    gtk_label_set_text(GTK_LABEL(window->response_error), "");
    update_response_control(window);
    update_empty_state(window);
}

void
ms_window_set_response_handler(struct ms_window *window,
                               void (*handler)(bool enabled, void *userdata),
                               void *userdata)
{
    if (window == NULL)
        return;
    window->response_handler = handler;
    window->response_userdata = userdata;
}

void
ms_window_set_response_pending(struct ms_window *window, bool pending)
{
    if (window == NULL)
        return;
    window->response_pending = pending;
    if (pending)
        gtk_label_set_text(GTK_LABEL(window->response_error), "");
    update_response_control(window);
}

void
ms_window_set_response_error(struct ms_window *window, const char *message)
{
    if (window == NULL)
        return;
    window->response_pending = false;
    gtk_label_set_text(GTK_LABEL(window->response_error), message == NULL ? "" : message);
    update_response_control(window);
}

const char *
ms_window_status_text(const struct ms_window *window)
{
    return window == NULL ? NULL : gtk_label_get_text(GTK_LABEL(window->status_label));
}

bool
ms_window_add_alert(struct ms_window *window, const struct ms_alert *alert)
{
    struct alert_view *view;
    if (window == NULL || alert == NULL || alert->id < 0 ||
        (alert->id == 0 && alert->observed_boottime_ns == 0))
        return false;
    for (guint index = 0; index < window->alerts->len; ++index) {
        const struct alert_view *existing = g_ptr_array_index(window->alerts, index);
        if ((alert->id > 0 && existing->alert.id == alert->id) ||
            (existing->alert.observed_boottime_ns == alert->observed_boottime_ns &&
             existing->alert.pid == alert->pid &&
             strcmp(existing->alert.rule_id, alert->rule_id) == 0))
            return false;
    }
    view = g_new0(struct alert_view, 1);
    view->alert = *alert;
    view->row = create_alert_row(view);
    g_object_set_data(G_OBJECT(view->row), "memspy-alert", view);
    g_ptr_array_add(window->alerts, view);
    gtk_container_add(GTK_CONTAINER(window->list), view->row);
    gtk_widget_show_all(view->row);
    gtk_list_box_invalidate_sort(GTK_LIST_BOX(window->list));
    gtk_list_box_invalidate_filter(GTK_LIST_BOX(window->list));
    update_filter_labels(window);
    return true;
}

void
ms_window_set_filter(struct ms_window *window, enum ms_ui_filter filter)
{
    if (window == NULL || filter < MS_UI_FILTER_ALL || filter > MS_UI_FILTER_MEDIUM)
        return;
    window->filter = filter;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(window->filter_buttons[filter]), true);
    gtk_list_box_invalidate_filter(GTK_LIST_BOX(window->list));
}

size_t
ms_window_visible_count(const struct ms_window *window)
{
    size_t count = 0;
    if (window == NULL)
        return 0;
    for (guint index = 0; index < window->alerts->len; ++index) {
        const struct alert_view *view = g_ptr_array_index(window->alerts, index);
        if (window->filter == MS_UI_FILTER_ALL ||
            (window->filter == MS_UI_FILTER_HIGH && view->alert.severity == MS_SEVERITY_HIGH) ||
            (window->filter == MS_UI_FILTER_MEDIUM && view->alert.severity == MS_SEVERITY_MEDIUM))
            ++count;
    }
    return count;
}

bool
ms_window_select_alert(struct ms_window *window, int64_t alert_id)
{
    if (window == NULL)
        return false;
    for (guint index = 0; index < window->alerts->len; ++index) {
        const struct alert_view *view = g_ptr_array_index(window->alerts, index);
        if (view->alert.id == alert_id) {
            ms_window_set_filter(window, MS_UI_FILTER_ALL);
            gtk_list_box_select_row(GTK_LIST_BOX(window->list), GTK_LIST_BOX_ROW(view->row));
            gtk_widget_grab_focus(view->row);
            return true;
        }
    }
    return false;
}

void
ms_window_present(struct ms_window *window)
{
    if (window == NULL)
        return;
    gtk_widget_show_all(window->window);
    gtk_window_present(GTK_WINDOW(window->window));
}

void
ms_window_free(struct ms_window *window)
{
    if (window == NULL)
        return;
    gtk_widget_destroy(window->window);
    g_ptr_array_free(window->alerts, true);
    g_free(window);
}
