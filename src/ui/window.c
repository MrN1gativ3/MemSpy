#include "window.h"

#include <stdio.h>
#include <string.h>

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

struct detail_section {
    GtkWidget *container;
    GtkWidget *grid;
    int row;
};

static GtkWidget *
new_summary_item(const char *title, const char *value, bool technical)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *heading = gtk_label_new(title);
    GtkWidget *content = gtk_label_new(value);

    gtk_label_set_xalign(GTK_LABEL(heading), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(content), 0.0F);
    gtk_label_set_ellipsize(GTK_LABEL(content), PANGO_ELLIPSIZE_END);
    gtk_widget_set_tooltip_text(content, value);
    add_class(box, "memspy-summary-item");
    add_class(heading, "memspy-summary-label");
    add_class(content, "memspy-summary-value");
    if (technical)
        add_class(content, "memspy-rule-id");
    gtk_box_pack_start(GTK_BOX(box), heading, false, false, 0);
    gtk_box_pack_start(GTK_BOX(box), content, false, false, 0);
    return box;
}

static struct detail_section
new_detail_section(const char *title)
{
    struct detail_section section = {0};
    GtkWidget *title_label = gtk_label_new(title);

    section.container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    section.grid = gtk_grid_new();
    gtk_label_set_xalign(GTK_LABEL(title_label), 0.0F);
    gtk_grid_set_column_spacing(GTK_GRID(section.grid), 12);
    gtk_grid_set_row_spacing(GTK_GRID(section.grid), 6);
    gtk_widget_set_hexpand(section.container, true);
    gtk_widget_set_size_request(section.container, 280, -1);
    add_class(section.container, "memspy-detail-section");
    add_class(title_label, "memspy-section-title");
    gtk_box_pack_start(GTK_BOX(section.container), title_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(section.container), section.grid, false, false, 0);
    return section;
}

static GtkWidget *
add_detail_field(struct detail_section *section, const char *title, const char *value,
                 bool technical)
{
    GtkWidget *heading;
    GtkWidget *content;

    if (value == NULL || value[0] == '\0')
        return NULL;
    heading = new_wrapping_label(title);
    content = new_wrapping_label(value);
    gtk_widget_set_halign(heading, GTK_ALIGN_START);
    gtk_widget_set_valign(heading, GTK_ALIGN_START);
    gtk_widget_set_hexpand(content, true);
    gtk_label_set_selectable(GTK_LABEL(content), true);
    gtk_widget_set_tooltip_text(content, value);
    add_class(heading, "memspy-detail-label");
    add_class(content, "memspy-detail-value");
    if (technical)
        add_class(content, "memspy-rule-id");
    gtk_grid_attach(GTK_GRID(section->grid), heading, 0, section->row, 1, 1);
    gtk_grid_attach(GTK_GRID(section->grid), content, 1, section->row, 1, 1);
    ++section->row;
    return content;
}

static const char *
hash_status_text(enum ms_hash_status status)
{
    switch (status) {
    case MS_HASH_COMPLETE: return "Hash complete";
    case MS_HASH_PROCESS_EXITED: return "Process exited before hashing";
    case MS_HASH_IMAGE_UNAVAILABLE: return "Executable image was unavailable";
    case MS_HASH_NO_FILESYSTEM_PATH: return "No filesystem path is available";
    case MS_HASH_TOO_LARGE: return "Image exceeds the 128 MiB hash limit";
    case MS_HASH_READ_ERROR: return "Executable image could not be read";
    case MS_HASH_IDENTITY_CHANGED: return "Process identity changed before hashing";
    case MS_HASH_BLOCKED_BEFORE_OPEN: return "Blocked before executable image opened";
    case MS_HASH_NOT_COLLECTED: return "Not collected";
    }
    return "Not collected";
}

static void
add_evidence_group(struct detail_section *section, const char *title, const char *path,
                   const char *md5, const char *sha256, enum ms_hash_status status)
{
    GtkWidget *heading;

    if ((path == NULL || path[0] == '\0') && (md5 == NULL || md5[0] == '\0') &&
        (sha256 == NULL || sha256[0] == '\0') && status == MS_HASH_NOT_COLLECTED)
        return;
    heading = new_wrapping_label(title);
    add_class(heading, "memspy-evidence-role");
    gtk_grid_attach(GTK_GRID(section->grid), heading, 0, section->row++, 2, 1);
    add_detail_field(section, "Path",
                     path == NULL || path[0] == '\0' ? "Unavailable" : path, true);
    add_detail_field(section, "MD5", md5, true);
    add_detail_field(section, "SHA-256", sha256, true);
    add_detail_field(section, "Collection status", hash_status_text(status), false);
}

static bool
is_exec_rule(const char *rule)
{
    return strstr(rule, "MEMFD_EXEC") != NULL || strstr(rule, "DELETED_EXEC") != NULL ||
           strcmp(rule, "INJECTION_CHAIN") == 0;
}

static void
incident_details_toggled(GtkToggleButton *button, gpointer userdata)
{
    GtkRevealer *details = userdata;
    const bool expanded = gtk_toggle_button_get_active(button);
    const char *name = expanded ? "Hide incident details" : "View incident details";

    gtk_button_set_image(GTK_BUTTON(button), gtk_image_new_from_icon_name(
        expanded ? "pan-up-symbolic" : "pan-down-symbolic", GTK_ICON_SIZE_BUTTON));
    gtk_widget_set_tooltip_text(GTK_WIDGET(button), name);
    atk_object_set_name(gtk_widget_get_accessible(GTK_WIDGET(button)), name);
    gtk_revealer_set_reveal_child(details, expanded);
}

static void
hide_incident_details(GtkButton *button, gpointer userdata)
{
    (void)button;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(userdata), false);
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
    snprintf(label, sizeof label, "All (%u)", window->alerts->len);
    gtk_button_set_label(GTK_BUTTON(window->filter_buttons[0]), label);
    snprintf(label, sizeof label, "High (%zu)", high);
    gtk_button_set_label(GTK_BUTTON(window->filter_buttons[1]), label);
    snprintf(label, sizeof label, "Medium (%zu)", medium);
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
    GtkWidget *explanation = new_wrapping_label(view->alert.explanation[0] == '\0' ?
                                                "Description unavailable" :
                                                view->alert.explanation);
    GtkWidget *summary = gtk_flow_box_new();
    GtkWidget *details_button = gtk_toggle_button_new();
    GtkWidget *details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    GtkWidget *details_grid = gtk_flow_box_new();
    GtkWidget *hide_button = gtk_button_new_with_label("Hide incident details ↑");
    GtkWidget *details_revealer = gtk_revealer_new();
    struct detail_section identity = new_detail_section("Identity");
    struct detail_section execution = new_detail_section("Execution");
    struct detail_section detection = new_detail_section("Detection");
    struct detail_section evidence = new_detail_section("Evidence");
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
    char alert_id[32];
    char accessible_name[256];
    char container[MS_CONTAINER_ID_BYTES + MS_CONTAINER_RUNTIME_BYTES + 8U];
    GtkWidget *outcome_value;

    snprintf(process_text, sizeof process_text, "%s · PID %d",
             view->alert.comm[0] == '\0' ? "Unavailable" : view->alert.comm,
             view->alert.pid);
    if (view->alert.username[0] != '\0')
        snprintf(user_text, sizeof user_text, "%s · UID %u", view->alert.username,
                 (unsigned int)view->alert.uid);
    else
        snprintf(user_text, sizeof user_text, "UID %u", (unsigned int)view->alert.uid);
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
    gtk_label_set_ellipsize(GTK_LABEL(rule_label), PANGO_ELLIPSIZE_END);
    gtk_widget_set_tooltip_text(rule_label, view->alert.rule_id);
    gtk_label_set_selectable(GTK_LABEL(rule_label), true);
    gtk_label_set_xalign(GTK_LABEL(severity_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(outcome_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(rule_label), 0.0F);
    gtk_box_pack_start(GTK_BOX(heading), severity_icon, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), severity_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), outcome_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), rule_label, true, true, 0);
    add_class(details_button, "memspy-expand-button");
    gtk_button_set_relief(GTK_BUTTON(details_button), GTK_RELIEF_NONE);
    gtk_button_set_image(GTK_BUTTON(details_button), gtk_image_new_from_icon_name(
        "pan-down-symbolic", GTK_ICON_SIZE_BUTTON));
    gtk_widget_set_tooltip_text(details_button, "View incident details");
    atk_object_set_name(gtk_widget_get_accessible(details_button), "View incident details");
    gtk_box_pack_end(GTK_BOX(heading), details_button, false, false, 0);
    gtk_box_pack_end(GTK_BOX(heading), timestamp, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), heading, false, false, 0);
    add_class(explanation, "memspy-incident-description");
    gtk_box_pack_start(GTK_BOX(content), explanation, false, false, 0);

    add_class(summary, "memspy-incident-summary");
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(summary), GTK_SELECTION_NONE);
    gtk_flow_box_set_homogeneous(GTK_FLOW_BOX(summary), true);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(summary), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(summary), 2);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(summary), 12);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(summary), 6);
    gtk_container_add(GTK_CONTAINER(summary), new_summary_item("User", user_text, false));
    gtk_container_add(GTK_CONTAINER(summary), new_summary_item("Process", process_text, true));
    gtk_container_add(GTK_CONTAINER(summary), new_summary_item(
        blocked ? "Attempted executable" : "Executable",
        view->alert.exe[0] == '\0' ? "Unavailable" : view->alert.exe, true));
    if (view->alert.ppid > 0) {
        snprintf(parent_pid, sizeof parent_pid, "%d", view->alert.ppid);
        gtk_container_add(GTK_CONTAINER(summary),
                          new_summary_item("Parent PID", parent_pid, true));
    }
    gtk_box_pack_start(GTK_BOX(content), summary, false, false, 0);

    add_detail_field(&identity, "User", user_text, false);
    add_detail_field(&identity, "Process", process_text, true);
    add_detail_field(&identity, "Parent process name", view->alert.parent_comm, true);
    if (view->alert.ppid > 0)
        add_detail_field(&identity, "Parent PID", parent_pid, true);
    add_detail_field(&identity, "Parent executable", view->alert.parent_exe, true);

    add_detail_field(&execution, blocked ? "Attempted executable" : "Executable",
                     view->alert.exe[0] == '\0' ? "Unavailable" : view->alert.exe, true);
    add_detail_field(&execution, "Command line", view->alert.cmdline, true);
    if (blocked)
        add_detail_field(&execution, "Launcher executable", view->alert.launcher_exe, true);
    add_detail_field(&execution, "TTY", view->alert.tty, true);

    outcome_value = add_detail_field(&detection, "Outcome", outcome, false);
    if (outcome_value != NULL) {
        add_class(outcome_value, "memspy-outcome");
        add_class(outcome_value, blocked ? "memspy-outcome-blocked" :
                                          "memspy-outcome-detected");
    }
    snprintf(alert_id, sizeof alert_id, "%lld", (long long)view->alert.id);
    add_detail_field(&detection, "Alert ID", alert_id, true);
    add_detail_field(&detection, "Rule", view->alert.rule_id, true);
    add_detail_field(&detection, "Detection signal",
                     view->alert.evidence[0] == '\0' ? "Unavailable" : view->alert.evidence,
                     false);

    if (is_exec_rule(view->alert.rule_id)) {
        if (blocked)
            add_evidence_group(&evidence, "Pre-exec launcher", view->alert.launcher_exe,
                               view->alert.launcher_md5, view->alert.launcher_sha256,
                               view->alert.launcher_hash_status);
        add_evidence_group(&evidence, "Payload / executed image", view->alert.exe,
                           view->alert.exe_md5, view->alert.exe_sha256,
                           view->alert.exe_hash_status);
    } else {
        add_evidence_group(&evidence, "Actor executable", view->alert.exe,
                           view->alert.exe_md5, view->alert.exe_sha256,
                           view->alert.exe_hash_status);
        add_evidence_group(&evidence, "Target executable", view->alert.target_exe,
                           view->alert.target_md5, view->alert.target_sha256,
                           view->alert.target_hash_status);
    }
    add_evidence_group(&evidence, "Parent process", view->alert.parent_exe,
                       view->alert.parent_md5, view->alert.parent_sha256,
                       view->alert.parent_hash_status);
    add_detail_field(&evidence, "Grandparent process name", view->alert.grandparent_comm, true);
    if (view->alert.grandparent_pid > 0) {
        snprintf(grandparent_pid, sizeof grandparent_pid, "%d", view->alert.grandparent_pid);
        add_detail_field(&evidence, "Grandparent PID", grandparent_pid, true);
    }
    add_detail_field(&evidence, "Grandparent executable", view->alert.grandparent_exe, true);
    if (view->alert.ssh_origin)
        add_detail_field(&evidence, "SSH origin", "Yes", false);
    add_detail_field(&evidence, "Systemd unit", view->alert.systemd_unit, true);
    if (view->alert.container_id[0] != '\0') {
        snprintf(container, sizeof container, "%s%s%s", view->alert.container_id,
                 view->alert.container_runtime[0] == '\0' ? "" : " · ",
                 view->alert.container_runtime);
        add_detail_field(&evidence, "Container", container, true);
    }
    add_detail_field(&evidence, "Cgroup", view->alert.cgroup_path, true);
    if (view->alert.pid_namespace != 0 || view->alert.mount_namespace != 0) {
        snprintf(namespace_text, sizeof namespace_text, "PID %llu · mount %llu",
                 (unsigned long long)view->alert.pid_namespace,
                 (unsigned long long)view->alert.mount_namespace);
        add_detail_field(&evidence, "Namespaces", namespace_text, true);
    }
    if (view->alert.target_pid > 0) {
        snprintf(target_pid, sizeof target_pid, "%d", view->alert.target_pid);
        add_detail_field(&evidence, "Target PID", target_pid, true);
    }
    if (view->alert.target_namespace_pid > 0) {
        snprintf(target_namespace_pid, sizeof target_namespace_pid, "%d",
                 view->alert.target_namespace_pid);
        add_detail_field(&evidence, "Target namespace PID", target_namespace_pid, true);
    }
    if (view->alert.bytes_written > 0) {
        snprintf(bytes_written, sizeof bytes_written, "%llu",
                 (unsigned long long)view->alert.bytes_written);
        add_detail_field(&evidence, "Bytes written", bytes_written, true);
    }
    if (view->alert.arguments_truncated)
        add_detail_field(&evidence, "Arguments truncated",
                         "Yes — captured command line is incomplete", false);

    add_class(details_grid, "memspy-detail-grid");
    gtk_flow_box_set_selection_mode(GTK_FLOW_BOX(details_grid), GTK_SELECTION_NONE);
    gtk_flow_box_set_min_children_per_line(GTK_FLOW_BOX(details_grid), 1);
    gtk_flow_box_set_max_children_per_line(GTK_FLOW_BOX(details_grid), 2);
    gtk_flow_box_set_column_spacing(GTK_FLOW_BOX(details_grid), 10);
    gtk_flow_box_set_row_spacing(GTK_FLOW_BOX(details_grid), 10);
    gtk_container_add(GTK_CONTAINER(details_grid), identity.container);
    gtk_container_add(GTK_CONTAINER(details_grid), execution.container);
    gtk_container_add(GTK_CONTAINER(details_grid), detection.container);
    gtk_container_add(GTK_CONTAINER(details_grid), evidence.container);
    add_class(hide_button, "memspy-details-toggle");
    add_class(details_revealer, "memspy-incident-details");
    gtk_box_pack_start(GTK_BOX(details), details_grid, false, false, 0);
    gtk_box_pack_start(GTK_BOX(details), hide_button, false, false, 0);
    gtk_revealer_set_transition_type(GTK_REVEALER(details_revealer),
                                     GTK_REVEALER_TRANSITION_TYPE_NONE);
    gtk_container_add(GTK_CONTAINER(details_revealer), details);
    g_signal_connect(details_button, "toggled", G_CALLBACK(incident_details_toggled),
                     details_revealer);
    g_signal_connect(hide_button, "clicked", G_CALLBACK(hide_incident_details),
                     details_button);
    gtk_box_pack_start(GTK_BOX(content), details_revealer, false, false, 0);
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
        name = "On — Blocking fileless execution and injection";
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
    GtkWidget *status_separator;

    window->window = application == NULL ? gtk_window_new(GTK_WINDOW_TOPLEVEL) :
        gtk_application_window_new(application);
    window->alerts = g_ptr_array_new_with_free_func(g_free);
    window->filter = MS_UI_FILTER_ALL;
    window->empty_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    window->empty_title = gtk_label_new("");
    window->empty_detail = gtk_label_new("");
    gtk_window_set_title(GTK_WINDOW(window->window), "MemSpy");
    gtk_window_set_default_size(GTK_WINDOW(window->window), 856, 539);
    gtk_window_set_resizable(GTK_WINDOW(window->window), false);
    gtk_window_set_titlebar(GTK_WINDOW(window->window), header);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "MemSpy");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "Fileless activity monitor");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), true);
    atk_object_set_name(gtk_widget_get_accessible(window->window), "Fileless malware alerts");
    add_class(window->window, "memspy-window");

    window->status_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    detector_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    response_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    status_separator = gtk_separator_new(GTK_ORIENTATION_VERTICAL);
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
    add_class(response_title, "memspy-response-title");
    add_class(window->response_label, "memspy-response-state");
    add_class(window->response_error, "memspy-response-error");
    gtk_box_pack_start(GTK_BOX(response_box), response_title, false, false, 0);
    gtk_box_pack_start(GTK_BOX(response_box), window->response_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(response_box), window->response_error, false, false, 0);
    gtk_box_pack_start(GTK_BOX(response_row), response_box, true, true, 0);
    gtk_box_pack_end(GTK_BOX(response_row), window->response_switch, false, false, 0);
    gtk_widget_set_hexpand(detector_row, true);
    gtk_widget_set_hexpand(response_row, true);
    add_class(detector_row, "memspy-status-section");
    add_class(response_row, "memspy-status-section");
    add_class(status_separator, "memspy-status-separator");
    gtk_box_pack_start(GTK_BOX(window->status_box), detector_row, true, true, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), status_separator, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), response_row, true, true, 0);
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
        set_status(window, "Monitoring stopped", "Detection is currently unavailable",
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
