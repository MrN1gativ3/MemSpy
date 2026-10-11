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
    GtkWidget *list;
    GtkWidget *empty_box;
    GtkWidget *empty_title;
    GtkWidget *empty_detail;
    GtkWidget *filter_buttons[3];
    GPtrArray *alerts;
    enum ms_ui_filter filter;
    bool monitoring;
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
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *heading = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *severity_label = gtk_label_new(severity);
    GtkWidget *rule_label = gtk_label_new(view->alert.rule_id);
    GtkWidget *timestamp;
    GtkWidget *explanation = new_wrapping_label(view->alert.explanation);
    GtkWidget *process;
    GtkWidget *expander = gtk_expander_new("Evidence details");
    GtkWidget *details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GDateTime *date = g_date_time_new_from_unix_local(view->alert.timestamp_utc);
    char *time_text = date == NULL ? g_strdup("Time unavailable") :
        g_date_time_format(date, "%x · %X");
    char process_text[256];
    char accessible_name[256];

    snprintf(process_text, sizeof process_text, "%s · PID %d", view->alert.comm, view->alert.pid);
    process = new_wrapping_label(process_text);
    timestamp = gtk_label_new(time_text);
    gtk_label_set_xalign(GTK_LABEL(timestamp), 1.0F);
    add_class(timestamp, "memspy-timestamp");
    if (date != NULL)
        g_date_time_unref(date);
    g_free(time_text);
    add_class(severity_label, "memspy-severity");
    add_class(rule_label, "memspy-rule-id");
    gtk_label_set_xalign(GTK_LABEL(severity_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(rule_label), 0.0F);
    gtk_box_pack_start(GTK_BOX(heading), severity_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), rule_label, true, true, 0);
    gtk_box_pack_end(GTK_BOX(heading), timestamp, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), heading, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), explanation, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), process, false, false, 0);

    gtk_box_pack_start(GTK_BOX(details), new_detail_field("Executable",
        view->alert.exe[0] == '\0' ? "Unavailable" : view->alert.exe, true), false, false, 0);
    gtk_box_pack_start(GTK_BOX(details), new_detail_field("Command line",
        view->alert.cmdline[0] == '\0' ? "Unavailable" : view->alert.cmdline, true), false, false, 0);
    gtk_box_pack_start(GTK_BOX(details), new_detail_field("Detection signal",
        view->alert.evidence, false), false, false, 0);
    gtk_container_add(GTK_CONTAINER(expander), details);
    gtk_box_pack_start(GTK_BOX(content), expander, false, false, 0);
    gtk_container_add(GTK_CONTAINER(row), content);
    add_class(row, "memspy-alert-row");
    add_class(row, view->alert.severity == MS_SEVERITY_HIGH ?
              "memspy-health-high" : "memspy-health-medium");
    snprintf(accessible_name, sizeof accessible_name, "%s alert, %s, process %s",
             severity, view->alert.rule_id, view->alert.comm);
    atk_object_set_name(gtk_widget_get_accessible(row), accessible_name);
    return row;
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

    window->status_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    window->status_icon = gtk_image_new_from_icon_name("memspy-offline-symbolic",
                                                       GTK_ICON_SIZE_BUTTON);
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
    gtk_box_pack_start(GTK_BOX(window->status_box), window->status_icon, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), window->spinner, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), status_copy, true, true, 0);
    add_class(window->status_box, "memspy-status-banner");
    atk_object_set_name(gtk_widget_get_accessible(window->status_box), "Detector status");

    filters = create_filters(window);
    add_class(root, "memspy-content");
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
    gtk_label_set_text(GTK_LABEL(window->status_label), "Connecting to detector…");
    gtk_label_set_text(GTK_LABEL(window->status_detail),
                       "Establishing a secure local connection");
    gtk_image_set_from_icon_name(GTK_IMAGE(window->status_icon), "memspy-offline-symbolic",
                                 GTK_ICON_SIZE_BUTTON);
    gtk_spinner_start(GTK_SPINNER(window->spinner));
    add_class(window->status_box, "memspy-health-offline");
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
    if (health->state == MS_HEALTH_HEALTHY && health->protected)
        set_status(window, "Monitoring active", "Kernel probes and alert storage are healthy",
                   "memspy-healthy-symbolic", "memspy-health-healthy");
    else if (health->state == MS_HEALTH_FAILED)
        set_status(window, "Monitoring failed", "Detection is currently unavailable",
                   "memspy-offline-symbolic", "memspy-health-offline");
    else
        set_status(window, "Monitoring degraded", "Detection continues with reduced coverage",
                   "memspy-medium-symbolic", "memspy-health-medium");
    update_empty_state(window);
}

void
ms_window_set_offline(struct ms_window *window, const char *message, const char *detail)
{
    if (window == NULL)
        return;
    window->monitoring = false;
    set_status(window, message == NULL ? "Detector unavailable" : message,
               detail == NULL ? "Detection is currently unavailable" : detail,
               "memspy-offline-symbolic", "memspy-health-offline");
    update_empty_state(window);
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
