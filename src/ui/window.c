#include "window.h"

#include <stdio.h>
#include <string.h>

struct alert_view {
    struct fl_alert alert;
    GtkWidget *row;
};

struct fl_window {
    GtkWidget *window;
    GtkWidget *status_box;
    GtkWidget *status_label;
    GtkWidget *spinner;
    GtkWidget *list;
    GtkWidget *filter_buttons[3];
    GPtrArray *alerts;
    enum fl_ui_filter filter;
};

static void
add_class(GtkWidget *widget, const char *name)
{
    gtk_style_context_add_class(gtk_widget_get_style_context(widget), name);
}

static gboolean
filter_row(GtkListBoxRow *row, gpointer userdata)
{
    struct fl_window *window = userdata;
    const struct alert_view *view = g_object_get_data(G_OBJECT(row), "fileless-alert");
    if (window->filter == FL_UI_FILTER_ALL)
        return true;
    if (window->filter == FL_UI_FILTER_HIGH)
        return view->alert.severity == FL_SEVERITY_HIGH;
    return view->alert.severity == FL_SEVERITY_MEDIUM;
}

static gint
sort_rows(GtkListBoxRow *left, GtkListBoxRow *right, gpointer userdata)
{
    const struct alert_view *a = g_object_get_data(G_OBJECT(left), "fileless-alert");
    const struct alert_view *b = g_object_get_data(G_OBJECT(right), "fileless-alert");
    (void)userdata;
    return a->alert.id < b->alert.id ? 1 : a->alert.id > b->alert.id ? -1 : 0;
}

static void
filter_toggled(GtkToggleButton *button, gpointer userdata)
{
    struct fl_window *window = userdata;
    if (!gtk_toggle_button_get_active(button))
        return;
    window->filter = (enum fl_ui_filter)GPOINTER_TO_INT(
        g_object_get_data(G_OBJECT(button), "fileless-filter"));
    gtk_list_box_invalidate_filter(GTK_LIST_BOX(window->list));
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
create_alert_row(struct alert_view *view)
{
    const char *severity = view->alert.severity == FL_SEVERITY_HIGH ? "High" : "Medium";
    GtkWidget *row = gtk_list_box_row_new();
    GtkWidget *content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    GtkWidget *heading = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    GtkWidget *severity_label = gtk_label_new(severity);
    GtkWidget *rule_label = gtk_label_new(view->alert.rule_id);
    GtkWidget *explanation = new_wrapping_label(view->alert.explanation);
    GtkWidget *process;
    GtkWidget *expander = gtk_expander_new("Evidence");
    GtkWidget *details = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    char process_text[256];
    char accessible_name[256];

    snprintf(process_text, sizeof process_text, "%s · PID %d", view->alert.comm, view->alert.pid);
    process = new_wrapping_label(process_text);
    add_class(rule_label, "fileless-rule-id");
    gtk_label_set_xalign(GTK_LABEL(severity_label), 0.0F);
    gtk_label_set_xalign(GTK_LABEL(rule_label), 0.0F);
    gtk_box_pack_start(GTK_BOX(heading), severity_label, false, false, 0);
    gtk_box_pack_start(GTK_BOX(heading), rule_label, true, true, 0);
    gtk_box_pack_start(GTK_BOX(content), heading, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), explanation, false, false, 0);
    gtk_box_pack_start(GTK_BOX(content), process, false, false, 0);

    GtkWidget *exe = new_wrapping_label(view->alert.exe[0] == '\0' ? "Executable unavailable" : view->alert.exe);
    GtkWidget *cmdline = new_wrapping_label(view->alert.cmdline[0] == '\0' ? "Command line unavailable" : view->alert.cmdline);
    GtkWidget *evidence = new_wrapping_label(view->alert.evidence);
    gtk_label_set_selectable(GTK_LABEL(exe), true);
    gtk_label_set_selectable(GTK_LABEL(cmdline), true);
    gtk_label_set_selectable(GTK_LABEL(evidence), true);
    add_class(exe, "fileless-rule-id");
    add_class(cmdline, "fileless-rule-id");
    gtk_box_pack_start(GTK_BOX(details), exe, false, false, 0);
    gtk_box_pack_start(GTK_BOX(details), cmdline, false, false, 0);
    gtk_box_pack_start(GTK_BOX(details), evidence, false, false, 0);
    gtk_container_add(GTK_CONTAINER(expander), details);
    gtk_box_pack_start(GTK_BOX(content), expander, false, false, 0);
    gtk_container_add(GTK_CONTAINER(row), content);
    add_class(row, "fileless-alert-row");
    add_class(row, view->alert.severity == FL_SEVERITY_HIGH ?
              "fileless-health-high" : "fileless-health-medium");
    snprintf(accessible_name, sizeof accessible_name, "%s alert, %s, process %s",
             severity, view->alert.rule_id, view->alert.comm);
    atk_object_set_name(gtk_widget_get_accessible(row), accessible_name);
    return row;
}

static GtkWidget *
create_filters(struct fl_window *window)
{
    static const char *labels[] = {"All", "High", "Medium"};
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GSList *group = NULL;
    for (unsigned int index = 0; index < 3; ++index) {
        GtkWidget *button = gtk_radio_button_new_with_label(group, labels[index]);
        group = gtk_radio_button_get_group(GTK_RADIO_BUTTON(button));
        g_object_set_data(G_OBJECT(button), "fileless-filter", GINT_TO_POINTER(index));
        g_signal_connect(button, "toggled", G_CALLBACK(filter_toggled), window);
        gtk_box_pack_start(GTK_BOX(box), button, false, false, 0);
        window->filter_buttons[index] = button;
    }
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(window->filter_buttons[0]), true);
    atk_object_set_name(gtk_widget_get_accessible(box), "Alert severity filter");
    return box;
}

struct fl_window *
fl_window_new(GtkApplication *application)
{
    struct fl_window *window = g_new0(struct fl_window, 1);
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    GtkWidget *filters;
    GtkWidget *scroller = gtk_scrolled_window_new(NULL, NULL);
    GtkWidget *placeholder = new_wrapping_label("No alerts in the last 30 days");
    GtkWidget *header = gtk_header_bar_new();

    window->window = application == NULL ? gtk_window_new(GTK_WINDOW_TOPLEVEL) :
        gtk_application_window_new(application);
    window->alerts = g_ptr_array_new_with_free_func(g_free);
    window->filter = FL_UI_FILTER_ALL;
    gtk_window_set_title(GTK_WINDOW(window->window), "Fileless Detector");
    gtk_window_set_default_size(GTK_WINDOW(window->window), 440, 560);
    gtk_window_set_titlebar(GTK_WINDOW(window->window), header);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Fileless Detector");
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), true);
    atk_object_set_name(gtk_widget_get_accessible(window->window), "Fileless malware alerts");
    add_class(window->window, "fileless-window");

    window->status_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    window->spinner = gtk_spinner_new();
    window->status_label = gtk_label_new("");
    gtk_label_set_xalign(GTK_LABEL(window->status_label), 0.0F);
    gtk_box_pack_start(GTK_BOX(window->status_box), window->spinner, false, false, 0);
    gtk_box_pack_start(GTK_BOX(window->status_box), window->status_label, true, true, 0);
    add_class(window->status_box, "fileless-status-banner");
    atk_object_set_name(gtk_widget_get_accessible(window->status_box), "Detector status");

    filters = create_filters(window);
    window->list = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(window->list), GTK_SELECTION_SINGLE);
    gtk_list_box_set_filter_func(GTK_LIST_BOX(window->list), filter_row, window, NULL);
    gtk_list_box_set_sort_func(GTK_LIST_BOX(window->list), sort_rows, window, NULL);
    gtk_list_box_set_placeholder(GTK_LIST_BOX(window->list), placeholder);
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
    fl_window_set_loading(window);
    gtk_widget_show_all(root);
    return window;
}

GtkWindow *
fl_window_widget(struct fl_window *window)
{
    return window == NULL ? NULL : GTK_WINDOW(window->window);
}

void
fl_window_set_loading(struct fl_window *window)
{
    if (window == NULL)
        return;
    gtk_label_set_text(GTK_LABEL(window->status_label), "Connecting to detector…");
    gtk_spinner_start(GTK_SPINNER(window->spinner));
    add_class(window->status_box, "fileless-health-offline");
}

static void
set_status(struct fl_window *window, const char *text, const char *style)
{
    GtkStyleContext *context = gtk_widget_get_style_context(window->status_box);
    static const char *classes[] = {
        "fileless-health-healthy", "fileless-health-medium",
        "fileless-health-high", "fileless-health-offline",
    };
    for (unsigned int index = 0; index < G_N_ELEMENTS(classes); ++index)
        gtk_style_context_remove_class(context, classes[index]);
    gtk_style_context_add_class(context, style);
    gtk_spinner_stop(GTK_SPINNER(window->spinner));
    gtk_label_set_text(GTK_LABEL(window->status_label), text);
}

void
fl_window_set_health(struct fl_window *window, const struct fl_health *health)
{
    if (window == NULL || health == NULL)
        return;
    if (health->state == FL_HEALTH_HEALTHY && health->protected)
        set_status(window, "Monitoring active", "fileless-health-healthy");
    else if (health->state == FL_HEALTH_FAILED)
        set_status(window, "Monitoring failed", "fileless-health-offline");
    else
        set_status(window, "Monitoring degraded", "fileless-health-medium");
}

void
fl_window_set_offline(struct fl_window *window, const char *message)
{
    if (window != NULL)
        set_status(window, message == NULL ? "Detector unavailable" : message,
                   "fileless-health-offline");
}

const char *
fl_window_status_text(const struct fl_window *window)
{
    return window == NULL ? NULL : gtk_label_get_text(GTK_LABEL(window->status_label));
}

bool
fl_window_add_alert(struct fl_window *window, const struct fl_alert *alert)
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
    g_object_set_data(G_OBJECT(view->row), "fileless-alert", view);
    g_ptr_array_add(window->alerts, view);
    gtk_container_add(GTK_CONTAINER(window->list), view->row);
    gtk_widget_show_all(view->row);
    gtk_list_box_invalidate_sort(GTK_LIST_BOX(window->list));
    gtk_list_box_invalidate_filter(GTK_LIST_BOX(window->list));
    return true;
}

void
fl_window_set_filter(struct fl_window *window, enum fl_ui_filter filter)
{
    if (window == NULL || filter < FL_UI_FILTER_ALL || filter > FL_UI_FILTER_MEDIUM)
        return;
    window->filter = filter;
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(window->filter_buttons[filter]), true);
    gtk_list_box_invalidate_filter(GTK_LIST_BOX(window->list));
}

size_t
fl_window_visible_count(const struct fl_window *window)
{
    size_t count = 0;
    if (window == NULL)
        return 0;
    for (guint index = 0; index < window->alerts->len; ++index) {
        const struct alert_view *view = g_ptr_array_index(window->alerts, index);
        if (window->filter == FL_UI_FILTER_ALL ||
            (window->filter == FL_UI_FILTER_HIGH && view->alert.severity == FL_SEVERITY_HIGH) ||
            (window->filter == FL_UI_FILTER_MEDIUM && view->alert.severity == FL_SEVERITY_MEDIUM))
            ++count;
    }
    return count;
}

bool
fl_window_select_alert(struct fl_window *window, int64_t alert_id)
{
    if (window == NULL)
        return false;
    for (guint index = 0; index < window->alerts->len; ++index) {
        const struct alert_view *view = g_ptr_array_index(window->alerts, index);
        if (view->alert.id == alert_id) {
            fl_window_set_filter(window, FL_UI_FILTER_ALL);
            gtk_list_box_select_row(GTK_LIST_BOX(window->list), GTK_LIST_BOX_ROW(view->row));
            gtk_widget_grab_focus(view->row);
            return true;
        }
    }
    return false;
}

void
fl_window_present(struct fl_window *window)
{
    if (window == NULL)
        return;
    gtk_widget_show_all(window->window);
    gtk_window_present(GTK_WINDOW(window->window));
}

void
fl_window_free(struct fl_window *window)
{
    if (window == NULL)
        return;
    gtk_widget_destroy(window->window);
    g_ptr_array_free(window->alerts, true);
    g_free(window);
}
