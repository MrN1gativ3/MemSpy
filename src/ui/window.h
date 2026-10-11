#ifndef FILELESS_UI_WINDOW_H
#define FILELESS_UI_WINDOW_H

#include <gtk/gtk.h>

#include "state.h"

struct fl_window;

struct fl_window *fl_window_new(GtkApplication *application);
GtkWindow *fl_window_widget(struct fl_window *window);
void fl_window_set_loading(struct fl_window *window);
void fl_window_set_health(struct fl_window *window, const struct fl_health *health);
void fl_window_set_offline(struct fl_window *window, const char *message);
const char *fl_window_status_text(const struct fl_window *window);
bool fl_window_add_alert(struct fl_window *window, const struct fl_alert *alert);
void fl_window_set_filter(struct fl_window *window, enum fl_ui_filter filter);
size_t fl_window_visible_count(const struct fl_window *window);
bool fl_window_select_alert(struct fl_window *window, int64_t alert_id);
void fl_window_present(struct fl_window *window);
void fl_window_free(struct fl_window *window);

#endif
