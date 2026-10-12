#ifndef MEMSPY_UI_WINDOW_H
#define MEMSPY_UI_WINDOW_H

#include <gtk/gtk.h>

#include "state.h"

struct ms_window;

struct ms_window *ms_window_new(GtkApplication *application);
GtkWindow *ms_window_widget(struct ms_window *window);
void ms_window_set_loading(struct ms_window *window);
void ms_window_set_health(struct ms_window *window, const struct ms_health *health);
void ms_window_set_offline(struct ms_window *window, const char *message, const char *detail);
void ms_window_set_response_handler(struct ms_window *window,
                                    void (*handler)(bool enabled, void *userdata),
                                    void *userdata);
void ms_window_set_response_pending(struct ms_window *window, bool pending);
void ms_window_set_response_error(struct ms_window *window, const char *message);
const char *ms_window_status_text(const struct ms_window *window);
bool ms_window_add_alert(struct ms_window *window, const struct ms_alert *alert);
void ms_window_set_filter(struct ms_window *window, enum ms_ui_filter filter);
size_t ms_window_visible_count(const struct ms_window *window);
bool ms_window_select_alert(struct ms_window *window, int64_t alert_id);
void ms_window_present(struct ms_window *window);
void ms_window_free(struct ms_window *window);

#endif
