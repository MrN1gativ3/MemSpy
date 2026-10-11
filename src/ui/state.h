#ifndef FILELESS_UI_STATE_H
#define FILELESS_UI_STATE_H

#include "fileless/alert.h"
#include "fileless/health.h"

enum fl_indicator_state {
    FL_INDICATOR_OFFLINE = 0,
    FL_INDICATOR_HEALTHY,
    FL_INDICATOR_MEDIUM,
    FL_INDICATOR_HIGH,
};

enum fl_ui_filter {
    FL_UI_FILTER_ALL = 0,
    FL_UI_FILTER_HIGH,
    FL_UI_FILTER_MEDIUM,
};

struct fl_ui_state {
    bool connected;
    struct fl_health health;
    enum fl_ui_filter filter;
    int64_t last_alert_id;
    int64_t last_seen_id;
    int64_t last_notified_id;
    uint64_t last_notified_boottime_ns;
    uint64_t unread_high;
    uint64_t unread_medium;
};

void fl_ui_state_init(struct fl_ui_state *state);
void fl_ui_state_apply_health(struct fl_ui_state *state, const struct fl_health *health);
void fl_ui_state_disconnect(struct fl_ui_state *state);
bool fl_ui_state_apply_alert(struct fl_ui_state *state, const struct fl_alert *alert);
void fl_ui_state_mark_visible_read(struct fl_ui_state *state);
void fl_ui_state_mark_notified(struct fl_ui_state *state, int64_t alert_id);
void fl_ui_state_mark_alert_notified(struct fl_ui_state *state, const struct fl_alert *alert);
enum fl_indicator_state fl_ui_state_indicator(const struct fl_ui_state *state);
bool fl_ui_state_should_notify(const struct fl_ui_state *state, const struct fl_alert *alert);
void fl_ui_state_set_filter(struct fl_ui_state *state, enum fl_ui_filter filter);
bool fl_ui_state_visible(const struct fl_ui_state *state, const struct fl_alert *alert);
bool fl_ui_state_load(struct fl_ui_state *state, const char *path, struct fl_error *error);
bool fl_ui_state_save(const struct fl_ui_state *state, const char *path, struct fl_error *error);

#endif
