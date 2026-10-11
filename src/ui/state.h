#ifndef MEMSPY_UI_STATE_H
#define MEMSPY_UI_STATE_H

#include "memspy/alert.h"
#include "memspy/health.h"

enum ms_indicator_state {
    MS_INDICATOR_OFFLINE = 0,
    MS_INDICATOR_HEALTHY,
    MS_INDICATOR_MEDIUM,
    MS_INDICATOR_HIGH,
};

enum ms_ui_filter {
    MS_UI_FILTER_ALL = 0,
    MS_UI_FILTER_HIGH,
    MS_UI_FILTER_MEDIUM,
};

struct ms_ui_state {
    bool connected;
    struct ms_health health;
    enum ms_ui_filter filter;
    int64_t last_alert_id;
    int64_t last_seen_id;
    int64_t last_notified_id;
    uint64_t last_notified_boottime_ns;
    uint64_t unread_high;
    uint64_t unread_medium;
};

void ms_ui_state_init(struct ms_ui_state *state);
void ms_ui_state_apply_health(struct ms_ui_state *state, const struct ms_health *health);
void ms_ui_state_disconnect(struct ms_ui_state *state);
bool ms_ui_state_apply_alert(struct ms_ui_state *state, const struct ms_alert *alert);
void ms_ui_state_mark_visible_read(struct ms_ui_state *state);
void ms_ui_state_mark_notified(struct ms_ui_state *state, int64_t alert_id);
void ms_ui_state_mark_alert_notified(struct ms_ui_state *state, const struct ms_alert *alert);
enum ms_indicator_state ms_ui_state_indicator(const struct ms_ui_state *state);
bool ms_ui_state_should_notify(const struct ms_ui_state *state, const struct ms_alert *alert);
void ms_ui_state_set_filter(struct ms_ui_state *state, enum ms_ui_filter filter);
bool ms_ui_state_visible(const struct ms_ui_state *state, const struct ms_alert *alert);
bool ms_ui_state_load(struct ms_ui_state *state, const char *path, struct ms_error *error);
bool ms_ui_state_save(const struct ms_ui_state *state, const char *path, struct ms_error *error);

#endif
