#define _GNU_SOURCE
#include "state.h"

#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void
set_error(struct fl_error *error, const char *code, const char *message)
{
    if (error == NULL)
        return;
    g_strlcpy(error->code, code, sizeof error->code);
    g_strlcpy(error->message, message, sizeof error->message);
}

void
fl_ui_state_init(struct fl_ui_state *state)
{
    if (state != NULL)
        *state = (struct fl_ui_state){.filter = FL_UI_FILTER_ALL};
}

void
fl_ui_state_apply_health(struct fl_ui_state *state, const struct fl_health *health)
{
    if (state == NULL || health == NULL)
        return;
    state->health = *health;
    state->connected = true;
}

void
fl_ui_state_disconnect(struct fl_ui_state *state)
{
    if (state != NULL)
        state->connected = false;
}

bool
fl_ui_state_apply_alert(struct fl_ui_state *state, const struct fl_alert *alert)
{
    if (state == NULL || alert == NULL || alert->id < 0 ||
        (alert->id == 0 && alert->observed_boottime_ns == 0) ||
        (alert->id > 0 && alert->id <= state->last_alert_id))
        return false;
    if (alert->id > 0)
        state->last_alert_id = alert->id;
    if (alert->id == 0 || alert->id > state->last_seen_id) {
        if (alert->severity == FL_SEVERITY_HIGH)
            ++state->unread_high;
        else
            ++state->unread_medium;
    }
    return true;
}

void
fl_ui_state_mark_visible_read(struct fl_ui_state *state)
{
    if (state == NULL)
        return;
    state->last_seen_id = state->last_alert_id;
    state->unread_high = 0;
    state->unread_medium = 0;
}

void
fl_ui_state_mark_notified(struct fl_ui_state *state, int64_t alert_id)
{
    if (state != NULL && alert_id > state->last_notified_id)
        state->last_notified_id = alert_id;
}

void
fl_ui_state_mark_alert_notified(struct fl_ui_state *state, const struct fl_alert *alert)
{
    if (state == NULL || alert == NULL)
        return;
    fl_ui_state_mark_notified(state, alert->id);
    if (alert->observed_boottime_ns > state->last_notified_boottime_ns)
        state->last_notified_boottime_ns = alert->observed_boottime_ns;
}

enum fl_indicator_state
fl_ui_state_indicator(const struct fl_ui_state *state)
{
    if (state == NULL || !state->connected || state->health.state != FL_HEALTH_HEALTHY ||
        !state->health.protected)
        return FL_INDICATOR_OFFLINE;
    if (state->unread_high > 0)
        return FL_INDICATOR_HIGH;
    if (state->unread_medium > 0)
        return FL_INDICATOR_MEDIUM;
    return FL_INDICATOR_HEALTHY;
}

bool
fl_ui_state_should_notify(const struct fl_ui_state *state, const struct fl_alert *alert)
{
    return state != NULL && alert != NULL && state->connected &&
           alert->severity == FL_SEVERITY_HIGH &&
           ((alert->id > 0 && alert->id > state->last_notified_id) ||
            (alert->id == 0 && alert->observed_boottime_ns > state->last_notified_boottime_ns));
}

void
fl_ui_state_set_filter(struct fl_ui_state *state, enum fl_ui_filter filter)
{
    if (state != NULL && filter >= FL_UI_FILTER_ALL && filter <= FL_UI_FILTER_MEDIUM)
        state->filter = filter;
}

bool
fl_ui_state_visible(const struct fl_ui_state *state, const struct fl_alert *alert)
{
    if (state == NULL || alert == NULL || state->filter == FL_UI_FILTER_ALL)
        return state != NULL && alert != NULL;
    return (state->filter == FL_UI_FILTER_HIGH && alert->severity == FL_SEVERITY_HIGH) ||
           (state->filter == FL_UI_FILTER_MEDIUM && alert->severity == FL_SEVERITY_MEDIUM);
}

bool
fl_ui_state_load(struct fl_ui_state *state, const char *path, struct fl_error *error)
{
    char contents[257];
    long long last_seen;
    long long last_notified;
    long long last_alert;
    unsigned long long last_notified_boottime;
    int consumed = 0;
    ssize_t length;
    int descriptor;

    if (state == NULL || path == NULL) {
        set_error(error, "state_invalid", "state and path are required");
        return false;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT)
            return true;
        set_error(error, "state_io", "cannot read UI state");
        return false;
    }
    length = read(descriptor, contents, sizeof contents - 1U);
    close(descriptor);
    if (length < 0 || (size_t)length == sizeof contents - 1U) {
        set_error(error, "state_io", "UI state is unreadable or too large");
        return false;
    }
    contents[length] = '\0';
    if (sscanf(contents, "last_seen=%lld\nlast_notified=%lld\nlast_alert=%lld\nlast_notified_boottime=%llu\n%n",
               &last_seen, &last_notified, &last_alert, &last_notified_boottime, &consumed) != 4 ||
        contents[consumed] != '\0' || last_seen < 0 || last_notified < 0 || last_alert < 0) {
        set_error(error, "state_data", "UI state is malformed");
        return false;
    }
    state->last_seen_id = last_seen;
    state->last_notified_id = last_notified;
    state->last_alert_id = last_alert;
    state->last_notified_boottime_ns = last_notified_boottime;
    return true;
}

bool
fl_ui_state_save(const struct fl_ui_state *state, const char *path, struct fl_error *error)
{
    g_autofree char *directory = NULL;
    char contents[128];
    size_t length;
    ssize_t written;
    int descriptor;

    if (state == NULL || path == NULL) {
        set_error(error, "state_invalid", "state and path are required");
        return false;
    }
    directory = g_path_get_dirname(path);
    if (g_mkdir_with_parents(directory, 0700) != 0) {
        set_error(error, "state_io", "cannot create UI state directory");
        return false;
    }
    descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0 || fchmod(descriptor, 0600) != 0) {
        if (descriptor >= 0)
            close(descriptor);
        set_error(error, "state_io", "cannot secure UI state");
        return false;
    }
    length = (size_t)snprintf(contents, sizeof contents,
                              "last_seen=%lld\nlast_notified=%lld\nlast_alert=%lld\nlast_notified_boottime=%llu\n",
                              (long long)state->last_seen_id,
                              (long long)state->last_notified_id,
                              (long long)state->last_alert_id,
                              (unsigned long long)state->last_notified_boottime_ns);
    written = write(descriptor, contents, length);
    if (written != (ssize_t)length || fsync(descriptor) != 0) {
        close(descriptor);
        set_error(error, "state_io", "cannot write UI state");
        return false;
    }
    close(descriptor);
    return true;
}
