#ifndef MEMSPY_ENFORCER_H
#define MEMSPY_ENFORCER_H

#include <stdbool.h>
#include <stdint.h>

#include <glib.h>

#include "memspy/alert.h"
#include "memspy/protocol.h"
#include "memspy_enforce_shared.h"

typedef void (*ms_blocked_cb)(const struct ms_alert *alert, void *userdata);

struct ms_enforcer_status {
    bool supported;
    bool enabled;
    uint64_t denied;
    uint64_t lost_events;
    char reason[256];
};

struct ms_enforcer;

enum ms_enforcer_pins {
    MS_ENFORCER_PINS_NONE,
    MS_ENFORCER_PINS_COMPATIBLE,
    MS_ENFORCER_PINS_INCOMPATIBLE,
};

struct ms_enforcer_ops {
    enum ms_enforcer_pins (*inspect)(void *context, const char *pin_dir);
    bool (*adopt)(void *context, const char *pin_dir, struct ms_enforcer *owner,
                  void **instance, struct ms_error *error);
    bool (*hold)(void *context, const char *pin_dir, void **instance,
                 struct ms_error *error);
    bool (*create)(void *context, struct ms_enforcer *owner, void **instance,
                   struct ms_error *error);
    bool (*configure)(void *context, void *instance, const GArray *launcher_keys,
                      bool enabled, struct ms_error *error);
    bool (*stage)(void *context, void *instance, const char *pin_dir,
                  struct ms_error *error);
    bool (*remove_owned)(void *context, const char *pin_dir, struct ms_error *error);
    bool (*promote)(void *context, const char *pin_dir, struct ms_error *error);
    bool (*set_enabled)(void *context, void *instance, bool enabled,
                        struct ms_error *error);
    int (*poll)(void *context, void *instance, int timeout_ms, uint64_t *denied,
                uint64_t *lost_events, struct ms_error *error);
    void (*release)(void *context, void *instance);
};

bool ms_enforcer_open(struct ms_enforcer **out, const char *pin_dir,
                      ms_blocked_cb callback, void *userdata, struct ms_error *error);
bool ms_enforcer_open_with_ops(struct ms_enforcer **out, const char *pin_dir,
                               ms_blocked_cb callback, void *userdata,
                               const struct ms_enforcer_ops *ops, void *ops_context,
                               struct ms_error *error);
bool ms_enforcer_attach(struct ms_enforcer *enforcer, const GArray *launcher_keys,
                        bool requested, struct ms_error *error);
bool ms_enforcer_set_enabled(struct ms_enforcer *enforcer, bool enabled,
                             struct ms_error *error);
int ms_enforcer_poll(struct ms_enforcer *enforcer, int timeout_ms,
                     struct ms_error *error);
bool ms_enforcer_remove_pins(struct ms_enforcer *enforcer, struct ms_error *error);
void ms_enforcer_status(const struct ms_enforcer *enforcer,
                        struct ms_enforcer_status *out);
void ms_enforcer_free(struct ms_enforcer *enforcer);

bool ms_enforcer_alert_from_event(const struct ms_enforce_event *event,
                                  struct ms_alert *alert, struct ms_error *error);

#endif
