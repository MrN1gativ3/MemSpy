#ifndef FILELESS_HEALTH_H
#define FILELESS_HEALTH_H

#include <stdbool.h>
#include <stdint.h>

enum fl_health_state {
    FL_HEALTH_HEALTHY = 1,
    FL_HEALTH_DEGRADED,
    FL_HEALTH_FAILED,
};

struct fl_health {
    enum fl_health_state state;
    bool protected;
    uint64_t lost_events;
    uint64_t map_pressure;
    uint64_t dropped_alerts;
    bool storage_available;
    char message[256];
};

#endif
