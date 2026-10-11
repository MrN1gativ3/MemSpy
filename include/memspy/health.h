#ifndef MEMSPY_HEALTH_H
#define MEMSPY_HEALTH_H

#include <stdbool.h>
#include <stdint.h>

enum ms_health_state {
    MS_HEALTH_HEALTHY = 1,
    MS_HEALTH_DEGRADED,
    MS_HEALTH_FAILED,
};

struct ms_health {
    enum ms_health_state state;
    bool protected;
    uint64_t lost_events;
    uint64_t map_pressure;
    uint64_t dropped_alerts;
    bool storage_available;
    char message[256];
};

#endif
