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
    /* Detection health and response health are separate. A healthy sensor
     * can still report response_supported=false, and a saved request does
     * not mean kernel enforcement is currently active. */
    enum ms_health_state state;
    bool protected;
    uint64_t lost_events;
    uint64_t map_pressure;
    uint64_t dropped_alerts;
    bool storage_available;
    bool response_supported;
    bool response_requested;
    bool response_active;
    uint64_t blocked_execs;
    uint64_t blocked_operations;
    uint64_t lost_block_events;
    uint64_t incomplete_observations;
    uint64_t journal_errors;
    char response_reason[256];
    char message[256];
};

#endif
