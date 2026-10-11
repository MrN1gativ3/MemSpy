#ifndef MEMSPY_DAEMON_HEALTH_H
#define MEMSPY_DAEMON_HEALTH_H

#include "memspy/health.h"

enum ms_health_signal {
    MS_HEALTH_PROBES_READY = 1,
    MS_HEALTH_EVENT_LOST,
    MS_HEALTH_MAP_PRESSURE,
    MS_HEALTH_STORE_FAILED,
    MS_HEALTH_STORE_RECOVERED,
    MS_HEALTH_ALERT_DROPPED,
    MS_HEALTH_REQUIRED_PROBE_FAILED,
};

void ms_health_apply(struct ms_health *health, enum ms_health_signal signal,
                     uint64_t count);

#endif
