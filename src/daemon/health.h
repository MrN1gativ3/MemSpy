#ifndef FILELESS_DAEMON_HEALTH_H
#define FILELESS_DAEMON_HEALTH_H

#include "fileless/health.h"

enum fl_health_signal {
    FL_HEALTH_PROBES_READY = 1,
    FL_HEALTH_EVENT_LOST,
    FL_HEALTH_MAP_PRESSURE,
    FL_HEALTH_STORE_FAILED,
    FL_HEALTH_STORE_RECOVERED,
    FL_HEALTH_ALERT_DROPPED,
    FL_HEALTH_REQUIRED_PROBE_FAILED,
};

void fl_health_apply(struct fl_health *health, enum fl_health_signal signal,
                     uint64_t count);

#endif
