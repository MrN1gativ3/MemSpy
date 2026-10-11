#include "health.h"

#include <stdio.h>

static void
degrade(struct fl_health *health, const char *message)
{
    if (health->state != FL_HEALTH_FAILED)
        health->state = FL_HEALTH_DEGRADED;
    health->protected = false;
    snprintf(health->message, sizeof health->message, "%s", message);
}

void
fl_health_apply(struct fl_health *health, enum fl_health_signal signal,
                uint64_t count)
{
    if (health == NULL)
        return;
    switch (signal) {
    case FL_HEALTH_PROBES_READY:
        if (health->state != FL_HEALTH_FAILED && health->storage_available &&
            health->lost_events == 0 && health->map_pressure == 0 &&
            health->dropped_alerts == 0) {
            health->state = FL_HEALTH_HEALTHY;
            health->protected = true;
            snprintf(health->message, sizeof health->message, "Monitoring active");
        }
        break;
    case FL_HEALTH_EVENT_LOST:
        health->lost_events += count;
        degrade(health, "Kernel events were lost");
        break;
    case FL_HEALTH_MAP_PRESSURE:
        health->map_pressure += count;
        degrade(health, "Correlation map reached capacity");
        break;
    case FL_HEALTH_STORE_FAILED:
        health->storage_available = false;
        degrade(health, "Alert storage unavailable; live detection continues");
        break;
    case FL_HEALTH_STORE_RECOVERED:
        health->storage_available = true;
        if (health->state != FL_HEALTH_FAILED && health->lost_events == 0 &&
            health->map_pressure == 0 && health->dropped_alerts == 0) {
            health->state = FL_HEALTH_HEALTHY;
            health->protected = true;
            snprintf(health->message, sizeof health->message, "Monitoring active");
        }
        break;
    case FL_HEALTH_ALERT_DROPPED:
        health->dropped_alerts += count;
        degrade(health, "Alert persistence queue overflowed");
        break;
    case FL_HEALTH_REQUIRED_PROBE_FAILED:
        health->state = FL_HEALTH_FAILED;
        health->protected = false;
        snprintf(health->message, sizeof health->message, "A required kernel probe failed");
        break;
    }
}
