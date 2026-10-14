#include "health.h"

#include <stdio.h>

static void
degrade(struct ms_health *health, const char *message)
{
    /* Keep "running" separate from "fully protected". Lost kernel events,
     * storage failures and other coverage gaps downgrade health even if the
     * process stays alive, so operators are not given a false green status. */
    if (health->state != MS_HEALTH_FAILED)
        health->state = MS_HEALTH_DEGRADED;
    health->protected = false;
    snprintf(health->message, sizeof health->message, "%s", message);
}

void
ms_health_apply(struct ms_health *health, enum ms_health_signal signal,
                uint64_t count)
{
    if (health == NULL)
        return;
    switch (signal) {
    case MS_HEALTH_PROBES_READY:
        if (health->state != MS_HEALTH_FAILED && health->storage_available &&
            health->lost_events == 0 && health->map_pressure == 0 &&
            health->dropped_alerts == 0 && health->incomplete_observations == 0 &&
            health->journal_errors == 0) {
            health->state = MS_HEALTH_HEALTHY;
            health->protected = true;
            snprintf(health->message, sizeof health->message, "Monitoring active");
        }
        break;
    case MS_HEALTH_EVENT_LOST:
        health->lost_events += count;
        degrade(health, "Kernel events were lost");
        break;
    case MS_HEALTH_MAP_PRESSURE:
        health->map_pressure += count;
        degrade(health, "Correlation map reached capacity");
        break;
    case MS_HEALTH_STORE_FAILED:
        health->storage_available = false;
        degrade(health, "Alert storage unavailable; live detection continues");
        break;
    case MS_HEALTH_STORE_RECOVERED:
        health->storage_available = true;
        if (health->state != MS_HEALTH_FAILED && health->lost_events == 0 &&
            health->map_pressure == 0 && health->dropped_alerts == 0 &&
            health->incomplete_observations == 0 && health->journal_errors == 0) {
            health->state = MS_HEALTH_HEALTHY;
            health->protected = true;
            snprintf(health->message, sizeof health->message, "Monitoring active");
        }
        break;
    case MS_HEALTH_ALERT_DROPPED:
        health->dropped_alerts += count;
        degrade(health, "Alert persistence queue overflowed");
        break;
    case MS_HEALTH_REQUIRED_PROBE_FAILED:
        health->state = MS_HEALTH_FAILED;
        health->protected = false;
        snprintf(health->message, sizeof health->message, "A required kernel probe failed");
        break;
    case MS_HEALTH_OBSERVATION_INCOMPLETE:
        health->incomplete_observations += count;
        degrade(health, "A short-lived process observation could not be confirmed");
        break;
    case MS_HEALTH_JOURNAL_FAILED:
        health->journal_errors += count;
        degrade(health, "Structured journal output failed; detection continues");
        break;
    }
}
