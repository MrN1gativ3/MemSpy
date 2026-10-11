#ifndef MEMSPY_POLICY_H
#define MEMSPY_POLICY_H

#include <stdint.h>

#include "memspy/observation.h"

enum ms_policy_result {
    MS_POLICY_NONE = 0,
    MS_POLICY_ALERT,
};

struct ms_policy;

struct ms_policy *ms_policy_new(void);
void ms_policy_free(struct ms_policy *policy);
enum ms_policy_result ms_policy_ingest(struct ms_policy *policy,
                                       const struct ms_observation *observation,
                                       struct ms_alert *alert);
uint64_t ms_policy_pressure(const struct ms_policy *policy);

#endif
