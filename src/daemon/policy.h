#ifndef FILELESS_POLICY_H
#define FILELESS_POLICY_H

#include <stdint.h>

#include "fileless/observation.h"

enum fl_policy_result {
    FL_POLICY_NONE = 0,
    FL_POLICY_ALERT,
};

struct fl_policy;

struct fl_policy *fl_policy_new(void);
void fl_policy_free(struct fl_policy *policy);
enum fl_policy_result fl_policy_ingest(struct fl_policy *policy,
                                       const struct fl_observation *observation,
                                       struct fl_alert *alert);
uint64_t fl_policy_pressure(const struct fl_policy *policy);

#endif
