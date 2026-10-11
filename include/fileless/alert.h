#ifndef FILELESS_ALERT_H
#define FILELESS_ALERT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <json-c/json.h>

#include "fileless/protocol.h"

#define FL_RULE_ID_BYTES 64U
#define FL_EXPLANATION_BYTES 256U
#define FL_COMM_BYTES 64U
#define FL_PATH_BYTES 4096U
#define FL_EVIDENCE_BYTES 1024U

enum fl_severity {
    FL_SEVERITY_MEDIUM = 1,
    FL_SEVERITY_HIGH = 2,
};

struct fl_alert {
    int64_t id;
    int64_t timestamp_utc;
    uint64_t observed_boottime_ns;
    enum fl_severity severity;
    char rule_id[FL_RULE_ID_BYTES];
    char explanation[FL_EXPLANATION_BYTES];
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char comm[FL_COMM_BYTES];
    char exe[FL_PATH_BYTES];
    char cmdline[FL_MAX_CMDLINE_BYTES + 1U];
    pid_t target_pid;
    char target_exe[FL_PATH_BYTES];
    char evidence[FL_EVIDENCE_BYTES];
    bool enrichment_incomplete;
};

json_object *fl_alert_to_json(const struct fl_alert *alert);
bool fl_alert_from_json(json_object *json, struct fl_alert *alert, struct fl_error *error);

#endif
