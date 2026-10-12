#ifndef MEMSPY_ALERT_H
#define MEMSPY_ALERT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include <json-c/json.h>

#include "memspy/protocol.h"

#define MS_RULE_ID_BYTES 64U
#define MS_EXPLANATION_BYTES 256U
#define MS_COMM_BYTES 64U
#define MS_USERNAME_BYTES 256U
#define MS_PATH_BYTES 4096U
#define MS_EVIDENCE_BYTES 1024U

enum ms_severity {
    MS_SEVERITY_MEDIUM = 1,
    MS_SEVERITY_HIGH = 2,
};

enum ms_alert_action {
    MS_ALERT_DETECTED = 0,
    MS_ALERT_BLOCKED = 1,
};

struct ms_alert {
    int64_t id;
    int64_t timestamp_utc;
    uint64_t observed_boottime_ns;
    enum ms_alert_action action;
    enum ms_severity severity;
    char rule_id[MS_RULE_ID_BYTES];
    char explanation[MS_EXPLANATION_BYTES];
    pid_t pid;
    pid_t ppid;
    uid_t uid;
    char comm[MS_COMM_BYTES];
    char username[MS_USERNAME_BYTES];
    char exe[MS_PATH_BYTES];
    char cmdline[MS_MAX_CMDLINE_BYTES + 1U];
    char launcher_exe[MS_PATH_BYTES];
    char parent_exe[MS_PATH_BYTES];
    pid_t target_pid;
    char target_exe[MS_PATH_BYTES];
    char evidence[MS_EVIDENCE_BYTES];
    bool enrichment_incomplete;
    bool arguments_truncated;
};

json_object *ms_alert_to_json(const struct ms_alert *alert);
bool ms_alert_from_json(json_object *json, struct ms_alert *alert, struct ms_error *error);

#endif
