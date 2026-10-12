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
#define MS_SHA256_BYTES 65U
#define MS_EVIDENCE_BYTES 1024U
#define MS_UNIT_BYTES 256U
#define MS_CGROUP_BYTES 1024U
#define MS_CONTAINER_ID_BYTES 129U
#define MS_CONTAINER_RUNTIME_BYTES 32U
#define MS_TTY_BYTES 64U

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
    char parent_comm[MS_COMM_BYTES];
    char parent_exe[MS_PATH_BYTES];
    char parent_sha256[MS_SHA256_BYTES];
    pid_t grandparent_pid;
    char grandparent_comm[MS_COMM_BYTES];
    char grandparent_exe[MS_PATH_BYTES];
    char systemd_unit[MS_UNIT_BYTES];
    char cgroup_path[MS_CGROUP_BYTES];
    char container_id[MS_CONTAINER_ID_BYTES];
    char container_runtime[MS_CONTAINER_RUNTIME_BYTES];
    char tty[MS_TTY_BYTES];
    bool ssh_origin;
    uint64_t pid_namespace;
    uint64_t mount_namespace;
    pid_t target_pid;
    pid_t target_namespace_pid;
    char target_exe[MS_PATH_BYTES];
    uint64_t bytes_written;
    char evidence[MS_EVIDENCE_BYTES];
    bool enrichment_incomplete;
    bool arguments_truncated;
};

json_object *ms_alert_to_json(const struct ms_alert *alert);
bool ms_alert_from_json(json_object *json, struct ms_alert *alert, struct ms_error *error);

#endif
