#include "policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MS_POLICY_MAX_TARGETS 4096U

struct injection_record {
    bool occupied;
    struct ms_process_id target;
    uint64_t observed_boottime_ns;
    enum ms_observation_kind kind;
};

struct ms_policy {
    struct injection_record injections[MS_POLICY_MAX_TARGETS];
    uint64_t pressure;
};

static void
copy_string(char *destination, size_t capacity, const char *source)
{
    snprintf(destination, capacity, "%s", source);
}

static void
fill_common_alert(const struct ms_observation *observation, struct ms_alert *alert)
{
    *alert = (struct ms_alert){
        .action = MS_ALERT_DETECTED,
        .timestamp_utc = observation->timestamp_utc,
        .observed_boottime_ns = observation->observed_boottime_ns,
        .pid = observation->process.pid,
        .ppid = observation->ppid,
        .uid = observation->uid,
        .target_pid = observation->target.pid,
        .grandparent_pid = observation->grandparent_pid,
        .ssh_origin = observation->ssh_origin,
        .pid_namespace = observation->pid_namespace,
        .mount_namespace = observation->mount_namespace,
        .target_namespace_pid = observation->target_namespace_pid,
        .bytes_written = observation->bytes_written,
        .enrichment_incomplete = observation->enrichment_incomplete,
        .arguments_truncated = observation->arguments_truncated,
    };
    copy_string(alert->comm, sizeof alert->comm, observation->comm);
    copy_string(alert->username, sizeof alert->username, observation->username);
    copy_string(alert->exe, sizeof alert->exe, observation->exe);
    copy_string(alert->exe_md5, sizeof alert->exe_md5, observation->exe_md5);
    copy_string(alert->exe_sha256, sizeof alert->exe_sha256, observation->exe_sha256);
    alert->exe_hash_status = observation->exe_hash_status;
    copy_string(alert->cmdline, sizeof alert->cmdline, observation->cmdline);
    copy_string(alert->parent_comm, sizeof alert->parent_comm, observation->parent_comm);
    copy_string(alert->parent_exe, sizeof alert->parent_exe, observation->parent_exe);
    copy_string(alert->parent_md5, sizeof alert->parent_md5, observation->parent_md5);
    copy_string(alert->parent_sha256, sizeof alert->parent_sha256,
                observation->parent_sha256);
    alert->parent_hash_status = observation->parent_hash_status;
    copy_string(alert->grandparent_comm, sizeof alert->grandparent_comm,
                observation->grandparent_comm);
    copy_string(alert->grandparent_exe, sizeof alert->grandparent_exe,
                observation->grandparent_exe);
    copy_string(alert->systemd_unit, sizeof alert->systemd_unit, observation->systemd_unit);
    copy_string(alert->cgroup_path, sizeof alert->cgroup_path, observation->cgroup_path);
    copy_string(alert->container_id, sizeof alert->container_id, observation->container_id);
    copy_string(alert->container_runtime, sizeof alert->container_runtime,
                observation->container_runtime);
    copy_string(alert->tty, sizeof alert->tty, observation->tty);
    copy_string(alert->target_exe, sizeof alert->target_exe, observation->target_exe);
    copy_string(alert->target_md5, sizeof alert->target_md5, observation->target_md5);
    copy_string(alert->target_sha256, sizeof alert->target_sha256,
                observation->target_sha256);
    alert->target_hash_status = observation->target_hash_status;
}

static void
set_rule(struct ms_alert *alert, const char *rule_id, enum ms_severity severity,
         const char *explanation, const char *evidence)
{
    alert->severity = severity;
    copy_string(alert->rule_id, sizeof alert->rule_id, rule_id);
    copy_string(alert->explanation, sizeof alert->explanation, explanation);
    copy_string(alert->evidence, sizeof alert->evidence, evidence);
}

static bool
same_process(struct ms_process_id left, struct ms_process_id right)
{
    return left.pid == right.pid && left.start_boottime_ns == right.start_boottime_ns;
}

static struct injection_record *
find_injection(struct ms_policy *policy, struct ms_process_id target, uint64_t now)
{
    size_t index;

    for (index = 0; index < MS_POLICY_MAX_TARGETS; ++index) {
        struct injection_record *record = &policy->injections[index];

        if (!record->occupied || !same_process(record->target, target))
            continue;
        if (now < record->observed_boottime_ns ||
            now - record->observed_boottime_ns > MS_CORRELATION_WINDOW_NS)
            return NULL;
        return record;
    }
    return NULL;
}

static void
remember_injection(struct ms_policy *policy, const struct ms_observation *observation)
{
    struct injection_record *slot = NULL;
    struct injection_record *oldest = &policy->injections[0];
    size_t index;

    if (observation->target.pid <= 0 || observation->target.start_boottime_ns == 0)
        return;

    for (index = 0; index < MS_POLICY_MAX_TARGETS; ++index) {
        struct injection_record *record = &policy->injections[index];

        if (record->occupied && same_process(record->target, observation->target)) {
            if (observation->observed_boottime_ns <= record->observed_boottime_ns)
                return;
            slot = record;
            break;
        }
        if (!record->occupied ||
            (observation->observed_boottime_ns >= record->observed_boottime_ns &&
             observation->observed_boottime_ns - record->observed_boottime_ns > MS_CORRELATION_WINDOW_NS)) {
            slot = record;
            break;
        }
        if (record->observed_boottime_ns < oldest->observed_boottime_ns)
            oldest = record;
    }
    if (slot == NULL) {
        slot = oldest;
        ++policy->pressure;
    }
    *slot = (struct injection_record){
        .occupied = true,
        .target = observation->target,
        .observed_boottime_ns = observation->observed_boottime_ns,
        .kind = observation->kind,
    };
}

struct ms_policy *
ms_policy_new(void)
{
    return calloc(1, sizeof(struct ms_policy));
}

void
ms_policy_free(struct ms_policy *policy)
{
    free(policy);
}

uint64_t
ms_policy_pressure(const struct ms_policy *policy)
{
    return policy == NULL ? 0 : policy->pressure;
}

enum ms_policy_result
ms_policy_ingest(struct ms_policy *policy, const struct ms_observation *observation,
                 struct ms_alert *alert)
{
    bool suspicious_exec;

    if (policy == NULL || observation == NULL || alert == NULL)
        return MS_POLICY_NONE;

    if (observation->kind == MS_OBSERVATION_PROCESS_VM_WRITE ||
        observation->kind == MS_OBSERVATION_PTRACE_WRITE ||
        observation->kind == MS_OBSERVATION_PROC_MEM_WRITE) {
        if (observation->syscall_result < 0 || observation->target.pid <= 0 ||
            observation->target.pid == observation->process.pid)
            return MS_POLICY_NONE;
        remember_injection(policy, observation);
        fill_common_alert(observation, alert);
        if (observation->kind == MS_OBSERVATION_PROCESS_VM_WRITE)
            set_rule(alert, "PROCESS_VM_WRITE", MS_SEVERITY_MEDIUM,
                     "A process wrote into another process", "successful process_vm_writev");
        else if (observation->kind == MS_OBSERVATION_PTRACE_WRITE)
            set_rule(alert, "PTRACE_WRITE", MS_SEVERITY_MEDIUM,
                     "A process used a modifying ptrace operation", "successful modifying ptrace");
        else
            set_rule(alert, "PROC_MEM_WRITE", MS_SEVERITY_MEDIUM,
                     "A process wrote through another process's proc memory file",
                     "successful write to canonical /proc/<pid>/mem descriptor");
        return MS_POLICY_ALERT;
    }

    if (observation->kind != MS_OBSERVATION_EXEC)
        return MS_POLICY_NONE;

    suspicious_exec = (observation->flags & (MS_OBSERVATION_MEMFD | MS_OBSERVATION_DELETED)) != 0;
    if (suspicious_exec && find_injection(policy, observation->process,
                                          observation->observed_boottime_ns) != NULL) {
        fill_common_alert(observation, alert);
        set_rule(alert, "INJECTION_CHAIN", MS_SEVERITY_HIGH,
                 "A modified process executed a suspicious image",
                 "cross-process write followed by memfd or deleted-image execution");
        return MS_POLICY_ALERT;
    }
    if ((observation->flags & MS_OBSERVATION_MEMFD) != 0) {
        fill_common_alert(observation, alert);
        set_rule(alert, "MEMFD_EXEC", MS_SEVERITY_HIGH,
                 "A process executed an image backed by memfd", "memfd-backed executable image");
        return MS_POLICY_ALERT;
    }
    if ((observation->flags & MS_OBSERVATION_DELETED) != 0) {
        fill_common_alert(observation, alert);
        set_rule(alert, "DELETED_EXEC", MS_SEVERITY_MEDIUM,
                 "A process executed an image already marked deleted", "deleted executable image");
        return MS_POLICY_ALERT;
    }
    return MS_POLICY_NONE;
}
