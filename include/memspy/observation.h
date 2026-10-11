#ifndef MEMSPY_OBSERVATION_H
#define MEMSPY_OBSERVATION_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "memspy/alert.h"

enum ms_observation_kind {
    MS_OBSERVATION_EXEC = 1,
    MS_OBSERVATION_PROCESS_VM_WRITE,
    MS_OBSERVATION_PTRACE_WRITE,
};

enum ms_observation_flag {
    MS_OBSERVATION_MEMFD = 1U << 0,
    MS_OBSERVATION_DELETED = 1U << 1,
};

struct ms_process_id {
    pid_t pid;
    uint64_t start_boottime_ns;
};

struct ms_observation {
    enum ms_observation_kind kind;
    struct ms_process_id process;
    struct ms_process_id target;
    uint64_t observed_boottime_ns;
    int64_t timestamp_utc;
    pid_t ppid;
    uid_t uid;
    long syscall_result;
    unsigned int flags;
    char comm[MS_COMM_BYTES];
    char exe[MS_PATH_BYTES];
    char cmdline[MS_MAX_CMDLINE_BYTES + 1U];
    char target_exe[MS_PATH_BYTES];
    bool enrichment_incomplete;
};

#endif
