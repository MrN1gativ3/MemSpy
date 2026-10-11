#ifndef FILELESS_OBSERVATION_H
#define FILELESS_OBSERVATION_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "fileless/alert.h"

enum fl_observation_kind {
    FL_OBSERVATION_EXEC = 1,
    FL_OBSERVATION_PROCESS_VM_WRITE,
    FL_OBSERVATION_PTRACE_WRITE,
};

enum fl_observation_flag {
    FL_OBSERVATION_MEMFD = 1U << 0,
    FL_OBSERVATION_DELETED = 1U << 1,
};

struct fl_process_id {
    pid_t pid;
    uint64_t start_boottime_ns;
};

struct fl_observation {
    enum fl_observation_kind kind;
    struct fl_process_id process;
    struct fl_process_id target;
    uint64_t observed_boottime_ns;
    int64_t timestamp_utc;
    pid_t ppid;
    uid_t uid;
    long syscall_result;
    unsigned int flags;
    char comm[FL_COMM_BYTES];
    char exe[FL_PATH_BYTES];
    char cmdline[FL_MAX_CMDLINE_BYTES + 1U];
    char target_exe[FL_PATH_BYTES];
    bool enrichment_incomplete;
};

#endif
