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
    MS_OBSERVATION_PROC_MEM_WRITE,
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
    char username[MS_USERNAME_BYTES];
    char exe[MS_PATH_BYTES];
    char exe_md5[MS_MD5_BYTES];
    char exe_sha256[MS_SHA256_BYTES];
    enum ms_hash_status exe_hash_status;
    char cmdline[MS_MAX_CMDLINE_BYTES + 1U];
    char parent_comm[MS_COMM_BYTES];
    char parent_exe[MS_PATH_BYTES];
    char parent_md5[MS_MD5_BYTES];
    char parent_sha256[MS_SHA256_BYTES];
    enum ms_hash_status parent_hash_status;
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
    pid_t target_namespace_pid;
    char target_exe[MS_PATH_BYTES];
    char target_md5[MS_MD5_BYTES];
    char target_sha256[MS_SHA256_BYTES];
    enum ms_hash_status target_hash_status;
    uint64_t bytes_written;
    bool enrichment_incomplete;
    bool arguments_truncated;
};

#endif
