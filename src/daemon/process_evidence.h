#ifndef MEMSPY_PROCESS_EVIDENCE_H
#define MEMSPY_PROCESS_EVIDENCE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include "memspy/alert.h"

struct ms_process_evidence {
    pid_t parent_pid;
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
    bool complete;
};

bool ms_process_cgroup_parse(const char *text, struct ms_process_evidence *evidence);
bool ms_process_evidence_read_at(const char *proc_root, pid_t pid,
                                 struct ms_process_evidence *evidence);
bool ms_process_evidence_read(pid_t pid, struct ms_process_evidence *evidence);
bool ms_proc_mem_target_read(const char *proc_root, pid_t source_pid, int fd,
                             pid_t *namespace_pid, pid_t *host_pid,
                             char *target_exe, size_t capacity);

#endif
