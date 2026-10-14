#ifndef MEMSPY_ENFORCE_SHARED_H
#define MEMSPY_ENFORCE_SHARED_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MS_ENFORCE_EVENT_ABI 2U
/* Kernel and userspace share this event layout. Fixed-size argument slots
 * bound BPF work and perf-event size; truncation flags tell userspace when
 * the original command line did not fit. Bump the ABI when layout changes. */
#define MS_ENFORCE_MAX_ARGS 16U
#define MS_ENFORCE_ARG_BYTES 2048U
#define MS_ENFORCE_ARG_SLOT_BYTES (MS_ENFORCE_ARG_BYTES / MS_ENFORCE_MAX_ARGS)
#define MS_ENFORCE_FILENAME_BYTES 256U
#define MS_ENFORCE_COMM_BYTES 16U

enum ms_enforce_event_kind {
    MS_ENFORCE_BLOCKED_MEMFD_EXEC = 1,
    MS_ENFORCE_BLOCKED_DELETED_EXEC,
    MS_ENFORCE_BLOCKED_PROCESS_VM_WRITE,
    MS_ENFORCE_BLOCKED_PTRACE_ACCESS,
    MS_ENFORCE_BLOCKED_PROC_MEM_WRITE,
    MS_ENFORCE_KIND_COUNT,
};

enum ms_response_rule {
    MS_RESPONSE_MEMFD_EXEC = 1,
    MS_RESPONSE_DELETED_EXEC,
    MS_RESPONSE_PROCESS_VM_WRITE,
    MS_RESPONSE_PTRACE_WRITE,
    MS_RESPONSE_PROC_MEM_WRITE,
};

enum ms_enforce_event_flag {
    MS_ENFORCE_ARGUMENTS_TRUNCATED = 1U << 0,
    MS_ENFORCE_FILENAME_TRUNCATED = 1U << 1,
};

struct ms_launcher_key {
    __u64 device;
    __u64 inode;
};

struct ms_allowlist_key {
    __u32 rule;
    __u32 reserved;
    __u64 device;
    __u64 inode;
};

struct ms_enforce_intent {
    __u32 kind;
    __u32 target_pid;
};

struct ms_enforce_event {
    __u16 abi_version;
    __u16 kind;
    __u32 flags;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 target_pid;
    __u32 target_namespace_pid;
    __s32 result;
    __u64 observed_boottime_ns;
    struct ms_launcher_key launcher;
    __u16 filename_length;
    __u16 arguments_length;
    __u8 argument_count;
    __u8 reserved[3];
    char comm[MS_ENFORCE_COMM_BYTES];
    char filename[MS_ENFORCE_FILENAME_BYTES];
    char arguments[MS_ENFORCE_MAX_ARGS][MS_ENFORCE_ARG_SLOT_BYTES];
};

struct ms_enforce_counters {
    __u64 denied[MS_ENFORCE_KIND_COUNT];
    __u64 event_errors;
};

static __inline int
ms_enforce_should_deny(__u32 enabled, __u32 shmem, __u32 memfd_name,
                       __u32 launcher_allowed)
{
    return enabled != 0 && shmem != 0 && memfd_name != 0 && launcher_allowed == 0;
}

static __inline int
ms_enforce_should_deny_cross_process(__u32 enabled, __u32 actor_pid,
                                     __u32 target_pid, __u32 target_verified,
                                     __u32 launcher_allowed)
{
    return enabled != 0 && actor_pid != 0 && target_pid != 0 &&
           actor_pid != target_pid && target_verified != 0 && launcher_allowed == 0;
}

#endif
