#ifndef MEMSPY_BPF_SHARED_H
#define MEMSPY_BPF_SHARED_H

#include <linux/types.h>

#define MS_KERNEL_EVENT_ABI 1U
#define MS_KERNEL_COMM_BYTES 16U

enum ms_kernel_event_kind {
    MS_KERNEL_EXEC = 1,
    MS_KERNEL_MEMFD_CREATE,
    MS_KERNEL_PROCESS_VM_WRITE,
    MS_KERNEL_PTRACE_WRITE,
    MS_KERNEL_FORK,
};

struct ms_kernel_event {
    __u16 abi_version;
    __u16 kind;
    __u32 flags;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 target_pid;
    __s64 result;
    __u64 observed_boottime_ns;
    __u64 aux;
    char comm[MS_KERNEL_COMM_BYTES];
};

static __inline int
ms_ptrace_request_modifies(unsigned long request)
{
    return request == 4 || request == 5 || request == 6 || request == 13 ||
           request == 14 || request == 19 || request == 0x4203 ||
           request == 0x4205 || request == 0x420b || request == 0x420d;
}

#endif
