#ifndef FILELESS_BPF_SHARED_H
#define FILELESS_BPF_SHARED_H

#include <linux/types.h>

#define FL_KERNEL_EVENT_ABI 1U
#define FL_KERNEL_COMM_BYTES 16U

enum fl_kernel_event_kind {
    FL_KERNEL_EXEC = 1,
    FL_KERNEL_MEMFD_CREATE,
    FL_KERNEL_PROCESS_VM_WRITE,
    FL_KERNEL_PTRACE_WRITE,
    FL_KERNEL_FORK,
};

struct fl_kernel_event {
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
    char comm[FL_KERNEL_COMM_BYTES];
};

static __inline int
fl_ptrace_request_modifies(unsigned long request)
{
    return request == 4 || request == 5 || request == 6 || request == 13 ||
           request == 14 || request == 19 || request == 0x4203 ||
           request == 0x4205 || request == 0x420b || request == 0x420d;
}

#endif
