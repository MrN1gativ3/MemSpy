#ifndef MEMSPY_BPF_SHARED_H
#define MEMSPY_BPF_SHARED_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define MS_KERNEL_EVENT_ABI 2U
#define MS_KERNEL_COMM_BYTES 16U
#define MS_PROC_SUPER_MAGIC 0x9fa0UL
#define MS_PROC_PID_BYTES 12U

enum ms_kernel_event_kind {
    MS_KERNEL_EXEC = 1,
    MS_KERNEL_MEMFD_CREATE,
    MS_KERNEL_PROCESS_VM_WRITE,
    MS_KERNEL_PTRACE_WRITE,
    MS_KERNEL_FORK,
    MS_KERNEL_FILE_WRITE,
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

static __inline int
ms_is_proc_mem_file(unsigned long magic, const char name[4])
{
    return magic == MS_PROC_SUPER_MAGIC && name[0] == 'm' && name[1] == 'e' &&
           name[2] == 'm' && name[3] == '\0';
}

static __inline __u32
ms_parse_proc_pid(const char *name)
{
    __u64 value = 0;

#ifdef __clang__
#pragma clang loop unroll(full)
#endif
    for (unsigned int index = 0; index < MS_PROC_PID_BYTES; ++index) {
        char character = name[index];

        if (character == '\0')
            return value > 0 && value <= 2147483647U ? (__u32)value : 0;
        if (character < '0' || character > '9')
            return 0;
        value = value * 10U + (__u64)(character - '0');
    }
    return 0;
}

#endif
