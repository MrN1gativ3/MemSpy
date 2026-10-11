#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "fileless_shared.h"

struct syscall_enter {
    unsigned long long unused;
    long syscall_id;
    unsigned long args[6];
};

struct syscall_exit {
    unsigned long long unused;
    long syscall_id;
    long result;
};

struct pending_call {
    __u32 kind;
    __u32 target_pid;
    __u64 aux;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct pending_call);
} pending SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __always_inline void
emit(void *context, const struct pending_call *call, long result)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    struct fl_kernel_event event = {
        .abi_version = FL_KERNEL_EVENT_ABI,
        .kind = call->kind,
        .pid = pid_tgid >> 32,
        .uid = uid_gid,
        .target_pid = call->target_pid,
        .result = result,
        .observed_boottime_ns = bpf_ktime_get_ns(),
        .aux = call->aux,
    };

    bpf_get_current_comm(event.comm, sizeof event.comm);
    bpf_perf_event_output(context, &events, BPF_F_CURRENT_CPU, &event, sizeof event);
}

static __always_inline int
remember(__u32 kind, __u32 target_pid, __u64 aux)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call call = {.kind = kind, .target_pid = target_pid, .aux = aux};
    return bpf_map_update_elem(&pending, &key, &call, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int enter_memfd_create(struct syscall_enter *context)
{
    (void)context;
    return remember(FL_KERNEL_MEMFD_CREATE, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int exit_memfd_create(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == FL_KERNEL_MEMFD_CREATE && context->result >= 0)
        emit(context, call, context->result);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int enter_process_vm_writev(struct syscall_enter *context)
{
    return remember(FL_KERNEL_PROCESS_VM_WRITE, (__u32)context->args[0], 0);
}

SEC("tracepoint/syscalls/sys_exit_process_vm_writev")
int exit_process_vm_writev(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == FL_KERNEL_PROCESS_VM_WRITE && context->result > 0)
        emit(context, call, context->result);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int enter_ptrace(struct syscall_enter *context)
{
    if (fl_ptrace_request_modifies(context->args[0]))
        return remember(FL_KERNEL_PTRACE_WRITE, (__u32)context->args[1], context->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int exit_ptrace(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == FL_KERNEL_PTRACE_WRITE && context->result >= 0)
        emit(context, call, context->result);
    bpf_map_delete_elem(&pending, &key);
    return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int process_exec(void *context)
{
    const struct pending_call call = {.kind = FL_KERNEL_EXEC};
    emit(context, &call, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int process_fork(void *context)
{
    const struct pending_call call = {.kind = FL_KERNEL_FORK};
    emit(context, &call, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
