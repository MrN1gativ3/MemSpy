#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "memspy_shared.h"

#define MS_CORE_READ(destination, source, field) \
    bpf_probe_read((destination), sizeof(*(destination)), \
                   __builtin_preserve_access_index(&(source)->field))

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

/* A syscall's entry gives us the target and operation; its exit gives us the result.
 * Keep the entry data under the calling thread ID, then emit only after a
 * successful exit. The LRU bound prevents abandoned entries from growing
 * without limit if an exit is missed. */
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
    struct ms_kernel_event event = {
        .abi_version = MS_KERNEL_EVENT_ABI,
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
    return remember(MS_KERNEL_MEMFD_CREATE, 0, 0);
}

SEC("tracepoint/syscalls/sys_exit_memfd_create")
int exit_memfd_create(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == MS_KERNEL_MEMFD_CREATE) {
        if (context->result >= 0)
            emit(context, call, context->result);
        bpf_map_delete_elem(&pending, &key);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int enter_process_vm_writev(struct syscall_enter *context)
{
    return remember(MS_KERNEL_PROCESS_VM_WRITE, (__u32)context->args[0], 0);
}

SEC("tracepoint/syscalls/sys_exit_process_vm_writev")
int exit_process_vm_writev(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == MS_KERNEL_PROCESS_VM_WRITE) {
        if (context->result > 0)
            emit(context, call, context->result);
        bpf_map_delete_elem(&pending, &key);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int enter_ptrace(struct syscall_enter *context)
{
    if (ms_ptrace_request_modifies(context->args[0]))
        return remember(MS_KERNEL_PTRACE_WRITE, (__u32)context->args[1], context->args[0]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int exit_ptrace(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == MS_KERNEL_PTRACE_WRITE) {
        if (context->result >= 0)
            emit(context, call, context->result);
        bpf_map_delete_elem(&pending, &key);
    }
    return 0;
}

static __always_inline __u32 proc_mem_target(__u32 fd, __u32 *namespace_pid)
{
    /* A path supplied by the caller is not trustworthy evidence of a write
     * through /proc/<pid>/mem. Walk the open descriptor to verify that it is
     * the procfs "mem" inode and discover which process it refers to. */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files;
    struct fdtable *table;
    struct file **descriptors;
    struct file *file = NULL;
    struct inode *inode;
    struct proc_inode *proc_inode;
    struct pid *pid;
    struct hlist_node *pid_node;
    struct task_struct *target_task;
    struct dentry *dentry;
    struct dentry *parent;
    struct super_block *superblock;
    const unsigned char *name;
    const unsigned char *parent_name;
    unsigned int maximum;
    unsigned long magic;
    int host_tgid;
    char filename[4] = {0};
    char process[MS_PROC_PID_BYTES] = {0};

    if (MS_CORE_READ(&files, task, files) != 0 || files == NULL)
        return 0;
    if (MS_CORE_READ(&table, files, fdt) != 0 || table == NULL)
        return 0;
    if (MS_CORE_READ(&maximum, table, max_fds) != 0)
        return 0;
    /* shortcut: Linux defaults to at most 1M fds; use a file-pointer hook if larger tables matter. */
    if (fd >= maximum || fd > 1048575U)
        return 0;
    if (MS_CORE_READ(&descriptors, table, fd) != 0)
        return 0;
    if (descriptors == NULL ||
        bpf_probe_read(&file, sizeof file, &descriptors[fd]) != 0 || file == NULL)
        return 0;
    if (MS_CORE_READ(&dentry, file, f_path.dentry) != 0 || dentry == NULL)
        return 0;
    if (MS_CORE_READ(&inode, file, f_inode) != 0 || inode == NULL)
        return 0;
    if (MS_CORE_READ(&superblock, dentry, d_sb) != 0 || superblock == NULL)
        return 0;
    if (MS_CORE_READ(&magic, superblock, s_magic) != 0 ||
        MS_CORE_READ(&name, dentry, d_name.name) != 0 || name == NULL ||
        bpf_probe_read(filename, sizeof filename, name) != 0 ||
        !ms_is_proc_mem_file(magic, filename))
        return 0;
    if (MS_CORE_READ(&parent, dentry, d_parent) != 0 || parent == NULL ||
        MS_CORE_READ(&parent_name, parent, d_name.name) != 0 || parent_name == NULL ||
        bpf_probe_read_str(process, sizeof process, parent_name) <= 0)
        return 0;
    *namespace_pid = ms_parse_proc_pid(process);
    if (*namespace_pid == 0)
        return 0;
    /* The directory name is the PID visible in this procfs mount. Follow the
     * proc inode to its task as well, so userspace can correlate the event
     * using the host PID even when namespaces give it a different number. */
    proc_inode = (struct proc_inode *)((char *)inode -
                 bpf_core_field_offset(struct proc_inode, vfs_inode));
    if (MS_CORE_READ(&pid, proc_inode, pid) != 0 || pid == NULL ||
        MS_CORE_READ(&pid_node, pid, tasks[0].first) != 0 || pid_node == NULL)
        return 0;
    target_task = (struct task_struct *)((char *)pid_node -
                  bpf_core_field_offset(struct task_struct, pid_links[0]));
    if (MS_CORE_READ(&host_tgid, target_task, tgid) != 0 || host_tgid <= 0)
        return 0;
    return (__u32)host_tgid;
}

static __always_inline int remember_file_write(struct syscall_enter *context)
{
    __u32 fd = (__u32)context->args[0];
    __u32 namespace_pid = 0;
    __u32 target_pid = proc_mem_target(fd, &namespace_pid);

    if (target_pid == 0)
        return 0;
    return remember(MS_KERNEL_FILE_WRITE, target_pid, namespace_pid);
}

static __always_inline int finish_file_write(struct syscall_exit *context)
{
    __u64 key = bpf_get_current_pid_tgid();
    struct pending_call *call = bpf_map_lookup_elem(&pending, &key);
    if (call != NULL && call->kind == MS_KERNEL_FILE_WRITE) {
        if (context->result > 0)
            emit(context, call, context->result);
        bpf_map_delete_elem(&pending, &key);
    }
    return 0;
}

#define MS_WRITE_TRACEPOINT(name) \
SEC("tracepoint/syscalls/sys_enter_" #name) \
int enter_##name(struct syscall_enter *context) { return remember_file_write(context); } \
SEC("tracepoint/syscalls/sys_exit_" #name) \
int exit_##name(struct syscall_exit *context) { return finish_file_write(context); }

MS_WRITE_TRACEPOINT(write)
MS_WRITE_TRACEPOINT(pwrite64)
MS_WRITE_TRACEPOINT(writev)
MS_WRITE_TRACEPOINT(pwritev)
MS_WRITE_TRACEPOINT(pwritev2)

SEC("tracepoint/sched/sched_process_exec")
int process_exec(void *context)
{
    const struct pending_call call = {.kind = MS_KERNEL_EXEC};
    emit(context, &call, 0);
    return 0;
}

SEC("tracepoint/sched/sched_process_fork")
int process_fork(void *context)
{
    const struct pending_call call = {.kind = MS_KERNEL_FORK};
    emit(context, &call, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
