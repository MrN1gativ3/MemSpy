#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memspy_enforce_shared.h"

#define MS_TMPFS_MAGIC 0x01021994UL
#define MS_EACCES 13

struct syscall_enter {
    unsigned long long unused;
    long syscall_id;
    unsigned long args[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} response_enabled SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct ms_launcher_key);
    __type(value, __u8);
} launcher_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ms_enforce_event);
} pending_exec SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} enforce_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_enforce_counters);
} enforce_counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct ms_enforce_event);
} enforce_scratch SEC(".maps");

static __always_inline void
clear_event(struct ms_enforce_event *event)
{
    volatile __u64 *words = (volatile __u64 *)event;

#pragma unroll
    for (unsigned int index = 0; index < sizeof(*event) / sizeof(__u64); ++index)
        words[index] = 0;
}

static __always_inline int
capture_exec(const char *filename, const char *const *arguments)
{
    __u64 process = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 zero = 0;
    struct ms_enforce_event *event = bpf_map_lookup_elem(&enforce_scratch, &zero);
    long length;

    if (event == NULL)
        return 0;
    clear_event(event);
    event->abi_version = MS_ENFORCE_EVENT_ABI;
    event->kind = MS_ENFORCE_BLOCKED_MEMFD_EXEC;
    event->pid = process >> 32;
    event->uid = uid_gid;
    bpf_get_current_comm(event->comm, sizeof(event->comm));
    length = bpf_probe_read_user_str(event->filename, sizeof(event->filename), filename);
    if (length > 0) {
        event->filename_length = length > sizeof(event->filename) ? sizeof(event->filename) - 1U :
            (__u16)(length - 1);
        if (length >= sizeof(event->filename))
            event->flags |= MS_ENFORCE_FILENAME_TRUNCATED;
    }

#pragma unroll
    for (unsigned int index = 0; index < MS_ENFORCE_MAX_ARGS; ++index) {
        const char *argument = NULL;

        if (bpf_probe_read_user(&argument, sizeof(argument), &arguments[index]) != 0 ||
            argument == NULL)
            break;
        length = bpf_probe_read_user_str(event->arguments[index],
                                         MS_ENFORCE_ARG_SLOT_BYTES, argument);
        if (length <= 0)
            break;
        event->argument_count = index + 1U;
        event->arguments_length += length >= MS_ENFORCE_ARG_SLOT_BYTES ?
            MS_ENFORCE_ARG_SLOT_BYTES - 1U : (__u16)(length - 1);
        if (length >= MS_ENFORCE_ARG_SLOT_BYTES)
            event->flags |= MS_ENFORCE_ARGUMENTS_TRUNCATED;
        if (index + 1U == MS_ENFORCE_MAX_ARGS) {
            const char *extra = NULL;
            if (bpf_probe_read_user(&extra, sizeof(extra), &arguments[index + 1U]) == 0 &&
                extra != NULL)
                event->flags |= MS_ENFORCE_ARGUMENTS_TRUNCATED;
        }
    }
    bpf_map_update_elem(&pending_exec, &process, event, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int enter_execve(struct syscall_enter *context)
{
    return capture_exec((const char *)context->args[0],
                        (const char *const *)context->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int enter_execveat(struct syscall_enter *context)
{
    return capture_exec((const char *)context->args[1],
                        (const char *const *)context->args[2]);
}

static __always_inline bool
has_memfd_name(const unsigned char *name)
{
    char prefix[6];

    if (bpf_probe_read_kernel(prefix, sizeof(prefix), name) != 0)
        return false;
    return prefix[0] == 'm' && prefix[1] == 'e' && prefix[2] == 'm' &&
           prefix[3] == 'f' && prefix[4] == 'd' && prefix[5] == ':';
}

static __always_inline bool
launcher_key(struct task_struct *task, struct ms_launcher_key *key)
{
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    struct file *file;
    struct inode *inode;
    struct super_block *superblock;

    if (mm == NULL)
        return false;
    file = BPF_CORE_READ(mm, exe_file);
    if (file == NULL)
        return false;
    inode = BPF_CORE_READ(file, f_inode);
    if (inode == NULL)
        return false;
    superblock = BPF_CORE_READ(inode, i_sb);
    if (superblock == NULL)
        return false;
    key->device = BPF_CORE_READ(superblock, s_dev);
    key->inode = BPF_CORE_READ(inode, i_ino);
    return true;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_memfd_exec, struct linux_binprm *bprm, int prior_result)
{
    __u64 process = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 zero = 0;
    __u32 *enabled;
    __u8 *allowed = NULL;
    struct file *file;
    struct dentry *dentry;
    struct super_block *superblock;
    const unsigned char *name;
    struct task_struct *task;
    struct task_struct *parent;
    struct ms_launcher_key launcher = {0};
    struct ms_enforce_event *event;
    struct ms_enforce_counters *counters;
    unsigned long magic;
    long length;

    if (prior_result != 0)
        return prior_result;
    enabled = bpf_map_lookup_elem(&response_enabled, &zero);
    if (enabled == NULL || *enabled == 0)
        return 0;
    file = BPF_CORE_READ(bprm, file);
    if (file == NULL)
        return 0;
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry == NULL)
        return 0;
    superblock = BPF_CORE_READ(dentry, d_sb);
    if (superblock == NULL)
        return 0;
    magic = BPF_CORE_READ(superblock, s_magic);
    name = BPF_CORE_READ(dentry, d_name.name);
    task = (struct task_struct *)bpf_get_current_task_btf();
    if (launcher_key(task, &launcher))
        allowed = bpf_map_lookup_elem(&launcher_allowlist, &launcher);
    if (!ms_enforce_should_deny(*enabled, magic == MS_TMPFS_MAGIC,
                                name != NULL && has_memfd_name(name), allowed != NULL))
        return 0;

    counters = bpf_map_lookup_elem(&enforce_counters, &zero);
    if (counters != NULL)
        ++counters->denied;
    event = bpf_map_lookup_elem(&pending_exec, &process);
    if (event == NULL) {
        event = bpf_map_lookup_elem(&enforce_scratch, &zero);
        if (event == NULL)
            return -MS_EACCES;
        clear_event(event);
        event->abi_version = MS_ENFORCE_EVENT_ABI;
        event->kind = MS_ENFORCE_BLOCKED_MEMFD_EXEC;
        event->pid = process >> 32;
        event->uid = uid_gid;
        bpf_get_current_comm(event->comm, sizeof(event->comm));
    }
    event->result = -MS_EACCES;
    event->observed_boottime_ns = bpf_ktime_get_ns();
    event->launcher = launcher;
    parent = BPF_CORE_READ(task, real_parent);
    if (parent != NULL)
        event->ppid = BPF_CORE_READ(parent, tgid);
    length = bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), name);
    if (length > 0) {
        event->filename_length = length >= sizeof(event->filename) ?
            sizeof(event->filename) - 1U : (__u16)(length - 1);
        if (length >= sizeof(event->filename))
            event->flags |= MS_ENFORCE_FILENAME_TRUNCATED;
    }
    if (bpf_perf_event_output((void *)bprm, &enforce_events, BPF_F_CURRENT_CPU,
                              event, sizeof(*event)) != 0 && counters != NULL)
        ++counters->event_errors;
    bpf_map_delete_elem(&pending_exec, &process);
    return -MS_EACCES;
}

char LICENSE[] SEC("license") = "GPL";
