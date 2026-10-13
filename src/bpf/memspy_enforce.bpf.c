#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "memspy_enforce_shared.h"

#define MS_TMPFS_MAGIC 0x01021994UL
#define MS_PROC_SUPER_MAGIC 0x9fa0UL
#define MS_EACCES 13
#define MS_MAY_WRITE 2
#define MS_PTRACE_ATTACH 16UL
#define MS_PTRACE_SEIZE 0x4206UL

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

enum ms_intent_kind {
    MS_INTENT_PROCESS_VM_WRITE = 1,
    MS_INTENT_PTRACE_ATTACH,
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
    __type(key, struct ms_allowlist_key);
    __type(value, __u8);
} launcher_allowlist SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u64);
    __type(value, struct ms_enforce_intent);
} pending_injection SEC(".maps");

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

static __always_inline bool
task_allowed(struct task_struct *task, enum ms_response_rule rule,
             struct ms_launcher_key *launcher)
{
    struct ms_allowlist_key key = {.rule = rule};

    if (!launcher_key(task, launcher))
        return false;
    key.device = launcher->device;
    key.inode = launcher->inode;
    return bpf_map_lookup_elem(&launcher_allowlist, &key) != NULL;
}

static __always_inline __u32
task_tgid(struct task_struct *task)
{
    return task == NULL ? 0 : (__u32)BPF_CORE_READ(task, tgid);
}

static __always_inline int
emit_simple_denial(void *context, enum ms_enforce_event_kind kind,
                   struct task_struct *actor, __u32 target_pid,
                   struct ms_launcher_key launcher)
{
    __u32 zero = 0;
    struct ms_enforce_counters *counters =
        bpf_map_lookup_elem(&enforce_counters, &zero);
    struct ms_enforce_event *event = bpf_map_lookup_elem(&enforce_scratch, &zero);

    if (counters != NULL)
        ++counters->denied[kind];
    if (event == NULL)
        return -MS_EACCES;
    clear_event(event);
    event->abi_version = MS_ENFORCE_EVENT_ABI;
    event->kind = kind;
    event->pid = task_tgid(actor);
    event->target_pid = target_pid;
    event->uid = (__u32)bpf_get_current_uid_gid();
    event->result = -MS_EACCES;
    event->observed_boottime_ns = bpf_ktime_get_ns();
    event->launcher = launcher;
    event->filename[0] = '?';
    event->filename_length = 1;
    if (actor != NULL) {
        struct task_struct *parent = BPF_CORE_READ(actor, real_parent);
        event->ppid = task_tgid(parent);
        bpf_probe_read_kernel_str(event->comm, sizeof(event->comm), actor->comm);
    }
    if (bpf_perf_event_output(context, &enforce_events, BPF_F_CURRENT_CPU,
                              event, sizeof(*event)) != 0 && counters != NULL)
        ++counters->event_errors;
    return -MS_EACCES;
}

static __always_inline int
remember_intent(__u32 kind, __u32 target_pid)
{
    __u64 process = bpf_get_current_pid_tgid();
    struct ms_enforce_intent intent = {.kind = kind, .target_pid = target_pid};

    return bpf_map_update_elem(&pending_injection, &process, &intent, BPF_ANY);
}

SEC("tracepoint/syscalls/sys_enter_process_vm_writev")
int enforce_enter_process_vm_writev(struct syscall_enter *context)
{
    return remember_intent(MS_INTENT_PROCESS_VM_WRITE, (__u32)context->args[0]);
}

SEC("tracepoint/syscalls/sys_exit_process_vm_writev")
int enforce_exit_process_vm_writev(struct syscall_exit *context)
{
    __u64 process = bpf_get_current_pid_tgid();
    (void)context;
    bpf_map_delete_elem(&pending_injection, &process);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int enforce_enter_ptrace(struct syscall_enter *context)
{
    if (context->args[0] == MS_PTRACE_ATTACH || context->args[0] == MS_PTRACE_SEIZE)
        return remember_intent(MS_INTENT_PTRACE_ATTACH, (__u32)context->args[1]);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_ptrace")
int enforce_exit_ptrace(struct syscall_exit *context)
{
    __u64 process = bpf_get_current_pid_tgid();
    (void)context;
    bpf_map_delete_elem(&pending_injection, &process);
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(block_suspicious_exec, struct linux_binprm *bprm, int prior_result)
{
    __u64 process = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 zero = 0;
    __u32 *enabled;
    bool allowed;
    struct file *file;
    struct inode *inode;
    struct dentry *dentry;
    struct super_block *superblock;
    const unsigned char *name;
    struct task_struct *task;
    struct task_struct *parent;
    struct ms_launcher_key launcher = {0};
    struct ms_enforce_event *event;
    struct ms_enforce_counters *counters;
    unsigned long magic;
    unsigned int links;
    enum ms_enforce_event_kind kind;
    enum ms_response_rule rule;
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
    inode = BPF_CORE_READ(file, f_inode);
    if (inode == NULL)
        return 0;
    links = BPF_CORE_READ(inode, i_nlink);
    name = BPF_CORE_READ(dentry, d_name.name);
    if (magic == MS_TMPFS_MAGIC && name != NULL && has_memfd_name(name)) {
        kind = MS_ENFORCE_BLOCKED_MEMFD_EXEC;
        rule = MS_RESPONSE_MEMFD_EXEC;
    } else if (links == 0) {
        kind = MS_ENFORCE_BLOCKED_DELETED_EXEC;
        rule = MS_RESPONSE_DELETED_EXEC;
    } else {
        return 0;
    }
    task = (struct task_struct *)bpf_get_current_task_btf();
    allowed = task_allowed(task, rule, &launcher);
    if (!ms_enforce_should_deny(*enabled, 1, 1, allowed))
        return 0;

    counters = bpf_map_lookup_elem(&enforce_counters, &zero);
    if (counters != NULL)
        ++counters->denied[kind];
    event = bpf_map_lookup_elem(&pending_exec, &process);
    if (event == NULL) {
        event = bpf_map_lookup_elem(&enforce_scratch, &zero);
        if (event == NULL)
            return -MS_EACCES;
        clear_event(event);
        event->abi_version = MS_ENFORCE_EVENT_ABI;
        event->kind = kind;
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
    if (bpf_perf_event_output(ctx, &enforce_events, BPF_F_CURRENT_CPU,
                              event, sizeof(*event)) != 0 && counters != NULL)
        ++counters->event_errors;
    bpf_map_delete_elem(&pending_exec, &process);
    return -MS_EACCES;
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(block_process_vm_write, struct task_struct *child, unsigned int mode,
             int prior_result)
{
    __u64 process = bpf_get_current_pid_tgid();
    __u32 actor_pid = process >> 32;
    __u32 target_pid = task_tgid(child);
    __u32 zero = 0;
    __u32 *enabled = bpf_map_lookup_elem(&response_enabled, &zero);
    struct ms_enforce_intent *intent = bpf_map_lookup_elem(&pending_injection, &process);
    struct task_struct *actor = (struct task_struct *)bpf_get_current_task_btf();
    struct ms_launcher_key launcher = {0};
    bool allowed;
    (void)mode;

    if (prior_result != 0 || enabled == NULL || intent == NULL ||
        intent->kind != MS_INTENT_PROCESS_VM_WRITE || intent->target_pid != target_pid)
        return prior_result;
    allowed = task_allowed(actor, MS_RESPONSE_PROCESS_VM_WRITE, &launcher);
    if (!ms_enforce_should_deny_cross_process(*enabled, actor_pid, target_pid, 1, allowed))
        return 0;
    return emit_simple_denial(ctx, MS_ENFORCE_BLOCKED_PROCESS_VM_WRITE,
                              actor, target_pid, launcher);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(block_ptrace_access, struct task_struct *child, unsigned int mode,
             int prior_result)
{
    __u64 process = bpf_get_current_pid_tgid();
    __u32 actor_pid = process >> 32;
    __u32 target_pid = task_tgid(child);
    __u32 zero = 0;
    __u32 *enabled = bpf_map_lookup_elem(&response_enabled, &zero);
    struct ms_enforce_intent *intent = bpf_map_lookup_elem(&pending_injection, &process);
    struct task_struct *actor = (struct task_struct *)bpf_get_current_task_btf();
    struct ms_launcher_key launcher = {0};
    bool allowed;
    (void)mode;

    if (prior_result != 0 || enabled == NULL || intent == NULL ||
        intent->kind != MS_INTENT_PTRACE_ATTACH || intent->target_pid != target_pid)
        return prior_result;
    allowed = task_allowed(actor, MS_RESPONSE_PTRACE_WRITE, &launcher);
    if (!ms_enforce_should_deny_cross_process(*enabled, actor_pid, target_pid, 1, allowed))
        return 0;
    return emit_simple_denial(ctx, MS_ENFORCE_BLOCKED_PTRACE_ACCESS,
                              actor, target_pid, launcher);
}

SEC("lsm/ptrace_traceme")
int BPF_PROG(block_ptrace_traceme, struct task_struct *parent, int prior_result)
{
    __u32 zero = 0;
    __u32 *enabled = bpf_map_lookup_elem(&response_enabled, &zero);
    struct task_struct *target = (struct task_struct *)bpf_get_current_task_btf();
    struct ms_launcher_key launcher = {0};
    __u32 actor_pid = task_tgid(parent);
    __u32 target_pid = task_tgid(target);
    bool allowed;

    if (prior_result != 0 || enabled == NULL)
        return prior_result;
    allowed = task_allowed(parent, MS_RESPONSE_PTRACE_WRITE, &launcher);
    if (!ms_enforce_should_deny_cross_process(*enabled, actor_pid, target_pid, 1, allowed))
        return 0;
    return emit_simple_denial(ctx, MS_ENFORCE_BLOCKED_PTRACE_ACCESS,
                              parent, target_pid, launcher);
}

static __always_inline __u32
proc_mem_target(struct file *file)
{
    struct inode *inode = BPF_CORE_READ(file, f_inode);
    struct proc_inode *proc_inode;
    struct pid *pid;
    struct hlist_node *pid_node;
    struct task_struct *target;

    if (inode == NULL)
        return 0;
    proc_inode = (struct proc_inode *)((char *)inode -
                 bpf_core_field_offset(struct proc_inode, vfs_inode));
    pid = BPF_CORE_READ(proc_inode, pid);
    if (pid == NULL)
        return 0;
    pid_node = BPF_CORE_READ(pid, tasks[0].first);
    if (pid_node == NULL)
        return 0;
    target = (struct task_struct *)((char *)pid_node -
             bpf_core_field_offset(struct task_struct, pid_links[0]));
    return task_tgid(target);
}

SEC("lsm/file_permission")
int BPF_PROG(block_proc_mem_write, struct file *file, int mask, int prior_result)
{
    __u32 zero = 0;
    __u32 *enabled = bpf_map_lookup_elem(&response_enabled, &zero);
    struct dentry *dentry;
    struct super_block *superblock;
    const unsigned char *name;
    struct task_struct *actor = (struct task_struct *)bpf_get_current_task_btf();
    struct ms_launcher_key launcher = {0};
    __u32 actor_pid = task_tgid(actor);
    __u32 target_pid;
    unsigned long magic;
    char filename[4] = {0};
    bool allowed;

    if (prior_result != 0 || enabled == NULL || *enabled == 0 ||
        (mask & MS_MAY_WRITE) == 0 || file == NULL)
        return prior_result;
    dentry = BPF_CORE_READ(file, f_path.dentry);
    if (dentry == NULL)
        return 0;
    superblock = BPF_CORE_READ(dentry, d_sb);
    name = BPF_CORE_READ(dentry, d_name.name);
    if (superblock == NULL || name == NULL)
        return 0;
    magic = BPF_CORE_READ(superblock, s_magic);
    if (magic != MS_PROC_SUPER_MAGIC ||
        bpf_probe_read_kernel(filename, sizeof(filename), name) != 0 ||
        filename[0] != 'm' || filename[1] != 'e' || filename[2] != 'm' ||
        filename[3] != '\0')
        return 0;
    target_pid = proc_mem_target(file);
    allowed = task_allowed(actor, MS_RESPONSE_PROC_MEM_WRITE, &launcher);
    if (!ms_enforce_should_deny_cross_process(*enabled, actor_pid, target_pid,
                                              target_pid != 0, allowed))
        return 0;
    return emit_simple_denial(ctx, MS_ENFORCE_BLOCKED_PROC_MEM_WRITE,
                              actor, target_pid, launcher);
}

char LICENSE[] SEC("license") = "GPL";
