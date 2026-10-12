#define _GNU_SOURCE
#include "enforcer.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "memspy_enforce.skel.h"
#include "process_evidence.h"

enum {
    MAP_ENABLED,
    MAP_ALLOWLIST,
    MAP_PENDING,
    MAP_EVENTS,
    MAP_COUNTERS,
    MAP_SCRATCH,
    MAP_COUNT,
};

enum {
    LINK_EXECVE,
    LINK_EXECVEAT,
    LINK_LSM,
    LINK_COUNT,
};

static const char *const map_names[MAP_COUNT] = {
    "response_enabled", "launcher_allowlist", "pending_exec", "enforce_events",
    "enforce_counters", "enforce_scratch",
};

static const char *const link_names[LINK_COUNT] = {
    "enter_execve", "enter_execveat", "block_memfd_exec",
};

struct real_instance {
    struct memspy_enforce_bpf *skeleton;
    struct bpf_link *links[LINK_COUNT];
    struct perf_buffer *buffer;
    int maps[MAP_COUNT];
    uint64_t perf_lost;
    struct ms_enforcer *owner;
};

struct ms_enforcer {
    char *pin_dir;
    ms_blocked_cb callback;
    void *userdata;
    const struct ms_enforcer_ops *ops;
    void *ops_context;
    void *instance;
    struct ms_enforcer_status status;
};

static void
set_error(struct ms_error *error, const char *code, const char *format, ...)
{
    va_list args;

    if (error == NULL)
        return;
    g_strlcpy(error->code, code, sizeof error->code);
    va_start(args, format);
    g_vsnprintf(error->message, sizeof error->message, format, args);
    va_end(args);
}

static bool
read_link(pid_t pid, char *destination, size_t capacity)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/exe", pid);
    ssize_t length = readlink(path, destination, capacity - 1U);

    if (length < 0 || (size_t)length >= capacity)
        return false;
    destination[length] = '\0';
    return true;
}

static bool
read_username(uid_t uid, char *destination, size_t capacity)
{
    long suggested = sysconf(_SC_GETPW_R_SIZE_MAX);
    size_t size = suggested > 0 ? (size_t)suggested : 16384U;
    g_autofree char *buffer = g_malloc(size);
    struct passwd entry;
    struct passwd *result = NULL;

    if (getpwuid_r(uid, &entry, buffer, size, &result) != 0 || result == NULL)
        return false;
    g_strlcpy(destination, result->pw_name, capacity);
    return destination[0] != '\0';
}

static bool
valid_event(const struct ms_enforce_event *event, struct ms_error *error)
{
    size_t argument_bytes = 0;

    if (event == NULL || event->abi_version != MS_ENFORCE_EVENT_ABI ||
        event->kind != MS_ENFORCE_BLOCKED_MEMFD_EXEC) {
        set_error(error, "enforcer_abi", "unsupported enforcement event ABI");
        return false;
    }
    if (event->pid == 0 || event->result != -EACCES ||
        event->argument_count > MS_ENFORCE_MAX_ARGS ||
        event->arguments_length > MS_ENFORCE_ARG_BYTES ||
        (event->flags & ~(MS_ENFORCE_ARGUMENTS_TRUNCATED |
                          MS_ENFORCE_FILENAME_TRUNCATED)) != 0 ||
        memchr(event->comm, '\0', sizeof event->comm) == NULL ||
        event->filename_length == 0 || event->filename_length >= sizeof event->filename ||
        event->filename[event->filename_length] != '\0' ||
        strnlen(event->filename, sizeof event->filename) != event->filename_length) {
        set_error(error, "enforcer_event", "invalid enforcement event");
        return false;
    }
    for (size_t index = 0; index < event->argument_count; ++index) {
        size_t length = strnlen(event->arguments[index], sizeof event->arguments[index]);
        if (length == sizeof event->arguments[index]) {
            set_error(error, "enforcer_event", "unterminated enforcement argument");
            return false;
        }
        argument_bytes += length;
    }
    if (argument_bytes != event->arguments_length) {
        set_error(error, "enforcer_event", "invalid enforcement argument length");
        return false;
    }
    return true;
}

bool
ms_enforcer_alert_from_event(const struct ms_enforce_event *event,
                             struct ms_alert *alert, struct ms_error *error)
{
    struct timespec now;
    size_t used = 0;
    bool complete;

    if (alert == NULL || !valid_event(event, error))
        return false;
    *alert = (struct ms_alert){
        .observed_boottime_ns = event->observed_boottime_ns,
        .action = MS_ALERT_BLOCKED,
        .severity = MS_SEVERITY_HIGH,
        .pid = (pid_t)event->pid,
        .ppid = (pid_t)event->ppid,
        .uid = (uid_t)event->uid,
        .arguments_truncated =
            (event->flags & MS_ENFORCE_ARGUMENTS_TRUNCATED) != 0,
        .enrichment_incomplete =
            (event->flags & MS_ENFORCE_FILENAME_TRUNCATED) != 0,
    };
    g_strlcpy(alert->rule_id, "BLOCKED_MEMFD_EXEC", sizeof alert->rule_id);
    g_strlcpy(alert->explanation, "MemSpy blocked a memory-backed executable image.",
              sizeof alert->explanation);
    g_strlcpy(alert->evidence, "BPF LSM denied memfd execution", sizeof alert->evidence);
    g_autofree char *valid_comm = g_utf8_make_valid(event->comm, -1);
    g_strlcpy(alert->comm, valid_comm, sizeof alert->comm);
    g_autofree char *valid_filename = g_utf8_make_valid(event->filename,
                                                        event->filename_length);
    g_strlcpy(alert->exe, valid_filename, sizeof alert->exe);
    for (size_t index = 0; index < event->argument_count; ++index) {
        g_autofree char *valid = g_utf8_make_valid(event->arguments[index], -1);
        g_autofree char *quoted = g_shell_quote(valid);
        size_t length = strlen(quoted);

        if (used + (used == 0 ? 0U : 1U) + length >= sizeof alert->cmdline) {
            alert->arguments_truncated = true;
            break;
        }
        if (used != 0)
            alert->cmdline[used++] = ' ';
        memcpy(alert->cmdline + used, quoted, length + 1U);
        used += length;
    }
    complete = read_username(alert->uid, alert->username, sizeof alert->username) &&
               read_link(alert->pid, alert->launcher_exe, sizeof alert->launcher_exe) &&
               ms_process_evidence_read(alert->ppid, alert->parent_comm,
                                        sizeof alert->parent_comm,
                                        alert->parent_exe, sizeof alert->parent_exe,
                                        alert->parent_sha256,
                                        sizeof alert->parent_sha256);
    alert->enrichment_incomplete |= !complete;
    clock_gettime(CLOCK_REALTIME, &now);
    alert->timestamp_utc = now.tv_sec;
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

static char *
pin_path(const char *directory, const char *name, bool staged)
{
    return g_strdup_printf("%s/%s%s", directory, name, staged ? "_new" : "");
}

static bool
map_compatible(int descriptor, size_t index)
{
    static const struct {
        enum bpf_map_type type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
    } expected[MAP_COUNT] = {
        {BPF_MAP_TYPE_ARRAY, 4, 4, 1},
        {BPF_MAP_TYPE_HASH, sizeof(struct ms_launcher_key), 1, 4096},
        {BPF_MAP_TYPE_LRU_HASH, 8, sizeof(struct ms_enforce_event), 4096},
        {BPF_MAP_TYPE_PERF_EVENT_ARRAY, 4, 4, 0},
        {BPF_MAP_TYPE_PERCPU_ARRAY, 4, sizeof(struct ms_enforce_counters), 1},
        {BPF_MAP_TYPE_PERCPU_ARRAY, 4, sizeof(struct ms_enforce_event), 1},
    };
    struct bpf_map_info info = {0};
    __u32 length = sizeof info;

    return bpf_obj_get_info_by_fd(descriptor, &info, &length) == 0 &&
           strcmp((const char *)info.name, map_names[index]) == 0 &&
           info.type == expected[index].type && info.key_size == expected[index].key_size &&
           info.value_size == expected[index].value_size &&
           (expected[index].max_entries == 0 ||
            info.max_entries == expected[index].max_entries);
}

static bool
link_compatible(struct bpf_link *link, size_t index)
{
    struct bpf_link_info link_info = {0};
    struct bpf_prog_info program_info = {0};
    __u32 length = sizeof link_info;
    __u32 program_length = sizeof program_info;
    int program_fd;
    bool compatible;

    if (libbpf_get_error(link) != 0 ||
        bpf_obj_get_info_by_fd(bpf_link__fd(link), &link_info, &length) != 0)
        return false;
    program_fd = bpf_prog_get_fd_by_id(link_info.prog_id);
    if (program_fd < 0)
        return false;
    compatible = bpf_obj_get_info_by_fd(program_fd, &program_info, &program_length) == 0 &&
                 strncmp((const char *)program_info.name, link_names[index],
                         sizeof program_info.name - 1U) == 0;
    close(program_fd);
    return compatible;
}

static enum ms_enforcer_pins
real_inspect(void *context, const char *directory)
{
    bool any = false;
    bool compatible = true;
    (void)context;

    for (size_t index = 0; index < MAP_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, map_names[index], false);
        int descriptor = bpf_obj_get(path);
        if (descriptor < 0) {
            if (g_file_test(path, G_FILE_TEST_EXISTS))
                any = true;
            compatible = false;
            continue;
        }
        any = true;
        compatible &= map_compatible(descriptor, index);
        close(descriptor);
    }
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, link_names[index], false);
        struct bpf_link *link = bpf_link__open(path);
        if (libbpf_get_error(link) != 0) {
            if (g_file_test(path, G_FILE_TEST_EXISTS))
                any = true;
            compatible = false;
            continue;
        }
        any = true;
        compatible &= link_compatible(link, index);
        bpf_link__destroy(link);
    }
    return !any ? MS_ENFORCER_PINS_NONE :
           compatible ? MS_ENFORCER_PINS_COMPATIBLE : MS_ENFORCER_PINS_INCOMPATIBLE;
}

static void on_lost(void *context, int cpu, __u64 lost);
static void on_sample(void *context, int cpu, void *data, __u32 size);

static bool
open_buffer(struct real_instance *instance, struct ms_error *error)
{
    instance->buffer = perf_buffer__new(instance->maps[MAP_EVENTS], 8, on_sample, on_lost,
                                        instance, NULL);
    if (libbpf_get_error(instance->buffer) == 0)
        return true;
    int result = (int)libbpf_get_error(instance->buffer);
    instance->buffer = NULL;
    set_error(error, "enforcer_buffer", "cannot create enforcement buffer: %s",
              strerror(-result));
    return false;
}

static bool
real_adopt(void *context, const char *directory, struct ms_enforcer *owner,
           void **output, struct ms_error *error)
{
    struct real_instance *instance = g_new0(struct real_instance, 1);
    (void)context;

    instance->owner = owner;
    for (size_t index = 0; index < MAP_COUNT; ++index)
        instance->maps[index] = -1;
    for (size_t index = 0; index < MAP_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, map_names[index], false);
        instance->maps[index] = bpf_obj_get(path);
        if (instance->maps[index] < 0 || !map_compatible(instance->maps[index], index))
            goto fail;
    }
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, link_names[index], false);
        instance->links[index] = bpf_link__open(path);
        if (!link_compatible(instance->links[index], index)) {
            instance->links[index] = NULL;
            goto fail;
        }
    }
    if (!open_buffer(instance, error))
        goto fail;
    *output = instance;
    return true;

fail:
    set_error(error, "enforcer_adopt", "cannot adopt compatible MemSpy BPF pins");
    for (size_t index = 0; index < LINK_COUNT; ++index)
        bpf_link__destroy(instance->links[index]);
    for (size_t index = 0; index < MAP_COUNT; ++index)
        if (instance->maps[index] >= 0)
            close(instance->maps[index]);
    g_free(instance);
    return false;
}

static bool
real_hold(void *context, const char *directory, void **output, struct ms_error *error)
{
    struct real_instance *instance = g_new0(struct real_instance, 1);
    (void)context;
    (void)error;

    for (size_t index = 0; index < MAP_COUNT; ++index)
        instance->maps[index] = -1;
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, link_names[index], false);
        instance->links[index] = bpf_link__open(path);
        if (libbpf_get_error(instance->links[index]) != 0)
            instance->links[index] = NULL;
    }
    *output = instance;
    return true;
}

static bool
real_create(void *context, struct ms_enforcer *owner, void **output,
            struct ms_error *error)
{
    struct real_instance *instance = g_new0(struct real_instance, 1);
    int result;
    (void)context;

    for (size_t index = 0; index < MAP_COUNT; ++index)
        instance->maps[index] = -1;
    instance->owner = owner;
    instance->skeleton = memspy_enforce_bpf__open();
    if (instance->skeleton == NULL) {
        set_error(error, "enforcer_open", "cannot open enforcement BPF object");
        goto fail;
    }
    result = memspy_enforce_bpf__load(instance->skeleton);
    if (result == 0)
        result = memspy_enforce_bpf__attach(instance->skeleton);
    if (result != 0) {
        set_error(error, "enforcer_attach", "cannot load or attach BPF LSM: %s",
                  strerror(-result));
        goto fail;
    }
    instance->maps[MAP_ENABLED] = bpf_map__fd(instance->skeleton->maps.response_enabled);
    instance->maps[MAP_ALLOWLIST] = bpf_map__fd(instance->skeleton->maps.launcher_allowlist);
    instance->maps[MAP_PENDING] = bpf_map__fd(instance->skeleton->maps.pending_exec);
    instance->maps[MAP_EVENTS] = bpf_map__fd(instance->skeleton->maps.enforce_events);
    instance->maps[MAP_COUNTERS] = bpf_map__fd(instance->skeleton->maps.enforce_counters);
    instance->maps[MAP_SCRATCH] = bpf_map__fd(instance->skeleton->maps.enforce_scratch);
    if (!open_buffer(instance, error))
        goto fail;
    *output = instance;
    return true;

fail:
    memspy_enforce_bpf__destroy(instance->skeleton);
    g_free(instance);
    return false;
}

static bool
clear_allowlist(int descriptor)
{
    struct ms_launcher_key key;

    while (bpf_map_get_next_key(descriptor, NULL, &key) == 0)
        if (bpf_map_delete_elem(descriptor, &key) != 0)
            return false;
    return errno == ENOENT;
}

static bool
real_configure(void *context, void *opaque, const GArray *keys, bool enabled,
               struct ms_error *error)
{
    struct real_instance *instance = opaque;
    __u8 allowed = 1;
    __u32 zero = 0;
    __u32 value = enabled;
    (void)context;

    if (!clear_allowlist(instance->maps[MAP_ALLOWLIST])) {
        set_error(error, "enforcer_allowlist", "cannot clear launcher allowlist: %s",
                  g_strerror(errno));
        return false;
    }
    if (keys != NULL)
        for (guint index = 0; index < keys->len; ++index) {
            const struct ms_launcher_key *key =
                &g_array_index(keys, struct ms_launcher_key, index);
            if (bpf_map_update_elem(instance->maps[MAP_ALLOWLIST], key, &allowed,
                                    BPF_NOEXIST) != 0) {
                set_error(error, "enforcer_allowlist", "cannot update launcher allowlist: %s",
                          g_strerror(errno));
                return false;
            }
        }
    if (bpf_map_update_elem(instance->maps[MAP_ENABLED], &zero, &value, BPF_ANY) != 0) {
        set_error(error, "enforcer_state", "cannot update response map: %s",
                  g_strerror(errno));
        return false;
    }
    return true;
}

static struct bpf_map *
skeleton_map(struct memspy_enforce_bpf *skeleton, size_t index)
{
    struct bpf_map *maps[MAP_COUNT] = {
        skeleton->maps.response_enabled, skeleton->maps.launcher_allowlist,
        skeleton->maps.pending_exec, skeleton->maps.enforce_events,
        skeleton->maps.enforce_counters, skeleton->maps.enforce_scratch,
    };
    return maps[index];
}

static struct bpf_link *
skeleton_link(struct memspy_enforce_bpf *skeleton, size_t index)
{
    struct bpf_link *links[LINK_COUNT] = {
        skeleton->links.enter_execve, skeleton->links.enter_execveat,
        skeleton->links.block_memfd_exec,
    };
    return links[index];
}

static bool
real_stage(void *context, void *opaque, const char *directory, struct ms_error *error)
{
    struct real_instance *instance = opaque;
    (void)context;

    if (instance->skeleton == NULL || g_mkdir_with_parents(directory, 0700) != 0) {
        set_error(error, "enforcer_pin", "cannot create MemSpy BPF pin directory: %s",
                  g_strerror(errno));
        return false;
    }
    for (size_t index = 0; index < MAP_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, map_names[index], true);
        unlink(path);
        if (bpf_map__pin(skeleton_map(instance->skeleton, index), path) != 0) {
            set_error(error, "enforcer_pin", "cannot stage MemSpy BPF map: %s",
                      g_strerror(errno));
            goto fail;
        }
    }
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, link_names[index], true);
        unlink(path);
        if (bpf_link__pin(skeleton_link(instance->skeleton, index), path) != 0) {
            set_error(error, "enforcer_pin", "cannot stage MemSpy BPF link: %s",
                      g_strerror(errno));
            goto fail;
        }
    }
    return true;

fail:
    for (size_t index = 0; index < MAP_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, map_names[index], true);
        unlink(path);
    }
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, link_names[index], true);
        unlink(path);
    }
    return false;
}

static bool
real_remove_owned(void *context, const char *directory, struct ms_error *error)
{
    (void)context;
    for (size_t index = 0; index < MAP_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, map_names[index], false);
        if (unlink(path) != 0 && errno != ENOENT)
            goto fail;
    }
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *path = pin_path(directory, link_names[index], false);
        if (unlink(path) != 0 && errno != ENOENT)
            goto fail;
    }
    return true;

fail:
    set_error(error, "enforcer_pin", "cannot remove an old MemSpy BPF pin: %s",
              g_strerror(errno));
    return false;
}

static bool
real_promote(void *context, const char *directory, struct ms_error *error)
{
    (void)context;
    for (size_t index = 0; index < MAP_COUNT; ++index) {
        g_autofree char *source = pin_path(directory, map_names[index], true);
        g_autofree char *destination = pin_path(directory, map_names[index], false);
        if (rename(source, destination) != 0)
            goto fail;
    }
    for (size_t index = 0; index < LINK_COUNT; ++index) {
        g_autofree char *source = pin_path(directory, link_names[index], true);
        g_autofree char *destination = pin_path(directory, link_names[index], false);
        if (rename(source, destination) != 0)
            goto fail;
    }
    return true;

fail:
    set_error(error, "enforcer_pin", "cannot publish MemSpy BPF pins: %s",
              g_strerror(errno));
    return false;
}

static bool
real_set_enabled(void *context, void *opaque, bool enabled, struct ms_error *error)
{
    struct real_instance *instance = opaque;
    __u32 zero = 0;
    __u32 value = enabled;
    (void)context;

    if (bpf_map_update_elem(instance->maps[MAP_ENABLED], &zero, &value, BPF_ANY) == 0)
        return true;
    set_error(error, "enforcer_state", "cannot update response map: %s", g_strerror(errno));
    return false;
}

static int
real_poll(void *context, void *opaque, int timeout_ms, uint64_t *denied,
          uint64_t *lost, struct ms_error *error)
{
    struct real_instance *instance = opaque;
    int count = libbpf_num_possible_cpus();
    struct ms_enforce_counters *values;
    __u32 zero = 0;
    int result;
    (void)context;

    result = perf_buffer__poll(instance->buffer, timeout_ms);
    if (result < 0 && result != -EINTR) {
        set_error(error, "enforcer_poll", "%s", strerror(-result));
        return result;
    }
    if (count <= 0)
        return result;
    values = g_new0(struct ms_enforce_counters, count);
    if (bpf_map_lookup_elem(instance->maps[MAP_COUNTERS], &zero, values) == 0)
        for (int index = 0; index < count; ++index) {
            *denied += values[index].denied;
            *lost += values[index].event_errors;
        }
    *lost += instance->perf_lost;
    g_free(values);
    return result;
}

static void
real_release(void *context, void *opaque)
{
    struct real_instance *instance = opaque;
    (void)context;

    if (instance == NULL)
        return;
    perf_buffer__free(instance->buffer);
    if (instance->skeleton != NULL) {
        memspy_enforce_bpf__destroy(instance->skeleton);
    } else {
        for (size_t index = 0; index < LINK_COUNT; ++index)
            bpf_link__destroy(instance->links[index]);
        for (size_t index = 0; index < MAP_COUNT; ++index)
            if (instance->maps[index] >= 0)
                close(instance->maps[index]);
    }
    g_free(instance);
}

static const struct ms_enforcer_ops real_ops = {
    .inspect = real_inspect,
    .adopt = real_adopt,
    .hold = real_hold,
    .create = real_create,
    .configure = real_configure,
    .stage = real_stage,
    .remove_owned = real_remove_owned,
    .promote = real_promote,
    .set_enabled = real_set_enabled,
    .poll = real_poll,
    .release = real_release,
};

static void
on_sample(void *context, int cpu, void *data, __u32 size)
{
    struct real_instance *instance = context;
    struct ms_alert alert;
    struct ms_error error = {0};
    (void)cpu;

    if (size >= sizeof(struct ms_enforce_event) &&
        ms_enforcer_alert_from_event(data, &alert, &error))
        instance->owner->callback(&alert, instance->owner->userdata);
}

static void
on_lost(void *context, int cpu, __u64 lost)
{
    struct real_instance *instance = context;
    (void)cpu;
    instance->perf_lost += lost;
}

bool
ms_enforcer_open_with_ops(struct ms_enforcer **out, const char *directory,
                          ms_blocked_cb callback, void *userdata,
                          const struct ms_enforcer_ops *ops, void *ops_context,
                          struct ms_error *error)
{
    g_autofree char *canonical = NULL;
    struct ms_enforcer *enforcer;

    if (out == NULL || directory == NULL || callback == NULL || ops == NULL ||
        ops->inspect == NULL || ops->adopt == NULL || ops->hold == NULL ||
        ops->create == NULL || ops->configure == NULL || ops->stage == NULL ||
        ops->remove_owned == NULL || ops->promote == NULL ||
        ops->set_enabled == NULL || ops->poll == NULL || ops->release == NULL ||
        !g_path_is_absolute(directory)) {
        set_error(error, "enforcer_invalid", "output, absolute pin directory and callback are required");
        return false;
    }
    canonical = g_canonicalize_filename(directory, NULL);
    if (strcmp(canonical, directory) != 0 || strcmp(directory, "/") == 0) {
        set_error(error, "enforcer_invalid", "pin directory must be an exact canonical path");
        return false;
    }
    enforcer = g_new0(struct ms_enforcer, 1);
    enforcer->pin_dir = g_strdup(directory);
    enforcer->callback = callback;
    enforcer->userdata = userdata;
    enforcer->ops = ops;
    enforcer->ops_context = ops_context;
    g_strlcpy(enforcer->status.reason, "response mode has not been probed",
              sizeof enforcer->status.reason);
    *out = enforcer;
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

bool
ms_enforcer_open(struct ms_enforcer **out, const char *directory,
                 ms_blocked_cb callback, void *userdata, struct ms_error *error)
{
    return ms_enforcer_open_with_ops(out, directory, callback, userdata,
                                     &real_ops, NULL, error);
}

static bool
unsupported(struct ms_enforcer *enforcer, void *instance, void *old,
            struct ms_error *operation_error, struct ms_error *caller_error)
{
    enforcer->ops->release(enforcer->ops_context, instance);
    enforcer->ops->release(enforcer->ops_context, old);
    enforcer->status = (struct ms_enforcer_status){0};
    g_strlcpy(enforcer->status.reason,
              operation_error != NULL && operation_error->message[0] != '\0' ?
                  operation_error->message : "response mode is unavailable",
              sizeof enforcer->status.reason);
    if (caller_error != NULL)
        *caller_error = (struct ms_error){0};
    return true;
}

bool
ms_enforcer_attach(struct ms_enforcer *enforcer, const GArray *launcher_keys,
                   bool requested, struct ms_error *error)
{
    struct ms_error operation_error = {0};
    enum ms_enforcer_pins pins;
    void *instance = NULL;
    void *old = NULL;

    if (enforcer == NULL) {
        set_error(error, "enforcer_invalid", "enforcer is required");
        return false;
    }
    if (enforcer->instance != NULL) {
        set_error(error, "enforcer_invalid", "enforcer is already attached");
        return false;
    }
    pins = enforcer->ops->inspect(enforcer->ops_context, enforcer->pin_dir);
    if (pins == MS_ENFORCER_PINS_COMPATIBLE) {
        if (!enforcer->ops->adopt(enforcer->ops_context, enforcer->pin_dir, enforcer,
                                  &instance, &operation_error) ||
            !enforcer->ops->configure(enforcer->ops_context, instance, launcher_keys,
                                      requested, &operation_error))
            return unsupported(enforcer, instance, NULL, &operation_error, error);
    } else {
        if (pins == MS_ENFORCER_PINS_INCOMPATIBLE &&
            !enforcer->ops->hold(enforcer->ops_context, enforcer->pin_dir, &old,
                                 &operation_error))
            return unsupported(enforcer, NULL, old, &operation_error, error);
        if (!enforcer->ops->create(enforcer->ops_context, enforcer, &instance,
                                   &operation_error) ||
            !enforcer->ops->configure(enforcer->ops_context, instance, launcher_keys,
                                      requested, &operation_error) ||
            !enforcer->ops->stage(enforcer->ops_context, instance, enforcer->pin_dir,
                                  &operation_error) ||
            (pins == MS_ENFORCER_PINS_INCOMPATIBLE &&
             !enforcer->ops->remove_owned(enforcer->ops_context, enforcer->pin_dir,
                                          &operation_error)) ||
            !enforcer->ops->promote(enforcer->ops_context, enforcer->pin_dir,
                                    &operation_error))
            return unsupported(enforcer, instance, old, &operation_error, error);
        enforcer->ops->release(enforcer->ops_context, old);
    }
    enforcer->instance = instance;
    enforcer->status.supported = true;
    enforcer->status.enabled = requested;
    enforcer->status.reason[0] = '\0';
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

bool
ms_enforcer_set_enabled(struct ms_enforcer *enforcer, bool enabled,
                        struct ms_error *error)
{
    if (enforcer == NULL || !enforcer->status.supported || enforcer->instance == NULL) {
        set_error(error, "enforcer_unavailable", "response mode is unavailable");
        return false;
    }
    if (!enforcer->ops->set_enabled(enforcer->ops_context, enforcer->instance, enabled,
                                    error))
        return false;
    enforcer->status.enabled = enabled;
    return true;
}

int
ms_enforcer_poll(struct ms_enforcer *enforcer, int timeout_ms, struct ms_error *error)
{
    uint64_t denied = 0;
    uint64_t lost = 0;
    int result;

    if (enforcer == NULL || !enforcer->status.supported || enforcer->instance == NULL)
        return 0;
    result = enforcer->ops->poll(enforcer->ops_context, enforcer->instance, timeout_ms,
                                 &denied, &lost, error);
    if (result >= 0) {
        enforcer->status.denied = denied;
        enforcer->status.lost_events = lost;
    }
    return result;
}

bool
ms_enforcer_remove_pins(struct ms_enforcer *enforcer, struct ms_error *error)
{
    if (enforcer == NULL || enforcer->instance == NULL) {
        set_error(error, "enforcer_unavailable", "enforcer is not attached");
        return false;
    }
    return enforcer->ops->remove_owned(enforcer->ops_context, enforcer->pin_dir, error);
}

void
ms_enforcer_status(const struct ms_enforcer *enforcer, struct ms_enforcer_status *out)
{
    if (enforcer != NULL && out != NULL)
        *out = enforcer->status;
}

void
ms_enforcer_free(struct ms_enforcer *enforcer)
{
    if (enforcer == NULL)
        return;
    enforcer->ops->release(enforcer->ops_context, enforcer->instance);
    g_free(enforcer->pin_dir);
    g_free(enforcer);
}
