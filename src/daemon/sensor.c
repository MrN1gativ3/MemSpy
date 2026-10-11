#define _GNU_SOURCE
#include "sensor.h"

#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <glib.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "fileless.skel.h"

struct fl_sensor {
    struct fileless_bpf *skeleton;
    struct perf_buffer *buffer;
    fl_observation_cb callback;
    void *userdata;
    struct fl_sensor_stats stats;
};

static void
set_error(struct fl_error *error, const char *code, const char *format, ...)
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
read_process_stat(pid_t pid, pid_t *ppid, uint64_t *start_ns)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/stat", pid);
    g_autofree char *contents = NULL;
    char *cursor;
    char *save = NULL;
    unsigned int field = 3;
    long ticks = sysconf(_SC_CLK_TCK);

    if (ticks <= 0 || !g_file_get_contents(path, &contents, NULL, NULL))
        return false;
    cursor = strrchr(contents, ')');
    if (cursor == NULL || cursor[1] != ' ')
        return false;
    cursor += 2;
    for (char *token = strtok_r(cursor, " ", &save); token != NULL;
         token = strtok_r(NULL, " ", &save), ++field) {
        if (field == 4 && ppid != NULL)
            *ppid = (pid_t)g_ascii_strtoll(token, NULL, 10);
        if (field == 22) {
            uint64_t ticks_since_boot = g_ascii_strtoull(token, NULL, 10);
            *start_ns = ticks_since_boot * 1000000000ULL / (uint64_t)ticks;
            return true;
        }
    }
    return false;
}

static bool
read_executable(pid_t pid, char *destination, size_t capacity)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/exe", pid);
    ssize_t length = readlink(path, destination, capacity - 1U);
    if (length < 0 || (size_t)length >= capacity)
        return false;
    destination[length] = '\0';
    return true;
}

static bool
read_command_line(pid_t pid, char *destination, size_t capacity)
{
    g_autofree char *path = g_strdup_printf("/proc/%d/cmdline", pid);
    int descriptor = open(path, O_RDONLY | O_CLOEXEC);
    char raw[FL_MAX_CMDLINE_BYTES];
    ssize_t length;
    g_autofree char *valid = NULL;

    if (descriptor < 0)
        return false;
    length = read(descriptor, raw, sizeof raw);
    close(descriptor);
    if (length < 0)
        return false;
    for (ssize_t index = 0; index < length; ++index) {
        if (raw[index] == '\0')
            raw[index] = ' ';
    }
    while (length > 0 && raw[length - 1] == ' ')
        --length;
    valid = g_utf8_make_valid(raw, length);
    g_strlcpy(destination, valid, capacity);
    return true;
}

bool
fl_sensor_observation_from_event(const struct fl_kernel_event *event,
                                 struct fl_observation *observation,
                                 struct fl_error *error)
{
    struct timespec now;
    bool actor_complete;

    if (event == NULL || observation == NULL || event->abi_version != FL_KERNEL_EVENT_ABI) {
        set_error(error, "sensor_abi", "unsupported kernel event ABI");
        return false;
    }
    if (event->pid == 0 || (event->kind != FL_KERNEL_EXEC &&
        event->kind != FL_KERNEL_PROCESS_VM_WRITE && event->kind != FL_KERNEL_PTRACE_WRITE))
        return false;

    *observation = (struct fl_observation){
        .kind = event->kind == FL_KERNEL_EXEC ? FL_OBSERVATION_EXEC :
                event->kind == FL_KERNEL_PROCESS_VM_WRITE ? FL_OBSERVATION_PROCESS_VM_WRITE :
                FL_OBSERVATION_PTRACE_WRITE,
        .process = {.pid = (pid_t)event->pid},
        .target = {.pid = (pid_t)event->target_pid},
        .observed_boottime_ns = event->observed_boottime_ns,
        .uid = (uid_t)event->uid,
        .syscall_result = (long)event->result,
    };
    memcpy(observation->comm, event->comm, sizeof event->comm);
    observation->comm[sizeof event->comm] = '\0';
    clock_gettime(CLOCK_REALTIME, &now);
    observation->timestamp_utc = now.tv_sec;

    actor_complete = read_process_stat(observation->process.pid, &observation->ppid,
                                       &observation->process.start_boottime_ns) &&
                     read_executable(observation->process.pid, observation->exe,
                                     sizeof observation->exe) &&
                     read_command_line(observation->process.pid, observation->cmdline,
                                       sizeof observation->cmdline);
    if (strstr(observation->exe, "memfd:") != NULL)
        observation->flags |= FL_OBSERVATION_MEMFD;
    if (g_str_has_suffix(observation->exe, " (deleted)"))
        observation->flags |= FL_OBSERVATION_DELETED;

    if (observation->target.pid > 0) {
        if (!read_process_stat(observation->target.pid, NULL,
                               &observation->target.start_boottime_ns) ||
            !read_executable(observation->target.pid, observation->target_exe,
                             sizeof observation->target_exe))
            actor_complete = false;
    }
    observation->enrichment_incomplete = !actor_complete;
    return true;
}

static void
on_sample(void *context, int cpu, void *data, __u32 size)
{
    struct fl_sensor *sensor = context;
    const struct fl_kernel_event *event = data;
    struct fl_observation observation;
    struct fl_error error = {0};
    (void)cpu;

    if (size == sizeof(struct fl_kernel_event) && event->abi_version == FL_KERNEL_EVENT_ABI &&
        (event->kind == FL_KERNEL_MEMFD_CREATE || event->kind == FL_KERNEL_FORK))
        return;
    if (size != sizeof(struct fl_kernel_event) ||
        !fl_sensor_observation_from_event(data, &observation, &error)) {
        ++sensor->stats.invalid_events;
        return;
    }
    ++sensor->stats.received_events;
    sensor->callback(&observation, sensor->userdata);
}

static void
on_lost(void *context, int cpu, __u64 lost)
{
    struct fl_sensor *sensor = context;
    (void)cpu;
    sensor->stats.lost_events += lost;
}

bool
fl_sensor_open(struct fl_sensor **out, fl_observation_cb callback, void *userdata,
               struct fl_error *error)
{
    struct fl_sensor *sensor;
    if (out == NULL || callback == NULL) {
        set_error(error, "sensor_invalid", "output and callback are required");
        return false;
    }
    sensor = g_new0(struct fl_sensor, 1);
    sensor->skeleton = fileless_bpf__open();
    if (sensor->skeleton == NULL) {
        set_error(error, "sensor_open", "cannot open BPF skeleton");
        g_free(sensor);
        return false;
    }
    sensor->callback = callback;
    sensor->userdata = userdata;
    *out = sensor;
    return true;
}

bool
fl_sensor_attach(struct fl_sensor *sensor, struct fl_error *error)
{
    int result;
    if (sensor == NULL)
        return false;
    result = fileless_bpf__load(sensor->skeleton);
    if (result == 0)
        result = fileless_bpf__attach(sensor->skeleton);
    if (result != 0) {
        set_error(error, "sensor_attach", "cannot load or attach BPF programs: %s", strerror(-result));
        return false;
    }
    sensor->buffer = perf_buffer__new(bpf_map__fd(sensor->skeleton->maps.events), 8,
                                      on_sample, on_lost, sensor, NULL);
    if (libbpf_get_error(sensor->buffer) != 0) {
        result = (int)libbpf_get_error(sensor->buffer);
        sensor->buffer = NULL;
        set_error(error, "sensor_buffer", "cannot create perf buffer: %s", strerror(-result));
        return false;
    }
    return true;
}

int
fl_sensor_poll(struct fl_sensor *sensor, int timeout_ms, struct fl_error *error)
{
    int result;
    if (sensor == NULL || sensor->buffer == NULL)
        return -1;
    result = perf_buffer__poll(sensor->buffer, timeout_ms);
    if (result < 0 && result != -EINTR)
        set_error(error, "sensor_poll", "%s", strerror(-result));
    return result;
}

void
fl_sensor_stats(const struct fl_sensor *sensor, struct fl_sensor_stats *stats)
{
    if (sensor != NULL && stats != NULL)
        *stats = sensor->stats;
}

void
fl_sensor_free(struct fl_sensor *sensor)
{
    if (sensor == NULL)
        return;
    perf_buffer__free(sensor->buffer);
    fileless_bpf__destroy(sensor->skeleton);
    g_free(sensor);
}
