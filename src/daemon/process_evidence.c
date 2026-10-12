#define _GNU_SOURCE
#include "process_evidence.h"

#include <fcntl.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MS_PARENT_HASH_LIMIT (128U * 1024U * 1024U)
#define MS_PROC_READ_LIMIT 8192U

static bool read_text(int directory, const char *name, char *output, size_t capacity)
{
    int descriptor;
    ssize_t length;
    g_autofree char *valid = NULL;

    if (capacity < 2U)
        return false;
    descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0)
        return false;
    length = read(descriptor, output, capacity);
    close(descriptor);
    if (length <= 0 || (size_t)length >= capacity)
        return false;
    output[length] = '\0';
    valid = g_utf8_make_valid(output, length);
    if (strlen(valid) >= capacity)
        return false;
    g_strlcpy(output, valid, capacity);
    return true;
}

static bool read_link(int directory, const char *name, char *output, size_t capacity)
{
    ssize_t length = readlinkat(directory, name, output, capacity - 1U);
    if (length <= 0 || (size_t)length >= capacity - 1U)
        return false;
    output[length] = '\0';
    if (!g_utf8_validate(output, length, NULL)) {
        g_autofree char *valid = g_utf8_make_valid(output, length);
        if (strlen(valid) >= capacity)
            return false;
        g_strlcpy(output, valid, capacity);
    }
    return true;
}

static bool hash_executable(int descriptor, char output[MS_SHA256_BYTES])
{
    struct stat metadata;
    g_autoptr(GChecksum) checksum = NULL;
    unsigned char buffer[64U * 1024U];
    uint64_t total = 0;
    ssize_t length;

    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size < 0 || (uint64_t)metadata.st_size > MS_PARENT_HASH_LIMIT)
        return false;
    checksum = g_checksum_new(G_CHECKSUM_SHA256);
    if (checksum == NULL)
        return false;
    while ((length = read(descriptor, buffer, sizeof buffer)) > 0) {
        total += (uint64_t)length;
        if (total > MS_PARENT_HASH_LIMIT)
            return false;
        g_checksum_update(checksum, buffer, (gsize)length);
    }
    if (length < 0)
        return false;
    g_strlcpy(output, g_checksum_get_string(checksum), MS_SHA256_BYTES);
    return true;
}

static bool parse_parent_pid(const char *stat, pid_t *parent)
{
    const char *after = strrchr(stat, ')');
    char state;
    long value;
    if (after == NULL || sscanf(after + 1, " %c %ld", &state, &value) != 2 ||
        value <= 0 || value > G_MAXINT)
        return false;
    *parent = (pid_t)value;
    return true;
}

static bool parse_namespace(const char *value, uint64_t *identifier)
{
    const char *open = strchr(value, '[');
    char *end = NULL;
    unsigned long long parsed;
    if (open == NULL)
        return false;
    parsed = strtoull(open + 1, &end, 10);
    if (end == open + 1 || *end != ']')
        return false;
    *identifier = parsed;
    return true;
}

static bool process_identity(int root, pid_t pid, char *comm, char *exe,
                             char *sha256, pid_t *parent)
{
    char name[32];
    char stat[MS_PROC_READ_LIMIT + 1U];
    int directory;
    int executable = -1;
    bool complete = true;

    snprintf(name, sizeof name, "%d", pid);
    directory = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0)
        return false;
    if (!read_text(directory, "comm", comm, MS_COMM_BYTES))
        complete = false;
    g_strchomp(comm);
    if (!read_link(directory, "exe", exe, MS_PATH_BYTES))
        complete = false;
    if (parent != NULL && (!read_text(directory, "stat", stat, sizeof stat) ||
                           !parse_parent_pid(stat, parent)))
        complete = false;
    if (sha256 != NULL) {
        executable = openat(directory, "exe", O_RDONLY | O_CLOEXEC);
        if (executable < 0 || !hash_executable(executable, sha256))
            complete = false;
        if (executable >= 0)
            close(executable);
    }
    close(directory);
    return complete;
}

static bool known_container_id(const char *component, char *output, size_t capacity)
{
    size_t length = strlen(component);
    const char *start = component;
    const char *dash;

    if (length > 6U && g_str_has_suffix(component, ".scope"))
        length -= 6U;
    dash = strrchr(component, '-');
    if (dash != NULL)
        start = dash + 1;
    length -= (size_t)(start - component);
    if (length < 12U || length >= capacity)
        return false;
    for (size_t index = 0; index < length; ++index)
        if (!g_ascii_isxdigit(start[index]))
            return false;
    memcpy(output, start, length);
    output[length] = '\0';
    return true;
}

bool ms_process_cgroup_parse(const char *text, struct ms_process_evidence *evidence)
{
    g_auto(GStrv) lines = NULL;
    g_auto(GStrv) components = NULL;
    const char *path = NULL;

    if (text == NULL || evidence == NULL || strlen(text) >= MS_CGROUP_BYTES)
        return false;
    lines = g_strsplit(text, "\n", -1);
    for (size_t index = 0; lines[index] != NULL; ++index) {
        const char *candidate = strrchr(lines[index], ':');
        if (candidate != NULL && candidate[1] == '/')
            path = candidate + 1;
    }
    if (path == NULL || strlen(path) >= sizeof evidence->cgroup_path)
        return false;
    g_strlcpy(evidence->cgroup_path, path, sizeof evidence->cgroup_path);
    components = g_strsplit(path, "/", -1);
    for (size_t index = 0; components[index] != NULL; ++index) {
        const char *part = components[index];
        if ((g_str_has_suffix(part, ".service") || g_str_has_suffix(part, ".scope")) &&
            strlen(part) < sizeof evidence->systemd_unit)
            g_strlcpy(evidence->systemd_unit, part, sizeof evidence->systemd_unit);
        if (strstr(part, "docker") != NULL &&
            known_container_id(part, evidence->container_id, sizeof evidence->container_id))
            g_strlcpy(evidence->container_runtime, "docker", sizeof evidence->container_runtime);
        else if (strstr(part, "libpod") != NULL &&
                 known_container_id(part, evidence->container_id, sizeof evidence->container_id))
            g_strlcpy(evidence->container_runtime, "podman", sizeof evidence->container_runtime);
        else if ((strstr(part, "cri-containerd") != NULL || strlen(part) == 64U) &&
                 known_container_id(part, evidence->container_id, sizeof evidence->container_id))
            g_strlcpy(evidence->container_runtime, "containerd", sizeof evidence->container_runtime);
    }
    return true;
}

bool ms_process_evidence_read_at(const char *proc_root, pid_t pid,
                                 struct ms_process_evidence *evidence)
{
    struct ms_process_evidence result = {0};
    char name[32];
    char cgroup[MS_CGROUP_BYTES + 1U];
    char namespace_link[128];
    char tty[MS_PATH_BYTES];
    char source_comm[MS_COMM_BYTES] = {0};
    char source_exe[MS_PATH_BYTES] = {0};
    pid_t parent = 0;
    int root;
    int directory;

    if (proc_root == NULL || evidence == NULL || pid <= 0)
        return false;
    root = open(proc_root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0)
        return false;
    result.complete = process_identity(root, pid, source_comm, source_exe, NULL, &parent);
    result.parent_pid = parent;
    if (parent <= 0 || !process_identity(root, parent, result.parent_comm, result.parent_exe,
                                         result.parent_sha256, &result.grandparent_pid))
        result.complete = false;
    if (result.grandparent_pid <= 0 ||
        !process_identity(root, result.grandparent_pid, result.grandparent_comm,
                          result.grandparent_exe, NULL, NULL))
        result.complete = false;
    snprintf(name, sizeof name, "%d", pid);
    directory = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory < 0) {
        close(root);
        *evidence = result;
        return false;
    }
    if (!read_text(directory, "cgroup", cgroup, sizeof cgroup) ||
        !ms_process_cgroup_parse(cgroup, &result))
        result.complete = false;
    if (read_link(directory, "fd/0", tty, sizeof tty) && g_str_has_prefix(tty, "/dev/"))
        g_strlcpy(result.tty, tty + 5, sizeof result.tty);
    if (!read_link(directory, "ns/pid", namespace_link, sizeof namespace_link) ||
        !parse_namespace(namespace_link, &result.pid_namespace))
        result.complete = false;
    if (!read_link(directory, "ns/mnt", namespace_link, sizeof namespace_link) ||
        !parse_namespace(namespace_link, &result.mount_namespace))
        result.complete = false;
    result.ssh_origin = strcmp(result.parent_comm, "sshd") == 0 ||
                        strcmp(result.grandparent_comm, "sshd") == 0;
    close(directory);
    close(root);
    *evidence = result;
    return result.complete;
}

bool ms_process_evidence_read(pid_t pid, struct ms_process_evidence *evidence)
{
    return ms_process_evidence_read_at("/proc", pid, evidence);
}

bool ms_proc_mem_target_read(const char *proc_root, pid_t source_pid, int fd,
                             pid_t *namespace_pid, pid_t *host_pid,
                             char *target_exe, size_t capacity)
{
    char descriptor[96];
    char link[MS_PATH_BYTES];
    char executable[96];
    const char *digits;
    char *end = NULL;
    long target;
    ssize_t length;

    if (proc_root == NULL || source_pid <= 0 || fd < 0 || namespace_pid == NULL ||
        host_pid == NULL || target_exe == NULL || capacity < 2U)
        return false;
    *namespace_pid = 0;
    *host_pid = 0;
    target_exe[0] = '\0';
    snprintf(descriptor, sizeof descriptor, "%s/%d/fd/%d", proc_root, source_pid, fd);
    length = readlink(descriptor, link, sizeof link - 1U);
    if (length <= 0 || (size_t)length >= sizeof link - 1U)
        return false;
    link[length] = '\0';
    if (!g_str_has_prefix(link, "/proc/"))
        return false;
    digits = link + strlen("/proc/");
    target = strtol(digits, &end, 10);
    if (end == digits || target <= 0 || target > G_MAXINT || strcmp(end, "/mem") != 0 ||
        target == source_pid)
        return false;
    *namespace_pid = (pid_t)target;

    /* Canonical host-visible procfs paths use the same PID; namespace aliases stay incomplete. */
    snprintf(executable, sizeof executable, "%s/%ld/exe", proc_root, target);
    length = readlink(executable, target_exe, capacity - 1U);
    if (length <= 0 || (size_t)length >= capacity - 1U) {
        target_exe[0] = '\0';
        return false;
    }
    target_exe[length] = '\0';
    *host_pid = (pid_t)target;
    return true;
}
