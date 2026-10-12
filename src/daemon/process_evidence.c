#define _GNU_SOURCE
#include "process_evidence.h"

#include <fcntl.h>
#include <glib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MS_PARENT_HASH_LIMIT (128U * 1024U * 1024U)

static bool
read_comm(int procfd, char *destination, size_t capacity)
{
    char raw[256];
    int descriptor = openat(procfd, "comm", O_RDONLY | O_CLOEXEC);
    ssize_t length;
    g_autofree char *valid = NULL;

    if (descriptor < 0)
        return false;
    length = read(descriptor, raw, sizeof raw - 1U);
    close(descriptor);
    if (length <= 0)
        return false;
    raw[length] = '\0';
    g_strchomp(raw);
    valid = g_utf8_make_valid(raw, -1);
    if (valid[0] == '\0' || strlen(valid) >= capacity)
        return false;
    g_strlcpy(destination, valid, capacity);
    return true;
}

static bool
hash_executable(int descriptor, char *destination, size_t capacity)
{
    struct stat metadata;
    g_autoptr(GChecksum) checksum = NULL;
    unsigned char buffer[64U * 1024U];
    uint64_t total = 0;
    ssize_t length;
    const char *digest;

    if (capacity < 65U || fstat(descriptor, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_size < 0 ||
        (uint64_t)metadata.st_size > MS_PARENT_HASH_LIMIT)
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
    digest = g_checksum_get_string(checksum);
    if (digest == NULL || strlen(digest) + 1U > capacity)
        return false;
    g_strlcpy(destination, digest, capacity);
    return true;
}

bool
ms_process_evidence_read(pid_t pid, char *comm, size_t comm_capacity,
                         char *exe, size_t exe_capacity,
                         char *sha256, size_t sha256_capacity)
{
    char proc_path[64];
    char descriptor_path[64];
    int procfd;
    int executable;
    ssize_t length;
    bool complete;

    if (pid <= 0 || comm == NULL || comm_capacity == 0 || exe == NULL ||
        exe_capacity < 2U || sha256 == NULL || sha256_capacity < 65U)
        return false;
    comm[0] = '\0';
    exe[0] = '\0';
    sha256[0] = '\0';
    snprintf(proc_path, sizeof proc_path, "/proc/%d", pid);
    procfd = open(proc_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (procfd < 0)
        return false;
    executable = openat(procfd, "exe", O_RDONLY | O_CLOEXEC);
    if (executable < 0) {
        close(procfd);
        return false;
    }
    snprintf(descriptor_path, sizeof descriptor_path, "/proc/self/fd/%d", executable);
    length = readlink(descriptor_path, exe, exe_capacity - 1U);
    if (length >= 0 && (size_t)length < exe_capacity)
        exe[length] = '\0';
    else
        exe[0] = '\0';
    complete = read_comm(procfd, comm, comm_capacity) && exe[0] != '\0' &&
               hash_executable(executable, sha256, sha256_capacity);
    close(executable);
    close(procfd);
    return complete;
}
