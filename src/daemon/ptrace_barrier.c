#define _POSIX_C_SOURCE 200809L

#include "ptrace_barrier.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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
numeric_pid(const char *name, unsigned int *pid)
{
    char *end = NULL;
    guint64 value;

    if (name == NULL || *name == '\0')
        return false;
    errno = 0;
    value = g_ascii_strtoull(name, &end, 10);
    if (errno != 0 || end == name || *end != '\0' || value == 0 || value > G_MAXUINT32)
        return false;
    *pid = (unsigned int)value;
    return true;
}

static bool
read_tracer(const char *status_path, unsigned int *tracer)
{
    g_autofree char *contents = NULL;
    g_auto(GStrv) lines = NULL;

    if (!g_file_get_contents(status_path, &contents, NULL, NULL))
        return false;
    lines = g_strsplit(contents, "\n", -1);
    for (size_t index = 0; lines[index] != NULL; ++index) {
        unsigned int value;
        char extra;

        if (!g_str_has_prefix(lines[index], "TracerPid:"))
            continue;
        if (sscanf(lines[index] + strlen("TracerPid:"), " %u %c", &value, &extra) != 1)
            return false;
        *tracer = value;
        return true;
    }
    return false;
}

static bool
tracer_allowed(const char *proc_root, unsigned int tracer, const GArray *allowlist)
{
    g_autofree char *exe = g_strdup_printf("%s/%u/exe", proc_root, tracer);
    struct stat metadata;

    if (stat(exe, &metadata) != 0)
        return false;
    for (guint index = 0; allowlist != NULL && index < allowlist->len; ++index) {
        const struct ms_allowlist_key *key =
            &g_array_index(allowlist, struct ms_allowlist_key, index);

        if (key->rule == MS_RESPONSE_PTRACE_WRITE &&
            key->device == (__u64)metadata.st_dev && key->inode == (__u64)metadata.st_ino)
            return true;
    }
    return false;
}

bool
ms_ptrace_barrier_check(const char *proc_root, const GArray *allowlist,
                        struct ms_error *error)
{
    /* Once enabled, the ptrace LSM rule can affect already-running tracers.
     * Scan current tracing relationships first and refuse activation if a
     * non-exempt tracer would unexpectedly lose access to its target. */
    GDir *directory;
    const char *name;

    if (proc_root == NULL || !g_path_is_absolute(proc_root)) {
        set_error(error, "response_ptrace_scan", "an absolute proc root is required");
        return false;
    }
    directory = g_dir_open(proc_root, 0, NULL);
    if (directory == NULL) {
        set_error(error, "response_ptrace_scan", "cannot scan %s", proc_root);
        return false;
    }
    while ((name = g_dir_read_name(directory)) != NULL) {
        g_autofree char *status = NULL;
        unsigned int pid;
        unsigned int tracer;

        if (!numeric_pid(name, &pid))
            continue;
        status = g_build_filename(proc_root, name, "status", NULL);
        if (!read_tracer(status, &tracer)) {
            set_error(error, "response_ptrace_scan",
                      "cannot verify ptrace state for PID %u", pid);
            g_dir_close(directory);
            return false;
        }
        if (tracer != 0 && !tracer_allowed(proc_root, tracer, allowlist)) {
            set_error(error, "response_ptrace_active",
                      "Cannot enable response mode while PID %u is traced by PID %u",
                      pid, tracer);
            g_dir_close(directory);
            return false;
        }
    }
    g_dir_close(directory);
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}
