#define _GNU_SOURCE

#include "response_config.h"

#include <errno.h>
#include <fcntl.h>
#include <glib/gstdio.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "memspy/alert.h"

#define MS_RESPONSE_MAX_LAUNCHERS 4096U
#define MS_RESPONSE_STATE_BYTES 64U

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
secure_regular_file(int descriptor, struct ms_error *error, const char *code)
{
    struct stat metadata;

    if (fstat(descriptor, &metadata) != 0) {
        set_error(error, code, "%s", g_strerror(errno));
        return false;
    }
    if (!S_ISREG(metadata.st_mode) || metadata.st_uid != geteuid() ||
        (metadata.st_mode & 0022U) != 0) {
        set_error(error, code, "file must be regular, owned by uid %ld, and not group/world writable",
                  (long)geteuid());
        return false;
    }
    return true;
}

bool
ms_response_state_load(const char *path, bool *enabled, struct ms_error *error)
{
    char contents[MS_RESPONSE_STATE_BYTES + 1U];
    ssize_t length;
    int descriptor;

    if (path == NULL || enabled == NULL) {
        set_error(error, "response_state_invalid", "path and output are required");
        return false;
    }
    *enabled = false;
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        if (errno == ENOENT) {
            if (error != NULL)
                *error = (struct ms_error){0};
            return true;
        }
        set_error(error, errno == ELOOP ? "response_state_security" : "response_state_io",
                  "cannot open '%s': %s", path, g_strerror(errno));
        return false;
    }
    if (!secure_regular_file(descriptor, error, "response_state_security")) {
        close(descriptor);
        return false;
    }
    length = read(descriptor, contents, sizeof contents);
    close(descriptor);
    if (length < 0) {
        set_error(error, "response_state_io", "cannot read '%s': %s", path, g_strerror(errno));
        return false;
    }
    if ((size_t)length > MS_RESPONSE_STATE_BYTES) {
        set_error(error, "response_state_invalid", "response state is too large");
        return false;
    }
    contents[length] = '\0';
    if (strcmp(contents, "enabled\n") == 0)
        *enabled = true;
    else if (strcmp(contents, "disabled\n") != 0) {
        set_error(error, "response_state_invalid", "response state is invalid");
        return false;
    }
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

static bool
write_all(int descriptor, const char *data, size_t length)
{
    while (length > 0) {
        ssize_t written = write(descriptor, data, length);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0)
            return false;
        data += written;
        length -= (size_t)written;
    }
    return true;
}

bool
ms_response_state_store(const char *path, bool enabled, struct ms_error *error)
{
    g_autofree char *directory = NULL;
    g_autofree char *basename = NULL;
    g_autofree char *nonce = NULL;
    g_autofree char *temporary = NULL;
    const char *contents = enabled ? "enabled\n" : "disabled\n";
    struct stat metadata;
    int directory_fd = -1;
    int descriptor = -1;
    bool success = false;

    if (path == NULL || !g_path_is_absolute(path)) {
        set_error(error, "response_state_invalid", "an absolute state path is required");
        return false;
    }
    directory = g_path_get_dirname(path);
    basename = g_path_get_basename(path);
    nonce = g_uuid_string_random();
    temporary = g_strdup_printf(".%s.tmp.%s", basename, nonce);
    directory_fd = open(directory, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (directory_fd < 0 || fstat(directory_fd, &metadata) != 0 ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 0022U) != 0) {
        set_error(error, "response_state_io", "state directory is unavailable or insecure");
        goto done;
    }
    descriptor = openat(directory_fd, temporary,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        set_error(error, "response_state_io", "cannot create response state: %s", g_strerror(errno));
        goto done;
    }
    if (!write_all(descriptor, contents, strlen(contents)) || fsync(descriptor) != 0 ||
        close(descriptor) != 0) {
        descriptor = -1;
        set_error(error, "response_state_io", "cannot persist response state: %s", g_strerror(errno));
        goto done;
    }
    descriptor = -1;
    if (renameat(directory_fd, temporary, directory_fd, basename) != 0 ||
        fsync(directory_fd) != 0) {
        set_error(error, "response_state_io", "cannot replace response state: %s", g_strerror(errno));
        goto done;
    }
    success = true;
    if (error != NULL)
        *error = (struct ms_error){0};

done:
    if (descriptor >= 0)
        close(descriptor);
    if (!success && directory_fd >= 0)
        unlinkat(directory_fd, temporary, 0);
    if (directory_fd >= 0)
        close(directory_fd);
    return success;
}

static char *
trim(char *text)
{
    char *end;

    while (g_ascii_isspace(*text))
        ++text;
    end = text + strlen(text);
    while (end > text && g_ascii_isspace(end[-1]))
        --end;
    *end = '\0';
    return text;
}

static bool
key_exists(const GArray *keys, const struct ms_launcher_key *candidate)
{
    for (guint index = 0; index < keys->len; ++index) {
        const struct ms_launcher_key *key = &g_array_index(keys, struct ms_launcher_key, index);
        if (key->device == candidate->device && key->inode == candidate->inode)
            return true;
    }
    return false;
}

bool
ms_response_allowlist_load(const char *path, GArray **keys, size_t *rejected,
                           struct ms_error *warning)
{
    char line[MS_PATH_BYTES + 2U];
    GArray *loaded;
    FILE *file;
    int descriptor;
    size_t rejected_count = 0;
    size_t entries = 0;

    if (path == NULL || keys == NULL || rejected == NULL) {
        set_error(warning, "response_allowlist_invalid", "path and outputs are required");
        return false;
    }
    descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (descriptor < 0) {
        set_error(warning, "response_allowlist_io", "cannot open '%s': %s", path, g_strerror(errno));
        return false;
    }
    if (!secure_regular_file(descriptor, warning, "response_allowlist_security")) {
        close(descriptor);
        return false;
    }
    file = fdopen(descriptor, "r");
    if (file == NULL) {
        set_error(warning, "response_allowlist_io", "%s", g_strerror(errno));
        close(descriptor);
        return false;
    }
    loaded = g_array_new(false, false, sizeof(struct ms_launcher_key));
    while (fgets(line, sizeof line, file) != NULL) {
        struct stat metadata;
        struct ms_launcher_key key;
        char *entry;
        bool overlong = strchr(line, '\n') == NULL && !feof(file);

        ++entries;
        if (overlong) {
            int byte;
            while ((byte = fgetc(file)) != '\n' && byte != EOF)
                ;
        }
        entry = trim(line);
        if (*entry == '\0' || *entry == '#')
            continue;
        if (entries > MS_RESPONSE_MAX_LAUNCHERS || overlong || entry[0] != '/' ||
            lstat(entry, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
            (metadata.st_mode & 0111U) == 0) {
            ++rejected_count;
            continue;
        }
        key = (struct ms_launcher_key){
            .device = (__u64)metadata.st_dev,
            .inode = (__u64)metadata.st_ino,
        };
        if (!key_exists(loaded, &key))
            g_array_append_val(loaded, key);
    }
    if (ferror(file)) {
        set_error(warning, "response_allowlist_io", "cannot read '%s': %s", path, g_strerror(errno));
        fclose(file);
        g_array_free(loaded, true);
        return false;
    }
    fclose(file);
    if (rejected_count > 0)
        set_error(warning, "response_allowlist_entries", "%zu unsafe entries were ignored", rejected_count);
    else if (warning != NULL)
        *warning = (struct ms_error){0};
    g_clear_pointer(keys, g_array_unref);
    *keys = loaded;
    *rejected = rejected_count;
    return true;
}
