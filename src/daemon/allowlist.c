#include "allowlist.h"

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "memspy/alert.h"

#define MS_ALLOWLIST_LINE_BYTES (MS_PATH_BYTES + MS_RULE_ID_BYTES + 32U)
#define MS_ALLOWLIST_MAX_ENTRIES 4096U

/* Each detection exclusion names one rule and one exact executable path.
 * It suppresses that alert only; it does not permit the executable through
 * a response-mode block. Response exemptions have a separate file and
 * kernel map so the two decisions cannot be confused. */
struct allowlist_entry {
    char *rule_id;
    char *path;
};

struct ms_allowlist {
    GPtrArray *entries;
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

static void
entry_free(gpointer data)
{
    struct allowlist_entry *entry = data;

    g_free(entry->rule_id);
    g_free(entry->path);
    g_free(entry);
}

void
ms_allowlist_free(struct ms_allowlist *allowlist)
{
    if (allowlist == NULL)
        return;
    g_ptr_array_free(allowlist->entries, true);
    g_free(allowlist);
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
parse_line(struct ms_allowlist *allowlist, char *line, size_t line_number,
           struct ms_error *error)
{
    char *rule = trim(line);
    char *path;
    struct allowlist_entry *entry;

    if (*rule == '\0' || *rule == '#')
        return true;
    path = rule;
    while (*path != '\0' && !g_ascii_isspace(*path))
        ++path;
    if (*path == '\0') {
        set_error(error, "invalid_allowlist", "line %zu: expected rule ID and absolute path", line_number);
        return false;
    }
    *path++ = '\0';
    path = trim(path);
    if (strlen(rule) >= MS_RULE_ID_BYTES || path[0] != '/' || strlen(path) >= MS_PATH_BYTES) {
        set_error(error, "invalid_allowlist", "line %zu: invalid rule ID or absolute path", line_number);
        return false;
    }
    if (allowlist->entries->len >= MS_ALLOWLIST_MAX_ENTRIES) {
        set_error(error, "invalid_allowlist", "line %zu: too many entries", line_number);
        return false;
    }
    entry = g_new0(struct allowlist_entry, 1);
    entry->rule_id = g_strdup(rule);
    entry->path = g_strdup(path);
    g_ptr_array_add(allowlist->entries, entry);
    return true;
}

bool
ms_allowlist_load(const char *path, struct ms_allowlist **out, struct ms_error *error)
{
    struct ms_allowlist *loaded;
    char line[MS_ALLOWLIST_LINE_BYTES];
    size_t line_number = 0;
    FILE *file;

    if (path == NULL || out == NULL) {
        set_error(error, "invalid_allowlist", "path and output are required");
        return false;
    }
    file = g_fopen(path, "r");
    if (file == NULL) {
        set_error(error, "allowlist_io", "cannot open '%s': %s", path, g_strerror(errno));
        return false;
    }
    loaded = g_new0(struct ms_allowlist, 1);
    loaded->entries = g_ptr_array_new_with_free_func(entry_free);

    while (fgets(line, sizeof line, file) != NULL) {
        ++line_number;
        if (strchr(line, '\n') == NULL && !feof(file)) {
            set_error(error, "invalid_allowlist", "line %zu: line is too long", line_number);
            ms_allowlist_free(loaded);
            fclose(file);
            return false;
        }
        if (!parse_line(loaded, line, line_number, error)) {
            ms_allowlist_free(loaded);
            fclose(file);
            return false;
        }
    }
    if (ferror(file)) {
        set_error(error, "allowlist_io", "cannot read '%s': %s", path, g_strerror(errno));
        ms_allowlist_free(loaded);
        fclose(file);
        return false;
    }
    fclose(file);
    ms_allowlist_free(*out);
    *out = loaded;
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

bool
ms_allowlist_matches(const struct ms_allowlist *allowlist, const char *rule_id,
                     const char *canonical_exe)
{
    guint index;

    if (allowlist == NULL || rule_id == NULL || canonical_exe == NULL)
        return false;
    for (index = 0; index < allowlist->entries->len; ++index) {
        const struct allowlist_entry *entry = g_ptr_array_index(allowlist->entries, index);

        if (strcmp(entry->rule_id, rule_id) == 0 && strcmp(entry->path, canonical_exe) == 0)
            return true;
    }
    return false;
}
