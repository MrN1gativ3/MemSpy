#include "memspy/alert.h"

#include <glib.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void
set_error(struct ms_error *error, const char *code, const char *format, ...)
{
    va_list args;

    if (error == NULL)
        return;
    g_strlcpy(error->code, code, sizeof error->code);
    va_start(args, format);
    vsnprintf(error->message, sizeof error->message, format, args);
    va_end(args);
}

static const char *
severity_name(enum ms_severity severity)
{
    switch (severity) {
    case MS_SEVERITY_MEDIUM:
        return "medium";
    case MS_SEVERITY_HIGH:
        return "high";
    }
    return NULL;
}

static const char *
action_name(enum ms_alert_action action)
{
    if (action == MS_ALERT_DETECTED)
        return "detected";
    if (action == MS_ALERT_BLOCKED)
        return "blocked";
    return NULL;
}

static bool
add_string(json_object *object, const char *name, const char *value, size_t capacity)
{
    const char *end = memchr(value, '\0', capacity);
    size_t length;
    g_autofree char *valid = NULL;

    if (end == NULL)
        return false;
    length = (size_t)(end - value);
    valid = g_utf8_make_valid(value, (gssize)length);
    json_object_object_add(object, name, json_object_new_string_len(valid, (int)strlen(valid)));
    return true;
}

const char *
ms_hash_status_name(enum ms_hash_status status)
{
    static const char *names[] = {
        "not_collected", "complete", "process_exited", "image_unavailable",
        "no_filesystem_path", "too_large", "read_error", "identity_changed",
        "blocked_before_open",
    };
    return status >= MS_HASH_NOT_COLLECTED && status <= MS_HASH_BLOCKED_BEFORE_OPEN ?
        names[status] : NULL;
}

static bool
parse_hash_status(const char *value, enum ms_hash_status *status)
{
    for (int candidate = MS_HASH_NOT_COLLECTED;
         candidate <= MS_HASH_BLOCKED_BEFORE_OPEN; ++candidate) {
        if (strcmp(value, ms_hash_status_name((enum ms_hash_status)candidate)) == 0) {
            *status = (enum ms_hash_status)candidate;
            return true;
        }
    }
    return false;
}

static bool
valid_hex_hash(const char *value, size_t capacity, size_t digits)
{
    const char *end = memchr(value, '\0', capacity);
    size_t length;

    if (end == NULL)
        return false;
    length = (size_t)(end - value);
    if (length == 0)
        return true;
    if (length != digits)
        return false;
    for (size_t index = 0; index < digits; ++index) {
        if (!g_ascii_isdigit(value[index]) &&
            (value[index] < 'a' || value[index] > 'f'))
            return false;
    }
    return true;
}

static bool valid_md5(const char *value) { return valid_hex_hash(value, MS_MD5_BYTES, 32U); }
static bool valid_sha256(const char *value) { return valid_hex_hash(value, MS_SHA256_BYTES, 64U); }

json_object *
ms_alert_to_json(const struct ms_alert *alert)
{
    const char *severity;
    const char *action;
    json_object *object;

    if (alert == NULL || (severity = severity_name(alert->severity)) == NULL ||
        (action = action_name(alert->action)) == NULL ||
        ms_hash_status_name(alert->exe_hash_status) == NULL ||
        ms_hash_status_name(alert->launcher_hash_status) == NULL ||
        ms_hash_status_name(alert->parent_hash_status) == NULL ||
        ms_hash_status_name(alert->target_hash_status) == NULL ||
        !valid_md5(alert->exe_md5) || !valid_sha256(alert->exe_sha256) ||
        !valid_md5(alert->launcher_md5) || !valid_sha256(alert->launcher_sha256) ||
        !valid_md5(alert->parent_md5) || !valid_sha256(alert->parent_sha256) ||
        !valid_md5(alert->target_md5) || !valid_sha256(alert->target_sha256))
        return NULL;

    object = json_object_new_object();
    json_object_object_add(object, "id", json_object_new_int64(alert->id));
    json_object_object_add(object, "timestamp_utc", json_object_new_int64(alert->timestamp_utc));
    json_object_object_add(object, "observed_boottime_ns", json_object_new_uint64(alert->observed_boottime_ns));
    json_object_object_add(object, "action", json_object_new_string(action));
    json_object_object_add(object, "severity", json_object_new_string(severity));
    json_object_object_add(object, "pid", json_object_new_int64(alert->pid));
    json_object_object_add(object, "ppid", json_object_new_int64(alert->ppid));
    json_object_object_add(object, "uid", json_object_new_uint64(alert->uid));
    json_object_object_add(object, "target_pid", json_object_new_int64(alert->target_pid));
    json_object_object_add(object, "grandparent_pid", json_object_new_int64(alert->grandparent_pid));
    json_object_object_add(object, "ssh_origin", json_object_new_boolean(alert->ssh_origin));
    json_object_object_add(object, "pid_namespace", json_object_new_uint64(alert->pid_namespace));
    json_object_object_add(object, "mount_namespace", json_object_new_uint64(alert->mount_namespace));
    json_object_object_add(object, "target_namespace_pid",
                           json_object_new_int64(alert->target_namespace_pid));
    json_object_object_add(object, "bytes_written", json_object_new_uint64(alert->bytes_written));
    json_object_object_add(object, "enrichment_incomplete", json_object_new_boolean(alert->enrichment_incomplete));
    json_object_object_add(object, "arguments_truncated", json_object_new_boolean(alert->arguments_truncated));
    json_object_object_add(object, "exe_hash_status",
                           json_object_new_string(ms_hash_status_name(alert->exe_hash_status)));
    json_object_object_add(object, "launcher_hash_status",
                           json_object_new_string(ms_hash_status_name(alert->launcher_hash_status)));
    json_object_object_add(object, "parent_hash_status",
                           json_object_new_string(ms_hash_status_name(alert->parent_hash_status)));
    json_object_object_add(object, "target_hash_status",
                           json_object_new_string(ms_hash_status_name(alert->target_hash_status)));

    if (!add_string(object, "rule_id", alert->rule_id, sizeof alert->rule_id) ||
        !add_string(object, "explanation", alert->explanation, sizeof alert->explanation) ||
        !add_string(object, "comm", alert->comm, sizeof alert->comm) ||
        !add_string(object, "username", alert->username, sizeof alert->username) ||
        !add_string(object, "exe", alert->exe, sizeof alert->exe) ||
        !add_string(object, "exe_md5", alert->exe_md5, sizeof alert->exe_md5) ||
        !add_string(object, "exe_sha256", alert->exe_sha256, sizeof alert->exe_sha256) ||
        !add_string(object, "cmdline", alert->cmdline, sizeof alert->cmdline) ||
        !add_string(object, "launcher_exe", alert->launcher_exe, sizeof alert->launcher_exe) ||
        !add_string(object, "launcher_md5", alert->launcher_md5, sizeof alert->launcher_md5) ||
        !add_string(object, "launcher_sha256", alert->launcher_sha256,
                    sizeof alert->launcher_sha256) ||
        !add_string(object, "parent_comm", alert->parent_comm, sizeof alert->parent_comm) ||
        !add_string(object, "parent_exe", alert->parent_exe, sizeof alert->parent_exe) ||
        !add_string(object, "parent_md5", alert->parent_md5, sizeof alert->parent_md5) ||
        !add_string(object, "parent_sha256", alert->parent_sha256,
                    sizeof alert->parent_sha256) ||
        !add_string(object, "grandparent_comm", alert->grandparent_comm,
                    sizeof alert->grandparent_comm) ||
        !add_string(object, "grandparent_exe", alert->grandparent_exe,
                    sizeof alert->grandparent_exe) ||
        !add_string(object, "systemd_unit", alert->systemd_unit, sizeof alert->systemd_unit) ||
        !add_string(object, "cgroup_path", alert->cgroup_path, sizeof alert->cgroup_path) ||
        !add_string(object, "container_id", alert->container_id, sizeof alert->container_id) ||
        !add_string(object, "container_runtime", alert->container_runtime,
                    sizeof alert->container_runtime) ||
        !add_string(object, "tty", alert->tty, sizeof alert->tty) ||
        !add_string(object, "target_exe", alert->target_exe, sizeof alert->target_exe) ||
        !add_string(object, "target_md5", alert->target_md5, sizeof alert->target_md5) ||
        !add_string(object, "target_sha256", alert->target_sha256,
                    sizeof alert->target_sha256) ||
        !add_string(object, "evidence", alert->evidence, sizeof alert->evidence)) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

static bool
get_required(json_object *parent, const char *name, enum json_type type,
             json_object **value, struct ms_error *error)
{
    if (!json_object_object_get_ex(parent, name, value) || json_object_get_type(*value) != type) {
        set_error(error, "invalid_alert", "field '%s' is missing or has the wrong type", name);
        return false;
    }
    return true;
}

static bool
copy_string(json_object *parent, const char *name, char *destination, size_t capacity,
            struct ms_error *error)
{
    json_object *value;
    const char *text;
    size_t length;

    if (!get_required(parent, name, json_type_string, &value, error))
        return false;
    text = json_object_get_string(value);
    length = (size_t)json_object_get_string_len(value);
    if (length >= capacity || memchr(text, '\0', length) != NULL || !g_utf8_validate(text, (gssize)length, NULL)) {
        set_error(error, "invalid_alert", "field '%s' is invalid or too long", name);
        return false;
    }
    memcpy(destination, text, length);
    destination[length] = '\0';
    return true;
}

static bool
copy_optional_string(json_object *parent, const char *name, char *destination,
                     size_t capacity, struct ms_error *error)
{
    json_object *value;

    if (!json_object_object_get_ex(parent, name, &value)) {
        destination[0] = '\0';
        return true;
    }
    return copy_string(parent, name, destination, capacity, error);
}

static bool
copy_optional_hash_status(json_object *parent, const char *name,
                          enum ms_hash_status *status, struct ms_error *error)
{
    json_object *value;
    if (!json_object_object_get_ex(parent, name, &value)) {
        *status = MS_HASH_NOT_COLLECTED;
        return true;
    }
    if (json_object_get_type(value) != json_type_string ||
        !parse_hash_status(json_object_get_string(value), status)) {
        set_error(error, "invalid_alert", "field '%s' is invalid", name);
        return false;
    }
    return true;
}

static bool
get_nonnegative_int(json_object *parent, const char *name, int64_t maximum,
                    int64_t *output, struct ms_error *error)
{
    json_object *value;
    int64_t number;

    if (!get_required(parent, name, json_type_int, &value, error))
        return false;
    number = json_object_get_int64(value);
    if (number < 0 || number > maximum) {
        set_error(error, "invalid_alert", "field '%s' is outside its valid range", name);
        return false;
    }
    *output = number;
    return true;
}

static bool
get_uint64(json_object *parent, const char *name, uint64_t *output, struct ms_error *error)
{
    json_object *value;

    if (!get_required(parent, name, json_type_int, &value, error))
        return false;
    if (json_object_get_int64(value) < 0) {
        set_error(error, "invalid_alert", "field '%s' cannot be negative", name);
        return false;
    }
    *output = json_object_get_uint64(value);
    return true;
}

bool
ms_alert_from_json(json_object *json, struct ms_alert *alert, struct ms_error *error)
{
    struct ms_alert parsed = {0};
    json_object *value;
    const char *severity;
    const char *action;
    int64_t number;

    if (json == NULL || alert == NULL || json_object_get_type(json) != json_type_object) {
        set_error(error, "invalid_alert", "alert must be a JSON object");
        return false;
    }
    if (!get_nonnegative_int(json, "id", INT64_MAX, &parsed.id, error) ||
        !get_nonnegative_int(json, "timestamp_utc", INT64_MAX, &parsed.timestamp_utc, error) ||
        !get_uint64(json, "observed_boottime_ns", &parsed.observed_boottime_ns, error))
        return false;

    if (!get_required(json, "severity", json_type_string, &value, error))
        return false;
    severity = json_object_get_string(value);
    if (strcmp(severity, "medium") == 0)
        parsed.severity = MS_SEVERITY_MEDIUM;
    else if (strcmp(severity, "high") == 0)
        parsed.severity = MS_SEVERITY_HIGH;
    else {
        set_error(error, "invalid_alert", "field 'severity' is invalid");
        return false;
    }

    if (!get_required(json, "action", json_type_string, &value, error))
        return false;
    action = json_object_get_string(value);
    if (strcmp(action, "detected") == 0)
        parsed.action = MS_ALERT_DETECTED;
    else if (strcmp(action, "blocked") == 0)
        parsed.action = MS_ALERT_BLOCKED;
    else {
        set_error(error, "invalid_alert", "field 'action' is invalid");
        return false;
    }

    if (!copy_string(json, "rule_id", parsed.rule_id, sizeof parsed.rule_id, error) ||
        !copy_string(json, "explanation", parsed.explanation, sizeof parsed.explanation, error) ||
        !get_nonnegative_int(json, "pid", INT_MAX, &number, error))
        return false;
    parsed.pid = (pid_t)number;
    if (!get_nonnegative_int(json, "ppid", INT_MAX, &number, error))
        return false;
    parsed.ppid = (pid_t)number;
    if (!get_nonnegative_int(json, "uid", UINT_MAX, &number, error))
        return false;
    parsed.uid = (uid_t)number;
    if (!copy_string(json, "comm", parsed.comm, sizeof parsed.comm, error) ||
        !copy_string(json, "username", parsed.username, sizeof parsed.username, error) ||
        !copy_string(json, "exe", parsed.exe, sizeof parsed.exe, error) ||
        !copy_optional_string(json, "exe_md5", parsed.exe_md5, sizeof parsed.exe_md5, error) ||
        !copy_optional_string(json, "exe_sha256", parsed.exe_sha256,
                              sizeof parsed.exe_sha256, error) ||
        !copy_optional_hash_status(json, "exe_hash_status", &parsed.exe_hash_status, error) ||
        !copy_string(json, "cmdline", parsed.cmdline, sizeof parsed.cmdline, error) ||
        !copy_string(json, "launcher_exe", parsed.launcher_exe, sizeof parsed.launcher_exe, error) ||
        !copy_optional_string(json, "launcher_md5", parsed.launcher_md5,
                              sizeof parsed.launcher_md5, error) ||
        !copy_optional_string(json, "launcher_sha256", parsed.launcher_sha256,
                              sizeof parsed.launcher_sha256, error) ||
        !copy_optional_hash_status(json, "launcher_hash_status",
                                   &parsed.launcher_hash_status, error) ||
        !copy_optional_string(json, "parent_comm", parsed.parent_comm,
                              sizeof parsed.parent_comm, error) ||
        !copy_string(json, "parent_exe", parsed.parent_exe, sizeof parsed.parent_exe, error) ||
        !copy_optional_string(json, "parent_md5", parsed.parent_md5,
                              sizeof parsed.parent_md5, error) ||
        !copy_optional_string(json, "parent_sha256", parsed.parent_sha256,
                              sizeof parsed.parent_sha256, error) ||
        !copy_optional_hash_status(json, "parent_hash_status",
                                   &parsed.parent_hash_status, error) ||
        !get_nonnegative_int(json, "target_pid", INT_MAX, &number, error))
        return false;
    if (!valid_md5(parsed.exe_md5) || !valid_sha256(parsed.exe_sha256) ||
        !valid_md5(parsed.launcher_md5) || !valid_sha256(parsed.launcher_sha256) ||
        !valid_md5(parsed.parent_md5) || !valid_sha256(parsed.parent_sha256)) {
        set_error(error, "invalid_alert", "an executable hash is invalid");
        return false;
    }
    parsed.target_pid = (pid_t)number;
    if (!get_nonnegative_int(json, "grandparent_pid", INT_MAX, &number, error))
        return false;
    parsed.grandparent_pid = (pid_t)number;
    if (!copy_string(json, "grandparent_comm", parsed.grandparent_comm,
                     sizeof parsed.grandparent_comm, error) ||
        !copy_string(json, "grandparent_exe", parsed.grandparent_exe,
                     sizeof parsed.grandparent_exe, error) ||
        !copy_string(json, "systemd_unit", parsed.systemd_unit,
                     sizeof parsed.systemd_unit, error) ||
        !copy_string(json, "cgroup_path", parsed.cgroup_path,
                     sizeof parsed.cgroup_path, error) ||
        !copy_string(json, "container_id", parsed.container_id,
                     sizeof parsed.container_id, error) ||
        !copy_string(json, "container_runtime", parsed.container_runtime,
                     sizeof parsed.container_runtime, error) ||
        !copy_string(json, "tty", parsed.tty, sizeof parsed.tty, error) ||
        !get_required(json, "ssh_origin", json_type_boolean, &value, error))
        return false;
    parsed.ssh_origin = json_object_get_boolean(value);
    if (!get_uint64(json, "pid_namespace", &parsed.pid_namespace, error) ||
        !get_uint64(json, "mount_namespace", &parsed.mount_namespace, error) ||
        !get_nonnegative_int(json, "target_namespace_pid", INT_MAX, &number, error))
        return false;
    parsed.target_namespace_pid = (pid_t)number;
    if (!get_uint64(json, "bytes_written", &parsed.bytes_written, error) ||
        !copy_string(json, "target_exe", parsed.target_exe, sizeof parsed.target_exe, error) ||
        !copy_optional_string(json, "target_md5", parsed.target_md5,
                              sizeof parsed.target_md5, error) ||
        !copy_optional_string(json, "target_sha256", parsed.target_sha256,
                              sizeof parsed.target_sha256, error) ||
        !copy_optional_hash_status(json, "target_hash_status",
                                   &parsed.target_hash_status, error) ||
        !copy_string(json, "evidence", parsed.evidence, sizeof parsed.evidence, error) ||
        !get_required(json, "enrichment_incomplete", json_type_boolean, &value, error))
        return false;
    parsed.enrichment_incomplete = json_object_get_boolean(value);
    if (!get_required(json, "arguments_truncated", json_type_boolean, &value, error))
        return false;
    parsed.arguments_truncated = json_object_get_boolean(value);
    if (!valid_md5(parsed.target_md5) || !valid_sha256(parsed.target_sha256)) {
        set_error(error, "invalid_alert", "a target executable hash is invalid");
        return false;
    }

    *alert = parsed;
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}
