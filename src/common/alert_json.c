#include "fileless/alert.h"

#include <glib.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static void
set_error(struct fl_error *error, const char *code, const char *format, ...)
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
severity_name(enum fl_severity severity)
{
    switch (severity) {
    case FL_SEVERITY_MEDIUM:
        return "medium";
    case FL_SEVERITY_HIGH:
        return "high";
    }
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

json_object *
fl_alert_to_json(const struct fl_alert *alert)
{
    const char *severity;
    json_object *object;

    if (alert == NULL || (severity = severity_name(alert->severity)) == NULL)
        return NULL;

    object = json_object_new_object();
    json_object_object_add(object, "id", json_object_new_int64(alert->id));
    json_object_object_add(object, "timestamp_utc", json_object_new_int64(alert->timestamp_utc));
    json_object_object_add(object, "observed_boottime_ns", json_object_new_uint64(alert->observed_boottime_ns));
    json_object_object_add(object, "severity", json_object_new_string(severity));
    json_object_object_add(object, "pid", json_object_new_int64(alert->pid));
    json_object_object_add(object, "ppid", json_object_new_int64(alert->ppid));
    json_object_object_add(object, "uid", json_object_new_uint64(alert->uid));
    json_object_object_add(object, "target_pid", json_object_new_int64(alert->target_pid));
    json_object_object_add(object, "enrichment_incomplete", json_object_new_boolean(alert->enrichment_incomplete));

    if (!add_string(object, "rule_id", alert->rule_id, sizeof alert->rule_id) ||
        !add_string(object, "explanation", alert->explanation, sizeof alert->explanation) ||
        !add_string(object, "comm", alert->comm, sizeof alert->comm) ||
        !add_string(object, "exe", alert->exe, sizeof alert->exe) ||
        !add_string(object, "cmdline", alert->cmdline, sizeof alert->cmdline) ||
        !add_string(object, "target_exe", alert->target_exe, sizeof alert->target_exe) ||
        !add_string(object, "evidence", alert->evidence, sizeof alert->evidence)) {
        json_object_put(object);
        return NULL;
    }
    return object;
}

static bool
get_required(json_object *parent, const char *name, enum json_type type,
             json_object **value, struct fl_error *error)
{
    if (!json_object_object_get_ex(parent, name, value) || json_object_get_type(*value) != type) {
        set_error(error, "invalid_alert", "field '%s' is missing or has the wrong type", name);
        return false;
    }
    return true;
}

static bool
copy_string(json_object *parent, const char *name, char *destination, size_t capacity,
            struct fl_error *error)
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
get_nonnegative_int(json_object *parent, const char *name, int64_t maximum,
                    int64_t *output, struct fl_error *error)
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
get_uint64(json_object *parent, const char *name, uint64_t *output, struct fl_error *error)
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
fl_alert_from_json(json_object *json, struct fl_alert *alert, struct fl_error *error)
{
    struct fl_alert parsed = {0};
    json_object *value;
    const char *severity;
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
        parsed.severity = FL_SEVERITY_MEDIUM;
    else if (strcmp(severity, "high") == 0)
        parsed.severity = FL_SEVERITY_HIGH;
    else {
        set_error(error, "invalid_alert", "field 'severity' is invalid");
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
        !copy_string(json, "exe", parsed.exe, sizeof parsed.exe, error) ||
        !copy_string(json, "cmdline", parsed.cmdline, sizeof parsed.cmdline, error) ||
        !get_nonnegative_int(json, "target_pid", INT_MAX, &number, error))
        return false;
    parsed.target_pid = (pid_t)number;
    if (!copy_string(json, "target_exe", parsed.target_exe, sizeof parsed.target_exe, error) ||
        !copy_string(json, "evidence", parsed.evidence, sizeof parsed.evidence, error) ||
        !get_required(json, "enrichment_incomplete", json_type_boolean, &value, error))
        return false;
    parsed.enrichment_incomplete = json_object_get_boolean(value);

    *alert = parsed;
    if (error != NULL)
        *error = (struct fl_error){0};
    return true;
}
