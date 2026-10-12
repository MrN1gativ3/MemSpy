#include "journal.h"

#include <json-c/json.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <systemd/sd-journal.h>
#include <syslog.h>

static void set_error(struct ms_error *error, const char *format, ...)
{
    va_list args;
    if (error == NULL)
        return;
    snprintf(error->code, sizeof error->code, "journal_error");
    va_start(args, format);
    vsnprintf(error->message, sizeof error->message, format, args);
    va_end(args);
}

int ms_journal_priority(const struct ms_alert *alert)
{
    return alert != NULL && alert->severity == MS_SEVERITY_HIGH ? LOG_ALERT : LOG_WARNING;
}

bool ms_journal_alert(const struct ms_alert *alert, struct ms_error *error)
{
    json_object *json;
    const char *severity;
    const char *action;
    int result;

    if (alert == NULL) {
        set_error(error, "alert is required");
        return false;
    }
    json = ms_alert_to_json(alert);
    if (json == NULL) {
        set_error(error, "alert cannot be encoded");
        return false;
    }
    severity = alert->severity == MS_SEVERITY_HIGH ? "high" : "medium";
    action = alert->action == MS_ALERT_BLOCKED ? "blocked" : "detected";
    result = sd_journal_send(
        "PRIORITY=%d", ms_journal_priority(alert),
        "SYSLOG_IDENTIFIER=memspyd",
        "MESSAGE=MemSpy %s alert: %s", severity, alert->rule_id,
        "MEMSPY_ALERT_ID=%lld", (long long)alert->id,
        "MEMSPY_RULE=%s", alert->rule_id,
        "MEMSPY_SEVERITY=%s", severity,
        "MEMSPY_ACTION=%s", action,
        "MEMSPY_PID=%d", alert->pid,
        "MEMSPY_UID=%u", (unsigned int)alert->uid,
        "MEMSPY_ALERT_JSON=%s",
        json_object_to_json_string_ext(json, JSON_C_TO_STRING_PLAIN),
        NULL);
    json_object_put(json);
    if (result < 0) {
        set_error(error, "sd_journal_send failed: %s", strerror(-result));
        return false;
    }
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}
