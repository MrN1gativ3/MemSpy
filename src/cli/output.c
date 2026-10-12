#include "output.h"

#include <inttypes.h>
#include <json-c/json.h>

static const char *severity(const struct ms_alert *alert)
{
    return alert->severity == MS_SEVERITY_HIGH ? "high" : "medium";
}

static const char *action(const struct ms_alert *alert)
{
    return alert->action == MS_ALERT_BLOCKED ? "blocked" : "detected";
}

bool
ms_cli_print_status(FILE *stream, const struct ms_health *health, bool json)
{
    if (stream == NULL || health == NULL)
        return false;
    if (json) {
        json_object *object = json_object_new_object();
        json_object_object_add(object, "state", json_object_new_int(health->state));
        json_object_object_add(object, "protected", json_object_new_boolean(health->protected));
        json_object_object_add(object, "storage_available", json_object_new_boolean(health->storage_available));
        json_object_object_add(object, "response_supported", json_object_new_boolean(health->response_supported));
        json_object_object_add(object, "response_requested", json_object_new_boolean(health->response_requested));
        json_object_object_add(object, "response_active", json_object_new_boolean(health->response_active));
        json_object_object_add(object, "lost_events", json_object_new_uint64(health->lost_events));
        json_object_object_add(object, "map_pressure", json_object_new_uint64(health->map_pressure));
        json_object_object_add(object, "dropped_alerts", json_object_new_uint64(health->dropped_alerts));
        json_object_object_add(object, "blocked_execs", json_object_new_uint64(health->blocked_execs));
        json_object_object_add(object, "lost_block_events", json_object_new_uint64(health->lost_block_events));
        json_object_object_add(object, "incomplete_observations", json_object_new_uint64(health->incomplete_observations));
        json_object_object_add(object, "journal_errors", json_object_new_uint64(health->journal_errors));
        json_object_object_add(object, "response_reason", json_object_new_string(health->response_reason));
        json_object_object_add(object, "message", json_object_new_string(health->message));
        fprintf(stream, "%s\n", json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN));
        json_object_put(object);
        return !ferror(stream);
    }
    fprintf(stream,
            "Detector: %s\nStorage: %s\nResponse: %s (supported=%s, requested=%s)\n"
            "Lost events: %" PRIu64 "\nIncomplete observations: %" PRIu64
            "\nJournal errors: %" PRIu64 "\n",
            health->state == MS_HEALTH_HEALTHY ? "healthy" :
            health->state == MS_HEALTH_DEGRADED ? "degraded" : "failed",
            health->storage_available ? "available" : "unavailable",
            health->response_active ? "active" : "inactive",
            health->response_supported ? "yes" : "no",
            health->response_requested ? "yes" : "no", health->lost_events,
            health->incomplete_observations, health->journal_errors);
    if (health->message[0] != '\0')
        fprintf(stream, "Message: %s\n", health->message);
    return !ferror(stream);
}

bool
ms_cli_print_alert(FILE *stream, const struct ms_alert *alert, bool json)
{
    if (stream == NULL || alert == NULL)
        return false;
    if (json) {
        json_object *object = ms_alert_to_json(alert);
        if (object == NULL)
            return false;
        fprintf(stream, "%s\n", json_object_to_json_string_ext(object, JSON_C_TO_STRING_PLAIN));
        json_object_put(object);
        return !ferror(stream);
    }
    fprintf(stream,
            "Alert: %" PRId64 "\nSeverity: %s\nAction: %s\nRule: %s\nExplanation: %s\n"
            "Process: %s (PID %d, UID %u)\nExecutable: %s\nCommand line: %s\n"
            "Parent: %s (PID %d) %s\nGrandparent: %s (PID %d) %s\n",
            alert->id, severity(alert), action(alert), alert->rule_id,
            alert->explanation, alert->comm, alert->pid, alert->uid, alert->exe,
            alert->cmdline, alert->parent_comm, alert->ppid, alert->parent_exe,
            alert->grandparent_comm, alert->grandparent_pid, alert->grandparent_exe);
    if (alert->systemd_unit[0] != '\0')
        fprintf(stream, "Systemd unit: %s\n", alert->systemd_unit);
    if (alert->container_id[0] != '\0')
        fprintf(stream, "Container: %s (%s)\n", alert->container_id, alert->container_runtime);
    if (alert->cgroup_path[0] != '\0')
        fprintf(stream, "Cgroup: %s\n", alert->cgroup_path);
    if (alert->target_pid > 0 || alert->target_namespace_pid > 0)
        fprintf(stream, "Target: host PID %d, namespace PID %d, %s\n",
                alert->target_pid, alert->target_namespace_pid, alert->target_exe);
    if (alert->bytes_written > 0)
        fprintf(stream, "Bytes written: %" PRIu64 "\n", alert->bytes_written);
    fprintf(stream, "Evidence: %s\nEnrichment incomplete: %s\n", alert->evidence,
            alert->enrichment_incomplete ? "yes" : "no");
    return !ferror(stream);
}

bool
ms_cli_print_alerts(FILE *stream, const struct ms_alert_page *page, bool json)
{
    if (stream == NULL || page == NULL)
        return false;
    if (json) {
        json_object *array = json_object_new_array_ext((int)page->length);
        for (size_t index = 0; index < page->length; ++index) {
            json_object *object = ms_alert_to_json(&page->items[index]);
            if (object == NULL) {
                json_object_put(array);
                return false;
            }
            json_object_array_add(array, object);
        }
        fprintf(stream, "%s\n", json_object_to_json_string_ext(array, JSON_C_TO_STRING_PLAIN));
        json_object_put(array);
        return !ferror(stream);
    }
    for (size_t index = 0; index < page->length; ++index)
        fprintf(stream, "%" PRId64 "\t%s\t%s\t%d\t%s\n", page->items[index].id,
                severity(&page->items[index]), page->items[index].rule_id,
                page->items[index].pid, page->items[index].comm);
    return !ferror(stream);
}
