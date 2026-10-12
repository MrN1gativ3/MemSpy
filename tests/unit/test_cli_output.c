#define _GNU_SOURCE

#include <glib.h>
#include <json-c/json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "output.h"

static char *render_alert(bool json)
{
    struct ms_alert alert = {
        .id = 7, .timestamp_utc = 10, .severity = MS_SEVERITY_HIGH,
        .action = MS_ALERT_BLOCKED, .pid = 42, .ppid = 1, .uid = 1000,
    };
    char *buffer = NULL;
    size_t length = 0;
    FILE *stream = open_memstream(&buffer, &length);

    g_strlcpy(alert.rule_id, "PROC_MEM_WRITE", sizeof alert.rule_id);
    g_strlcpy(alert.explanation, "process memory write", sizeof alert.explanation);
    g_strlcpy(alert.comm, "writer", sizeof alert.comm);
    g_strlcpy(alert.exe, "/usr/bin/writer", sizeof alert.exe);
    g_strlcpy(alert.parent_comm, "systemd", sizeof alert.parent_comm);
    g_strlcpy(alert.systemd_unit, "fixture.service", sizeof alert.systemd_unit);
    g_assert_true(ms_cli_print_alert(stream, &alert, json));
    fclose(stream);
    return buffer;
}

static void test_human_alert(void)
{
    g_autofree char *output = render_alert(false);
    g_assert_nonnull(strstr(output, "Rule: PROC_MEM_WRITE"));
    g_assert_nonnull(strstr(output, "Process: writer"));
    g_assert_nonnull(strstr(output, "Action: blocked"));
    g_assert_nonnull(strstr(output, "Systemd unit: fixture.service"));
}

static void test_json_alert(void)
{
    g_autofree char *output = render_alert(true);
    json_object *object = json_tokener_parse(output);
    json_object *field;
    g_assert_nonnull(object);
    g_assert_true(json_object_object_get_ex(object, "rule_id", &field));
    g_assert_cmpstr(json_object_get_string(field), ==, "PROC_MEM_WRITE");
    json_object_put(object);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/cli-output/human-alert", test_human_alert);
    g_test_add_func("/cli-output/json-alert", test_json_alert);
    return g_test_run();
}
