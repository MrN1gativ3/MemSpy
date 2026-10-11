#include <glib.h>
#include <json-c/json.h>
#include <string.h>

#include "memspy/alert.h"

static struct ms_alert
fixture_memfd_alert(void)
{
    struct ms_alert alert = {
        .id = 42,
        .timestamp_utc = 1791676800,
        .observed_boottime_ns = 123456789,
        .severity = MS_SEVERITY_HIGH,
        .pid = 1200,
        .ppid = 1100,
        .uid = 1000,
        .target_pid = 0,
        .enrichment_incomplete = false,
    };

    g_strlcpy(alert.rule_id, "MEMFD_EXEC", sizeof alert.rule_id);
    g_strlcpy(alert.explanation, "Executable image is backed by memfd", sizeof alert.explanation);
    g_strlcpy(alert.comm, "payload", sizeof alert.comm);
    g_strlcpy(alert.exe, "/memfd:payload (deleted)", sizeof alert.exe);
    g_strlcpy(alert.cmdline, "payload --run", sizeof alert.cmdline);
    g_strlcpy(alert.evidence, "execveat fd=4", sizeof alert.evidence);
    return alert;
}

static void
test_alert_json_round_trip(void)
{
    struct ms_alert input = fixture_memfd_alert();
    json_object *json = ms_alert_to_json(&input);
    struct ms_alert output = {0};
    struct ms_error error = {0};

    g_assert_nonnull(json);
    g_assert_true(ms_alert_from_json(json, &output, &error));
    g_assert_cmpint(output.id, ==, 42);
    g_assert_cmpint(output.severity, ==, MS_SEVERITY_HIGH);
    g_assert_cmpstr(output.rule_id, ==, "MEMFD_EXEC");
    g_assert_cmpstr(output.cmdline, ==, "payload --run");
    g_assert_cmpuint(strlen(output.cmdline), <=, MS_MAX_CMDLINE_BYTES);
    json_object_put(json);
}

static void
test_alert_json_rejects_missing_field(void)
{
    struct ms_alert input = fixture_memfd_alert();
    json_object *json = ms_alert_to_json(&input);
    struct ms_alert output = {0};
    struct ms_error error = {0};

    json_object_object_del(json, "rule_id");
    g_assert_false(ms_alert_from_json(json, &output, &error));
    g_assert_cmpstr(error.code, ==, "invalid_alert");
    json_object_put(json);
}

static void
test_alert_json_rejects_embedded_nul(void)
{
    static const char invalid[] = {'r', 'u', 'n', '\0', 'x'};
    struct ms_alert input = fixture_memfd_alert();
    json_object *json = ms_alert_to_json(&input);
    struct ms_alert output = {0};

    json_object_object_add(json, "cmdline", json_object_new_string_len(invalid, sizeof invalid));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

static void
test_alert_json_rejects_overlong_command(void)
{
    struct ms_alert input = fixture_memfd_alert();
    json_object *json = ms_alert_to_json(&input);
    struct ms_alert output = {0};
    g_autofree char *command = g_strnfill(MS_MAX_CMDLINE_BYTES + 1U, 'x');

    json_object_object_add(json, "cmdline", json_object_new_string(command));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

static void
test_alert_json_rejects_negative_boottime(void)
{
    struct ms_alert input = fixture_memfd_alert();
    json_object *json = ms_alert_to_json(&input);
    struct ms_alert output = {0};

    json_object_object_add(json, "observed_boottime_ns", json_object_new_int64(-1));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/alert-json/round-trip", test_alert_json_round_trip);
    g_test_add_func("/alert-json/missing-field", test_alert_json_rejects_missing_field);
    g_test_add_func("/alert-json/embedded-nul", test_alert_json_rejects_embedded_nul);
    g_test_add_func("/alert-json/overlong-command", test_alert_json_rejects_overlong_command);
    g_test_add_func("/alert-json/negative-boottime", test_alert_json_rejects_negative_boottime);
    return g_test_run();
}
