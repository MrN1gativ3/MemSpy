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
        .action = MS_ALERT_DETECTED,
        .severity = MS_SEVERITY_HIGH,
        .pid = 1200,
        .ppid = 1100,
        .uid = 1000,
        .grandparent_pid = 1000,
        .ssh_origin = true,
        .pid_namespace = 4026531836ULL,
        .mount_namespace = 4026531841ULL,
        .target_namespace_pid = 77,
        .bytes_written = 128,
        .target_pid = 0,
        .exe_hash_status = MS_HASH_NO_FILESYSTEM_PATH,
        .launcher_hash_status = MS_HASH_COMPLETE,
        .parent_hash_status = MS_HASH_COMPLETE,
        .target_hash_status = MS_HASH_NOT_COLLECTED,
        .enrichment_incomplete = false,
        .arguments_truncated = true,
    };

    g_strlcpy(alert.rule_id, "MEMFD_EXEC", sizeof alert.rule_id);
    g_strlcpy(alert.explanation, "Executable image is backed by memfd", sizeof alert.explanation);
    g_strlcpy(alert.comm, "payload", sizeof alert.comm);
    g_strlcpy(alert.username, "alice", sizeof alert.username);
    g_strlcpy(alert.exe, "/memfd:payload (deleted)", sizeof alert.exe);
    g_strlcpy(alert.cmdline, "payload --run", sizeof alert.cmdline);
    g_strlcpy(alert.launcher_exe, "/usr/bin/launcher", sizeof alert.launcher_exe);
    g_strlcpy(alert.parent_exe, "/usr/bin/parent", sizeof alert.parent_exe);
    g_strlcpy(alert.parent_comm, "parent", sizeof alert.parent_comm);
    g_strlcpy(alert.exe_md5, "0123456789abcdef0123456789abcdef", sizeof alert.exe_md5);
    g_strlcpy(alert.exe_sha256,
              "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              sizeof alert.exe_sha256);
    g_strlcpy(alert.launcher_md5, "1123456789abcdef0123456789abcdef",
              sizeof alert.launcher_md5);
    g_strlcpy(alert.launcher_sha256,
              "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              sizeof alert.launcher_sha256);
    g_strlcpy(alert.parent_md5, "2123456789abcdef0123456789abcdef",
              sizeof alert.parent_md5);
    g_strlcpy(alert.parent_sha256,
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              sizeof alert.parent_sha256);
    g_strlcpy(alert.grandparent_comm, "sshd", sizeof alert.grandparent_comm);
    g_strlcpy(alert.grandparent_exe, "/usr/sbin/sshd", sizeof alert.grandparent_exe);
    g_strlcpy(alert.systemd_unit, "ssh.service", sizeof alert.systemd_unit);
    g_strlcpy(alert.cgroup_path, "/system.slice/ssh.service", sizeof alert.cgroup_path);
    g_strlcpy(alert.container_id, "0123456789abcdef", sizeof alert.container_id);
    g_strlcpy(alert.container_runtime, "docker", sizeof alert.container_runtime);
    g_strlcpy(alert.tty, "pts/2", sizeof alert.tty);
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
    g_assert_cmpint(output.action, ==, MS_ALERT_DETECTED);
    g_assert_cmpint(output.severity, ==, MS_SEVERITY_HIGH);
    g_assert_cmpstr(output.rule_id, ==, "MEMFD_EXEC");
    g_assert_cmpstr(output.cmdline, ==, "payload --run");
    g_assert_cmpstr(output.username, ==, "alice");
    g_assert_cmpstr(output.launcher_exe, ==, "/usr/bin/launcher");
    g_assert_cmpstr(output.parent_exe, ==, "/usr/bin/parent");
    g_assert_cmpstr(output.parent_comm, ==, "parent");
    g_assert_cmpstr(output.parent_sha256, ==,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    g_assert_cmpstr(output.exe_md5, ==, "0123456789abcdef0123456789abcdef");
    g_assert_cmpint(output.exe_hash_status, ==, MS_HASH_NO_FILESYSTEM_PATH);
    g_assert_cmpstr(output.launcher_sha256, ==,
                    "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    g_assert_cmpint(output.launcher_hash_status, ==, MS_HASH_COMPLETE);
    g_assert_cmpstr(output.parent_md5, ==, "2123456789abcdef0123456789abcdef");
    g_assert_cmpint(output.parent_hash_status, ==, MS_HASH_COMPLETE);
    g_assert_cmpint(output.target_hash_status, ==, MS_HASH_NOT_COLLECTED);
    g_assert_true(output.arguments_truncated);
    g_assert_cmpint(output.grandparent_pid, ==, 1000);
    g_assert_cmpstr(output.grandparent_comm, ==, "sshd");
    g_assert_cmpstr(output.systemd_unit, ==, "ssh.service");
    g_assert_cmpstr(output.cgroup_path, ==, "/system.slice/ssh.service");
    g_assert_cmpstr(output.container_runtime, ==, "docker");
    g_assert_cmpstr(output.tty, ==, "pts/2");
    g_assert_true(output.ssh_origin);
    g_assert_cmpuint(output.pid_namespace, ==, 4026531836ULL);
    g_assert_cmpint(output.target_namespace_pid, ==, 77);
    g_assert_cmpuint(output.bytes_written, ==, 128);
    g_assert_cmpuint(strlen(output.cmdline), <=, MS_MAX_CMDLINE_BYTES);
    json_object_put(json);
}

static void
test_alert_json_rejects_overlong_server_context(void)
{
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json = ms_alert_to_json(&input);
    g_autofree char *cgroup = g_strnfill(MS_CGROUP_BYTES, 'x');

    json_object_object_add(json, "cgroup_path", json_object_new_string(cgroup));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

static void
test_alert_json_rejects_invalid_parent_hash(void)
{
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json = ms_alert_to_json(&input);

    json_object_object_add(json, "parent_sha256", json_object_new_string("not-a-sha256"));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

static void
test_alert_json_accepts_older_parent_evidence(void)
{
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json = ms_alert_to_json(&input);

    json_object_object_del(json, "parent_comm");
    json_object_object_del(json, "parent_sha256");
    json_object_object_del(json, "exe_md5");
    json_object_object_del(json, "exe_sha256");
    json_object_object_del(json, "exe_hash_status");
    json_object_object_del(json, "launcher_md5");
    json_object_object_del(json, "launcher_sha256");
    json_object_object_del(json, "launcher_hash_status");
    json_object_object_del(json, "parent_md5");
    json_object_object_del(json, "parent_hash_status");
    json_object_object_del(json, "target_md5");
    json_object_object_del(json, "target_sha256");
    json_object_object_del(json, "target_hash_status");
    g_assert_true(ms_alert_from_json(json, &output, NULL));
    g_assert_cmpstr(output.parent_comm, ==, "");
    g_assert_cmpstr(output.parent_sha256, ==, "");
    g_assert_cmpint(output.exe_hash_status, ==, MS_HASH_NOT_COLLECTED);
    g_assert_cmpint(output.launcher_hash_status, ==, MS_HASH_NOT_COLLECTED);
    g_assert_cmpint(output.parent_hash_status, ==, MS_HASH_NOT_COLLECTED);
    g_assert_cmpint(output.target_hash_status, ==, MS_HASH_NOT_COLLECTED);
    json_object_put(json);
}

static void
test_alert_json_rejects_invalid_hash_evidence(void)
{
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json = ms_alert_to_json(&input);

    json_object_object_add(json, "exe_md5", json_object_new_string("not-md5"));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_object_add(json, "exe_md5",
                           json_object_new_string("0123456789abcdef0123456789abcdef"));
    json_object_object_add(json, "target_hash_status", json_object_new_string("unknown"));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

static void
test_alert_json_round_trips_blocked_action(void)
{
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json;

    input.action = MS_ALERT_BLOCKED;
    json = ms_alert_to_json(&input);
    g_assert_nonnull(json);
    g_assert_true(ms_alert_from_json(json, &output, NULL));
    g_assert_cmpint(output.action, ==, MS_ALERT_BLOCKED);
    json_object_put(json);
}

static void
test_alert_json_rejects_missing_or_invalid_action(void)
{
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json = ms_alert_to_json(&input);

    json_object_object_del(json, "action");
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_object_add(json, "action", json_object_new_string("allowed"));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
    json_object_put(json);
}

static void
test_alert_json_rejects_invalid_username(void)
{
    static const char invalid[] = {(char)0xff};
    struct ms_alert input = fixture_memfd_alert();
    struct ms_alert output = {0};
    json_object *json = ms_alert_to_json(&input);

    json_object_object_add(json, "username", json_object_new_string_len(invalid, sizeof invalid));
    g_assert_false(ms_alert_from_json(json, &output, NULL));
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
    g_test_add_func("/alert-json/round-trip-blocked", test_alert_json_round_trips_blocked_action);
    g_test_add_func("/alert-json/invalid-parent-hash",
                    test_alert_json_rejects_invalid_parent_hash);
    g_test_add_func("/alert-json/older-parent-evidence",
                    test_alert_json_accepts_older_parent_evidence);
    g_test_add_func("/alert-json/invalid-hash-evidence",
                    test_alert_json_rejects_invalid_hash_evidence);
    g_test_add_func("/alert-json/action", test_alert_json_rejects_missing_or_invalid_action);
    g_test_add_func("/alert-json/invalid-username", test_alert_json_rejects_invalid_username);
    g_test_add_func("/alert-json/missing-field", test_alert_json_rejects_missing_field);
    g_test_add_func("/alert-json/embedded-nul", test_alert_json_rejects_embedded_nul);
    g_test_add_func("/alert-json/overlong-command", test_alert_json_rejects_overlong_command);
    g_test_add_func("/alert-json/negative-boottime", test_alert_json_rejects_negative_boottime);
    g_test_add_func("/alert-json/server-context-bounds",
                    test_alert_json_rejects_overlong_server_context);
    return g_test_run();
}
