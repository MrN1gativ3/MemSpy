#include <glib.h>
#include <string.h>

#include "policy.h"

static struct ms_observation
observation(enum ms_observation_kind kind, pid_t pid, uint64_t start_ns, uint64_t observed_ns)
{
    struct ms_observation value = {
        .kind = kind,
        .process = {.pid = pid, .start_boottime_ns = start_ns},
        .observed_boottime_ns = observed_ns,
        .timestamp_utc = 1791676800,
        .ppid = 10,
        .uid = 1000,
        .syscall_result = 0,
    };

    g_strlcpy(value.comm, "fixture", sizeof value.comm);
    g_strlcpy(value.exe, "/usr/bin/fixture", sizeof value.exe);
    g_strlcpy(value.cmdline, "fixture --test", sizeof value.cmdline);
    g_strlcpy(value.parent_comm, "shell", sizeof value.parent_comm);
    g_strlcpy(value.exe_md5, "0123456789abcdef0123456789abcdef", sizeof value.exe_md5);
    g_strlcpy(value.parent_md5, "1123456789abcdef0123456789abcdef",
              sizeof value.parent_md5);
    value.exe_hash_status = MS_HASH_COMPLETE;
    value.parent_hash_status = MS_HASH_COMPLETE;
    g_strlcpy(value.parent_exe, "/usr/bin/shell", sizeof value.parent_exe);
    g_strlcpy(value.parent_sha256,
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              sizeof value.parent_sha256);
    value.grandparent_pid = 2;
    value.ssh_origin = true;
    value.pid_namespace = 101;
    value.mount_namespace = 202;
    g_strlcpy(value.grandparent_comm, "sshd", sizeof value.grandparent_comm);
    g_strlcpy(value.grandparent_exe, "/usr/sbin/sshd", sizeof value.grandparent_exe);
    g_strlcpy(value.systemd_unit, "fixture.service", sizeof value.systemd_unit);
    g_strlcpy(value.cgroup_path, "/system.slice/fixture.service", sizeof value.cgroup_path);
    return value;
}

static void
assert_rule(struct ms_observation value, const char *rule_id, enum ms_severity severity)
{
    struct ms_policy *policy = ms_policy_new();
    struct ms_alert alert = {0};

    g_assert_nonnull(policy);
    g_assert_cmpint(ms_policy_ingest(policy, &value, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, rule_id);
    g_assert_cmpint(alert.severity, ==, severity);
    g_assert_cmpstr(alert.parent_comm, ==, "shell");
    g_assert_cmpstr(alert.parent_exe, ==, "/usr/bin/shell");
    g_assert_cmpstr(alert.parent_sha256, ==,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    g_assert_cmpstr(alert.exe_md5, ==, "0123456789abcdef0123456789abcdef");
    g_assert_cmpstr(alert.parent_md5, ==, "1123456789abcdef0123456789abcdef");
    g_assert_cmpint(alert.exe_hash_status, ==, MS_HASH_COMPLETE);
    g_assert_cmpint(alert.grandparent_pid, ==, 2);
    g_assert_cmpstr(alert.grandparent_comm, ==, "sshd");
    g_assert_cmpstr(alert.systemd_unit, ==, "fixture.service");
    g_assert_true(alert.ssh_origin);
    ms_policy_free(policy);
}

static void
test_policy_maps_direct_rules(void)
{
    struct ms_observation value = observation(MS_OBSERVATION_EXEC, 100, 1000, 2000);

    value.flags = MS_OBSERVATION_MEMFD;
    assert_rule(value, "MEMFD_EXEC", MS_SEVERITY_HIGH);
    value.flags = MS_OBSERVATION_DELETED;
    assert_rule(value, "DELETED_EXEC", MS_SEVERITY_MEDIUM);

    value = observation(MS_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, 2000);
    value.target = (struct ms_process_id){.pid = 200, .start_boottime_ns = 900};
    value.syscall_result = 32;
    assert_rule(value, "PROCESS_VM_WRITE", MS_SEVERITY_MEDIUM);

    value.kind = MS_OBSERVATION_PTRACE_WRITE;
    value.syscall_result = 0;
    assert_rule(value, "PTRACE_WRITE", MS_SEVERITY_MEDIUM);

    value.kind = MS_OBSERVATION_PROC_MEM_WRITE;
    value.syscall_result = 64;
    value.bytes_written = 64;
    value.target_namespace_pid = value.target.pid;
    assert_rule(value, "PROC_MEM_WRITE", MS_SEVERITY_MEDIUM);
}

static void
test_policy_correlates_injection_chain(void)
{
    struct ms_policy *policy = ms_policy_new();
    struct ms_observation write = observation(MS_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, 100000);
    struct ms_observation execute = observation(MS_OBSERVATION_EXEC, 200, 900, 100000 + MS_CORRELATION_WINDOW_NS);
    struct ms_alert alert = {0};

    write.target = execute.process;
    write.syscall_result = 8;
    execute.flags = MS_OBSERVATION_MEMFD;
    g_assert_cmpint(ms_policy_ingest(policy, &write, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpint(ms_policy_ingest(policy, &execute, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "INJECTION_CHAIN");
    g_assert_cmpint(alert.severity, ==, MS_SEVERITY_HIGH);
    ms_policy_free(policy);
}

static void
test_policy_does_not_false_correlate(void)
{
    struct ms_policy *policy = ms_policy_new();
    struct ms_alert alert = {0};
    struct ms_observation write = observation(MS_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, 100000);
    struct ms_observation execute = observation(MS_OBSERVATION_EXEC, 200, 900, 100001);

    write.target = execute.process;
    write.syscall_result = -1;
    execute.flags = MS_OBSERVATION_MEMFD;
    g_assert_cmpint(ms_policy_ingest(policy, &write, &alert), ==, MS_POLICY_NONE);
    g_assert_cmpint(ms_policy_ingest(policy, &execute, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "MEMFD_EXEC");

    write.syscall_result = 8;
    write.target = write.process;
    g_assert_cmpint(ms_policy_ingest(policy, &write, &alert), ==, MS_POLICY_NONE);

    write.target = (struct ms_process_id){.pid = 300, .start_boottime_ns = 3000};
    g_assert_cmpint(ms_policy_ingest(policy, &write, &alert), ==, MS_POLICY_ALERT);
    execute = observation(MS_OBSERVATION_EXEC, 300, 3001, 100002);
    execute.flags = MS_OBSERVATION_MEMFD;
    g_assert_cmpint(ms_policy_ingest(policy, &execute, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "MEMFD_EXEC");

    write.target = (struct ms_process_id){.pid = 400, .start_boottime_ns = 4000};
    write.observed_boottime_ns = 200000;
    g_assert_cmpint(ms_policy_ingest(policy, &write, &alert), ==, MS_POLICY_ALERT);
    execute = observation(MS_OBSERVATION_EXEC, 400, 4000, 199999);
    execute.flags = MS_OBSERVATION_DELETED;
    g_assert_cmpint(ms_policy_ingest(policy, &execute, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "DELETED_EXEC");

    execute = observation(MS_OBSERVATION_EXEC, 400, 4000, 200000 + MS_CORRELATION_WINDOW_NS + 1U);
    execute.flags = 0;
    g_assert_cmpint(ms_policy_ingest(policy, &execute, &alert), ==, MS_POLICY_NONE);
    ms_policy_free(policy);
}

static void
test_policy_keeps_newest_injection_for_out_of_order_events(void)
{
    struct ms_policy *policy = ms_policy_new();
    struct ms_alert alert = {0};
    struct ms_observation newest = observation(
        MS_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, MS_CORRELATION_WINDOW_NS * 2U);
    struct ms_observation older = newest;
    struct ms_observation execute = observation(
        MS_OBSERVATION_EXEC, 200, 900, newest.observed_boottime_ns + 1U);

    newest.target = execute.process;
    older.target = execute.process;
    newest.syscall_result = 8;
    older.observed_boottime_ns = 1;
    execute.flags = MS_OBSERVATION_MEMFD;
    g_assert_cmpint(ms_policy_ingest(policy, &newest, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpint(ms_policy_ingest(policy, &older, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpint(ms_policy_ingest(policy, &execute, &alert), ==, MS_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "INJECTION_CHAIN");
    ms_policy_free(policy);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/policy/direct-rules", test_policy_maps_direct_rules);
    g_test_add_func("/policy/injection-chain", test_policy_correlates_injection_chain);
    g_test_add_func("/policy/no-false-correlation", test_policy_does_not_false_correlate);
    g_test_add_func("/policy/out-of-order-injections",
                    test_policy_keeps_newest_injection_for_out_of_order_events);
    return g_test_run();
}
