#include <glib.h>
#include <string.h>

#include "policy.h"

static struct fl_observation
observation(enum fl_observation_kind kind, pid_t pid, uint64_t start_ns, uint64_t observed_ns)
{
    struct fl_observation value = {
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
    return value;
}

static void
assert_rule(struct fl_observation value, const char *rule_id, enum fl_severity severity)
{
    struct fl_policy *policy = fl_policy_new();
    struct fl_alert alert = {0};

    g_assert_nonnull(policy);
    g_assert_cmpint(fl_policy_ingest(policy, &value, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, rule_id);
    g_assert_cmpint(alert.severity, ==, severity);
    fl_policy_free(policy);
}

static void
test_policy_maps_direct_rules(void)
{
    struct fl_observation value = observation(FL_OBSERVATION_EXEC, 100, 1000, 2000);

    value.flags = FL_OBSERVATION_MEMFD;
    assert_rule(value, "FL-MEMFD-EXEC", FL_SEVERITY_HIGH);
    value.flags = FL_OBSERVATION_DELETED;
    assert_rule(value, "FL-DELETED-EXEC", FL_SEVERITY_MEDIUM);

    value = observation(FL_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, 2000);
    value.target = (struct fl_process_id){.pid = 200, .start_boottime_ns = 900};
    value.syscall_result = 32;
    assert_rule(value, "FL-PROCESS-VM-WRITE", FL_SEVERITY_MEDIUM);

    value.kind = FL_OBSERVATION_PTRACE_WRITE;
    value.syscall_result = 0;
    assert_rule(value, "FL-PTRACE-WRITE", FL_SEVERITY_MEDIUM);
}

static void
test_policy_correlates_injection_chain(void)
{
    struct fl_policy *policy = fl_policy_new();
    struct fl_observation write = observation(FL_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, 100000);
    struct fl_observation execute = observation(FL_OBSERVATION_EXEC, 200, 900, 100000 + FL_CORRELATION_WINDOW_NS);
    struct fl_alert alert = {0};

    write.target = execute.process;
    write.syscall_result = 8;
    execute.flags = FL_OBSERVATION_MEMFD;
    g_assert_cmpint(fl_policy_ingest(policy, &write, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpint(fl_policy_ingest(policy, &execute, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "FL-INJECTION-CHAIN");
    g_assert_cmpint(alert.severity, ==, FL_SEVERITY_HIGH);
    fl_policy_free(policy);
}

static void
test_policy_does_not_false_correlate(void)
{
    struct fl_policy *policy = fl_policy_new();
    struct fl_alert alert = {0};
    struct fl_observation write = observation(FL_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, 100000);
    struct fl_observation execute = observation(FL_OBSERVATION_EXEC, 200, 900, 100001);

    write.target = execute.process;
    write.syscall_result = -1;
    execute.flags = FL_OBSERVATION_MEMFD;
    g_assert_cmpint(fl_policy_ingest(policy, &write, &alert), ==, FL_POLICY_NONE);
    g_assert_cmpint(fl_policy_ingest(policy, &execute, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "FL-MEMFD-EXEC");

    write.syscall_result = 8;
    write.target = write.process;
    g_assert_cmpint(fl_policy_ingest(policy, &write, &alert), ==, FL_POLICY_NONE);

    write.target = (struct fl_process_id){.pid = 300, .start_boottime_ns = 3000};
    g_assert_cmpint(fl_policy_ingest(policy, &write, &alert), ==, FL_POLICY_ALERT);
    execute = observation(FL_OBSERVATION_EXEC, 300, 3001, 100002);
    execute.flags = FL_OBSERVATION_MEMFD;
    g_assert_cmpint(fl_policy_ingest(policy, &execute, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "FL-MEMFD-EXEC");

    write.target = (struct fl_process_id){.pid = 400, .start_boottime_ns = 4000};
    write.observed_boottime_ns = 200000;
    g_assert_cmpint(fl_policy_ingest(policy, &write, &alert), ==, FL_POLICY_ALERT);
    execute = observation(FL_OBSERVATION_EXEC, 400, 4000, 199999);
    execute.flags = FL_OBSERVATION_DELETED;
    g_assert_cmpint(fl_policy_ingest(policy, &execute, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "FL-DELETED-EXEC");

    execute = observation(FL_OBSERVATION_EXEC, 400, 4000, 200000 + FL_CORRELATION_WINDOW_NS + 1U);
    execute.flags = 0;
    g_assert_cmpint(fl_policy_ingest(policy, &execute, &alert), ==, FL_POLICY_NONE);
    fl_policy_free(policy);
}

static void
test_policy_keeps_newest_injection_for_out_of_order_events(void)
{
    struct fl_policy *policy = fl_policy_new();
    struct fl_alert alert = {0};
    struct fl_observation newest = observation(
        FL_OBSERVATION_PROCESS_VM_WRITE, 100, 1000, FL_CORRELATION_WINDOW_NS * 2U);
    struct fl_observation older = newest;
    struct fl_observation execute = observation(
        FL_OBSERVATION_EXEC, 200, 900, newest.observed_boottime_ns + 1U);

    newest.target = execute.process;
    older.target = execute.process;
    newest.syscall_result = 8;
    older.observed_boottime_ns = 1;
    execute.flags = FL_OBSERVATION_MEMFD;
    g_assert_cmpint(fl_policy_ingest(policy, &newest, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpint(fl_policy_ingest(policy, &older, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpint(fl_policy_ingest(policy, &execute, &alert), ==, FL_POLICY_ALERT);
    g_assert_cmpstr(alert.rule_id, ==, "FL-INJECTION-CHAIN");
    fl_policy_free(policy);
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
