#include <glib.h>

#include "memspy_enforce_shared.h"

static void
test_enforce_decision_requires_every_condition(void)
{
    g_assert_false(ms_enforce_should_deny(0, 1, 1, 0));
    g_assert_false(ms_enforce_should_deny(1, 0, 1, 0));
    g_assert_false(ms_enforce_should_deny(1, 1, 0, 0));
    g_assert_false(ms_enforce_should_deny(1, 1, 1, 1));
    g_assert_true(ms_enforce_should_deny(1, 1, 1, 0));
}

static void
test_cross_process_decision_requires_verified_other_target(void)
{
    g_assert_false(ms_enforce_should_deny_cross_process(0, 10, 20, 1, 0));
    g_assert_false(ms_enforce_should_deny_cross_process(1, 10, 10, 1, 0));
    g_assert_false(ms_enforce_should_deny_cross_process(1, 10, 20, 0, 0));
    g_assert_false(ms_enforce_should_deny_cross_process(1, 10, 20, 1, 1));
    g_assert_true(ms_enforce_should_deny_cross_process(1, 10, 20, 1, 0));
}

static void
test_enforce_event_abi_is_fixed(void)
{
    g_assert_cmpuint(MS_ENFORCE_EVENT_ABI, ==, 2);
    g_assert_cmpuint(MS_ENFORCE_BLOCKED_MEMFD_EXEC, ==, 1);
    g_assert_cmpuint(MS_ENFORCE_BLOCKED_DELETED_EXEC, ==, 2);
    g_assert_cmpuint(MS_ENFORCE_BLOCKED_PROCESS_VM_WRITE, ==, 3);
    g_assert_cmpuint(MS_ENFORCE_BLOCKED_PTRACE_ACCESS, ==, 4);
    g_assert_cmpuint(MS_ENFORCE_BLOCKED_PROC_MEM_WRITE, ==, 5);
    g_assert_cmpuint(MS_ENFORCE_KIND_COUNT, ==, 6);
    g_assert_cmpuint(MS_ENFORCE_MAX_ARGS, ==, 16);
    g_assert_cmpuint(MS_ENFORCE_ARG_BYTES, ==, 2048);
    g_assert_cmpuint(MS_ENFORCE_FILENAME_BYTES, ==, 256);
    g_assert_cmpuint(MS_ENFORCE_ARGUMENTS_TRUNCATED, ==, 1U << 0);
    g_assert_cmpuint(MS_ENFORCE_FILENAME_TRUNCATED, ==, 1U << 1);
    g_assert_cmpuint(sizeof(struct ms_enforce_event), ==, 2384);
    g_assert_cmpuint(sizeof(struct ms_enforce_counters), ==, 56);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/enforce-abi/decision", test_enforce_decision_requires_every_condition);
    g_test_add_func("/enforce-abi/cross-process-decision",
                    test_cross_process_decision_requires_verified_other_target);
    g_test_add_func("/enforce-abi/layout", test_enforce_event_abi_is_fixed);
    return g_test_run();
}
