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
test_enforce_event_abi_is_fixed(void)
{
    g_assert_cmpuint(MS_ENFORCE_EVENT_ABI, ==, 1);
    g_assert_cmpuint(MS_ENFORCE_MAX_ARGS, ==, 16);
    g_assert_cmpuint(MS_ENFORCE_ARG_BYTES, ==, 2048);
    g_assert_cmpuint(MS_ENFORCE_FILENAME_BYTES, ==, 256);
    g_assert_cmpuint(MS_ENFORCE_ARGUMENTS_TRUNCATED, ==, 1U << 0);
    g_assert_cmpuint(MS_ENFORCE_FILENAME_TRUNCATED, ==, 1U << 1);
    g_assert_cmpuint(sizeof(struct ms_enforce_event), ==, 2376);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/enforce-abi/decision", test_enforce_decision_requires_every_condition);
    g_test_add_func("/enforce-abi/layout", test_enforce_event_abi_is_fixed);
    return g_test_run();
}
