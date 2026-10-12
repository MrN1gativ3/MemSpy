#include <glib.h>
#include <syslog.h>

#include "journal.h"

static void test_priorities(void)
{
    struct ms_alert alert = {.severity = MS_SEVERITY_HIGH};
    g_assert_cmpint(ms_journal_priority(&alert), ==, LOG_ALERT);
    alert.severity = MS_SEVERITY_MEDIUM;
    g_assert_cmpint(ms_journal_priority(&alert), ==, LOG_WARNING);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/journal/priorities", test_priorities);
    return g_test_run();
}
