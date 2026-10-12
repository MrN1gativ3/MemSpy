#define _POSIX_C_SOURCE 200809L

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

#include "process_evidence.h"

static void test_cgroup_systemd(void)
{
    struct ms_process_evidence evidence = {0};
    g_assert_true(ms_process_cgroup_parse("0::/system.slice/ssh.service\n", &evidence));
    g_assert_cmpstr(evidence.cgroup_path, ==, "/system.slice/ssh.service");
    g_assert_cmpstr(evidence.systemd_unit, ==, "ssh.service");
    g_assert_cmpstr(evidence.container_runtime, ==, "");
}

static void test_cgroup_container(void)
{
    static const char id[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    struct ms_process_evidence evidence = {0};
    g_autofree char *cgroup = g_strdup_printf(
        "0::/system.slice/docker-%s.scope\n", id);

    g_assert_true(ms_process_cgroup_parse(cgroup, &evidence));
    g_assert_cmpstr(evidence.container_runtime, ==, "docker");
    g_assert_cmpstr(evidence.container_id, ==, id);
}

static void test_cgroup_rejects_oversized(void)
{
    struct ms_process_evidence evidence = {0};
    g_autofree char *text = g_strnfill(MS_CGROUP_BYTES, 'x');
    g_assert_false(ms_process_cgroup_parse(text, &evidence));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/process-evidence/systemd", test_cgroup_systemd);
    g_test_add_func("/process-evidence/container", test_cgroup_container);
    g_test_add_func("/process-evidence/oversized", test_cgroup_rejects_oversized);
    return g_test_run();
}
