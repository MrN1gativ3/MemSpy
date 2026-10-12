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

static void test_proc_mem_target_resolution(void)
{
    g_autofree char *root = g_dir_make_tmp("memspy-proc-mem-XXXXXX", NULL);
    g_autofree char *source = g_build_filename(root, "100", NULL);
    g_autofree char *fd_dir = g_build_filename(source, "fd", NULL);
    g_autofree char *fd_path = g_build_filename(fd_dir, "7", NULL);
    g_autofree char *target = g_build_filename(root, "200", NULL);
    g_autofree char *exe = g_build_filename(target, "exe", NULL);
    char target_exe[MS_PATH_BYTES];
    pid_t namespace_pid = 0;
    pid_t host_pid = 0;

    g_assert_cmpint(g_mkdir_with_parents(fd_dir, 0700), ==, 0);
    g_assert_cmpint(g_mkdir_with_parents(target, 0700), ==, 0);
    g_assert_cmpint(symlink("/proc/200/mem", fd_path), ==, 0);
    g_assert_cmpint(symlink("/usr/bin/target", exe), ==, 0);
    g_assert_cmpint(ms_proc_mem_target_read(root, 100, 7, &namespace_pid, &host_pid,
                                            target_exe, sizeof target_exe),
                    ==, MS_PROC_MEM_RESOLVED);
    g_assert_cmpint(namespace_pid, ==, 200);
    g_assert_cmpint(host_pid, ==, 200);
    g_assert_cmpstr(target_exe, ==, "/usr/bin/target");
    g_unlink(fd_path);
    g_assert_cmpint(symlink("/tmp/ordinary", fd_path), ==, 0);
    g_assert_cmpint(ms_proc_mem_target_read(root, 100, 7, &namespace_pid, &host_pid,
                                            target_exe, sizeof target_exe),
                    ==, MS_PROC_MEM_IRRELEVANT);
    g_unlink(fd_path);
    g_unlink(exe);
    g_rmdir(fd_dir);
    g_rmdir(source);
    g_rmdir(target);
    g_rmdir(root);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/process-evidence/systemd", test_cgroup_systemd);
    g_test_add_func("/process-evidence/container", test_cgroup_container);
    g_test_add_func("/process-evidence/oversized", test_cgroup_rejects_oversized);
    g_test_add_func("/process-evidence/proc-mem-target", test_proc_mem_target_resolution);
    return g_test_run();
}
