#define _POSIX_C_SOURCE 200809L

#include <glib.h>
#include <glib/gstdio.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "process_evidence.h"

static void
test_executable_hashes_current_process(void)
{
    struct ms_executable_evidence evidence = {0};

    g_assert_true(ms_executable_evidence_read_at("/proc", getpid(), 0, &evidence));
    g_assert_cmpint(evidence.status, ==, MS_HASH_COMPLETE);
    g_assert_cmpuint(strlen(evidence.md5), ==, 32);
    g_assert_cmpuint(strlen(evidence.sha256), ==, 64);
    g_assert_true(g_path_is_absolute(evidence.path));
}

static void
test_executable_hash_reports_exited_process(void)
{
    struct ms_executable_evidence evidence = {0};

    g_assert_false(ms_executable_evidence_read_at("/proc", G_MAXINT, 0, &evidence));
    g_assert_cmpint(evidence.status, ==, MS_HASH_PROCESS_EXITED);
}

static void
test_executable_hash_rejects_identity_change_and_oversize(void)
{
    g_autofree char *root = g_dir_make_tmp("memspy-image-XXXXXX", NULL);
    g_autofree char *process = g_build_filename(root, "123", NULL);
    g_autofree char *stat_path = g_build_filename(process, "stat", NULL);
    g_autofree char *exe_path = g_build_filename(process, "exe", NULL);
    g_autofree char *source_stat = NULL;
    g_autofree char *large_path = NULL;
    struct ms_executable_evidence evidence = {0};
    int large;

    g_assert_cmpint(g_mkdir(process, 0700), ==, 0);
    g_assert_true(g_file_get_contents("/proc/self/stat", &source_stat, NULL, NULL));
    g_assert_true(g_file_set_contents(stat_path, source_stat, -1, NULL));
    g_assert_false(ms_executable_evidence_read_at(root, 123, 1, &evidence));
    g_assert_cmpint(evidence.status, ==, MS_HASH_IDENTITY_CHANGED);

    large = g_file_open_tmp("memspy-large-XXXXXX", &large_path, NULL);
    g_assert_cmpint(large, >=, 0);
    g_assert_cmpint(ftruncate(large, (off_t)(129U * 1024U * 1024U)), ==, 0);
    close(large);
    g_assert_cmpint(symlink(large_path, exe_path), ==, 0);
    g_assert_false(ms_executable_evidence_read_at(root, 123, 0, &evidence));
    g_assert_cmpint(evidence.status, ==, MS_HASH_TOO_LARGE);

    g_unlink(exe_path);
    g_unlink(large_path);
    g_unlink(stat_path);
    g_rmdir(process);
    g_rmdir(root);
}

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
    g_test_add_func("/process-evidence/executable-complete",
                    test_executable_hashes_current_process);
    g_test_add_func("/process-evidence/executable-exited",
                    test_executable_hash_reports_exited_process);
    g_test_add_func("/process-evidence/executable-identity-and-size",
                    test_executable_hash_rejects_identity_change_and_oversize);
    return g_test_run();
}
