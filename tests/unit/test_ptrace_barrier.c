#define _POSIX_C_SOURCE 200809L

#include <glib.h>
#include <glib/gstdio.h>
#include <sys/stat.h>

#include "ptrace_barrier.h"

static void
write_status(const char *root, unsigned int pid, const char *tracer)
{
    g_autofree char *directory = g_strdup_printf("%s/%u", root, pid);
    g_autofree char *status = g_build_filename(directory, "status", NULL);
    g_autofree char *contents = g_strdup_printf("Name:\tfixture\nTracerPid:\t%s\n", tracer);

    g_assert_cmpint(g_mkdir_with_parents(directory, 0700), ==, 0);
    g_assert_true(g_file_set_contents(status, contents, -1, NULL));
}

static void
test_barrier_rejects_non_exempt_tracer(void)
{
    g_autofree char *root = g_dir_make_tmp("memspy-proc-XXXXXX", NULL);
    g_autofree char *target = g_build_filename(root, "20", NULL);
    g_autofree char *status = g_build_filename(target, "status", NULL);
    GArray *keys = g_array_new(false, false, sizeof(struct ms_allowlist_key));
    struct ms_error error = {0};

    write_status(root, 20, "10");
    g_assert_false(ms_ptrace_barrier_check(root, keys, &error));
    g_assert_cmpstr(error.code, ==, "response_ptrace_active");
    g_assert_nonnull(strstr(error.message, "PID 20 is traced by PID 10"));
    g_array_free(keys, true);
    g_unlink(status);
    g_rmdir(target);
    g_rmdir(root);
}

static void
test_barrier_accepts_no_tracers(void)
{
    g_autofree char *root = g_dir_make_tmp("memspy-proc-XXXXXX", NULL);
    g_autofree char *target = g_build_filename(root, "20", NULL);
    g_autofree char *status = g_build_filename(target, "status", NULL);
    GArray *keys = g_array_new(false, false, sizeof(struct ms_allowlist_key));
    struct ms_error error = {0};

    write_status(root, 20, "0");
    g_assert_true(ms_ptrace_barrier_check(root, keys, &error));
    g_array_free(keys, true);
    g_unlink(status);
    g_rmdir(target);
    g_rmdir(root);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ptrace-barrier/non-exempt", test_barrier_rejects_non_exempt_tracer);
    g_test_add_func("/ptrace-barrier/none", test_barrier_accepts_no_tracers);
    return g_test_run();
}
