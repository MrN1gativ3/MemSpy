#define _POSIX_C_SOURCE 200809L

#include <fcntl.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "response_config.h"

struct fixture {
    char *directory;
    char *state_path;
    char *allowlist_path;
};

static void
fixture_setup(struct fixture *fixture, gconstpointer data)
{
    (void)data;
    fixture->directory = g_dir_make_tmp("memspy-response-XXXXXX", NULL);
    g_assert_nonnull(fixture->directory);
    fixture->state_path = g_build_filename(fixture->directory, "response-mode", NULL);
    fixture->allowlist_path = g_build_filename(fixture->directory, "response-allowlist.conf", NULL);
}

static void
fixture_teardown(struct fixture *fixture, gconstpointer data)
{
    g_autofree char *temporary = g_strconcat(fixture->state_path, ".tmp", NULL);

    (void)data;
    g_unlink(temporary);
    g_unlink(fixture->state_path);
    g_unlink(fixture->allowlist_path);
    g_rmdir(fixture->directory);
    g_free(fixture->allowlist_path);
    g_free(fixture->state_path);
    g_free(fixture->directory);
}

static void
write_secure(const char *path, const char *contents, mode_t mode)
{
    g_assert_true(g_file_set_contents(path, contents, -1, NULL));
    g_assert_cmpint(g_chmod(path, mode), ==, 0);
}

static void
test_state_missing_defaults_disabled(struct fixture *fixture, gconstpointer data)
{
    bool enabled = true;
    struct ms_error error = {0};

    (void)data;
    g_assert_true(ms_response_state_load(fixture->state_path, &enabled, &error));
    g_assert_false(enabled);
    g_assert_cmpstr(error.code, ==, "");
}

static void
test_state_round_trips_exact_values(struct fixture *fixture, gconstpointer data)
{
    bool enabled = false;
    struct stat metadata;
    g_autofree char *contents = NULL;
    struct ms_error error = {0};

    (void)data;
    g_assert_true(ms_response_state_store(fixture->state_path, true, &error));
    g_assert_true(g_file_get_contents(fixture->state_path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "enabled\n");
    g_assert_cmpint(g_stat(fixture->state_path, &metadata), ==, 0);
    g_assert_cmpuint(metadata.st_mode & 0777U, ==, 0600U);
    g_assert_true(ms_response_state_load(fixture->state_path, &enabled, &error));
    g_assert_true(enabled);
    g_clear_pointer(&contents, g_free);
    g_assert_true(ms_response_state_store(fixture->state_path, false, &error));
    g_assert_true(g_file_get_contents(fixture->state_path, &contents, NULL, NULL));
    g_assert_cmpstr(contents, ==, "disabled\n");
}

static void
test_state_rejects_unsafe_files(struct fixture *fixture, gconstpointer data)
{
    g_autofree char *target = g_build_filename(fixture->directory, "target", NULL);
    bool enabled = false;
    struct ms_error error = {0};

    (void)data;
    write_secure(target, "enabled\n", 0600);
    g_assert_cmpint(symlink(target, fixture->state_path), ==, 0);
    g_assert_false(ms_response_state_load(fixture->state_path, &enabled, &error));
    g_assert_cmpstr(error.code, ==, "response_state_security");
    g_unlink(fixture->state_path);
    write_secure(fixture->state_path, "enabled\n", 0620);
    g_assert_false(ms_response_state_load(fixture->state_path, &enabled, &error));
    g_unlink(target);
}

static void
test_state_rejects_invalid_and_oversized_content(struct fixture *fixture, gconstpointer data)
{
    bool enabled = false;
    struct ms_error error = {0};
    g_autofree char *oversized = g_strnfill(65, 'x');

    (void)data;
    write_secure(fixture->state_path, "yes\n", 0600);
    g_assert_false(ms_response_state_load(fixture->state_path, &enabled, &error));
    write_secure(fixture->state_path, oversized, 0600);
    g_assert_false(ms_response_state_load(fixture->state_path, &enabled, &error));
}

static void
test_state_failed_store_preserves_previous(struct fixture *fixture, gconstpointer data)
{
    bool enabled = false;
    struct ms_error error = {0};

    (void)data;
    g_assert_true(ms_response_state_store(fixture->state_path, true, &error));
    g_assert_cmpint(g_chmod(fixture->directory, 0500), ==, 0);
    if (geteuid() == 0) {
        g_test_skip("root bypasses directory write permissions");
    } else {
        g_assert_false(ms_response_state_store(fixture->state_path, false, &error));
        g_assert_true(ms_response_state_load(fixture->state_path, &enabled, &error));
        g_assert_true(enabled);
    }
    g_assert_cmpint(g_chmod(fixture->directory, 0700), ==, 0);
}

static void
test_allowlist_keeps_only_valid_unique_launchers(struct fixture *fixture, gconstpointer data)
{
    g_autofree char *valid = g_build_filename(fixture->directory, "valid", NULL);
    g_autofree char *nonexec = g_build_filename(fixture->directory, "nonexec", NULL);
    g_autofree char *link = g_build_filename(fixture->directory, "link", NULL);
    g_autofree char *contents = NULL;
    GArray *keys = NULL;
    size_t rejected = 0;
    struct ms_error warning = {0};

    (void)data;
    write_secure(valid, "fixture", 0700);
    write_secure(nonexec, "fixture", 0600);
    g_assert_cmpint(symlink(valid, link), ==, 0);
    contents = g_strdup_printf("# launchers\n%s\n%s\n%s\n%s\nrelative\n%s\n",
                               valid, valid, nonexec, fixture->directory, link);
    write_secure(fixture->allowlist_path, contents, 0600);
    g_assert_true(ms_response_allowlist_load(fixture->allowlist_path, &keys,
                                             &rejected, &warning));
    g_assert_cmpuint(keys->len, ==, 1);
    g_assert_cmpuint(rejected, ==, 4);
    g_assert_cmpstr(warning.code, ==, "response_allowlist_entries");
    g_array_free(keys, true);
    g_unlink(link);
    g_unlink(nonexec);
    g_unlink(valid);
}

static void
test_allowlist_bounds_input(struct fixture *fixture, gconstpointer data)
{
    g_autoptr(GString) contents = g_string_new(NULL);
    GArray *keys = NULL;
    size_t rejected = 0;
    struct ms_error warning = {0};

    (void)data;
    for (unsigned int index = 0; index < 4097U; ++index)
        g_string_append_printf(contents, "/missing/%u\n", index);
    write_secure(fixture->allowlist_path, contents->str, 0600);
    g_assert_true(ms_response_allowlist_load(fixture->allowlist_path, &keys,
                                             &rejected, &warning));
    g_assert_cmpuint(keys->len, ==, 0);
    g_assert_cmpuint(rejected, ==, 4097);
    g_array_free(keys, true);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add("/response-config/state-missing", struct fixture, NULL, fixture_setup,
               test_state_missing_defaults_disabled, fixture_teardown);
    g_test_add("/response-config/state-round-trip", struct fixture, NULL, fixture_setup,
               test_state_round_trips_exact_values, fixture_teardown);
    g_test_add("/response-config/state-security", struct fixture, NULL, fixture_setup,
               test_state_rejects_unsafe_files, fixture_teardown);
    g_test_add("/response-config/state-content", struct fixture, NULL, fixture_setup,
               test_state_rejects_invalid_and_oversized_content, fixture_teardown);
    g_test_add("/response-config/state-atomic", struct fixture, NULL, fixture_setup,
               test_state_failed_store_preserves_previous, fixture_teardown);
    g_test_add("/response-config/allowlist-filter", struct fixture, NULL, fixture_setup,
               test_allowlist_keeps_only_valid_unique_launchers, fixture_teardown);
    g_test_add("/response-config/allowlist-bound", struct fixture, NULL, fixture_setup,
               test_allowlist_bounds_input, fixture_teardown);
    return g_test_run();
}
