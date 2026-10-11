#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>
#include <unistd.h>

#include "allowlist.h"

static char *
write_config(const char *contents)
{
    char *path = NULL;
    int descriptor = g_file_open_tmp("memspy-allowlist-XXXXXX", &path, NULL);

    g_assert_cmpint(descriptor, >=, 0);
    g_assert_cmpint(close(descriptor), ==, 0);
    g_assert_true(g_file_set_contents(path, contents, -1, NULL));
    return path;
}

static void
test_allowlist_matches_only_exact_rule_and_path(void)
{
    g_autofree char *path = write_config(
        "# known developer tools\n"
        "\n"
        "MEMFD_EXEC /usr/bin/browser\n"
        "PTRACE_WRITE /opt/Debug Tool\n"
        "MEMFD_EXEC /usr/bin/*\n");
    struct ms_allowlist *allowlist = NULL;
    struct ms_error error = {0};

    g_assert_true(ms_allowlist_load(path, &allowlist, &error));
    g_assert_true(ms_allowlist_matches(allowlist, "MEMFD_EXEC", "/usr/bin/browser"));
    g_assert_true(ms_allowlist_matches(allowlist, "PTRACE_WRITE", "/opt/Debug Tool"));
    g_assert_false(ms_allowlist_matches(allowlist, "PTRACE_WRITE", "/usr/bin/browser"));
    g_assert_false(ms_allowlist_matches(allowlist, "MEMFD_EXEC", "/usr/bin/bash"));
    g_assert_true(ms_allowlist_matches(allowlist, "MEMFD_EXEC", "/usr/bin/*"));

    ms_allowlist_free(allowlist);
    g_assert_cmpint(g_unlink(path), ==, 0);
}

static void
test_allowlist_rejects_bad_line_without_replacing_previous(void)
{
    g_autofree char *good_path = write_config("MEMFD_EXEC /usr/bin/browser\n");
    g_autofree char *bad_path = write_config("MEMFD_EXEC relative/path\n");
    struct ms_allowlist *allowlist = NULL;
    struct ms_allowlist *previous;
    struct ms_error error = {0};

    g_assert_true(ms_allowlist_load(good_path, &allowlist, &error));
    previous = allowlist;
    g_assert_false(ms_allowlist_load(bad_path, &allowlist, &error));
    g_assert_true(allowlist == previous);
    g_assert_nonnull(strstr(error.message, "line 1"));
    g_assert_true(ms_allowlist_matches(allowlist, "MEMFD_EXEC", "/usr/bin/browser"));

    ms_allowlist_free(allowlist);
    g_assert_cmpint(g_unlink(good_path), ==, 0);
    g_assert_cmpint(g_unlink(bad_path), ==, 0);
}

static void
test_allowlist_rejects_unbounded_entries(void)
{
    g_autoptr(GString) contents = g_string_new(NULL);
    struct ms_allowlist *allowlist = NULL;
    struct ms_error error = {0};

    for (unsigned int index = 0; index < 4097U; ++index)
        g_string_append_printf(contents, "MEMFD_EXEC /usr/bin/tool-%u\n", index);
    g_autofree char *path = write_config(contents->str);

    g_assert_false(ms_allowlist_load(path, &allowlist, &error));
    g_assert_null(allowlist);
    g_assert_nonnull(strstr(error.message, "too many entries"));
    g_assert_cmpint(g_unlink(path), ==, 0);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/allowlist/exact-match", test_allowlist_matches_only_exact_rule_and_path);
    g_test_add_func("/allowlist/reload-failure", test_allowlist_rejects_bad_line_without_replacing_previous);
    g_test_add_func("/allowlist/entry-limit", test_allowlist_rejects_unbounded_entries);
    return g_test_run();
}
