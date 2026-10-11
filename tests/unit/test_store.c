#include <glib.h>
#include <glib/gstdio.h>
#include <sqlite3.h>
#include <string.h>
#include <sys/stat.h>

#include "store.h"

struct store_fixture {
    char *directory;
    char *path;
    struct ms_store *store;
};

static void
fixture_setup(struct store_fixture *fixture, gconstpointer user_data)
{
    struct ms_error error = {0};

    (void)user_data;
    fixture->directory = g_dir_make_tmp("memspy-store-XXXXXX", NULL);
    g_assert_nonnull(fixture->directory);
    fixture->path = g_build_filename(fixture->directory, "alerts.db", NULL);
    g_assert_true(ms_store_open(fixture->path, &fixture->store, &error));
}

static void
fixture_teardown(struct store_fixture *fixture, gconstpointer user_data)
{
    g_autofree char *wal = g_strconcat(fixture->path, "-wal", NULL);
    g_autofree char *shm = g_strconcat(fixture->path, "-shm", NULL);

    (void)user_data;
    ms_store_close(fixture->store);
    g_unlink(wal);
    g_unlink(shm);
    g_unlink(fixture->path);
    g_rmdir(fixture->directory);
    g_free(fixture->path);
    g_free(fixture->directory);
}

static struct ms_alert
alert_at(int64_t timestamp, enum ms_severity severity, const char *rule_id)
{
    struct ms_alert alert = {
        .timestamp_utc = timestamp,
        .observed_boottime_ns = (uint64_t)timestamp * 1000000000ULL,
        .severity = severity,
        .pid = 100,
        .ppid = 10,
        .uid = 1000,
    };

    g_strlcpy(alert.rule_id, rule_id, sizeof alert.rule_id);
    g_strlcpy(alert.explanation, "test alert", sizeof alert.explanation);
    g_strlcpy(alert.comm, "fixture", sizeof alert.comm);
    g_strlcpy(alert.exe, "/usr/bin/fixture", sizeof alert.exe);
    g_strlcpy(alert.cmdline, "fixture --test", sizeof alert.cmdline);
    g_strlcpy(alert.evidence, "synthetic", sizeof alert.evidence);
    return alert;
}

static void
test_store_schema_permissions_and_wal(struct store_fixture *fixture, gconstpointer user_data)
{
    struct stat metadata;
    sqlite3 *database = NULL;
    sqlite3_stmt *statement = NULL;

    (void)user_data;
    g_assert_cmpint(g_stat(fixture->path, &metadata), ==, 0);
    g_assert_cmpuint(metadata.st_mode & 0777U, ==, 0600U);
    g_assert_cmpint(sqlite3_open_v2(fixture->path, &database, SQLITE_OPEN_READONLY, NULL), ==, SQLITE_OK);
    g_assert_cmpint(sqlite3_prepare_v2(database, "PRAGMA user_version", -1, &statement, NULL), ==, SQLITE_OK);
    g_assert_cmpint(sqlite3_step(statement), ==, SQLITE_ROW);
    g_assert_cmpint(sqlite3_column_int(statement, 0), ==, 1);
    sqlite3_finalize(statement);
    g_assert_cmpint(sqlite3_prepare_v2(database, "PRAGMA journal_mode", -1, &statement, NULL), ==, SQLITE_OK);
    g_assert_cmpint(sqlite3_step(statement), ==, SQLITE_ROW);
    g_assert_cmpstr((const char *)sqlite3_column_text(statement, 0), ==, "wal");
    sqlite3_finalize(statement);
    sqlite3_close(database);
}

static void
test_store_inserts_and_paginates_without_duplicates(struct store_fixture *fixture,
                                                     gconstpointer user_data)
{
    struct ms_error error = {0};
    struct ms_alert first = alert_at(100, MS_SEVERITY_MEDIUM, "DELETED_EXEC");
    struct ms_alert second = alert_at(101, MS_SEVERITY_HIGH, "MEMFD_EXEC");
    struct ms_alert third = alert_at(102, MS_SEVERITY_MEDIUM, "PTRACE_WRITE");
    struct ms_alert_page page = {0};

    (void)user_data;
    g_assert_true(ms_store_insert(fixture->store, &first, &error));
    g_assert_true(ms_store_insert(fixture->store, &second, &error));
    g_assert_true(ms_store_insert(fixture->store, &third, &error));
    g_assert_cmpint(first.id, >, 0);

    g_assert_true(ms_store_list(fixture->store, 0, MS_SEVERITY_MEDIUM, 2, &page, &error));
    g_assert_cmpuint(page.length, ==, 2);
    g_assert_cmpint(page.items[0].id, ==, third.id);
    g_assert_cmpint(page.items[1].id, ==, second.id);
    int64_t cursor = page.next_before_id;
    ms_alert_page_clear(&page);

    g_assert_true(ms_store_list(fixture->store, cursor, MS_SEVERITY_MEDIUM, 2, &page, &error));
    g_assert_cmpuint(page.length, ==, 1);
    g_assert_cmpint(page.items[0].id, ==, first.id);
    ms_alert_page_clear(&page);

    g_assert_true(ms_store_list(fixture->store, 0, MS_SEVERITY_HIGH, 2000, &page, &error));
    g_assert_cmpuint(page.length, ==, 1);
    g_assert_cmpstr(page.items[0].rule_id, ==, "MEMFD_EXEC");
    ms_alert_page_clear(&page);
}

static void
test_store_prunes_at_most_one_hundred(struct store_fixture *fixture, gconstpointer user_data)
{
    struct ms_error error = {0};
    struct ms_alert alert = alert_at(1, MS_SEVERITY_MEDIUM, "DELETED_EXEC");

    (void)user_data;
    for (unsigned int index = 0; index < 101U; ++index)
        g_assert_true(ms_store_insert(fixture->store, &alert, &error));
    g_assert_cmpuint(ms_store_prune_before(fixture->store, 2, 100, &error), ==, 100);
    g_assert_cmpuint(ms_store_prune_before(fixture->store, 2, 100, &error), ==, 1);
}

static void
test_store_preserves_corrupt_database(void)
{
    g_autofree char *directory = g_dir_make_tmp("memspy-corrupt-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(directory, "alerts.db", NULL);
    struct ms_store *store = NULL;
    struct ms_error error = {0};
    g_autofree char *contents = NULL;
    gsize length = 0;

    g_assert_true(g_file_set_contents(path, "not a sqlite database", -1, NULL));
    g_assert_false(ms_store_open(path, &store, &error));
    g_assert_null(store);
    g_assert_true(g_file_get_contents(path, &contents, &length, NULL));
    g_assert_cmpuint(length, ==, strlen("not a sqlite database"));
    g_assert_cmpmem(contents, length, "not a sqlite database", strlen("not a sqlite database"));
    g_unlink(path);
    g_rmdir(directory);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add("/store/schema", struct store_fixture, NULL, fixture_setup,
               test_store_schema_permissions_and_wal, fixture_teardown);
    g_test_add("/store/pagination", struct store_fixture, NULL, fixture_setup,
               test_store_inserts_and_paginates_without_duplicates, fixture_teardown);
    g_test_add("/store/prune-limit", struct store_fixture, NULL, fixture_setup,
               test_store_prunes_at_most_one_hundred, fixture_teardown);
    g_test_add_func("/store/corrupt-preserved", test_store_preserves_corrupt_database);
    return g_test_run();
}
