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
    g_assert_cmpint(sqlite3_column_int(statement, 0), ==, 5);
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
    second.action = MS_ALERT_BLOCKED;
    second.arguments_truncated = true;
    g_strlcpy(second.username, "alice", sizeof second.username);
    g_strlcpy(second.launcher_exe, "/usr/bin/launcher", sizeof second.launcher_exe);
    g_strlcpy(second.parent_exe, "/usr/bin/parent", sizeof second.parent_exe);
    g_strlcpy(second.parent_comm, "parent", sizeof second.parent_comm);
    g_strlcpy(second.exe_md5, "0123456789abcdef0123456789abcdef", sizeof second.exe_md5);
    second.exe_hash_status = MS_HASH_COMPLETE;
    g_strlcpy(second.parent_md5, "1123456789abcdef0123456789abcdef",
              sizeof second.parent_md5);
    second.parent_hash_status = MS_HASH_COMPLETE;
    g_strlcpy(second.parent_sha256,
              "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              sizeof second.parent_sha256);
    second.grandparent_pid = 9;
    second.ssh_origin = true;
    second.pid_namespace = 101;
    second.mount_namespace = 202;
    second.target_namespace_pid = 303;
    second.bytes_written = 64;
    g_strlcpy(second.grandparent_comm, "sshd", sizeof second.grandparent_comm);
    g_strlcpy(second.grandparent_exe, "/usr/sbin/sshd", sizeof second.grandparent_exe);
    g_strlcpy(second.systemd_unit, "fixture.service", sizeof second.systemd_unit);
    g_strlcpy(second.cgroup_path, "/system.slice/fixture.service", sizeof second.cgroup_path);
    g_strlcpy(second.container_id, "deadbeef", sizeof second.container_id);
    g_strlcpy(second.container_runtime, "podman", sizeof second.container_runtime);
    g_strlcpy(second.tty, "pts/3", sizeof second.tty);
    g_assert_true(ms_store_insert(fixture->store, &first, &error));
    g_assert_true(ms_store_insert(fixture->store, &second, &error));
    g_assert_true(ms_store_insert(fixture->store, &third, &error));
    g_assert_cmpint(first.id, >, 0);

    g_assert_true(ms_store_list(fixture->store, 0, MS_SEVERITY_MEDIUM, 2, &page, &error));
    g_assert_cmpuint(page.length, ==, 2);
    g_assert_cmpint(page.items[0].id, ==, third.id);
    g_assert_cmpint(page.items[1].id, ==, second.id);
    g_assert_cmpint(page.items[1].action, ==, MS_ALERT_BLOCKED);
    g_assert_cmpstr(page.items[1].username, ==, "alice");
    g_assert_cmpstr(page.items[1].launcher_exe, ==, "/usr/bin/launcher");
    g_assert_cmpstr(page.items[1].parent_exe, ==, "/usr/bin/parent");
    g_assert_cmpstr(page.items[1].parent_comm, ==, "parent");
    g_assert_cmpstr(page.items[1].parent_sha256, ==,
                    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    g_assert_cmpstr(page.items[1].exe_md5, ==, "0123456789abcdef0123456789abcdef");
    g_assert_cmpint(page.items[1].exe_hash_status, ==, MS_HASH_COMPLETE);
    g_assert_cmpstr(page.items[1].parent_md5, ==, "1123456789abcdef0123456789abcdef");
    g_assert_cmpint(page.items[1].parent_hash_status, ==, MS_HASH_COMPLETE);
    g_assert_true(page.items[1].arguments_truncated);
    g_assert_cmpint(page.items[1].grandparent_pid, ==, 9);
    g_assert_cmpstr(page.items[1].systemd_unit, ==, "fixture.service");
    g_assert_true(page.items[1].ssh_origin);
    g_assert_cmpuint(page.items[1].bytes_written, ==, 64);
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
test_store_get_by_id(struct store_fixture *fixture, gconstpointer user_data)
{
    struct ms_error error = {0};
    struct ms_alert inserted = alert_at(200, MS_SEVERITY_HIGH, "MEMFD_EXEC");
    struct ms_alert fetched = {.id = -1};

    (void)user_data;
    g_assert_true(ms_store_insert(fixture->store, &inserted, &error));
    g_assert_true(ms_store_get(fixture->store, inserted.id, &fetched, &error));
    g_assert_cmpint(fetched.id, ==, inserted.id);
    g_assert_cmpstr(fetched.rule_id, ==, inserted.rule_id);
    fetched.id = -1;
    g_assert_false(ms_store_get(fixture->store, inserted.id + 100, &fetched, &error));
    g_assert_cmpstr(error.code, ==, "store_not_found");
    g_assert_cmpint(fetched.id, ==, -1);
}

static void
test_store_migrates_version_one(void)
{
    static const char schema[] =
        "CREATE TABLE alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp_utc INTEGER NOT NULL,observed_boottime_ns INTEGER NOT NULL,"
        "severity INTEGER NOT NULL CHECK(severity IN (1,2)),"
        "rule_id TEXT NOT NULL,explanation TEXT NOT NULL,"
        "pid INTEGER NOT NULL,ppid INTEGER NOT NULL,uid INTEGER NOT NULL,"
        "comm TEXT NOT NULL,exe TEXT NOT NULL,cmdline TEXT NOT NULL,"
        "target_pid INTEGER NOT NULL,target_exe TEXT NOT NULL,"
        "evidence TEXT NOT NULL,enrichment_incomplete INTEGER NOT NULL CHECK(enrichment_incomplete IN (0,1)));"
        "INSERT INTO alerts VALUES(1,100,1000,2,'MEMFD_EXEC','existing',42,7,1000,"
        "'fixture','/memfd:fixture (deleted)','fixture --old',0,'','memfd',0);"
        "PRAGMA user_version=1;";
    g_autofree char *directory = g_dir_make_tmp("memspy-migrate-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(directory, "alerts.db", NULL);
    sqlite3 *database = NULL;
    struct ms_store *store = NULL;
    struct ms_alert_page page = {0};
    struct ms_error error = {0};

    g_assert_cmpint(sqlite3_open(path, &database), ==, SQLITE_OK);
    g_assert_cmpint(sqlite3_exec(database, schema, NULL, NULL, NULL), ==, SQLITE_OK);
    sqlite3_close(database);
    g_assert_true(ms_store_open(path, &store, &error));
    g_assert_true(ms_store_list(store, 0, MS_SEVERITY_MEDIUM, 10, &page, &error));
    g_assert_cmpuint(page.length, ==, 1);
    g_assert_cmpstr(page.items[0].rule_id, ==, "MEMFD_EXEC");
    g_assert_cmpint(page.items[0].action, ==, MS_ALERT_DETECTED);
    g_assert_cmpstr(page.items[0].username, ==, "");
    g_assert_cmpstr(page.items[0].launcher_exe, ==, "");
    g_assert_cmpstr(page.items[0].parent_exe, ==, "");
    g_assert_cmpstr(page.items[0].parent_comm, ==, "");
    g_assert_cmpstr(page.items[0].parent_sha256, ==, "");
    g_assert_cmpint(page.items[0].exe_hash_status, ==, MS_HASH_NOT_COLLECTED);
    g_assert_false(page.items[0].arguments_truncated);
    ms_alert_page_clear(&page);
    ms_store_close(store);
    g_unlink(path);
    g_rmdir(directory);
}

static void
test_store_migrates_version_two(void)
{
    static const char schema[] =
        "CREATE TABLE alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp_utc INTEGER NOT NULL,observed_boottime_ns INTEGER NOT NULL,"
        "severity INTEGER NOT NULL CHECK(severity IN (1,2)),"
        "rule_id TEXT NOT NULL,explanation TEXT NOT NULL,"
        "pid INTEGER NOT NULL,ppid INTEGER NOT NULL,uid INTEGER NOT NULL,"
        "comm TEXT NOT NULL,exe TEXT NOT NULL,cmdline TEXT NOT NULL,"
        "target_pid INTEGER NOT NULL,target_exe TEXT NOT NULL,evidence TEXT NOT NULL,"
        "enrichment_incomplete INTEGER NOT NULL CHECK(enrichment_incomplete IN (0,1)),"
        "action INTEGER NOT NULL DEFAULT 0 CHECK(action IN (0,1)),"
        "username TEXT NOT NULL DEFAULT '',launcher_exe TEXT NOT NULL DEFAULT '',"
        "parent_exe TEXT NOT NULL DEFAULT '',"
        "arguments_truncated INTEGER NOT NULL DEFAULT 0 CHECK(arguments_truncated IN (0,1)));"
        "INSERT INTO alerts VALUES(1,100,1000,2,'MEMFD_EXEC','existing',42,7,1000,"
        "'fixture','/memfd:fixture (deleted)','fixture --old',0,'','memfd',0,0,"
        "'alice','/usr/bin/launcher','/usr/bin/parent',0);"
        "PRAGMA user_version=2;";
    g_autofree char *directory = g_dir_make_tmp("memspy-migrate-v2-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(directory, "alerts.db", NULL);
    sqlite3 *database = NULL;
    struct ms_store *store = NULL;
    struct ms_alert_page page = {0};
    struct ms_error error = {0};

    g_assert_cmpint(sqlite3_open(path, &database), ==, SQLITE_OK);
    g_assert_cmpint(sqlite3_exec(database, schema, NULL, NULL, NULL), ==, SQLITE_OK);
    sqlite3_close(database);
    g_assert_true(ms_store_open(path, &store, &error));
    g_assert_true(ms_store_list(store, 0, MS_SEVERITY_MEDIUM, 10, &page, &error));
    g_assert_cmpuint(page.length, ==, 1);
    g_assert_cmpstr(page.items[0].parent_exe, ==, "/usr/bin/parent");
    g_assert_cmpstr(page.items[0].parent_comm, ==, "");
    g_assert_cmpstr(page.items[0].parent_sha256, ==, "");
    ms_alert_page_clear(&page);
    ms_store_close(store);
    g_unlink(path);
    g_rmdir(directory);
}

static void
test_store_migrates_version_three(void)
{
    static const char schema[] =
        "CREATE TABLE alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp_utc INTEGER NOT NULL,observed_boottime_ns INTEGER NOT NULL,"
        "severity INTEGER NOT NULL CHECK(severity IN (1,2)),"
        "rule_id TEXT NOT NULL,explanation TEXT NOT NULL,"
        "pid INTEGER NOT NULL,ppid INTEGER NOT NULL,uid INTEGER NOT NULL,"
        "comm TEXT NOT NULL,exe TEXT NOT NULL,cmdline TEXT NOT NULL,"
        "target_pid INTEGER NOT NULL,target_exe TEXT NOT NULL,evidence TEXT NOT NULL,"
        "enrichment_incomplete INTEGER NOT NULL CHECK(enrichment_incomplete IN (0,1)),"
        "action INTEGER NOT NULL DEFAULT 0 CHECK(action IN (0,1)),"
        "username TEXT NOT NULL DEFAULT '',launcher_exe TEXT NOT NULL DEFAULT '',"
        "parent_exe TEXT NOT NULL DEFAULT '',"
        "arguments_truncated INTEGER NOT NULL DEFAULT 0 CHECK(arguments_truncated IN (0,1)),"
        "parent_comm TEXT NOT NULL DEFAULT '',parent_sha256 TEXT NOT NULL DEFAULT '');"
        "INSERT INTO alerts VALUES(1,100,1000,2,'MEMFD_EXEC','existing',42,7,1000,"
        "'fixture','/memfd:fixture (deleted)','fixture --old',0,'','memfd',0,0,"
        "'alice','/usr/bin/launcher','/usr/bin/parent',0,'parent','abc');"
        "PRAGMA user_version=3;";
    g_autofree char *directory = g_dir_make_tmp("memspy-migrate-v3-XXXXXX", NULL);
    g_autofree char *path = g_build_filename(directory, "alerts.db", NULL);
    sqlite3 *database = NULL;
    struct ms_store *store = NULL;
    struct ms_alert alert = {0};
    struct ms_error error = {0};

    g_assert_cmpint(sqlite3_open(path, &database), ==, SQLITE_OK);
    g_assert_cmpint(sqlite3_exec(database, schema, NULL, NULL, NULL), ==, SQLITE_OK);
    sqlite3_close(database);
    g_assert_true(ms_store_open(path, &store, &error));
    g_assert_true(ms_store_get(store, 1, &alert, &error));
    g_assert_cmpstr(alert.parent_comm, ==, "parent");
    g_assert_cmpstr(alert.parent_sha256, ==, "abc");
    g_assert_cmpint(alert.grandparent_pid, ==, 0);
    g_assert_cmpstr(alert.systemd_unit, ==, "");
    g_assert_cmpuint(alert.bytes_written, ==, 0);
    ms_store_close(store);
    g_unlink(path);
    g_rmdir(directory);
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
    g_test_add("/store/get-by-id", struct store_fixture, NULL, fixture_setup,
               test_store_get_by_id, fixture_teardown);
    g_test_add_func("/store/corrupt-preserved", test_store_preserves_corrupt_database);
    g_test_add_func("/store/migrate-v1", test_store_migrates_version_one);
    g_test_add_func("/store/migrate-v2", test_store_migrates_version_two);
    g_test_add_func("/store/migrate-v3", test_store_migrates_version_three);
    return g_test_run();
}
