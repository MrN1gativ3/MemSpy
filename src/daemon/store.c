#define _POSIX_C_SOURCE 200809L

#include "store.h"

#include <errno.h>
#include <fcntl.h>
#include <sqlite3.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MS_STORE_SCHEMA_VERSION 4
#define MS_STORE_MAX_PAGE 200U
#define MS_STORE_MAX_PRUNE_BATCH 100U

struct ms_store {
    sqlite3 *database;
};

static void
set_error(struct ms_error *error, const char *code, const char *format, ...)
{
    va_list args;

    if (error == NULL)
        return;
    snprintf(error->code, sizeof error->code, "%s", code);
    va_start(args, format);
    vsnprintf(error->message, sizeof error->message, format, args);
    va_end(args);
}

static bool
execute(sqlite3 *database, const char *sql, struct ms_error *error)
{
    char *message = NULL;
    int result = sqlite3_exec(database, sql, NULL, NULL, &message);

    if (result == SQLITE_OK)
        return true;
    set_error(error, "store_error", "%s", message == NULL ? sqlite3_errmsg(database) : message);
    sqlite3_free(message);
    return false;
}

static bool
read_user_version(sqlite3 *database, int *version, struct ms_error *error)
{
    sqlite3_stmt *statement = NULL;
    int result = sqlite3_prepare_v2(database, "PRAGMA user_version", -1, &statement, NULL);

    if (result != SQLITE_OK) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(database));
        return false;
    }
    result = sqlite3_step(statement);
    if (result != SQLITE_ROW) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(database));
        sqlite3_finalize(statement);
        return false;
    }
    *version = sqlite3_column_int(statement, 0);
    sqlite3_finalize(statement);
    return true;
}

static bool
migrate(sqlite3 *database, struct ms_error *error)
{
    static const char schema[] =
        "BEGIN IMMEDIATE;"
        "CREATE TABLE alerts ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp_utc INTEGER NOT NULL,"
        "observed_boottime_ns INTEGER NOT NULL,"
        "severity INTEGER NOT NULL CHECK(severity IN (1,2)),"
        "rule_id TEXT NOT NULL, explanation TEXT NOT NULL,"
        "pid INTEGER NOT NULL, ppid INTEGER NOT NULL, uid INTEGER NOT NULL,"
        "comm TEXT NOT NULL, exe TEXT NOT NULL, cmdline TEXT NOT NULL,"
        "target_pid INTEGER NOT NULL, target_exe TEXT NOT NULL,"
        "evidence TEXT NOT NULL, enrichment_incomplete INTEGER NOT NULL CHECK(enrichment_incomplete IN (0,1)),"
        "action INTEGER NOT NULL DEFAULT 0 CHECK(action IN (0,1)),"
        "username TEXT NOT NULL DEFAULT '', launcher_exe TEXT NOT NULL DEFAULT '',"
        "parent_exe TEXT NOT NULL DEFAULT '',"
        "arguments_truncated INTEGER NOT NULL DEFAULT 0 CHECK(arguments_truncated IN (0,1)),"
        "parent_comm TEXT NOT NULL DEFAULT '',"
        "parent_sha256 TEXT NOT NULL DEFAULT '',"
        "grandparent_pid INTEGER NOT NULL DEFAULT 0,"
        "grandparent_comm TEXT NOT NULL DEFAULT '',grandparent_exe TEXT NOT NULL DEFAULT '',"
        "systemd_unit TEXT NOT NULL DEFAULT '',cgroup_path TEXT NOT NULL DEFAULT '',"
        "container_id TEXT NOT NULL DEFAULT '',container_runtime TEXT NOT NULL DEFAULT '',"
        "tty TEXT NOT NULL DEFAULT '',ssh_origin INTEGER NOT NULL DEFAULT 0 CHECK(ssh_origin IN (0,1)),"
        "pid_namespace INTEGER NOT NULL DEFAULT 0,mount_namespace INTEGER NOT NULL DEFAULT 0,"
        "target_namespace_pid INTEGER NOT NULL DEFAULT 0,bytes_written INTEGER NOT NULL DEFAULT 0"
        ");"
        "CREATE INDEX alerts_timestamp_idx ON alerts(timestamp_utc);"
        "CREATE INDEX alerts_severity_id_idx ON alerts(severity,id);"
        "PRAGMA user_version=4;"
        "COMMIT;";
    static const char migrate_v1[] =
        "BEGIN IMMEDIATE;"
        "ALTER TABLE alerts ADD COLUMN action INTEGER NOT NULL DEFAULT 0 CHECK(action IN (0,1));"
        "ALTER TABLE alerts ADD COLUMN username TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN launcher_exe TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN parent_exe TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN arguments_truncated INTEGER NOT NULL DEFAULT 0 CHECK(arguments_truncated IN (0,1));"
        "ALTER TABLE alerts ADD COLUMN parent_comm TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN parent_sha256 TEXT NOT NULL DEFAULT '';"
        "PRAGMA user_version=3;"
        "COMMIT;";
    static const char migrate_v2[] =
        "BEGIN IMMEDIATE;"
        "ALTER TABLE alerts ADD COLUMN parent_comm TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN parent_sha256 TEXT NOT NULL DEFAULT '';"
        "PRAGMA user_version=3;"
        "COMMIT;";
    static const char migrate_v3[] =
        "BEGIN IMMEDIATE;"
        "ALTER TABLE alerts ADD COLUMN grandparent_pid INTEGER NOT NULL DEFAULT 0;"
        "ALTER TABLE alerts ADD COLUMN grandparent_comm TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN grandparent_exe TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN systemd_unit TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN cgroup_path TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN container_id TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN container_runtime TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN tty TEXT NOT NULL DEFAULT '';"
        "ALTER TABLE alerts ADD COLUMN ssh_origin INTEGER NOT NULL DEFAULT 0 CHECK(ssh_origin IN (0,1));"
        "ALTER TABLE alerts ADD COLUMN pid_namespace INTEGER NOT NULL DEFAULT 0;"
        "ALTER TABLE alerts ADD COLUMN mount_namespace INTEGER NOT NULL DEFAULT 0;"
        "ALTER TABLE alerts ADD COLUMN target_namespace_pid INTEGER NOT NULL DEFAULT 0;"
        "ALTER TABLE alerts ADD COLUMN bytes_written INTEGER NOT NULL DEFAULT 0;"
        "PRAGMA user_version=4;"
        "COMMIT;";
    int version;

    if (!read_user_version(database, &version, error))
        return false;
    if (version == MS_STORE_SCHEMA_VERSION)
        return true;
    if (version == 1) {
        if (!execute(database, migrate_v1, error)) {
            sqlite3_exec(database, "ROLLBACK", NULL, NULL, NULL);
            return false;
        }
        return migrate(database, error);
    }
    if (version == 3) {
        if (!execute(database, migrate_v3, error)) {
            sqlite3_exec(database, "ROLLBACK", NULL, NULL, NULL);
            return false;
        }
        return migrate(database, error);
    }
    if (version == 2) {
        if (!execute(database, migrate_v2, error)) {
            sqlite3_exec(database, "ROLLBACK", NULL, NULL, NULL);
            return false;
        }
        return migrate(database, error);
    }
    if (version != 0) {
        set_error(error, "store_schema", "unsupported schema version %d", version);
        return false;
    }
    if (!execute(database, schema, error)) {
        sqlite3_exec(database, "ROLLBACK", NULL, NULL, NULL);
        return false;
    }
    return true;
}

bool
ms_store_open(const char *path, struct ms_store **out, struct ms_error *error)
{
    struct ms_store *store;
    int descriptor;
    int result;

    if (path == NULL || out == NULL) {
        set_error(error, "store_invalid", "path and output are required");
        return false;
    }
    descriptor = open(path, O_CREAT | O_RDWR, 0600);
    if (descriptor < 0) {
        set_error(error, "store_io", "cannot open '%s': %s", path, strerror(errno));
        return false;
    }
    if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0 || fchmod(descriptor, 0600) != 0) {
        set_error(error, "store_io", "cannot secure '%s': %s", path, strerror(errno));
        close(descriptor);
        return false;
    }
    close(descriptor);

    store = calloc(1, sizeof *store);
    if (store == NULL) {
        set_error(error, "store_memory", "cannot allocate store");
        return false;
    }
    result = sqlite3_open_v2(path, &store->database,
                             SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
                             NULL);
    if (result != SQLITE_OK) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        ms_store_close(store);
        return false;
    }
    sqlite3_busy_timeout(store->database, 3000);
    if (!execute(store->database, "PRAGMA journal_mode=WAL", error) ||
        !execute(store->database, "PRAGMA synchronous=FULL", error) ||
        !migrate(store->database, error)) {
        ms_store_close(store);
        return false;
    }
    *out = store;
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
}

void
ms_store_close(struct ms_store *store)
{
    if (store == NULL)
        return;
    if (store->database != NULL)
        sqlite3_close(store->database);
    free(store);
}

static bool
bind_alert(sqlite3_stmt *statement, const struct ms_alert *alert)
{
    int index = 1;

    return sqlite3_bind_int64(statement, index++, alert->timestamp_utc) == SQLITE_OK &&
           sqlite3_bind_int64(statement, index++, (sqlite3_int64)alert->observed_boottime_ns) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->severity) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->rule_id, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->explanation, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->pid) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->ppid) == SQLITE_OK &&
           sqlite3_bind_int64(statement, index++, alert->uid) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->comm, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->exe, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->cmdline, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->target_pid) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->target_exe, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->evidence, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->enrichment_incomplete) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->action) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->username, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->launcher_exe, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->parent_exe, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->arguments_truncated) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->parent_comm, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->parent_sha256, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->grandparent_pid) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->grandparent_comm, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->grandparent_exe, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->systemd_unit, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->cgroup_path, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->container_id, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->container_runtime, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_text(statement, index++, alert->tty, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->ssh_origin) == SQLITE_OK &&
           sqlite3_bind_int64(statement, index++, (sqlite3_int64)alert->pid_namespace) == SQLITE_OK &&
           sqlite3_bind_int64(statement, index++, (sqlite3_int64)alert->mount_namespace) == SQLITE_OK &&
           sqlite3_bind_int(statement, index++, alert->target_namespace_pid) == SQLITE_OK &&
           sqlite3_bind_int64(statement, index, (sqlite3_int64)alert->bytes_written) == SQLITE_OK;
}

bool
ms_store_insert(struct ms_store *store, struct ms_alert *alert, struct ms_error *error)
{
    static const char sql[] =
        "INSERT INTO alerts(timestamp_utc,observed_boottime_ns,severity,rule_id,explanation,pid,ppid,uid,comm,exe,cmdline,target_pid,target_exe,evidence,enrichment_incomplete,action,username,launcher_exe,parent_exe,arguments_truncated,parent_comm,parent_sha256,grandparent_pid,grandparent_comm,grandparent_exe,systemd_unit,cgroup_path,container_id,container_runtime,tty,ssh_origin,pid_namespace,mount_namespace,target_namespace_pid,bytes_written)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
    sqlite3_stmt *statement = NULL;
    int result;

    if (store == NULL || alert == NULL) {
        set_error(error, "store_invalid", "store and alert are required");
        return false;
    }
    result = sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL);
    if (result != SQLITE_OK || !bind_alert(statement, alert)) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        sqlite3_finalize(statement);
        return false;
    }
    result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (result != SQLITE_DONE) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        return false;
    }
    alert->id = sqlite3_last_insert_rowid(store->database);
    return true;
}

static bool
copy_column(sqlite3_stmt *statement, int column, char *destination, size_t capacity,
            struct ms_error *error)
{
    const unsigned char *text = sqlite3_column_text(statement, column);
    int length = sqlite3_column_bytes(statement, column);

    if (text == NULL || length < 0 || (size_t)length >= capacity ||
        memchr(text, '\0', (size_t)length) != NULL) {
        set_error(error, "store_data", "stored alert contains an invalid string");
        return false;
    }
    memcpy(destination, text, (size_t)length);
    destination[length] = '\0';
    return true;
}

static bool
read_alert(sqlite3_stmt *statement, struct ms_alert *alert, struct ms_error *error)
{
    *alert = (struct ms_alert){
        .id = sqlite3_column_int64(statement, 0),
        .timestamp_utc = sqlite3_column_int64(statement, 1),
        .observed_boottime_ns = (uint64_t)sqlite3_column_int64(statement, 2),
        .severity = (enum ms_severity)sqlite3_column_int(statement, 3),
        .pid = sqlite3_column_int(statement, 6),
        .ppid = sqlite3_column_int(statement, 7),
        .uid = (uid_t)sqlite3_column_int64(statement, 8),
        .target_pid = sqlite3_column_int(statement, 12),
        .enrichment_incomplete = sqlite3_column_int(statement, 15) != 0,
        .action = (enum ms_alert_action)sqlite3_column_int(statement, 16),
        .arguments_truncated = sqlite3_column_int(statement, 20) != 0,
        .grandparent_pid = sqlite3_column_int(statement, 23),
        .ssh_origin = sqlite3_column_int(statement, 31) != 0,
        .pid_namespace = (uint64_t)sqlite3_column_int64(statement, 32),
        .mount_namespace = (uint64_t)sqlite3_column_int64(statement, 33),
        .target_namespace_pid = sqlite3_column_int(statement, 34),
        .bytes_written = (uint64_t)sqlite3_column_int64(statement, 35),
    };
    if (alert->action != MS_ALERT_DETECTED && alert->action != MS_ALERT_BLOCKED) {
        set_error(error, "store_data", "stored alert contains an invalid action");
        return false;
    }
    return copy_column(statement, 4, alert->rule_id, sizeof alert->rule_id, error) &&
           copy_column(statement, 5, alert->explanation, sizeof alert->explanation, error) &&
           copy_column(statement, 9, alert->comm, sizeof alert->comm, error) &&
           copy_column(statement, 10, alert->exe, sizeof alert->exe, error) &&
           copy_column(statement, 11, alert->cmdline, sizeof alert->cmdline, error) &&
           copy_column(statement, 13, alert->target_exe, sizeof alert->target_exe, error) &&
           copy_column(statement, 14, alert->evidence, sizeof alert->evidence, error) &&
           copy_column(statement, 17, alert->username, sizeof alert->username, error) &&
           copy_column(statement, 18, alert->launcher_exe, sizeof alert->launcher_exe, error) &&
           copy_column(statement, 19, alert->parent_exe, sizeof alert->parent_exe, error) &&
           copy_column(statement, 21, alert->parent_comm, sizeof alert->parent_comm, error) &&
           copy_column(statement, 22, alert->parent_sha256, sizeof alert->parent_sha256, error) &&
           copy_column(statement, 24, alert->grandparent_comm, sizeof alert->grandparent_comm, error) &&
           copy_column(statement, 25, alert->grandparent_exe, sizeof alert->grandparent_exe, error) &&
           copy_column(statement, 26, alert->systemd_unit, sizeof alert->systemd_unit, error) &&
           copy_column(statement, 27, alert->cgroup_path, sizeof alert->cgroup_path, error) &&
           copy_column(statement, 28, alert->container_id, sizeof alert->container_id, error) &&
           copy_column(statement, 29, alert->container_runtime, sizeof alert->container_runtime, error) &&
           copy_column(statement, 30, alert->tty, sizeof alert->tty, error);
}

bool
ms_store_get(struct ms_store *store, int64_t id, struct ms_alert *alert,
             struct ms_error *error)
{
    static const char sql[] =
        "SELECT id,timestamp_utc,observed_boottime_ns,severity,rule_id,explanation,pid,ppid,uid,comm,exe,cmdline,target_pid,target_exe,evidence,enrichment_incomplete,action,username,launcher_exe,parent_exe,arguments_truncated,parent_comm,parent_sha256,grandparent_pid,grandparent_comm,grandparent_exe,systemd_unit,cgroup_path,container_id,container_runtime,tty,ssh_origin,pid_namespace,mount_namespace,target_namespace_pid,bytes_written FROM alerts WHERE id=?";
    sqlite3_stmt *statement = NULL;
    struct ms_alert result = {0};
    int step;

    if (store == NULL || alert == NULL || id <= 0) {
        set_error(error, "store_invalid", "store, alert, and a positive id are required");
        return false;
    }
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, id) != SQLITE_OK) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        sqlite3_finalize(statement);
        return false;
    }
    step = sqlite3_step(statement);
    if (step == SQLITE_ROW && read_alert(statement, &result, error)) {
        sqlite3_finalize(statement);
        *alert = result;
        return true;
    }
    if (step == SQLITE_DONE)
        set_error(error, "store_not_found", "alert not found");
    else if (step != SQLITE_ROW)
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
    sqlite3_finalize(statement);
    return false;
}

void
ms_alert_page_clear(struct ms_alert_page *page)
{
    if (page == NULL)
        return;
    free(page->items);
    *page = (struct ms_alert_page){0};
}

bool
ms_store_list(struct ms_store *store, int64_t before_id, enum ms_severity minimum,
              size_t limit, struct ms_alert_page *page, struct ms_error *error)
{
    static const char sql[] =
        "SELECT id,timestamp_utc,observed_boottime_ns,severity,rule_id,explanation,pid,ppid,uid,comm,exe,cmdline,target_pid,target_exe,evidence,enrichment_incomplete,action,username,launcher_exe,parent_exe,arguments_truncated,parent_comm,parent_sha256,grandparent_pid,grandparent_comm,grandparent_exe,systemd_unit,cgroup_path,container_id,container_runtime,tty,ssh_origin,pid_namespace,mount_namespace,target_namespace_pid,bytes_written "
        "FROM alerts WHERE (?=0 OR id<?) AND severity>=? ORDER BY id DESC LIMIT ?";
    sqlite3_stmt *statement = NULL;
    struct ms_alert_page result = {0};
    int step;

    if (store == NULL || page == NULL || limit == 0) {
        set_error(error, "store_invalid", "store, page, and a nonzero limit are required");
        return false;
    }
    if (limit > MS_STORE_MAX_PAGE)
        limit = MS_STORE_MAX_PAGE;
    result.items = calloc(limit, sizeof *result.items);
    if (result.items == NULL) {
        set_error(error, "store_memory", "cannot allocate alert page");
        return false;
    }
    if (sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, before_id) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 2, before_id) != SQLITE_OK ||
        sqlite3_bind_int(statement, 3, minimum) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 4, (sqlite3_int64)limit) != SQLITE_OK) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        sqlite3_finalize(statement);
        ms_alert_page_clear(&result);
        return false;
    }
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        if (!read_alert(statement, &result.items[result.length], error)) {
            sqlite3_finalize(statement);
            ms_alert_page_clear(&result);
            return false;
        }
        ++result.length;
    }
    if (step != SQLITE_DONE) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        sqlite3_finalize(statement);
        ms_alert_page_clear(&result);
        return false;
    }
    sqlite3_finalize(statement);
    if (result.length > 0)
        result.next_before_id = result.items[result.length - 1].id;
    ms_alert_page_clear(page);
    *page = result;
    return true;
}

size_t
ms_store_prune_before(struct ms_store *store, int64_t utc_cutoff, size_t batch,
                      struct ms_error *error)
{
    static const char sql[] =
        "DELETE FROM alerts WHERE id IN (SELECT id FROM alerts WHERE timestamp_utc<? ORDER BY id LIMIT ?)";
    sqlite3_stmt *statement = NULL;
    size_t removed;
    int result;

    if (store == NULL || batch == 0) {
        set_error(error, "store_invalid", "store and a nonzero batch are required");
        return 0;
    }
    if (batch > MS_STORE_MAX_PRUNE_BATCH)
        batch = MS_STORE_MAX_PRUNE_BATCH;
    if (!execute(store->database, "BEGIN IMMEDIATE", error))
        return 0;
    result = sqlite3_prepare_v2(store->database, sql, -1, &statement, NULL);
    if (result == SQLITE_OK)
        result = sqlite3_bind_int64(statement, 1, utc_cutoff);
    if (result == SQLITE_OK)
        result = sqlite3_bind_int64(statement, 2, (sqlite3_int64)batch);
    if (result == SQLITE_OK)
        result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (result != SQLITE_DONE) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        sqlite3_exec(store->database, "ROLLBACK", NULL, NULL, NULL);
        return 0;
    }
    removed = (size_t)sqlite3_changes(store->database);
    if (!execute(store->database, "COMMIT", error)) {
        sqlite3_exec(store->database, "ROLLBACK", NULL, NULL, NULL);
        return 0;
    }
    return removed;
}
