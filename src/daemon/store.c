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

#define FL_STORE_SCHEMA_VERSION 1
#define FL_STORE_MAX_PAGE 200U
#define FL_STORE_MAX_PRUNE_BATCH 100U

struct fl_store {
    sqlite3 *database;
};

static void
set_error(struct fl_error *error, const char *code, const char *format, ...)
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
execute(sqlite3 *database, const char *sql, struct fl_error *error)
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
read_user_version(sqlite3 *database, int *version, struct fl_error *error)
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
migrate(sqlite3 *database, struct fl_error *error)
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
        "evidence TEXT NOT NULL, enrichment_incomplete INTEGER NOT NULL CHECK(enrichment_incomplete IN (0,1))"
        ");"
        "CREATE INDEX alerts_timestamp_idx ON alerts(timestamp_utc);"
        "CREATE INDEX alerts_severity_id_idx ON alerts(severity,id);"
        "PRAGMA user_version=1;"
        "COMMIT;";
    int version;

    if (!read_user_version(database, &version, error))
        return false;
    if (version == FL_STORE_SCHEMA_VERSION)
        return true;
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
fl_store_open(const char *path, struct fl_store **out, struct fl_error *error)
{
    struct fl_store *store;
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
        fl_store_close(store);
        return false;
    }
    sqlite3_busy_timeout(store->database, 3000);
    if (!execute(store->database, "PRAGMA journal_mode=WAL", error) ||
        !execute(store->database, "PRAGMA synchronous=FULL", error) ||
        !migrate(store->database, error)) {
        fl_store_close(store);
        return false;
    }
    *out = store;
    if (error != NULL)
        *error = (struct fl_error){0};
    return true;
}

void
fl_store_close(struct fl_store *store)
{
    if (store == NULL)
        return;
    if (store->database != NULL)
        sqlite3_close(store->database);
    free(store);
}

static bool
bind_alert(sqlite3_stmt *statement, const struct fl_alert *alert)
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
           sqlite3_bind_int(statement, index, alert->enrichment_incomplete) == SQLITE_OK;
}

bool
fl_store_insert(struct fl_store *store, struct fl_alert *alert, struct fl_error *error)
{
    static const char sql[] =
        "INSERT INTO alerts(timestamp_utc,observed_boottime_ns,severity,rule_id,explanation,pid,ppid,uid,comm,exe,cmdline,target_pid,target_exe,evidence,enrichment_incomplete)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
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
            struct fl_error *error)
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
read_alert(sqlite3_stmt *statement, struct fl_alert *alert, struct fl_error *error)
{
    *alert = (struct fl_alert){
        .id = sqlite3_column_int64(statement, 0),
        .timestamp_utc = sqlite3_column_int64(statement, 1),
        .observed_boottime_ns = (uint64_t)sqlite3_column_int64(statement, 2),
        .severity = (enum fl_severity)sqlite3_column_int(statement, 3),
        .pid = sqlite3_column_int(statement, 6),
        .ppid = sqlite3_column_int(statement, 7),
        .uid = (uid_t)sqlite3_column_int64(statement, 8),
        .target_pid = sqlite3_column_int(statement, 12),
        .enrichment_incomplete = sqlite3_column_int(statement, 15) != 0,
    };
    return copy_column(statement, 4, alert->rule_id, sizeof alert->rule_id, error) &&
           copy_column(statement, 5, alert->explanation, sizeof alert->explanation, error) &&
           copy_column(statement, 9, alert->comm, sizeof alert->comm, error) &&
           copy_column(statement, 10, alert->exe, sizeof alert->exe, error) &&
           copy_column(statement, 11, alert->cmdline, sizeof alert->cmdline, error) &&
           copy_column(statement, 13, alert->target_exe, sizeof alert->target_exe, error) &&
           copy_column(statement, 14, alert->evidence, sizeof alert->evidence, error);
}

void
fl_alert_page_clear(struct fl_alert_page *page)
{
    if (page == NULL)
        return;
    free(page->items);
    *page = (struct fl_alert_page){0};
}

bool
fl_store_list(struct fl_store *store, int64_t before_id, enum fl_severity minimum,
              size_t limit, struct fl_alert_page *page, struct fl_error *error)
{
    static const char sql[] =
        "SELECT id,timestamp_utc,observed_boottime_ns,severity,rule_id,explanation,pid,ppid,uid,comm,exe,cmdline,target_pid,target_exe,evidence,enrichment_incomplete "
        "FROM alerts WHERE (?=0 OR id<?) AND severity>=? ORDER BY id DESC LIMIT ?";
    sqlite3_stmt *statement = NULL;
    struct fl_alert_page result = {0};
    int step;

    if (store == NULL || page == NULL || limit == 0) {
        set_error(error, "store_invalid", "store, page, and a nonzero limit are required");
        return false;
    }
    if (limit > FL_STORE_MAX_PAGE)
        limit = FL_STORE_MAX_PAGE;
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
        fl_alert_page_clear(&result);
        return false;
    }
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        if (!read_alert(statement, &result.items[result.length], error)) {
            sqlite3_finalize(statement);
            fl_alert_page_clear(&result);
            return false;
        }
        ++result.length;
    }
    if (step != SQLITE_DONE) {
        set_error(error, "store_error", "%s", sqlite3_errmsg(store->database));
        sqlite3_finalize(statement);
        fl_alert_page_clear(&result);
        return false;
    }
    sqlite3_finalize(statement);
    if (result.length > 0)
        result.next_before_id = result.items[result.length - 1].id;
    fl_alert_page_clear(page);
    *page = result;
    return true;
}

size_t
fl_store_prune_before(struct fl_store *store, int64_t utc_cutoff, size_t batch,
                      struct fl_error *error)
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
    if (batch > FL_STORE_MAX_PRUNE_BATCH)
        batch = FL_STORE_MAX_PRUNE_BATCH;
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
