#include "app.h"

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "allowlist.h"
#include "api.h"
#include "policy.h"
#include "sensor.h"
#include "store.h"

struct ms_app {
    struct ms_policy *policy;
    struct ms_allowlist *allowlist;
    struct ms_store *store;
    struct ms_api *api;
    struct ms_sensor *sensor;
    char *database_path;
    struct ms_app_dependencies dependencies;
    struct ms_health health;
    struct ms_alert *queue;
    size_t queue_head;
    size_t queue_length;
    uint64_t reported_pressure;
    uint64_t reported_lost;
    int64_t next_prune_utc;
    volatile sig_atomic_t stopping;
    bool injected;
};

static void
set_error(struct ms_error *error, const char *code, const char *message)
{
    if (error == NULL)
        return;
    g_strlcpy(error->code, code, sizeof error->code);
    g_strlcpy(error->message, message, sizeof error->message);
}

static bool
store_insert(struct ms_app *app, struct ms_alert *alert, struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.store_insert(app->dependencies.userdata, alert, error);
    return ms_store_insert(app->store, alert, error);
}

static size_t
store_prune(struct ms_app *app, int64_t cutoff, struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.store_prune == NULL ? 0 :
            app->dependencies.store_prune(app->dependencies.userdata, cutoff, 100, error);
    return ms_store_prune_before(app->store, cutoff, 100, error);
}

static void
publish_health(struct ms_app *app)
{
    if (app->injected) {
        if (app->dependencies.publish_health != NULL)
            app->dependencies.publish_health(app->dependencies.userdata, &app->health);
    } else {
        ms_api_publish_health(app->api, &app->health);
    }
}

static void
apply_health(struct ms_app *app, enum ms_health_signal signal, uint64_t count)
{
    ms_health_apply(&app->health, signal, count);
    publish_health(app);
}

static void
publish_alert(struct ms_app *app, const struct ms_alert *alert)
{
    if (app->injected)
        app->dependencies.publish_alert(app->dependencies.userdata, alert);
    else
        ms_api_publish_alert(app->api, alert);
}

static bool
queue_push(struct ms_app *app, const struct ms_alert *alert)
{
    size_t slot;
    if (app->queue_length == MS_APP_QUEUE_CAPACITY) {
        apply_health(app, MS_HEALTH_ALERT_DROPPED, 1);
        return false;
    }
    slot = (app->queue_head + app->queue_length) % MS_APP_QUEUE_CAPACITY;
    app->queue[slot] = *alert;
    ++app->queue_length;
    return true;
}

static void
drain_queue(struct ms_app *app)
{
    struct ms_error error = {0};
    bool had_items = app->queue_length > 0;
    while (app->queue_length > 0) {
        struct ms_alert *alert = &app->queue[app->queue_head];
        if (!store_insert(app, alert, &error)) {
            if (app->health.storage_available)
                apply_health(app, MS_HEALTH_STORE_FAILED, 1);
            return;
        }
        app->queue_head = (app->queue_head + 1) % MS_APP_QUEUE_CAPACITY;
        --app->queue_length;
    }
    if (had_items && !app->health.storage_available)
        apply_health(app, MS_HEALTH_STORE_RECOVERED, 1);
}

void
ms_app_observe(struct ms_app *app, const struct ms_observation *observation)
{
    struct ms_alert alert;
    struct ms_error error = {0};
    uint64_t pressure;

    if (app == NULL || observation == NULL || app->stopping)
        return;
    if (ms_policy_ingest(app->policy, observation, &alert) != MS_POLICY_ALERT)
        return;
    pressure = ms_policy_pressure(app->policy);
    if (pressure > app->reported_pressure) {
        apply_health(app, MS_HEALTH_MAP_PRESSURE, pressure - app->reported_pressure);
        app->reported_pressure = pressure;
    }
    if (ms_allowlist_matches(app->allowlist, alert.rule_id, alert.exe))
        return;

    if (app->queue_length > 0) {
        queue_push(app, &alert);
        drain_queue(app);
    } else if (!store_insert(app, &alert, &error)) {
        apply_health(app, MS_HEALTH_STORE_FAILED, 1);
        queue_push(app, &alert);
    }
    publish_alert(app, &alert);
}

void
ms_app_maintain(struct ms_app *app, int64_t now_utc)
{
    struct ms_error error = {0};
    if (app == NULL)
        return;
    drain_queue(app);
    if (now_utc >= app->next_prune_utc) {
        if (!app->injected && app->store == NULL) {
            if (!ms_store_open(app->database_path, &app->store, &error)) {
                app->next_prune_utc = now_utc + 60;
                return;
            }
            ms_api_set_store(app->api, app->store);
            apply_health(app, MS_HEALTH_STORE_RECOVERED, 1);
            drain_queue(app);
        }
        size_t removed = store_prune(app, now_utc - MS_RETENTION_SECONDS, &error);
        if (error.code[0] != '\0') {
            if (app->health.storage_available)
                apply_health(app, MS_HEALTH_STORE_FAILED, 1);
            app->next_prune_utc = now_utc + 60;
        } else {
            if (!app->health.storage_available && app->queue_length == 0)
            apply_health(app, MS_HEALTH_STORE_RECOVERED, 1);
            app->next_prune_utc = now_utc + (removed == 100 ? 1 : 3600);
        }
    }
}

static void
sensor_observation(const struct ms_observation *observation, void *userdata)
{
    ms_app_observe(userdata, observation);
}

static void
peer_connected(pid_t pid, uid_t uid, void *userdata)
{
    (void)userdata;
    g_message("local API client connected: pid=%ld uid=%ld", (long)pid, (long)uid);
}

struct ms_app *
ms_app_new(const struct ms_app_config *config,
           const struct ms_app_dependencies *dependencies,
           struct ms_error *error)
{
    struct ms_app *app;
    struct ms_error store_error = {0};
    const struct ms_api_callbacks api_callbacks = {.peer_connected = peer_connected};

    if (config == NULL || config->allowlist_path == NULL) {
        set_error(error, "config", "an allowlist path is required");
        return NULL;
    }
    if (dependencies != NULL &&
        (dependencies->store_insert == NULL || dependencies->publish_alert == NULL)) {
        set_error(error, "dependencies", "injected storage and alert publishing are required");
        return NULL;
    }
    if (dependencies == NULL && (config->database_path == NULL || config->socket_path == NULL)) {
        set_error(error, "config", "database and socket paths are required");
        return NULL;
    }
    app = g_new0(struct ms_app, 1);
    app->queue = g_new0(struct ms_alert, MS_APP_QUEUE_CAPACITY);
    app->policy = ms_policy_new();
    app->health = (struct ms_health){
        .state = MS_HEALTH_DEGRADED,
        .storage_available = true,
    };
    if (app->policy == NULL ||
        !ms_allowlist_load(config->allowlist_path, &app->allowlist, error)) {
        ms_app_free(app);
        return NULL;
    }
    if (dependencies != NULL) {
        app->dependencies = *dependencies;
        app->injected = true;
        app->health.state = MS_HEALTH_HEALTHY;
        app->health.protected = true;
        return app;
    }
    app->database_path = g_strdup(config->database_path);
    if (!ms_store_open(config->database_path, &app->store, &store_error)) {
        ms_health_apply(&app->health, MS_HEALTH_STORE_FAILED, 1);
        g_warning("alert storage unavailable at startup: %s", store_error.message);
    }
    if (!ms_sensor_open(&app->sensor, sensor_observation, app, error)) {
        ms_app_free(app);
        return NULL;
    }
    app->api = ms_api_new(config->socket_path, app->store, &api_callbacks);
    if (app->api == NULL) {
        set_error(error, "socket", "cannot initialize local API");
        ms_app_free(app);
        return NULL;
    }
    if (error != NULL)
        *error = (struct ms_error){0};
    return app;
}

int
ms_app_run(struct ms_app *app)
{
    struct ms_error error = {0};
    struct ms_sensor_stats stats = {0};

    if (app == NULL || app->injected)
        return 2;
    if (!ms_sensor_attach(app->sensor, &error)) {
        apply_health(app, MS_HEALTH_REQUIRED_PROBE_FAILED, 1);
        g_printerr("memspyd: %s: %s\n", error.code, error.message);
        return 1;
    }
    if (!ms_api_start(app->api, &error)) {
        g_printerr("memspyd: %s: %s\n", error.code, error.message);
        return 1;
    }
    apply_health(app, MS_HEALTH_PROBES_READY, 1);
    while (!app->stopping) {
        if (ms_sensor_poll(app->sensor, 500, &error) < 0) {
            apply_health(app, MS_HEALTH_REQUIRED_PROBE_FAILED, 1);
            g_printerr("memspyd: %s: %s\n", error.code, error.message);
            return 1;
        }
        ms_sensor_stats(app->sensor, &stats);
        if (stats.lost_events > app->reported_lost) {
            apply_health(app, MS_HEALTH_EVENT_LOST, stats.lost_events - app->reported_lost);
            app->reported_lost = stats.lost_events;
        }
        ms_app_maintain(app, time(NULL));
    }
    ms_app_maintain(app, time(NULL));
    return 0;
}

void
ms_app_stop(struct ms_app *app)
{
    if (app != NULL)
        app->stopping = 1;
}

const struct ms_health *
ms_app_health(const struct ms_app *app)
{
    return app == NULL ? NULL : &app->health;
}

void
ms_app_free(struct ms_app *app)
{
    if (app == NULL)
        return;
    ms_api_free(app->api);
    ms_sensor_free(app->sensor);
    ms_store_close(app->store);
    ms_allowlist_free(app->allowlist);
    ms_policy_free(app->policy);
    g_free(app->queue);
    g_free(app->database_path);
    g_free(app);
}
