#include "app.h"

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "allowlist.h"
#include "api.h"
#include "authorizer.h"
#include "enforcer.h"
#include "journal.h"
#include "policy.h"
#include "ptrace_barrier.h"
#include "response_config.h"
#include "sensor.h"
#include "store.h"

struct ms_app {
    struct ms_policy *policy;
    struct ms_allowlist *allowlist;
    struct ms_store *store;
    struct ms_api *api;
    struct ms_sensor *sensor;
    struct ms_enforcer *enforcer;
    struct ms_authorizer *authorizer;
    char *database_path;
    char *response_state_path;
    GArray *response_allowlist;
    struct ms_app_dependencies dependencies;
    struct ms_health health;
    struct ms_alert *queue;
    size_t queue_head;
    size_t queue_length;
    uint64_t reported_pressure;
    uint64_t reported_lost;
    uint64_t reported_incomplete;
    int64_t last_journal_warning;
    int64_t next_prune_utc;
    volatile sig_atomic_t stopping;
    bool injected;
    bool response_configured;
    GMutex response_lock;
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

static bool
response_state_load(struct ms_app *app, const char *path, bool *enabled,
                    struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.response_state_load(app->dependencies.userdata, path,
                                                     enabled, error);
    return ms_response_state_load(path, enabled, error);
}

static bool
response_state_store(struct ms_app *app, bool enabled, struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.response_state_store(app->dependencies.userdata,
                                                      app->response_state_path,
                                                      enabled, error);
    return ms_response_state_store(app->response_state_path, enabled, error);
}

static bool
response_allowlist_load(struct ms_app *app, const char *path, GArray **keys,
                        size_t *rejected, struct ms_error *warning)
{
    if (app->injected)
        return app->dependencies.response_allowlist_load(app->dependencies.userdata,
                                                         path, keys, rejected, warning);
    return ms_response_allowlist_load(path, keys, rejected, warning);
}

static bool
response_attach(struct ms_app *app, const GArray *keys, bool requested,
                struct ms_enforcer_status *status, struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.response_attach(app->dependencies.userdata, keys,
                                                 requested, status, error);
    if (!ms_enforcer_attach(app->enforcer, keys, requested, error))
        return false;
    ms_enforcer_status(app->enforcer, status);
    return true;
}

static bool
response_set_enabled(struct ms_app *app, bool enabled, struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.response_set_enabled(app->dependencies.userdata,
                                                      enabled, error);
    return ms_enforcer_set_enabled(app->enforcer, enabled, error);
}

static bool
response_barrier_check(struct ms_app *app, struct ms_error *error)
{
    if (app->injected)
        return app->dependencies.response_barrier_check == NULL ||
               app->dependencies.response_barrier_check(app->dependencies.userdata,
                                                         app->response_allowlist, error);
    return ms_ptrace_barrier_check("/proc", app->response_allowlist, error);
}

static int
response_poll(struct ms_app *app, int timeout_ms, struct ms_enforcer_status *status,
              struct ms_error *error)
{
    int result;

    if (app->injected)
        return app->dependencies.response_poll(app->dependencies.userdata, timeout_ms,
                                               status, error);
    result = ms_enforcer_poll(app->enforcer, timeout_ms, error);
    ms_enforcer_status(app->enforcer, status);
    return result;
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

static void
publish_journal(struct ms_app *app, const struct ms_alert *alert)
{
    struct ms_error error = {0};
    bool success;
    int64_t now;

    if (app->injected)
        success = app->dependencies.journal_alert == NULL ||
            app->dependencies.journal_alert(app->dependencies.userdata, alert, &error);
    else
        success = ms_journal_alert(alert, &error);
    if (success)
        return;
    apply_health(app, MS_HEALTH_JOURNAL_FAILED, 1);
    now = time(NULL);
    if (app->last_journal_warning == 0 || now - app->last_journal_warning >= 60) {
        g_warning("structured journal output failed: %s", error.message);
        app->last_journal_warning = now;
    }
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

static void drain_queue(struct ms_app *app);

static void
accept_alert(struct ms_app *app, const struct ms_alert *alert)
{
    struct ms_alert stored = *alert;
    struct ms_error error = {0};

    if (app->queue_length > 0) {
        queue_push(app, &stored);
        drain_queue(app);
    } else if (!store_insert(app, &stored, &error)) {
        apply_health(app, MS_HEALTH_STORE_FAILED, 1);
        queue_push(app, &stored);
    } else
        publish_journal(app, &stored);
    publish_alert(app, &stored);
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
        publish_journal(app, alert);
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

    (void)error;
    accept_alert(app, &alert);
}

void
ms_app_blocked(struct ms_app *app, const struct ms_alert *alert)
{
    if (app != NULL && alert != NULL && !app->stopping)
        accept_alert(app, alert);
}

static void
blocked_alert(const struct ms_alert *alert, void *userdata)
{
    ms_app_blocked(userdata, alert);
}

static void
degrade_response(struct ms_app *app, const char *reason)
{
    if (app->health.state != MS_HEALTH_FAILED)
        app->health.state = MS_HEALTH_DEGRADED;
    g_strlcpy(app->health.response_reason, reason, sizeof app->health.response_reason);
}

static void
initialize_response(struct ms_app *app, const struct ms_app_config *config)
{
    g_autoptr(GArray) keys = NULL;
    struct ms_enforcer_status status = {0};
    struct ms_error state_error = {0};
    struct ms_error allowlist_warning = {0};
    struct ms_error operation_error = {0};
    bool requested = false;
    size_t rejected = 0;

    app->response_state_path = g_strdup(config->response_state_path);
    if (!response_state_load(app, config->response_state_path, &requested, &state_error)) {
        requested = false;
        degrade_response(app, state_error.message);
    }
    if (!response_allowlist_load(app, config->response_allowlist_path, &keys, &rejected,
                                 &allowlist_warning)) {
        keys = g_array_new(false, false, sizeof(struct ms_allowlist_key));
        degrade_response(app, allowlist_warning.message);
    } else if (rejected > 0) {
        degrade_response(app, allowlist_warning.message);
    }
    if (!app->injected &&
        !ms_enforcer_open(&app->enforcer, config->response_pin_dir, blocked_alert, app,
                          &operation_error)) {
        status.supported = false;
        g_strlcpy(status.reason, operation_error.message, sizeof status.reason);
    } else if (!response_attach(app, keys, false, &status, &operation_error)) {
        status.supported = false;
        g_strlcpy(status.reason, operation_error.message, sizeof status.reason);
    }
    app->health.response_requested = requested;
    app->health.response_supported = status.supported;
    app->health.response_active = false;
    app->health.blocked_execs = status.denied_execs;
    app->health.blocked_operations = status.denied;
    app->health.lost_block_events = status.lost_events;
    app->response_allowlist = g_array_ref(keys);
    if (requested && status.supported) {
        if (!response_set_enabled(app, true, &operation_error) ||
            !response_barrier_check(app, &operation_error)) {
            struct ms_error ignored = {0};

            response_set_enabled(app, false, &ignored);
            response_state_store(app, false, &ignored);
            app->health.response_requested = false;
            g_strlcpy(app->health.response_reason, operation_error.message,
                      sizeof app->health.response_reason);
        } else {
            app->health.response_active = true;
        }
    }
    if (app->health.response_reason[0] == '\0')
        g_strlcpy(app->health.response_reason, status.reason,
                  sizeof app->health.response_reason);
}

void
ms_app_maintain(struct ms_app *app, int64_t now_utc)
{
    struct ms_error error = {0};
    if (app == NULL)
        return;
    if (app->response_configured) {
        struct ms_enforcer_status status = {0};

        g_mutex_lock(&app->response_lock);
        if (response_poll(app, 0, &status, &error) >= 0) {
            bool changed = app->health.response_supported != status.supported ||
                           app->health.response_active != status.enabled ||
                           app->health.blocked_execs != status.denied_execs ||
                           app->health.blocked_operations != status.denied ||
                           app->health.lost_block_events != status.lost_events;
            app->health.response_supported = status.supported;
            app->health.response_active = status.supported && status.enabled;
            app->health.blocked_execs = status.denied_execs;
            app->health.blocked_operations = status.denied;
            app->health.lost_block_events = status.lost_events;
            if (status.reason[0] != '\0')
                g_strlcpy(app->health.response_reason, status.reason,
                          sizeof app->health.response_reason);
            if (changed)
                publish_health(app);
        }
        g_mutex_unlock(&app->response_lock);
    }
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

static bool
authorize_response_request(const struct ms_peer_identity *peer, void *userdata,
                           struct ms_error *error)
{
    struct ms_app *app = userdata;
    return ms_authorizer_check(app->authorizer, peer, error);
}

static bool
set_response_request(const struct ms_peer_identity *peer, bool enabled, void *userdata,
                     struct ms_error *error)
{
    (void)peer;
    return ms_app_set_response(userdata, enabled, error);
}

struct ms_app *
ms_app_new(const struct ms_app_config *config,
           const struct ms_app_dependencies *dependencies,
           struct ms_error *error)
{
    struct ms_app *app;
    struct ms_error store_error = {0};
    struct ms_api_callbacks api_callbacks = {0};

    bool response_configured;

    if (config == NULL || config->allowlist_path == NULL) {
        set_error(error, "config", "an allowlist path is required");
        return NULL;
    }
    if (dependencies != NULL &&
        (dependencies->store_insert == NULL || dependencies->publish_alert == NULL)) {
        set_error(error, "dependencies", "injected storage and alert publishing are required");
        return NULL;
    }
    response_configured = config->response_state_path != NULL ||
                          config->response_allowlist_path != NULL ||
                          config->response_pin_dir != NULL;
    if (response_configured && (config->response_state_path == NULL ||
        config->response_allowlist_path == NULL || config->response_pin_dir == NULL)) {
        set_error(error, "config", "all response paths are required together");
        return NULL;
    }
    if (response_configured && dependencies != NULL &&
        (dependencies->response_state_load == NULL ||
         dependencies->response_state_store == NULL ||
         dependencies->response_allowlist_load == NULL ||
         dependencies->response_attach == NULL ||
         dependencies->response_set_enabled == NULL ||
         dependencies->response_poll == NULL)) {
        set_error(error, "dependencies", "injected response operations are required");
        return NULL;
    }
    if (dependencies == NULL && (config->database_path == NULL || config->socket_path == NULL)) {
        set_error(error, "config", "database and socket paths are required");
        return NULL;
    }
    app = g_new0(struct ms_app, 1);
    g_mutex_init(&app->response_lock);
    app->queue = g_new0(struct ms_alert, MS_APP_QUEUE_CAPACITY);
    app->policy = ms_policy_new();
    app->health = (struct ms_health){
        .state = MS_HEALTH_DEGRADED,
        .storage_available = true,
    };
    app->response_configured = response_configured;
    if (dependencies != NULL) {
        app->dependencies = *dependencies;
        app->injected = true;
        app->health.state = MS_HEALTH_HEALTHY;
        app->health.protected = true;
    }
    if (app->policy == NULL ||
        !ms_allowlist_load(config->allowlist_path, &app->allowlist, error)) {
        ms_app_free(app);
        return NULL;
    }
    if (response_configured)
        initialize_response(app, config);
    if (dependencies != NULL) {
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
    app->authorizer = ms_authorizer_new();
    api_callbacks = (struct ms_api_callbacks){
        .peer_connected = peer_connected,
        .authorize_response = authorize_response_request,
        .set_response = set_response_request,
        .userdata = app,
    };
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

bool
ms_app_set_response(struct ms_app *app, bool enabled, struct ms_error *error)
{
    bool previous;
    struct ms_error rollback_error = {0};

    if (app == NULL || !app->response_configured || !app->health.response_supported) {
        set_error(error, "response_unavailable", "response mode is unavailable");
        return false;
    }
    g_mutex_lock(&app->response_lock);
    previous = app->health.response_active;
    if (!response_set_enabled(app, enabled, error)) {
        g_mutex_unlock(&app->response_lock);
        return false;
    }
    if (enabled && !response_barrier_check(app, error)) {
        if (!response_set_enabled(app, previous, &rollback_error))
            degrade_response(app, "response state rollback failed");
        app->health.response_active = previous;
        g_strlcpy(app->health.response_reason, error->message,
                  sizeof app->health.response_reason);
        publish_health(app);
        g_mutex_unlock(&app->response_lock);
        return false;
    }
    if (!response_state_store(app, enabled, error)) {
        if (!response_set_enabled(app, previous, &rollback_error))
            degrade_response(app, "response state rollback failed");
        app->health.response_active = previous;
        publish_health(app);
        g_mutex_unlock(&app->response_lock);
        return false;
    }
    app->health.response_requested = enabled;
    app->health.response_active = enabled;
    app->health.response_reason[0] = '\0';
    publish_health(app);
    g_mutex_unlock(&app->response_lock);
    if (error != NULL)
        *error = (struct ms_error){0};
    return true;
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
        if (stats.incomplete_observations > app->reported_incomplete) {
            apply_health(app, MS_HEALTH_OBSERVATION_INCOMPLETE,
                         stats.incomplete_observations - app->reported_incomplete);
            app->reported_incomplete = stats.incomplete_observations;
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
    ms_authorizer_free(app->authorizer);
    g_clear_pointer(&app->response_allowlist, g_array_unref);
    ms_enforcer_free(app->enforcer);
    ms_sensor_free(app->sensor);
    ms_store_close(app->store);
    ms_allowlist_free(app->allowlist);
    ms_policy_free(app->policy);
    g_free(app->queue);
    g_free(app->database_path);
    g_free(app->response_state_path);
    g_mutex_clear(&app->response_lock);
    g_free(app);
}
