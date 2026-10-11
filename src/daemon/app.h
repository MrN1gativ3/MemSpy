#ifndef MEMSPY_APP_H
#define MEMSPY_APP_H

#include <signal.h>

#include "memspy/observation.h"
#include "health.h"

#define MS_APP_QUEUE_CAPACITY 1024U
#define MS_RETENTION_SECONDS (30LL * 86400LL)

struct ms_app_config {
    const char *allowlist_path;
    const char *database_path;
    const char *socket_path;
};

struct ms_app_dependencies {
    bool (*store_insert)(void *userdata, struct ms_alert *alert, struct ms_error *error);
    size_t (*store_prune)(void *userdata, int64_t cutoff, size_t batch,
                         struct ms_error *error);
    void (*publish_alert)(void *userdata, const struct ms_alert *alert);
    void (*publish_health)(void *userdata, const struct ms_health *health);
    void *userdata;
};

struct ms_app;

struct ms_app *ms_app_new(const struct ms_app_config *config,
                          const struct ms_app_dependencies *dependencies,
                          struct ms_error *error);
int ms_app_run(struct ms_app *app);
void ms_app_stop(struct ms_app *app);
void ms_app_observe(struct ms_app *app, const struct ms_observation *observation);
void ms_app_maintain(struct ms_app *app, int64_t now_utc);
const struct ms_health *ms_app_health(const struct ms_app *app);
void ms_app_free(struct ms_app *app);

#endif
