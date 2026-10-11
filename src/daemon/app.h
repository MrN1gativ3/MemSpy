#ifndef FILELESS_APP_H
#define FILELESS_APP_H

#include <signal.h>

#include "fileless/observation.h"
#include "health.h"

#define FL_APP_QUEUE_CAPACITY 1024U
#define FL_RETENTION_SECONDS (30LL * 86400LL)

struct fl_app_config {
    const char *allowlist_path;
    const char *database_path;
    const char *socket_path;
};

struct fl_app_dependencies {
    bool (*store_insert)(void *userdata, struct fl_alert *alert, struct fl_error *error);
    size_t (*store_prune)(void *userdata, int64_t cutoff, size_t batch,
                         struct fl_error *error);
    void (*publish_alert)(void *userdata, const struct fl_alert *alert);
    void (*publish_health)(void *userdata, const struct fl_health *health);
    void *userdata;
};

struct fl_app;

struct fl_app *fl_app_new(const struct fl_app_config *config,
                          const struct fl_app_dependencies *dependencies,
                          struct fl_error *error);
int fl_app_run(struct fl_app *app);
void fl_app_stop(struct fl_app *app);
void fl_app_observe(struct fl_app *app, const struct fl_observation *observation);
void fl_app_maintain(struct fl_app *app, int64_t now_utc);
const struct fl_health *fl_app_health(const struct fl_app *app);
void fl_app_free(struct fl_app *app);

#endif
