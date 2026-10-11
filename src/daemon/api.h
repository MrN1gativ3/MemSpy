#ifndef MEMSPY_API_H
#define MEMSPY_API_H

#include <stdbool.h>
#include <sys/types.h>

#include "memspy/health.h"
#include "store.h"

struct ms_api_callbacks {
    void (*peer_connected)(pid_t pid, uid_t uid, void *userdata);
    void *userdata;
};

struct ms_api;

struct ms_api *ms_api_new(const char *socket_path, struct ms_store *store,
                          const struct ms_api_callbacks *callbacks);
bool ms_api_start(struct ms_api *api, struct ms_error *error);
void ms_api_set_store(struct ms_api *api, struct ms_store *store);
bool ms_api_accept_fd(struct ms_api *api, int connected_fd);
void ms_api_publish_alert(struct ms_api *api, const struct ms_alert *alert);
void ms_api_publish_health(struct ms_api *api, const struct ms_health *health);
void ms_api_free(struct ms_api *api);

#endif
