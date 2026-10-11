#ifndef FILELESS_API_H
#define FILELESS_API_H

#include <stdbool.h>
#include <sys/types.h>

#include "fileless/health.h"
#include "store.h"

struct fl_api_callbacks {
    void (*peer_connected)(pid_t pid, uid_t uid, void *userdata);
    void *userdata;
};

struct fl_api;

struct fl_api *fl_api_new(const char *socket_path, struct fl_store *store,
                          const struct fl_api_callbacks *callbacks);
bool fl_api_start(struct fl_api *api, struct fl_error *error);
void fl_api_set_store(struct fl_api *api, struct fl_store *store);
bool fl_api_accept_fd(struct fl_api *api, int connected_fd);
void fl_api_publish_alert(struct fl_api *api, const struct fl_alert *alert);
void fl_api_publish_health(struct fl_api *api, const struct fl_health *health);
void fl_api_free(struct fl_api *api);

#endif
