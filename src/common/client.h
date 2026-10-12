#ifndef MEMSPY_CLIENT_H
#define MEMSPY_CLIENT_H

#include <stdbool.h>

#include "memspy/health.h"
#include "store.h"

struct ms_client;

bool ms_client_connect(const char *path, struct ms_client **out, struct ms_error *error);
bool ms_client_connect_fd(int connected_fd, struct ms_client **out, struct ms_error *error);
bool ms_client_get_status(struct ms_client *client, struct ms_health *health,
                          struct ms_error *error);
bool ms_client_set_response(struct ms_client *client, bool enabled,
                            struct ms_health *confirmed, struct ms_error *error);
bool ms_client_list_alerts(struct ms_client *client, int64_t before_id,
                           enum ms_severity minimum, size_t limit,
                           struct ms_alert_page *page, struct ms_error *error);
bool ms_client_get_alert(struct ms_client *client, int64_t id,
                         struct ms_alert *alert, struct ms_error *error);
bool ms_client_subscribe(struct ms_client *client,
                         void (*on_alert)(const struct ms_alert *, void *),
                         void (*on_health)(const struct ms_health *, void *),
                         void *userdata, struct ms_error *error);
void ms_client_interrupt(struct ms_client *client);
void ms_client_wait(struct ms_client *client);
void ms_client_close(struct ms_client *client);

#endif
