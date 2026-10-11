#ifndef FILELESS_CLIENT_H
#define FILELESS_CLIENT_H

#include <stdbool.h>

#include "fileless/health.h"
#include "store.h"

struct fl_client;

bool fl_client_connect(const char *path, struct fl_client **out, struct fl_error *error);
bool fl_client_connect_fd(int connected_fd, struct fl_client **out, struct fl_error *error);
bool fl_client_get_status(struct fl_client *client, struct fl_health *health,
                          struct fl_error *error);
bool fl_client_list_alerts(struct fl_client *client, int64_t before_id,
                           enum fl_severity minimum, size_t limit,
                           struct fl_alert_page *page, struct fl_error *error);
bool fl_client_subscribe(struct fl_client *client,
                         void (*on_alert)(const struct fl_alert *, void *),
                         void (*on_health)(const struct fl_health *, void *),
                         void *userdata, struct fl_error *error);
void fl_client_interrupt(struct fl_client *client);
void fl_client_wait(struct fl_client *client);
void fl_client_close(struct fl_client *client);

#endif
