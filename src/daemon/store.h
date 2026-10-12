#ifndef MEMSPY_STORE_H
#define MEMSPY_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "memspy/alert.h"

struct ms_alert_page {
    struct ms_alert *items;
    size_t length;
    int64_t next_before_id;
};

struct ms_store;

bool ms_store_open(const char *path, struct ms_store **out, struct ms_error *error);
void ms_store_close(struct ms_store *store);
bool ms_store_insert(struct ms_store *store, struct ms_alert *alert, struct ms_error *error);
bool ms_store_get(struct ms_store *store, int64_t id, struct ms_alert *alert,
                  struct ms_error *error);
bool ms_store_list(struct ms_store *store, int64_t before_id, enum ms_severity minimum,
                   size_t limit, struct ms_alert_page *page, struct ms_error *error);
void ms_alert_page_clear(struct ms_alert_page *page);
size_t ms_store_prune_before(struct ms_store *store, int64_t utc_cutoff, size_t batch,
                             struct ms_error *error);

#endif
