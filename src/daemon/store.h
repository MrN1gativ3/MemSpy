#ifndef FILELESS_STORE_H
#define FILELESS_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fileless/alert.h"

struct fl_alert_page {
    struct fl_alert *items;
    size_t length;
    int64_t next_before_id;
};

struct fl_store;

bool fl_store_open(const char *path, struct fl_store **out, struct fl_error *error);
void fl_store_close(struct fl_store *store);
bool fl_store_insert(struct fl_store *store, struct fl_alert *alert, struct fl_error *error);
bool fl_store_list(struct fl_store *store, int64_t before_id, enum fl_severity minimum,
                   size_t limit, struct fl_alert_page *page, struct fl_error *error);
void fl_alert_page_clear(struct fl_alert_page *page);
size_t fl_store_prune_before(struct fl_store *store, int64_t utc_cutoff, size_t batch,
                             struct fl_error *error);

#endif
