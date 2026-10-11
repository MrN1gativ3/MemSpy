#ifndef FILELESS_ALLOWLIST_H
#define FILELESS_ALLOWLIST_H

#include <stdbool.h>

#include "fileless/protocol.h"

struct fl_allowlist;

bool fl_allowlist_load(const char *path, struct fl_allowlist **out, struct fl_error *error);
bool fl_allowlist_matches(const struct fl_allowlist *allowlist, const char *rule_id,
                          const char *canonical_exe);
void fl_allowlist_free(struct fl_allowlist *allowlist);

#endif
