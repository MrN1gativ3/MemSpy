#ifndef MEMSPY_ALLOWLIST_H
#define MEMSPY_ALLOWLIST_H

#include <stdbool.h>

#include "memspy/protocol.h"

struct ms_allowlist;

bool ms_allowlist_load(const char *path, struct ms_allowlist **out, struct ms_error *error);
bool ms_allowlist_matches(const struct ms_allowlist *allowlist, const char *rule_id,
                          const char *canonical_exe);
void ms_allowlist_free(struct ms_allowlist *allowlist);

#endif
