#ifndef MEMSPY_RESPONSE_CONFIG_H
#define MEMSPY_RESPONSE_CONFIG_H

#include <stdbool.h>
#include <stddef.h>

#include <glib.h>

#include "memspy/protocol.h"
#include "memspy_enforce_shared.h"

bool ms_response_state_load(const char *path, bool *enabled, struct ms_error *error);
bool ms_response_state_store(const char *path, bool enabled, struct ms_error *error);
bool ms_response_allowlist_load(const char *path, GArray **keys, size_t *rejected,
                                struct ms_error *warning);

#endif
