#ifndef MEMSPY_PTRACE_BARRIER_H
#define MEMSPY_PTRACE_BARRIER_H

#include <stdbool.h>

#include <glib.h>

#include "memspy/protocol.h"
#include "memspy_enforce_shared.h"

bool ms_ptrace_barrier_check(const char *proc_root, const GArray *allowlist,
                             struct ms_error *error);

#endif
