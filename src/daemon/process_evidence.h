#ifndef MEMSPY_PROCESS_EVIDENCE_H
#define MEMSPY_PROCESS_EVIDENCE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

bool ms_process_evidence_read(pid_t pid, char *comm, size_t comm_capacity,
                              char *exe, size_t exe_capacity,
                              char *sha256, size_t sha256_capacity);

#endif
