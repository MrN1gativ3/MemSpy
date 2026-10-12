#ifndef MEMSPY_PROTOCOL_H
#define MEMSPY_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define MS_PROTOCOL_VERSION 3
#define MS_MAX_MESSAGE_BYTES 65536U
#define MS_MAX_CMDLINE_BYTES 4096U
#define MS_CORRELATION_WINDOW_NS 30000000000ULL

struct ms_error {
    char code[32];
    char message[256];
};

struct ms_peer_identity {
    pid_t pid;
    uid_t uid;
    uint64_t start_time;
};

#endif
