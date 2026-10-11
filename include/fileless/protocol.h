#ifndef FILELESS_PROTOCOL_H
#define FILELESS_PROTOCOL_H

#include <stddef.h>

#define FL_PROTOCOL_VERSION 1
#define FL_MAX_MESSAGE_BYTES 65536U
#define FL_MAX_CMDLINE_BYTES 4096U
#define FL_CORRELATION_WINDOW_NS 30000000000ULL

struct fl_error {
    char code[32];
    char message[256];
};

#endif
