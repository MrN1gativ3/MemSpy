#ifndef MEMSPY_AUTHORIZER_H
#define MEMSPY_AUTHORIZER_H

#include <gio/gio.h>
#include <stdbool.h>

#include "memspy/protocol.h"

struct ms_authorizer;

struct ms_authorizer *ms_authorizer_new(void);
bool ms_peer_identity_read(pid_t pid, uid_t uid, struct ms_peer_identity *identity,
                           struct ms_error *error);
bool ms_authorizer_check(struct ms_authorizer *authorizer,
                         const struct ms_peer_identity *peer,
                         struct ms_error *error);
bool ms_authorizer_parse_reply(GVariant *reply, struct ms_error *error);
void ms_authorizer_free(struct ms_authorizer *authorizer);

#endif
