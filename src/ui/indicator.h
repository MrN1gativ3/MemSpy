#ifndef MEMSPY_UI_INDICATOR_H
#define MEMSPY_UI_INDICATOR_H

#include "state.h"

struct ms_indicator;

struct ms_indicator *ms_indicator_new(void (*open)(void *), void (*quit)(void *),
                                      void *userdata);
void ms_indicator_update(struct ms_indicator *indicator,
                         enum ms_indicator_state state,
                         const struct ms_alert *latest);
void ms_indicator_free(struct ms_indicator *indicator);

#endif
