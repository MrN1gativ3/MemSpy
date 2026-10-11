#ifndef FILELESS_UI_INDICATOR_H
#define FILELESS_UI_INDICATOR_H

#include "state.h"

struct fl_indicator;

struct fl_indicator *fl_indicator_new(void (*open)(void *), void (*quit)(void *),
                                      void *userdata);
void fl_indicator_update(struct fl_indicator *indicator,
                         enum fl_indicator_state state,
                         const struct fl_alert *latest);
void fl_indicator_free(struct fl_indicator *indicator);

#endif
