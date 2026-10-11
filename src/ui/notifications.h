#ifndef MEMSPY_UI_NOTIFICATIONS_H
#define MEMSPY_UI_NOTIFICATIONS_H

#include "memspy/alert.h"

bool ms_notifications_init(void);
bool ms_notifications_show(const struct ms_alert *alert,
                           void (*open_alert)(int64_t alert_id, void *userdata),
                           void *userdata);
void ms_notifications_uninit(void);

#endif
