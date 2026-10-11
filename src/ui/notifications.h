#ifndef FILELESS_UI_NOTIFICATIONS_H
#define FILELESS_UI_NOTIFICATIONS_H

#include "fileless/alert.h"

bool fl_notifications_init(void);
bool fl_notifications_show(const struct fl_alert *alert,
                           void (*open_alert)(int64_t alert_id, void *userdata),
                           void *userdata);
void fl_notifications_uninit(void);

#endif
