#include "notifications.h"

#include <libnotify/notify.h>
#include <stdio.h>

/* Notification callbacks retain only an alert ID, not a pointer into the UI list. */
struct notification_action {
    int64_t alert_id;
    void (*open_alert)(int64_t, void *);
    void *userdata;
};

static void
notification_open(NotifyNotification *notification, char *action, gpointer userdata)
{
    const struct notification_action *context = userdata;
    (void)notification;
    (void)action;
    context->open_alert(context->alert_id, context->userdata);
}

bool
ms_notifications_init(void)
{
    return notify_init("MemSpy");
}

bool
ms_notifications_show(const struct ms_alert *alert,
                      void (*open_alert)(int64_t alert_id, void *userdata),
                      void *userdata)
{
    NotifyNotification *notification;
    struct notification_action *context;
    GError *error = NULL;
    char body[320];
    bool shown;

    if (alert == NULL || alert->severity != MS_SEVERITY_HIGH || open_alert == NULL)
        return false;
    snprintf(body, sizeof body, "%s\n%s", alert->rule_id, alert->explanation);
    notification = notify_notification_new("High-severity fileless malware alert",
                                           body, "memspy-high-symbolic");
    notify_notification_set_urgency(notification, NOTIFY_URGENCY_CRITICAL);
    context = g_new0(struct notification_action, 1);
    context->alert_id = alert->id;
    context->open_alert = open_alert;
    context->userdata = userdata;
    notify_notification_add_action(notification, "open-alert", "Open alert",
                                   notification_open, context, g_free);
    shown = notify_notification_show(notification, &error);
    if (error != NULL)
        g_error_free(error);
    g_object_unref(notification);
    return shown;
}

void
ms_notifications_uninit(void)
{
    if (notify_is_initted())
        notify_uninit();
}
