#include "indicator.h"

#include <gtk/gtk.h>
#include <libayatana-appindicator/app-indicator.h>
#include <stdio.h>

struct ms_indicator {
    AppIndicator *indicator;
    GtkWidget *menu;
    GtkWidget *status;
    GtkWidget *latest;
    void (*open)(void *);
    void (*quit)(void *);
    void *userdata;
};

static void
open_activated(GtkMenuItem *item, gpointer userdata)
{
    struct ms_indicator *indicator = userdata;
    (void)item;
    indicator->open(indicator->userdata);
}

static void
quit_activated(GtkMenuItem *item, gpointer userdata)
{
    struct ms_indicator *indicator = userdata;
    (void)item;
    indicator->quit(indicator->userdata);
}

struct ms_indicator *
ms_indicator_new(void (*open)(void *), void (*quit)(void *), void *userdata)
{
    struct ms_indicator *indicator;
    GtkWidget *open_item;
    GtkWidget *quit_item;

    if (open == NULL || quit == NULL)
        return NULL;
    indicator = g_new0(struct ms_indicator, 1);
    indicator->open = open;
    indicator->quit = quit;
    indicator->userdata = userdata;
    indicator->indicator = g_object_new(APP_INDICATOR_TYPE,
                                         "id", "memspy",
                                         "icon-name", "memspy-offline-symbolic",
                                         "category", APP_INDICATOR_CATEGORY_SYSTEM_SERVICES,
                                         NULL);
    if (indicator->indicator == NULL) {
        g_free(indicator);
        return NULL;
    }
    indicator->menu = gtk_menu_new();
    indicator->status = gtk_menu_item_new_with_label("Detector unavailable");
    indicator->latest = gtk_menu_item_new_with_label("No alerts");
    open_item = gtk_menu_item_new_with_label("Open alerts");
    quit_item = gtk_menu_item_new_with_label("Quit UI");
    gtk_widget_set_sensitive(indicator->status, false);
    gtk_widget_set_sensitive(indicator->latest, false);
    gtk_menu_shell_append(GTK_MENU_SHELL(indicator->menu), indicator->status);
    gtk_menu_shell_append(GTK_MENU_SHELL(indicator->menu), indicator->latest);
    gtk_menu_shell_append(GTK_MENU_SHELL(indicator->menu), gtk_separator_menu_item_new());
    gtk_menu_shell_append(GTK_MENU_SHELL(indicator->menu), open_item);
    gtk_menu_shell_append(GTK_MENU_SHELL(indicator->menu), quit_item);
    g_signal_connect(open_item, "activate", G_CALLBACK(open_activated), indicator);
    g_signal_connect(quit_item, "activate", G_CALLBACK(quit_activated), indicator);
    gtk_widget_show_all(indicator->menu);
    app_indicator_set_menu(indicator->indicator, GTK_MENU(indicator->menu));
    app_indicator_set_status(indicator->indicator, APP_INDICATOR_STATUS_ACTIVE);
    app_indicator_set_title(indicator->indicator, "MemSpy");
    return indicator;
}

void
ms_indicator_update(struct ms_indicator *indicator, enum ms_indicator_state state,
                    const struct ms_alert *latest)
{
    static const char *icons[] = {
        "memspy-offline-symbolic", "memspy-healthy-symbolic",
        "memspy-medium-symbolic", "memspy-high-symbolic",
    };
    static const char *labels[] = {
        "Detector unavailable", "Monitoring active",
        "Unread medium alert", "Unread high alert",
    };
    char summary[160];

    if (indicator == NULL || state < MS_INDICATOR_OFFLINE || state > MS_INDICATOR_HIGH)
        return;
    app_indicator_set_icon_full(indicator->indicator, icons[state], labels[state]);
    gtk_menu_item_set_label(GTK_MENU_ITEM(indicator->status), labels[state]);
    if (latest == NULL) {
        gtk_menu_item_set_label(GTK_MENU_ITEM(indicator->latest), "No alerts");
    } else {
        snprintf(summary, sizeof summary, "Latest: %s · %s",
                 latest->severity == MS_SEVERITY_HIGH ? "High" : "Medium",
                 latest->rule_id);
        gtk_menu_item_set_label(GTK_MENU_ITEM(indicator->latest), summary);
    }
}

void
ms_indicator_free(struct ms_indicator *indicator)
{
    if (indicator == NULL)
        return;
    app_indicator_set_status(indicator->indicator, APP_INDICATOR_STATUS_PASSIVE);
    gtk_widget_destroy(indicator->menu);
    g_object_unref(indicator->indicator);
    g_free(indicator);
}
