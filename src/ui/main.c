#include <gtk/gtk.h>
#include <signal.h>
#include <string.h>

#include "client.h"
#include "indicator.h"
#include "notifications.h"
#include "state.h"
#include "window.h"

#define MEMSPY_UI_VERSION "0.1.0"
#define MEMSPY_SOCKET_PATH "/run/memspy/memspy.sock"
#define MS_UI_MAX_HISTORY 10000U

struct ui_app {
    GtkApplication *application;
    struct ms_window *window;
    struct ms_indicator *indicator;
    struct ms_ui_state state;
    struct ms_alert latest;
    bool have_latest;
    bool background;
    gint stopping;
    bool notifications_ready;
    char *state_path;
    GThread *connection_thread;
    GThread *response_thread;
    GMutex mutex;
    GCond wake;
    struct ms_client *client;
    struct ms_client *response_client;
    guint response_source;
    int64_t known_id;
};

struct snapshot {
    struct ui_app *ui;
    struct ms_health health;
    GArray *alerts;
};

struct alert_event {
    struct ui_app *ui;
    struct ms_alert alert;
};

struct health_event {
    struct ui_app *ui;
    struct ms_health health;
};

struct response_request {
    struct ui_app *ui;
    bool enabled;
    bool success;
    struct ms_health health;
    struct ms_error error;
};

static void
save_state(struct ui_app *ui)
{
    struct ms_error error = {0};
    if (!ms_ui_state_save(&ui->state, ui->state_path, &error))
        g_warning("cannot save UI state: %s", error.message);
}

static void
update_indicator(struct ui_app *ui)
{
    if (ui->indicator != NULL)
        ms_indicator_update(ui->indicator, ms_ui_state_indicator(&ui->state),
                            ui->have_latest ? &ui->latest : NULL);
}

static void
open_window(void *userdata)
{
    struct ui_app *ui = userdata;
    ms_window_present(ui->window);
    ms_ui_state_mark_visible_read(&ui->state);
    save_state(ui);
    update_indicator(ui);
}

static void
quit_ui(void *userdata)
{
    struct ui_app *ui = userdata;
    g_application_quit(G_APPLICATION(ui->application));
}

static void
open_alert(int64_t alert_id, void *userdata)
{
    struct ui_app *ui = userdata;
    open_window(ui);
    ms_window_select_alert(ui->window, alert_id);
}

static gboolean
apply_alert(gpointer userdata)
{
    struct alert_event *event = userdata;
    struct ui_app *ui = event->ui;
    bool is_new;

    if (g_atomic_int_get(&ui->stopping)) {
        g_free(event);
        return G_SOURCE_REMOVE;
    }
    is_new = ms_window_add_alert(ui->window, &event->alert) &&
             ms_ui_state_apply_alert(&ui->state, &event->alert);
    if (is_new) {
        ui->latest = event->alert;
        ui->have_latest = true;
        g_mutex_lock(&ui->mutex);
        if (event->alert.id > ui->known_id)
            ui->known_id = event->alert.id;
        g_mutex_unlock(&ui->mutex);
        if (ui->notifications_ready && ms_ui_state_should_notify(&ui->state, &event->alert)) {
            ms_notifications_show(&event->alert, open_alert, ui);
            ms_ui_state_mark_alert_notified(&ui->state, &event->alert);
            save_state(ui);
        }
    }
    update_indicator(ui);
    g_free(event);
    return G_SOURCE_REMOVE;
}

static gboolean
apply_health(gpointer userdata)
{
    struct health_event *event = userdata;
    if (!g_atomic_int_get(&event->ui->stopping)) {
        ms_ui_state_apply_health(&event->ui->state, &event->health);
        ms_window_set_health(event->ui->window, &event->health);
        update_indicator(event->ui);
    }
    g_free(event);
    return G_SOURCE_REMOVE;
}

static gboolean
apply_snapshot(gpointer userdata)
{
    /* History and health arrive from the socket worker, which must not touch
     * GTK widgets. Apply this snapshot on the main loop, then let the live
     * subscription deliver newer events through the same handoff pattern. */
    struct snapshot *snapshot = userdata;
    struct ui_app *ui = snapshot->ui;
    if (!g_atomic_int_get(&ui->stopping)) {
        ms_ui_state_apply_health(&ui->state, &snapshot->health);
        ms_window_set_health(ui->window, &snapshot->health);
        /* The API pages history newest first. Apply it oldest first so the
         * last-seen ID advances in order and reconnects do not count old
         * alerts as new notifications. */
        for (guint index = snapshot->alerts->len; index > 0; --index) {
            struct ms_alert *alert = &g_array_index(snapshot->alerts, struct ms_alert, index - 1U);
            if (ms_window_add_alert(ui->window, alert) &&
                ms_ui_state_apply_alert(&ui->state, alert)) {
                ui->latest = *alert;
                ui->have_latest = true;
            }
        }
        g_mutex_lock(&ui->mutex);
        ui->known_id = ui->state.last_alert_id;
        g_mutex_unlock(&ui->mutex);
        update_indicator(ui);
    }
    g_array_free(snapshot->alerts, true);
    g_free(snapshot);
    return G_SOURCE_REMOVE;
}

static gboolean
apply_disconnected(gpointer userdata)
{
    struct ui_app *ui = userdata;
    if (!g_atomic_int_get(&ui->stopping)) {
        ms_ui_state_disconnect(&ui->state);
        ms_window_set_offline(ui->window, "Detector unavailable",
                              "MemSpy will reconnect automatically");
        update_indicator(ui);
    }
    return G_SOURCE_REMOVE;
}

static const char *
response_error_message(const struct ms_error *error)
{
    if (strcmp(error->code, "authorization_cancelled") == 0)
        return "Administrator authentication was cancelled";
    if (strcmp(error->code, "authorization_denied") == 0)
        return "Administrator authorization was denied";
    if (strcmp(error->code, "authorization_unavailable") == 0)
        return "Administrator authentication is unavailable";
    if (strcmp(error->code, "authorization_timeout") == 0)
        return "Administrator authentication timed out";
    if (strcmp(error->code, "authorization_stale_peer") == 0)
        return "Authorization expired; try again";
    if (strcmp(error->code, "connect_failed") == 0 ||
        strcmp(error->code, "disconnected") == 0)
        return "Detector connection was lost";
    return "Response mode could not be changed";
}

static gboolean
apply_response_result(gpointer userdata)
{
    /* The switch is confirmed only from the daemon's returned health.
     * Authentication and the socket request run in a worker so the GTK
     * window remains responsive while PolicyKit prompts the user. */
    struct response_request *request = userdata;
    struct ui_app *ui = request->ui;
    GThread *thread;

    g_mutex_lock(&ui->mutex);
    thread = ui->response_thread;
    ui->response_thread = NULL;
    ui->response_source = 0;
    g_mutex_unlock(&ui->mutex);
    if (thread != NULL)
        g_thread_join(thread);
    if (g_atomic_int_get(&ui->stopping))
        return G_SOURCE_REMOVE;
    if (request->success) {
        ms_ui_state_apply_health(&ui->state, &request->health);
        ms_window_set_health(ui->window, &request->health);
        ms_window_set_response_pending(ui->window, false);
        update_indicator(ui);
    } else {
        ms_window_set_response_error(ui->window, response_error_message(&request->error));
    }
    return G_SOURCE_REMOVE;
}

static gpointer
response_worker(gpointer userdata)
{
    struct response_request *request = userdata;
    struct ui_app *ui = request->ui;
    struct ms_client *client = NULL;

    request->success = ms_client_connect(MEMSPY_SOCKET_PATH, &client, &request->error);
    if (request->success) {
        g_mutex_lock(&ui->mutex);
        if (g_atomic_int_get(&ui->stopping)) {
            g_mutex_unlock(&ui->mutex);
            ms_client_close(client);
            g_free(request);
            return NULL;
        }
        ui->response_client = client;
        g_mutex_unlock(&ui->mutex);
        request->success = ms_client_set_response(client, request->enabled,
                                                  &request->health, &request->error);
        g_mutex_lock(&ui->mutex);
        if (ui->response_client == client)
            ui->response_client = NULL;
        g_mutex_unlock(&ui->mutex);
        ms_client_close(client);
    }

    g_mutex_lock(&ui->mutex);
    if (g_atomic_int_get(&ui->stopping)) {
        g_mutex_unlock(&ui->mutex);
        g_free(request);
        return NULL;
    }
    ui->response_source = g_idle_add_full(G_PRIORITY_DEFAULT, apply_response_result,
                                          request, g_free);
    g_mutex_unlock(&ui->mutex);
    return NULL;
}

static void
set_response(bool enabled, void *userdata)
{
    struct ui_app *ui = userdata;
    struct response_request *request = g_new0(struct response_request, 1);

    request->ui = ui;
    request->enabled = enabled;
    g_mutex_lock(&ui->mutex);
    if (ui->response_thread == NULL && !g_atomic_int_get(&ui->stopping)) {
        ms_window_set_response_pending(ui->window, true);
        ui->response_thread = g_thread_new("memspy-ui-response", response_worker, request);
    } else {
        g_free(request);
    }
    g_mutex_unlock(&ui->mutex);
}

static void
thread_alert(const struct ms_alert *alert, void *userdata)
{
    struct alert_event *event = g_new(struct alert_event, 1);
    event->ui = userdata;
    event->alert = *alert;
    g_idle_add(apply_alert, event);
}

static void
thread_health(const struct ms_health *health, void *userdata)
{
    struct health_event *event = g_new(struct health_event, 1);
    event->ui = userdata;
    event->health = *health;
    g_idle_add(apply_health, event);
}

static GArray *
load_history(struct ms_client *client, int64_t known_id, struct ms_error *error)
{
    GArray *alerts = g_array_new(false, false, sizeof(struct ms_alert));
    int64_t before_id = 0;
    bool reached_known = false;

    while (!reached_known && alerts->len < MS_UI_MAX_HISTORY) {
        struct ms_alert_page page = {0};
        if (!ms_client_list_alerts(client, before_id, MS_SEVERITY_MEDIUM, 200, &page, error)) {
            ms_alert_page_clear(&page);
            g_array_free(alerts, true);
            return NULL;
        }
        for (size_t index = 0; index < page.length; ++index) {
            if (known_id > 0 && page.items[index].id <= known_id)
                reached_known = true;
            g_array_append_val(alerts, page.items[index]);
        }
        before_id = page.next_before_id;
        bool finished = page.length == 0 || before_id == 0;
        ms_alert_page_clear(&page);
        if (finished)
            break;
    }
    /* shortcut: retain at most 10k rows in the desktop process; add virtual paging if field volumes exceed this. */
    return alerts;
}

static gpointer
connection_worker(gpointer userdata)
{
    struct ui_app *ui = userdata;
    unsigned int delay_seconds = 1;

    while (true) {
        struct ms_client *client = NULL;
        struct ms_error error = {0};
        struct ms_health health = {0};
        int64_t known_id;

        g_mutex_lock(&ui->mutex);
        if (g_atomic_int_get(&ui->stopping)) {
            g_mutex_unlock(&ui->mutex);
            break;
        }
        known_id = ui->known_id;
        g_mutex_unlock(&ui->mutex);
        if (ms_client_connect(MEMSPY_SOCKET_PATH, &client, &error)) {
            GArray *history;
            g_mutex_lock(&ui->mutex);
            ui->client = client;
            g_mutex_unlock(&ui->mutex);
            history = ms_client_get_status(client, &health, &error) ?
                load_history(client, known_id, &error) : NULL;
            if (history != NULL && ms_client_subscribe(client, thread_alert, thread_health, ui, &error)) {
                struct snapshot *snapshot = g_new(struct snapshot, 1);
                snapshot->ui = ui;
                snapshot->health = health;
                snapshot->alerts = history;
                g_idle_add(apply_snapshot, snapshot);
                delay_seconds = 1;
                ms_client_wait(client);
            } else if (history != NULL) {
                g_array_free(history, true);
            }
            g_mutex_lock(&ui->mutex);
            if (ui->client == client)
                ui->client = NULL;
            g_mutex_unlock(&ui->mutex);
            ms_client_close(client);
        }
        g_idle_add(apply_disconnected, ui);
        g_mutex_lock(&ui->mutex);
        if (!g_atomic_int_get(&ui->stopping)) {
            gint64 deadline = g_get_monotonic_time() + (gint64)delay_seconds * G_TIME_SPAN_SECOND;
            g_cond_wait_until(&ui->wake, &ui->mutex, deadline);
        }
        bool stop = g_atomic_int_get(&ui->stopping);
        g_mutex_unlock(&ui->mutex);
        if (stop)
            break;
        if (delay_seconds < 30)
            delay_seconds = MIN(delay_seconds * 2U, 30U);
    }
    return NULL;
}

static gboolean
hide_on_delete(GtkWidget *widget, GdkEvent *event, gpointer userdata)
{
    (void)event;
    (void)userdata;
    gtk_widget_hide(widget);
    return true;
}

static void
load_css(void)
{
    GtkCssProvider *provider = gtk_css_provider_new();
    GtkSettings *settings = gtk_settings_get_default();
    const char *installed = "/opt/memspy/share/memspy/memspy-ui.css";
    const char *path = g_file_test(installed, G_FILE_TEST_IS_REGULAR) ? installed : "data/memspy-ui.css";

    if (settings != NULL)
        g_object_set(settings, "gtk-application-prefer-dark-theme", true, NULL);
    gtk_css_provider_load_from_path(provider, path, NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
        GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}

static void
activate(GtkApplication *application, gpointer userdata)
{
    struct ui_app *ui = userdata;
    struct ms_error error = {0};
    if (ui->window != NULL) {
        open_window(ui);
        return;
    }
    ui->application = application;
    load_css();
    ui->window = ms_window_new(application);
    ms_window_set_response_handler(ui->window, set_response, ui);
    g_signal_connect(ms_window_widget(ui->window), "delete-event",
                     G_CALLBACK(hide_on_delete), ui);
    ms_ui_state_init(&ui->state);
    if (!ms_ui_state_load(&ui->state, ui->state_path, &error))
        g_warning("cannot load UI state: %s", error.message);
    ui->known_id = ui->state.last_alert_id;
    ui->notifications_ready = ms_notifications_init();
    ui->indicator = ms_indicator_new(open_window, quit_ui, ui);
    if (ui->indicator == NULL) {
        ms_window_set_offline(ui->window, "Panel indicator unavailable",
                              "Alerts remain available in this window");
        ui->background = false;
    }
    update_indicator(ui);
    ui->connection_thread = g_thread_new("memspy-ui-connection", connection_worker, ui);
    if (!ui->background)
        ms_window_present(ui->window);
}

static void
shutdown_ui(struct ui_app *ui)
{
    GThread *response_thread;
    guint response_source;

    g_mutex_lock(&ui->mutex);
    g_atomic_int_set(&ui->stopping, true);
    if (ui->client != NULL)
        ms_client_interrupt(ui->client);
    if (ui->response_client != NULL)
        ms_client_interrupt(ui->response_client);
    g_cond_signal(&ui->wake);
    g_mutex_unlock(&ui->mutex);
    if (ui->connection_thread != NULL)
        g_thread_join(ui->connection_thread);
    g_mutex_lock(&ui->mutex);
    response_thread = ui->response_thread;
    ui->response_thread = NULL;
    response_source = ui->response_source;
    ui->response_source = 0;
    g_mutex_unlock(&ui->mutex);
    if (response_thread != NULL)
        g_thread_join(response_thread);
    if (response_source != 0)
        g_source_remove(response_source);
    save_state(ui);
    ms_indicator_free(ui->indicator);
    ms_notifications_uninit();
    ms_window_free(ui->window);
}

int
main(int argc, char **argv)
{
    struct ui_app ui = {0};
    GtkApplication *application;
    int result;

    signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        g_print("memspy-ui %s\n", MEMSPY_UI_VERSION);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--background") == 0) {
        ui.background = true;
        argc = 1;
    } else if (argc != 1) {
        g_printerr("Usage: memspy-ui [--background|--version]\n");
        return 2;
    }
    g_mutex_init(&ui.mutex);
    g_cond_init(&ui.wake);
    ui.state_path = g_build_filename(g_get_user_state_dir(), "memspy", "ui-state", NULL);
    application = gtk_application_new("org.memspy.MemSpyUI", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(application, "activate", G_CALLBACK(activate), &ui);
    result = g_application_run(G_APPLICATION(application), argc, argv);
    if (ui.window != NULL)
        shutdown_ui(&ui);
    g_object_unref(application);
    g_free(ui.state_path);
    g_cond_clear(&ui.wake);
    g_mutex_clear(&ui.mutex);
    return result;
}
