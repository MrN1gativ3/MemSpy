#include <errno.h>
#include <getopt.h>
#include <glib/gstdio.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "app.h"
#include "enforcer.h"

#define MEMSPYD_VERSION "0.1.0"

static struct ms_app *running_app;

enum {
    OPT_RESPONSE_STATE = 1000,
    OPT_RESPONSE_ALLOWLIST,
    OPT_RESPONSE_PIN_DIR,
    OPT_CHECK_RESPONSE,
};

static void
handle_signal(int signal_number)
{
    (void)signal_number;
    ms_app_stop(running_app);
}

static void
usage(FILE *stream)
{
    fprintf(stream,
            "Usage: memspyd [OPTIONS]\n"
            "  --config PATH    Exact-path allowlist (default /etc/memspy/allowlist.conf)\n"
            "  --database PATH  Alert database (default /var/lib/memspy/alerts.db)\n"
            "  --socket PATH    Local API socket (default /run/memspy/memspy.sock)\n"
            "  --response-state PATH      Response state (default /var/lib/memspy/response-mode)\n"
            "  --response-allowlist PATH  Launcher allowlist (default /etc/memspy/response-allowlist.conf)\n"
            "  --response-pin-dir PATH    BPF pins (default /sys/fs/bpf/memspy)\n"
            "  --check-response           Probe response support and exit\n"
            "  --foreground     Stay in foreground (default behavior)\n"
            "  --version        Show version\n"
            "  --help           Show this help\n");
}

static void
ignore_blocked_alert(const struct ms_alert *alert, void *userdata)
{
    (void)alert;
    (void)userdata;
}

static int
check_response(const char *pin_directory)
{
    g_autofree char *probe_directory =
        g_strdup_printf("%s_probe_%ld", pin_directory, (long)getpid());
    g_autoptr(GArray) keys = g_array_new(false, false, sizeof(struct ms_allowlist_key));
    struct ms_enforcer *enforcer = NULL;
    struct ms_enforcer_status status = {0};
    struct ms_error error = {0};
    int result = 3;

    if (!ms_enforcer_open(&enforcer, probe_directory, ignore_blocked_alert, NULL, &error) ||
        !ms_enforcer_attach(enforcer, keys, false, &error))
        goto unavailable;
    ms_enforcer_status(enforcer, &status);
    if (!status.supported) {
        g_strlcpy(error.message, status.reason, sizeof error.message);
        goto unavailable;
    }
    if (!ms_enforcer_remove_pins(enforcer, &error))
        goto unavailable;
    g_rmdir(probe_directory);
    printf("Detection and response available\n");
    result = 0;
    goto done;

unavailable:
    fprintf(stderr, "Detection available; response unavailable: %s\n",
            error.message[0] != '\0' ? error.message : "BPF LSM probe failed");
done:
    ms_enforcer_free(enforcer);
    return result;
}

static bool
validate_host(struct ms_error *error)
{
    struct utsname host;
    unsigned int major = 0;
    unsigned int minor = 0;

#ifndef __x86_64__
    snprintf(error->code, sizeof error->code, "unsupported_arch");
    snprintf(error->message, sizeof error->message, "memspyd requires x86_64");
    return false;
#endif
    if (uname(&host) != 0) {
        snprintf(error->code, sizeof error->code, "kernel");
        snprintf(error->message, sizeof error->message, "cannot read kernel version: %s", strerror(errno));
        return false;
    }
    if (strcmp(host.machine, "x86_64") != 0) {
        snprintf(error->code, sizeof error->code, "unsupported_arch");
        snprintf(error->message, sizeof error->message, "memspyd requires x86_64, found %s", host.machine);
        return false;
    }
    if (sscanf(host.release, "%u.%u", &major, &minor) != 2 ||
        major < 5 || (major == 5 && minor < 4)) {
        snprintf(error->code, sizeof error->code, "unsupported_kernel");
        snprintf(error->message, sizeof error->message, "memspyd requires Linux 5.4 or newer");
        return false;
    }
    if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
        snprintf(error->code, sizeof error->code, "missing_btf");
        snprintf(error->message, sizeof error->message, "kernel BTF is unavailable at /sys/kernel/btf/vmlinux");
        return false;
    }
    return true;
}

int
main(int argc, char **argv)
{
    static const struct option options[] = {
        {"config", required_argument, NULL, 'c'},
        {"database", required_argument, NULL, 'd'},
        {"socket", required_argument, NULL, 's'},
        {"response-state", required_argument, NULL, OPT_RESPONSE_STATE},
        {"response-allowlist", required_argument, NULL, OPT_RESPONSE_ALLOWLIST},
        {"response-pin-dir", required_argument, NULL, OPT_RESPONSE_PIN_DIR},
        {"check-response", no_argument, NULL, OPT_CHECK_RESPONSE},
        {"foreground", no_argument, NULL, 'f'},
        {"version", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    struct ms_app_config config = {
        .allowlist_path = "/etc/memspy/allowlist.conf",
        .database_path = "/var/lib/memspy/alerts.db",
        .socket_path = "/run/memspy/memspy.sock",
        .response_state_path = "/var/lib/memspy/response-mode",
        .response_allowlist_path = "/etc/memspy/response-allowlist.conf",
        .response_pin_dir = "/sys/fs/bpf/memspy",
    };
    struct ms_error error = {0};
    struct sigaction action = {.sa_handler = handle_signal};
    int option;
    int result;
    bool probe_response = false;

    while ((option = getopt_long(argc, argv, "c:d:s:fvh", options, NULL)) != -1) {
        switch (option) {
        case 'c': config.allowlist_path = optarg; break;
        case 'd': config.database_path = optarg; break;
        case 's': config.socket_path = optarg; break;
        case OPT_RESPONSE_STATE: config.response_state_path = optarg; break;
        case OPT_RESPONSE_ALLOWLIST: config.response_allowlist_path = optarg; break;
        case OPT_RESPONSE_PIN_DIR: config.response_pin_dir = optarg; break;
        case OPT_CHECK_RESPONSE: probe_response = true; break;
        case 'f': break;
        case 'v': printf("memspyd %s\n", MEMSPYD_VERSION); return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 2;
    }
    if (!validate_host(&error)) {
        fprintf(stderr, "memspyd: %s: %s\n", error.code, error.message);
        return probe_response ? 3 : 1;
    }
    if (probe_response)
        return check_response(config.response_pin_dir);
    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    running_app = ms_app_new(&config, NULL, &error);
    if (running_app == NULL) {
        fprintf(stderr, "memspyd: %s: %s\n", error.code, error.message);
        return 1;
    }
    result = ms_app_run(running_app);
    ms_app_free(running_app);
    running_app = NULL;
    return result;
}
