#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "app.h"

#define FILELESSD_VERSION "0.1.0"

static struct fl_app *running_app;

static void
handle_signal(int signal_number)
{
    (void)signal_number;
    fl_app_stop(running_app);
}

static void
usage(FILE *stream)
{
    fprintf(stream,
            "Usage: filelessd [OPTIONS]\n"
            "  --config PATH    Exact-path allowlist (default /etc/filelessd/allowlist.conf)\n"
            "  --database PATH  Alert database (default /var/lib/filelessd/alerts.db)\n"
            "  --socket PATH    Local API socket (default /run/filelessd/filelessd.sock)\n"
            "  --foreground     Stay in foreground (default behavior)\n"
            "  --version        Show version\n"
            "  --help           Show this help\n");
}

static bool
validate_host(struct fl_error *error)
{
    struct utsname host;
    unsigned int major = 0;
    unsigned int minor = 0;

#ifndef __x86_64__
    snprintf(error->code, sizeof error->code, "unsupported_arch");
    snprintf(error->message, sizeof error->message, "filelessd requires x86_64");
    return false;
#endif
    if (uname(&host) != 0) {
        snprintf(error->code, sizeof error->code, "kernel");
        snprintf(error->message, sizeof error->message, "cannot read kernel version: %s", strerror(errno));
        return false;
    }
    if (strcmp(host.machine, "x86_64") != 0) {
        snprintf(error->code, sizeof error->code, "unsupported_arch");
        snprintf(error->message, sizeof error->message, "filelessd requires x86_64, found %s", host.machine);
        return false;
    }
    if (sscanf(host.release, "%u.%u", &major, &minor) != 2 ||
        major < 5 || (major == 5 && minor < 4)) {
        snprintf(error->code, sizeof error->code, "unsupported_kernel");
        snprintf(error->message, sizeof error->message, "filelessd requires Linux 5.4 or newer");
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
        {"foreground", no_argument, NULL, 'f'},
        {"version", no_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };
    struct fl_app_config config = {
        .allowlist_path = "/etc/filelessd/allowlist.conf",
        .database_path = "/var/lib/filelessd/alerts.db",
        .socket_path = "/run/filelessd/filelessd.sock",
    };
    struct fl_error error = {0};
    struct sigaction action = {.sa_handler = handle_signal};
    int option;
    int result;

    while ((option = getopt_long(argc, argv, "c:d:s:fvh", options, NULL)) != -1) {
        switch (option) {
        case 'c': config.allowlist_path = optarg; break;
        case 'd': config.database_path = optarg; break;
        case 's': config.socket_path = optarg; break;
        case 'f': break;
        case 'v': printf("filelessd %s\n", FILELESSD_VERSION); return 0;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind != argc) {
        usage(stderr);
        return 2;
    }
    if (!validate_host(&error)) {
        fprintf(stderr, "filelessd: %s: %s\n", error.code, error.message);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&action.sa_mask);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGINT, &action, NULL);
    running_app = fl_app_new(&config, NULL, &error);
    if (running_app == NULL) {
        fprintf(stderr, "filelessd: %s: %s\n", error.code, error.message);
        return 1;
    }
    result = fl_app_run(running_app);
    fl_app_free(running_app);
    running_app = NULL;
    return result;
}
