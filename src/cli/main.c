#include "output.h"

#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#define MEMSPY_SOCKET_PATH "/run/memspy/memspy.sock"
#define MEMSPY_VERSION "0.1.0"

static void usage(FILE *stream)
{
    fprintf(stream, "Usage: memspyctl [--json] status|alerts|show ID|export ID|response on|off|version\n");
}

static bool positive_number(const char *text, int64_t maximum, int64_t *value)
{
    char *end = NULL;
    long long parsed;

    errno = 0;
    parsed = strtoll(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed <= 0 || parsed > maximum)
        return false;
    *value = parsed;
    return true;
}

static int client_error(const struct ms_error *error)
{
    fprintf(stderr, "memspyctl: %s\n", error->message[0] != '\0' ? error->message : error->code);
    if (strcmp(error->code, "alert_not_found") == 0)
        return 5;
    if (strncmp(error->code, "authorization_", 14) == 0)
        return 4;
    return 3;
}

int main(int argc, char **argv)
{
    struct ms_client *client = NULL;
    struct ms_error error = {0};
    bool json = false;
    int index = 1;
    int result = 0;

    if (index < argc && strcmp(argv[index], "--json") == 0) {
        json = true;
        ++index;
    }
    if (index >= argc) {
        usage(stderr);
        return 2;
    }
    if (strcmp(argv[index], "version") == 0 && index + 1 == argc) {
        puts("memspyctl " MEMSPY_VERSION);
        return 0;
    }
    if (!ms_client_connect(MEMSPY_SOCKET_PATH, &client, &error))
        return client_error(&error);

    if (strcmp(argv[index], "status") == 0 &&
        (index + 1 == argc ||
         (index + 2 == argc && strcmp(argv[index + 1], "--json") == 0))) {
        struct ms_health health = {0};
        json = json || index + 2 == argc;
        if (!ms_client_get_status(client, &health, &error))
            result = client_error(&error);
        else if (!ms_cli_print_status(stdout, &health, json))
            result = 3;
    } else if (strcmp(argv[index], "alerts") == 0) {
        struct ms_alert_page page = {0};
        enum ms_severity minimum = MS_SEVERITY_MEDIUM;
        size_t limit = 100;
        for (++index; index < argc; ++index) {
            int64_t number;
            if (strcmp(argv[index], "--json") == 0)
                json = true;
            else if (strcmp(argv[index], "--limit") == 0 && ++index < argc &&
                     positive_number(argv[index], 200, &number))
                limit = (size_t)number;
            else if (strcmp(argv[index], "--minimum") == 0 && ++index < argc &&
                     (strcmp(argv[index], "high") == 0 || strcmp(argv[index], "medium") == 0))
                minimum = strcmp(argv[index], "high") == 0 ? MS_SEVERITY_HIGH : MS_SEVERITY_MEDIUM;
            else {
                usage(stderr);
                result = 2;
                goto done;
            }
        }
        if (!ms_client_list_alerts(client, 0, minimum, limit, &page, &error))
            result = client_error(&error);
        else if (!ms_cli_print_alerts(stdout, &page, json))
            result = 3;
        ms_alert_page_clear(&page);
    } else if ((strcmp(argv[index], "show") == 0 || strcmp(argv[index], "export") == 0) &&
               index + 1 < argc) {
        struct ms_alert alert = {0};
        int64_t id;
        bool export = strcmp(argv[index], "export") == 0;
        if (!positive_number(argv[++index], INT64_MAX, &id) ||
            (index + 1 < argc && !(index + 2 == argc && strcmp(argv[index + 1], "--json") == 0))) {
            usage(stderr);
            result = 2;
        } else if (!ms_client_get_alert(client, id, &alert, &error)) {
            result = client_error(&error);
        } else if (!ms_cli_print_alert(stdout, &alert, export || json || index + 1 < argc)) {
            result = 3;
        }
    } else if (strcmp(argv[index], "response") == 0 &&
               (index + 2 == argc ||
                (index + 3 == argc && strcmp(argv[index + 2], "--json") == 0)) &&
               (strcmp(argv[index + 1], "on") == 0 || strcmp(argv[index + 1], "off") == 0)) {
        struct ms_health health = {0};
        bool enabled = strcmp(argv[index + 1], "on") == 0;
        json = json || index + 3 == argc;
        if (!ms_client_set_response(client, enabled, &health, &error))
            result = client_error(&error);
        else if (!ms_cli_print_status(stdout, &health, json))
            result = 3;
    } else {
        usage(stderr);
        result = 2;
    }

done:
    ms_client_close(client);
    return result;
}
