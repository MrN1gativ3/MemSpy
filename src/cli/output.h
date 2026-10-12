#ifndef MEMSPY_CLI_OUTPUT_H
#define MEMSPY_CLI_OUTPUT_H

#include <stdbool.h>
#include <stdio.h>

#include "client.h"

bool ms_cli_print_status(FILE *stream, const struct ms_health *health, bool json);
bool ms_cli_print_alert(FILE *stream, const struct ms_alert *alert, bool json);
bool ms_cli_print_alerts(FILE *stream, const struct ms_alert_page *page, bool json);

#endif
