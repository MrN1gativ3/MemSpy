#ifndef MEMSPY_JOURNAL_H
#define MEMSPY_JOURNAL_H

#include <stdbool.h>

#include "memspy/alert.h"

int ms_journal_priority(const struct ms_alert *alert);
bool ms_journal_alert(const struct ms_alert *alert, struct ms_error *error);

#endif
