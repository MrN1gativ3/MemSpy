#ifndef FILELESS_SENSOR_H
#define FILELESS_SENSOR_H

#include <stdbool.h>
#include <stdint.h>

#include "fileless/observation.h"
#include "fileless_shared.h"

typedef void (*fl_observation_cb)(const struct fl_observation *observation, void *userdata);

struct fl_sensor_stats {
    uint64_t received_events;
    uint64_t lost_events;
    uint64_t invalid_events;
};

struct fl_sensor;

bool fl_sensor_open(struct fl_sensor **out, fl_observation_cb callback, void *userdata,
                    struct fl_error *error);
bool fl_sensor_attach(struct fl_sensor *sensor, struct fl_error *error);
int fl_sensor_poll(struct fl_sensor *sensor, int timeout_ms, struct fl_error *error);
void fl_sensor_stats(const struct fl_sensor *sensor, struct fl_sensor_stats *stats);
void fl_sensor_free(struct fl_sensor *sensor);
bool fl_sensor_observation_from_event(const struct fl_kernel_event *event,
                                      struct fl_observation *observation,
                                      struct fl_error *error);

#endif
