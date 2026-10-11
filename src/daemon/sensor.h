#ifndef MEMSPY_SENSOR_H
#define MEMSPY_SENSOR_H

#include <stdbool.h>
#include <stdint.h>

#include "memspy/observation.h"
#include "memspy_shared.h"

typedef void (*ms_observation_cb)(const struct ms_observation *observation, void *userdata);

struct ms_sensor_stats {
    uint64_t received_events;
    uint64_t lost_events;
    uint64_t invalid_events;
    uint32_t last_event_size;
    uint16_t last_abi_version;
    uint16_t last_kind;
    uint32_t last_pid;
};

struct ms_sensor;

bool ms_sensor_open(struct ms_sensor **out, ms_observation_cb callback, void *userdata,
                    struct ms_error *error);
bool ms_sensor_attach(struct ms_sensor *sensor, struct ms_error *error);
int ms_sensor_poll(struct ms_sensor *sensor, int timeout_ms, struct ms_error *error);
void ms_sensor_stats(const struct ms_sensor *sensor, struct ms_sensor_stats *stats);
void ms_sensor_free(struct ms_sensor *sensor);
bool ms_sensor_observation_from_event(const struct ms_kernel_event *event,
                                      struct ms_observation *observation,
                                      struct ms_error *error);

#endif
