#include <glib.h>
#include <signal.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "policy.h"
#include "sensor.h"

struct harness {
    struct ms_policy *policy;
    pid_t fixture_pid;
    const char *expected_rule;
    bool expect_none;
    bool found;
};

static void
on_observation(const struct ms_observation *observation, void *userdata)
{
    struct harness *harness = userdata;
    struct ms_alert alert = {0};

    if (observation->process.pid != harness->fixture_pid)
        return;
    if (ms_policy_ingest(harness->policy, observation, &alert) != MS_POLICY_ALERT)
        return;
    if (harness->expect_none || strcmp(alert.rule_id, harness->expected_rule) == 0)
        harness->found = true;
}

int
main(int argc, char **argv)
{
    struct ms_sensor *sensor = NULL;
    struct ms_error error = {0};
    struct harness harness = {0};
    int child_status = 0;
    bool child_reaped = false;

    if (argc != 3)
        return 2;
    harness.expected_rule = argv[2];
    harness.expect_none = strcmp(argv[2], "NONE") == 0;
    harness.policy = ms_policy_new();
    if (!ms_sensor_open(&sensor, on_observation, &harness, &error) ||
        !ms_sensor_attach(sensor, &error)) {
        g_printerr("%s: %s\n", error.code, error.message);
        return 2;
    }
    harness.fixture_pid = fork();
    if (harness.fixture_pid == 0) {
        execl(argv[1], argv[1], NULL);
        _exit(127);
    }
    if (harness.fixture_pid < 0) {
        ms_sensor_free(sensor);
        ms_policy_free(harness.policy);
        return 2;
    }
    for (unsigned int attempt = 0; attempt < 50U && !harness.found; ++attempt) {
        ms_sensor_poll(sensor, 100, &error);
        if (!child_reaped && waitpid(harness.fixture_pid, &child_status, WNOHANG) == harness.fixture_pid)
            child_reaped = true;
    }
    if (!child_reaped)
        waitpid(harness.fixture_pid, &child_status, 0);
    ms_sensor_free(sensor);
    ms_policy_free(harness.policy);
    if (harness.expect_none && harness.found) {
        g_printerr("unexpected alert observed for ordinary execution\n");
        return 1;
    }
    if (!harness.expect_none && !harness.found) {
        g_printerr("expected rule not observed: %s\n", argv[2]);
        return 1;
    }
    return 0;
}
