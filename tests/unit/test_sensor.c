#include <glib.h>
#include <string.h>
#include <unistd.h>

#include "sensor.h"

static void
test_sensor_converts_and_enriches_exec(void)
{
    struct fl_kernel_event event = {
        .abi_version = FL_KERNEL_EVENT_ABI,
        .kind = FL_KERNEL_EXEC,
        .pid = (uint32_t)getpid(),
        .uid = (uint32_t)getuid(),
        .observed_boottime_ns = 1234,
    };
    struct fl_observation observation = {0};
    struct fl_error error = {0};

    memcpy(event.comm, "test-sensor", strlen("test-sensor"));
    g_assert_true(fl_sensor_observation_from_event(&event, &observation, &error));
    g_assert_cmpint(observation.kind, ==, FL_OBSERVATION_EXEC);
    g_assert_cmpint(observation.process.pid, ==, getpid());
    g_assert_cmpuint(observation.process.start_boottime_ns, >, 0);
    g_assert_cmpint(observation.ppid, ==, getppid());
    g_assert_cmpuint(observation.uid, ==, getuid());
    g_assert_cmpstr(observation.comm, ==, "test-sensor");
    g_assert_true(g_path_is_absolute(observation.exe));
    g_assert_nonnull(strstr(observation.cmdline, "test-sensor"));
    g_assert_false(observation.enrichment_incomplete);
}

static void
test_sensor_rejects_wrong_abi(void)
{
    struct fl_kernel_event event = {.abi_version = 99, .kind = FL_KERNEL_EXEC, .pid = 1};
    struct fl_observation observation = {0};
    struct fl_error error = {0};

    g_assert_false(fl_sensor_observation_from_event(&event, &observation, &error));
    g_assert_cmpstr(error.code, ==, "sensor_abi");
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/sensor/enrich-exec", test_sensor_converts_and_enriches_exec);
    g_test_add_func("/sensor/reject-abi", test_sensor_rejects_wrong_abi);
    return g_test_run();
}
