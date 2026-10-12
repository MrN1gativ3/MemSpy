#include <glib.h>
#include <string.h>
#include <unistd.h>

#include "sensor.h"

static void
test_sensor_formats_argument_boundaries(void)
{
    static const char raw[] = "alpha\0two words\0a'b\0\0";
    char formatted[256];
    bool truncated = false;

    g_assert_true(ms_format_proc_arguments(raw, sizeof raw - 1U, formatted,
                                           sizeof formatted, &truncated));
    g_assert_cmpstr(formatted, ==, "'alpha' 'two words' 'a'\\''b' ''");
    g_assert_false(truncated);
}

static void
test_sensor_repairs_invalid_utf8_arguments(void)
{
    static const char raw[] = {'x', (char)0xff, '\0'};
    char formatted[64];
    bool truncated = false;

    g_assert_true(ms_format_proc_arguments(raw, sizeof raw, formatted,
                                           sizeof formatted, &truncated));
    g_assert_true(g_utf8_validate(formatted, -1, NULL));
    g_assert_cmpstr(formatted, ==, "'x�'");
    g_assert_false(truncated);
}

static void
test_sensor_marks_argument_count_truncated(void)
{
    char raw[34];
    char formatted[256];
    bool truncated = false;
    g_auto(GStrv) arguments = NULL;

    for (size_t index = 0; index < 17U; ++index) {
        raw[index * 2U] = 'a';
        raw[index * 2U + 1U] = '\0';
    }
    g_assert_true(ms_format_proc_arguments(raw, sizeof raw, formatted,
                                           sizeof formatted, &truncated));
    g_assert_true(truncated);
    arguments = g_strsplit(formatted, " ", -1);
    g_assert_cmpuint(g_strv_length(arguments), ==, 16);
}

static void
test_sensor_marks_argument_bytes_truncated(void)
{
    g_autofree char *raw = g_malloc0(2050U);
    char formatted[MS_MAX_CMDLINE_BYTES + 1U];
    bool truncated = false;

    memset(raw, 'x', 2049U);
    g_assert_true(ms_format_proc_arguments(raw, 2050U, formatted,
                                           sizeof formatted, &truncated));
    g_assert_true(truncated);
    g_assert_cmpuint(strlen(formatted), ==, 2050U);
}

static void
test_sensor_converts_and_enriches_exec(void)
{
    struct ms_kernel_event event = {
        .abi_version = MS_KERNEL_EVENT_ABI,
        .kind = MS_KERNEL_EXEC,
        .pid = (uint32_t)getpid(),
        .uid = (uint32_t)getuid(),
        .observed_boottime_ns = 1234,
    };
    struct ms_observation observation = {0};
    struct ms_error error = {0};

    memcpy(event.comm, "test-sensor", strlen("test-sensor"));
    g_assert_true(ms_sensor_observation_from_event(&event, &observation, &error));
    g_assert_cmpint(observation.kind, ==, MS_OBSERVATION_EXEC);
    g_assert_cmpint(observation.process.pid, ==, getpid());
    g_assert_cmpuint(observation.process.start_boottime_ns, >, 0);
    g_assert_cmpint(observation.ppid, ==, getppid());
    g_assert_cmpuint(observation.uid, ==, getuid());
    g_assert_cmpstr(observation.comm, ==, "test-sensor");
    g_assert_true(g_path_is_absolute(observation.exe));
    g_assert_nonnull(strstr(observation.cmdline, "test-sensor"));
    g_assert_cmpstr(observation.username, !=, "");
    g_assert_true(g_path_is_absolute(observation.parent_exe));
    g_assert_false(observation.enrichment_incomplete);
}

static void
test_sensor_rejects_wrong_abi(void)
{
    struct ms_kernel_event event = {.abi_version = 99, .kind = MS_KERNEL_EXEC, .pid = 1};
    struct ms_observation observation = {0};
    struct ms_error error = {0};

    g_assert_false(ms_sensor_observation_from_event(&event, &observation, &error));
    g_assert_cmpstr(error.code, ==, "sensor_abi");
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/sensor/enrich-exec", test_sensor_converts_and_enriches_exec);
    g_test_add_func("/sensor/reject-abi", test_sensor_rejects_wrong_abi);
    g_test_add_func("/sensor/format-argument-boundaries", test_sensor_formats_argument_boundaries);
    g_test_add_func("/sensor/format-invalid-utf8", test_sensor_repairs_invalid_utf8_arguments);
    g_test_add_func("/sensor/format-argument-count", test_sensor_marks_argument_count_truncated);
    g_test_add_func("/sensor/format-argument-bytes", test_sensor_marks_argument_bytes_truncated);
    return g_test_run();
}
