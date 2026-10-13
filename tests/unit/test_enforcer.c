#include <errno.h>
#include <glib.h>
#include <pwd.h>
#include <string.h>
#include <unistd.h>

#include "enforcer.h"

struct fake_backend {
    enum ms_enforcer_pins pins;
    bool fail_create;
    bool unrelated_pin;
    uint64_t denied;
    uint64_t lost;
    GString *calls;
};

static void
record(struct fake_backend *fake, const char *call)
{
    if (fake->calls->len > 0)
        g_string_append_c(fake->calls, ' ');
    g_string_append(fake->calls, call);
}

static enum ms_enforcer_pins
fake_inspect(void *context, const char *pin_dir)
{
    struct fake_backend *fake = context;
    g_assert_cmpstr(pin_dir, ==, "/sys/fs/bpf/memspy");
    record(fake, "inspect");
    return fake->pins;
}

static bool
fake_instance(void *context, const char *call, void **instance)
{
    struct fake_backend *fake = context;
    record(fake, call);
    *instance = g_malloc0(1);
    return true;
}

static bool
fake_adopt(void *context, const char *pin_dir, struct ms_enforcer *owner,
           void **instance, struct ms_error *error)
{
    (void)pin_dir;
    (void)owner;
    (void)error;
    return fake_instance(context, "adopt", instance);
}

static bool
fake_hold(void *context, const char *pin_dir, void **instance, struct ms_error *error)
{
    (void)pin_dir;
    (void)error;
    return fake_instance(context, "hold", instance);
}

static bool
fake_create(void *context, struct ms_enforcer *owner, void **instance,
            struct ms_error *error)
{
    struct fake_backend *fake = context;
    (void)owner;
    record(fake, "create");
    if (fake->fail_create) {
        g_strlcpy(error->code, "enforcer_attach", sizeof error->code);
        g_strlcpy(error->message, "BPF LSM unavailable", sizeof error->message);
        return false;
    }
    *instance = g_malloc0(1);
    return true;
}

static bool
fake_configure(void *context, void *instance, const GArray *keys, bool enabled,
               struct ms_error *error)
{
    (void)instance;
    (void)keys;
    (void)error;
    record(context, enabled ? "configure-on" : "configure-off");
    return true;
}

static bool
fake_path_op(void *context, const char *pin_dir, struct ms_error *error,
             const char *call)
{
    (void)pin_dir;
    (void)error;
    record(context, call);
    return true;
}

static bool fake_stage(void *c, void *i, const char *p, struct ms_error *e)
{ (void)i; return fake_path_op(c, p, e, "stage"); }
static bool fake_remove(void *c, const char *p, struct ms_error *e)
{ return fake_path_op(c, p, e, "remove-owned"); }
static bool fake_promote(void *c, const char *p, struct ms_error *e)
{ return fake_path_op(c, p, e, "promote"); }

static bool
fake_set_enabled(void *context, void *instance, bool enabled, struct ms_error *error)
{
    (void)instance;
    (void)error;
    record(context, enabled ? "enable" : "disable");
    return true;
}

static int
fake_poll(void *context, void *instance, int timeout_ms, uint64_t *denied,
          uint64_t *lost, struct ms_error *error)
{
    struct fake_backend *fake = context;
    (void)instance;
    (void)timeout_ms;
    (void)error;
    *denied = fake->denied;
    *lost = fake->lost;
    return 0;
}

static void
fake_release(void *context, void *instance)
{
    record(context, "release");
    g_free(instance);
}

static const struct ms_enforcer_ops fake_ops = {
    .inspect = fake_inspect,
    .adopt = fake_adopt,
    .hold = fake_hold,
    .create = fake_create,
    .configure = fake_configure,
    .stage = fake_stage,
    .remove_owned = fake_remove,
    .promote = fake_promote,
    .set_enabled = fake_set_enabled,
    .poll = fake_poll,
    .release = fake_release,
};

static struct fake_backend
fake_backend_new(enum ms_enforcer_pins pins)
{
    return (struct fake_backend){
        .pins = pins,
        .unrelated_pin = true,
        .calls = g_string_new(NULL),
    };
}

static struct ms_enforce_event
valid_event(void)
{
    struct ms_enforce_event event = {
        .abi_version = MS_ENFORCE_EVENT_ABI,
        .kind = MS_ENFORCE_BLOCKED_MEMFD_EXEC,
        .flags = MS_ENFORCE_ARGUMENTS_TRUNCATED,
        .pid = (uint32_t)getpid(),
        .ppid = (uint32_t)getppid(),
        .uid = (uint32_t)getuid(),
        .result = -EACCES,
        .observed_boottime_ns = 123456,
        .argument_count = 3,
    };
    const char *arguments[] = {"runner", "two words", "a'b"};

    g_strlcpy(event.comm, "blocked-test", sizeof event.comm);
    g_strlcpy(event.filename, "memfd:payload", sizeof event.filename);
    event.filename_length = strlen(event.filename);
    for (size_t index = 0; index < G_N_ELEMENTS(arguments); ++index) {
        g_strlcpy(event.arguments[index], arguments[index], sizeof event.arguments[index]);
        event.arguments_length += strlen(arguments[index]);
    }
    return event;
}

static void
ignore_alert(const struct ms_alert *alert, void *userdata)
{
    (void)alert;
    (void)userdata;
}

static void
test_event_conversion(void)
{
    struct ms_enforce_event event = valid_event();
    struct ms_alert alert;
    struct ms_error error = {0};
    struct passwd *password = getpwuid(getuid());

    g_assert_true(ms_enforcer_alert_from_event(&event, &alert, &error));
    g_assert_cmpstr(alert.rule_id, ==, "BLOCKED_MEMFD_EXEC");
    g_assert_cmpint(alert.action, ==, MS_ALERT_BLOCKED);
    g_assert_cmpint(alert.severity, ==, MS_SEVERITY_HIGH);
    g_assert_cmpint(alert.pid, ==, getpid());
    g_assert_cmpint(alert.ppid, ==, getppid());
    g_assert_cmpuint(alert.uid, ==, getuid());
    g_assert_cmpstr(alert.exe, ==, "memfd:payload");
    g_assert_cmpstr(alert.cmdline, ==, "'runner' 'two words' 'a'\\''b'");
    g_assert_true(alert.arguments_truncated);
    g_assert_cmpstr(alert.evidence, ==, "BPF LSM denied memfd execution");
    g_assert_nonnull(strstr(alert.launcher_exe, "test-enforcer"));
    g_assert_true(alert.parent_exe[0] == '/' || alert.enrichment_incomplete);
    g_assert_true(alert.parent_comm[0] != '\0' || alert.enrichment_incomplete);
    g_assert_true(strlen(alert.parent_sha256) == 64U || alert.enrichment_incomplete);
    if (password != NULL)
        g_assert_cmpstr(alert.username, ==, password->pw_name);
}

static void
test_event_validation(void)
{
    struct ms_enforce_event event = valid_event();
    struct ms_alert alert;
    struct ms_error error = {0};

    event.abi_version++;
    g_assert_false(ms_enforcer_alert_from_event(&event, &alert, &error));
    event = valid_event();
    event.pid = 0;
    g_assert_false(ms_enforcer_alert_from_event(&event, &alert, &error));
    event = valid_event();
    memset(event.filename, 'x', sizeof event.filename);
    event.filename_length = sizeof event.filename - 1U;
    g_assert_false(ms_enforcer_alert_from_event(&event, &alert, &error));
    event = valid_event();
    event.argument_count = MS_ENFORCE_MAX_ARGS + 1U;
    g_assert_false(ms_enforcer_alert_from_event(&event, &alert, &error));
    event = valid_event();
    event.arguments_length++;
    g_assert_false(ms_enforcer_alert_from_event(&event, &alert, &error));
}

static struct ms_enforcer *
open_fake(struct fake_backend *fake)
{
    struct ms_enforcer *enforcer = NULL;
    struct ms_error error = {0};
    g_assert_true(ms_enforcer_open_with_ops(&enforcer, "/sys/fs/bpf/memspy",
                                            ignore_alert, NULL,
                                            &fake_ops, fake, &error));
    return enforcer;
}

static void
test_unsupported_is_not_fatal(void)
{
    struct fake_backend fake = fake_backend_new(MS_ENFORCER_PINS_NONE);
    struct ms_enforcer *enforcer = open_fake(&fake);
    struct ms_enforcer_status status;
    struct ms_error error = {0};

    fake.fail_create = true;
    g_assert_true(ms_enforcer_attach(enforcer, NULL, true, &error));
    ms_enforcer_status(enforcer, &status);
    g_assert_false(status.supported);
    g_assert_false(status.enabled);
    g_assert_cmpstr(status.reason, ==, "BPF LSM unavailable");
    g_assert_cmpstr(error.code, ==, "");
    ms_enforcer_free(enforcer);
    g_string_free(fake.calls, true);
}

static void
test_adopts_compatible_pins(void)
{
    struct fake_backend fake = fake_backend_new(MS_ENFORCER_PINS_COMPATIBLE);
    struct ms_enforcer *enforcer = open_fake(&fake);
    struct ms_enforcer_status status;
    struct ms_error error = {0};

    g_assert_true(ms_enforcer_attach(enforcer, NULL, true, &error));
    ms_enforcer_status(enforcer, &status);
    g_assert_true(status.supported);
    g_assert_true(status.enabled);
    g_assert_cmpstr(fake.calls->str, ==, "inspect adopt configure-on");
    ms_enforcer_free(enforcer);
    g_string_free(fake.calls, true);
}

static void
test_replaces_incompatible_without_gap(void)
{
    struct fake_backend fake = fake_backend_new(MS_ENFORCER_PINS_INCOMPATIBLE);
    struct ms_enforcer *enforcer = open_fake(&fake);
    struct ms_error error = {0};

    g_assert_true(ms_enforcer_attach(enforcer, NULL, true, &error));
    g_assert_cmpstr(fake.calls->str, ==,
                    "inspect hold create configure-on stage remove-owned promote release");
    g_assert_true(fake.unrelated_pin);
    ms_enforcer_free(enforcer);
    g_string_free(fake.calls, true);
}

static void
test_poll_updates_counters(void)
{
    struct fake_backend fake = fake_backend_new(MS_ENFORCER_PINS_COMPATIBLE);
    struct ms_enforcer *enforcer = open_fake(&fake);
    struct ms_enforcer_status status;
    struct ms_error error = {0};

    g_assert_true(ms_enforcer_attach(enforcer, NULL, false, &error));
    fake.denied = 7;
    fake.lost = 3;
    g_assert_cmpint(ms_enforcer_poll(enforcer, 0, &error), ==, 0);
    ms_enforcer_status(enforcer, &status);
    g_assert_cmpuint(status.denied, ==, 7);
    g_assert_cmpuint(status.lost_events, ==, 3);
    g_assert_true(ms_enforcer_set_enabled(enforcer, true, &error));
    ms_enforcer_status(enforcer, &status);
    g_assert_true(status.enabled);
    ms_enforcer_free(enforcer);
    g_string_free(fake.calls, true);
}

static void
test_remove_pins_preserves_unrelated_objects(void)
{
    struct fake_backend fake = fake_backend_new(MS_ENFORCER_PINS_NONE);
    struct ms_enforcer *enforcer = open_fake(&fake);
    struct ms_error error = {0};

    g_assert_true(ms_enforcer_attach(enforcer, NULL, false, &error));
    g_assert_true(ms_enforcer_remove_pins(enforcer, &error));
    g_assert_true(fake.unrelated_pin);
    g_assert_true(g_str_has_suffix(fake.calls->str, "remove-owned"));
    ms_enforcer_free(enforcer);
    g_string_free(fake.calls, true);
}

static void
test_bpf_lsm_must_be_active(void)
{
    g_assert_true(ms_enforcer_lsm_list_has_bpf("lockdown,capability,bpf\n"));
    g_assert_true(ms_enforcer_lsm_list_has_bpf("bpf,apparmor"));
    g_assert_false(ms_enforcer_lsm_list_has_bpf(
        "lockdown,capability,landlock,yama,apparmor,ima,evm"));
    g_assert_false(ms_enforcer_lsm_list_has_bpf("capability,bpfilter,apparmor"));
    g_assert_false(ms_enforcer_lsm_list_has_bpf(NULL));
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/enforcer/event-conversion", test_event_conversion);
    g_test_add_func("/enforcer/event-validation", test_event_validation);
    g_test_add_func("/enforcer/unsupported", test_unsupported_is_not_fatal);
    g_test_add_func("/enforcer/adopt", test_adopts_compatible_pins);
    g_test_add_func("/enforcer/replace", test_replaces_incompatible_without_gap);
    g_test_add_func("/enforcer/counters", test_poll_updates_counters);
    g_test_add_func("/enforcer/remove-pins", test_remove_pins_preserves_unrelated_objects);
    g_test_add_func("/enforcer/bpf-lsm-active", test_bpf_lsm_must_be_active);
    return g_test_run();
}
