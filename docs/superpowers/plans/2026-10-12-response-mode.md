# MemSpy Response Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional, Polkit-authorized BPF LSM prevention for `memfd` execution and show complete bounded process evidence in the desktop UI.

**Architecture:** Keep the existing tracepoint detector unchanged and load a separate CO-RE enforcement object only on capable hosts. `memspyd` owns the pinned LSM program, persistent mode, allowlist, authorization and alerts; the existing Unix socket carries status and authenticated mode-change requests to the unprivileged GTK UI.

**Tech Stack:** C17, libbpf CO-RE/eBPF LSM, GLib/GIO, Polkit GObject API, json-c, SQLite, GTK 3, Meson, systemd.

**Spec:** `docs/superpowers/specs/2026-10-12-response-mode-design.md`

## Global Constraints

- Target x86_64 Linux 5.4 or newer; response mode is runtime-optional and requires an active BPF LSM.
- Response mode blocks only `memfd` execution and is off by default.
- Unsupported enforcement must not prevent detection, alert history or the UI from working.
- Both enable and disable require `org.memspy.response.configure` Polkit authorization.
- Existing 30-day alert history must survive schema migration.
- Capture at most 16 arguments and 2048 argument bytes; mark truncated evidence.
- Never log command-line contents, accept caller-supplied identities, or render evidence as markup.
- Do not modify boot parameters or other applications' bpffs objects.

## Review Focus

- PID reuse between socket acceptance and authorization must fail closed; Task 6 tests a mismatched process start time.
- A state-file write failure after a kernel-map change must roll the map back; Task 5 tests both transition directions.
- A full blocked-event buffer must still deny execution; Task 3 tests the decision independently and Task 9 verifies it in a VM.
- Argument strings containing whitespace, quotes, invalid UTF-8 or over-limit data must remain unambiguous; Task 1 tests escaping and truncation.
- Stale or incompatible pinned BPF objects must not create an enforcement gap or remove unrelated pins; Tasks 4 and 9 test adoption, replacement and cleanup scope.

---

### Task 1: Alert Evidence and Schema Version 2

**Files:**
- Modify: `include/memspy/alert.h`
- Modify: `src/common/alert_json.c`
- Modify: `src/daemon/store.c`
- Modify: `src/daemon/sensor.c`
- Test: `tests/unit/test_alert_json.c`
- Test: `tests/unit/test_store.c`
- Test: `tests/unit/test_sensor.c`

**Interfaces:**
- Produces: `enum ms_alert_action { MS_ALERT_DETECTED, MS_ALERT_BLOCKED }`.
- Produces: alert fields `action`, `username`, `launcher_exe`, `parent_exe`, and `arguments_truncated`.
- Produces: `bool ms_format_proc_arguments(const char *raw, size_t length, char *out, size_t capacity, bool *truncated)` in `sensor.h`.

- [ ] **Step 1: Write failing JSON and argument-format tests**

Add round-trip assertions for both actions and every new field. Add malformed/missing action, overlong field and invalid UTF-8 cases. Add argument cases for spaces, single quotes, empty arguments, embedded invalid UTF-8, more than 16 arguments and more than 2048 bytes; assert shell-safe quoting and `truncated=true` at either limit.

- [ ] **Step 2: Run the focused tests and confirm failure**

Run: `meson test -C build alert-json sensor --print-errorlogs`

Expected: FAIL because the new fields and formatter do not exist.

- [ ] **Step 3: Add the alert contract and bounded formatter**

Set detected alerts as the default action. Parse `/proc/<pid>/cmdline` as NUL-delimited arguments, validate each string with GLib, and produce a selectable shell-escaped display string without invoking a shell. Resolve username and parent executable during the existing process-enrichment pass; failure marks enrichment incomplete without discarding the alert.

- [ ] **Step 4: Write a failing schema migration test**

Create a version-1 database containing one known alert, open it through `ms_store_open`, then assert `PRAGMA user_version=2`, preservation of the row and the default new values. Also assert a fresh version-2 database round-trips a blocked alert.

- [ ] **Step 5: Implement transactional schema migration and JSON v2**

Use `ALTER TABLE ... ADD COLUMN ... DEFAULT ...` inside one immediate transaction. Update insert/select bindings and JSON validation without accepting unknown action values.

- [ ] **Step 6: Run focused tests**

Run: `meson test -C build alert-json store sensor --print-errorlogs`

Expected: all three PASS.

- [ ] **Step 7: Commit**

```bash
git add include/memspy/alert.h src/common/alert_json.c src/daemon/store.c src/daemon/sensor.c src/daemon/sensor.h tests/unit/test_alert_json.c tests/unit/test_store.c tests/unit/test_sensor.c
git commit -m "Add response evidence to alert records"
```

### Task 2: Persistent Response State and Launcher Allowlist

**Files:**
- Create: `src/daemon/response_config.h`
- Create: `src/daemon/response_config.c`
- Create: `src/bpf/memspy_enforce_shared.h`
- Create: `config/response-allowlist.conf`
- Create: `tests/unit/test_response_config.c`
- Modify: `tests/meson.build`

**Interfaces:**
- Produces: `struct ms_launcher_key { __u64 device; __u64 inode; }` in the shared kernel/userspace header.
- Produces: `bool ms_response_state_load(const char *path, bool *enabled, struct ms_error *error)`.
- Produces: `bool ms_response_state_store(const char *path, bool enabled, struct ms_error *error)`.
- Produces: `bool ms_response_allowlist_load(const char *path, GArray **keys, size_t *rejected, struct ms_error *warning)`.

- [ ] **Step 1: Write failing state and allowlist tests**

Cover missing state as disabled, exact `enabled\n`/`disabled\n` values, rejection of symlinks, unexpected ownership, group/world-writable files, oversized content, relative paths, non-regular/non-executable launchers, duplicate entries and more than 4096 entries. Assert invalid allowlist entries are omitted and counted while valid entries remain, and a failed state replacement leaves the prior confirmed file intact.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `meson test -C build response-config --print-errorlogs`

Expected: FAIL because the response-config module does not exist.

- [ ] **Step 3: Implement secure state and allowlist loading**

Open files with `O_NOFOLLOW|O_CLOEXEC`, require ownership by the effective daemon UID and reject group/world write bits. Persist state with a same-directory temporary file, mode `0600`, `fsync`, `rename` and directory `fsync`. Resolve valid allowlist entries to unique `st_dev`/`st_ino` keys without retaining open descriptors; skip unsafe entries and return their count plus a bounded warning so enforcement stays fail-closed.

- [ ] **Step 4: Add the empty default allowlist**

Document that each non-comment line is an absolute launcher path and that allowing a launcher permits all of its memfd executions.

- [ ] **Step 5: Run focused tests**

Run: `meson test -C build response-config --print-errorlogs`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/daemon/response_config.c src/daemon/response_config.h src/bpf/memspy_enforce_shared.h config/response-allowlist.conf tests/unit/test_response_config.c tests/meson.build
git commit -m "Add secure response mode configuration"
```

### Task 3: BPF LSM Decision and Event ABI

**Files:**
- Modify: `src/bpf/memspy_enforce_shared.h`
- Create: `src/bpf/memspy_enforce.bpf.c`
- Modify: `meson.build`
- Create: `tests/unit/test_enforce_abi.c`
- Modify: `tests/meson.build`

**Interfaces:**
- Produces: `MS_ENFORCE_EVENT_ABI`, `MS_ENFORCE_MAX_ARGS=16`, `MS_ENFORCE_ARG_BYTES=2048`.
- Produces: `struct ms_enforce_event` and the pure `ms_enforce_should_deny()` decision helper; consumes Task 2's `struct ms_launcher_key`.
- Produces BPF maps: `response_enabled`, `launcher_allowlist`, `pending_exec`, `enforce_events`, and `enforce_counters`.
- Produces build targets `memspy-enforce-bpf` and `memspy-enforce-bpf-skeleton`.

- [ ] **Step 1: Write the failing ABI/decision test**

Assert disabled mode always allows, enabled non-memfd allows, tmpfs without `memfd:` allows, matching memfd plus allowlisted launcher allows, and matching memfd without an exemption denies. Assert fixed structure sizes and flag values used by userspace.

- [ ] **Step 2: Run the test and confirm failure**

Run: `meson test -C build enforce-abi --print-errorlogs`

Expected: FAIL because the shared ABI does not exist.

- [ ] **Step 3: Add the CO-RE build target**

Generate build-directory `vmlinux.h` from `/sys/kernel/btf/vmlinux`, then compile the separate enforcement object with `bpf_core_read.h`. Do not add LSM sections to the existing detection object.

- [ ] **Step 4: Implement exec capture and LSM denial**

Capture `execve` and `execveat` filename/arguments into `pending_exec`. In `lsm/bprm_check_security`, combine shmem/tmpfs superblock identity with the kernel-created `memfd:` dentry prefix, compare the pre-exec launcher key, emit a bounded event and return `-EACCES`. Increment a denial counter before attempting event delivery.

- [ ] **Step 5: Compile and run the ABI test**

Run: `meson compile -C build memspy-enforce-bpf && meson test -C build enforce-abi --print-errorlogs`

Expected: object compiles and test PASS.

- [ ] **Step 6: Commit**

```bash
git add src/bpf/memspy_enforce.bpf.c src/bpf/memspy_enforce_shared.h meson.build tests/unit/test_enforce_abi.c tests/meson.build
git commit -m "Add optional BPF LSM memfd enforcement"
```

### Task 4: Userspace Enforcer and Pinned Lifecycle

**Files:**
- Create: `src/daemon/enforcer.h`
- Create: `src/daemon/enforcer.c`
- Create: `tests/unit/test_enforcer.c`
- Modify: `tests/meson.build`
- Modify: `meson.build`

**Interfaces:**
- Produces: `typedef void (*ms_blocked_cb)(const struct ms_alert *alert, void *userdata)`.
- Produces: `struct ms_enforcer_status { bool supported; bool enabled; uint64_t denied; uint64_t lost_events; char reason[256]; }`.
- Produces: `bool ms_enforcer_open(struct ms_enforcer **out, const char *pin_dir, ms_blocked_cb callback, void *userdata, struct ms_error *error)`.
- Produces: `bool ms_enforcer_attach(struct ms_enforcer *enforcer, const GArray *launcher_keys, bool requested, struct ms_error *error)`.
- Produces: `bool ms_enforcer_set_enabled(struct ms_enforcer *enforcer, bool enabled, struct ms_error *error)`.
- Produces: `int ms_enforcer_poll(struct ms_enforcer *enforcer, int timeout_ms, struct ms_error *error)` and `void ms_enforcer_status(const struct ms_enforcer *enforcer, struct ms_enforcer_status *out)`.

- [ ] **Step 1: Write failing event-conversion and lifecycle tests**

Convert a valid blocked event into `BLOCKED_MEMFD_EXEC` with action blocked, high severity, launcher data, username/UID, parent executable, escaped arguments and truncation flags. Reject wrong ABI, zero PID, unterminated fields and invalid lengths. Through injected BPF filesystem operations, test unsupported attach, compatible pin adoption, incompatible replacement ordering, unrelated pin preservation and lost-event accounting.

- [ ] **Step 2: Run the focused test and confirm failure**

Run: `meson test -C build enforcer --print-errorlogs`

Expected: FAIL because the enforcer does not exist.

- [ ] **Step 3: Implement optional loading and blocked-event conversion**

Treat load/attach/pin failures as `supported=false` status, not daemon-fatal errors. Validate every event before reading process metadata. Do not log captured arguments.

- [ ] **Step 4: Implement safe pin adoption and replacement**

Confine paths to the exact configured MemSpy pin directory. Validate object/map ABI before adoption. For replacement, attach and enable the new object before closing and unlinking the old MemSpy link. Never enumerate or remove the parent bpffs directory.

- [ ] **Step 5: Run focused tests**

Run: `meson test -C build enforcer --print-errorlogs`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/daemon/enforcer.c src/daemon/enforcer.h tests/unit/test_enforcer.c tests/meson.build meson.build
git commit -m "Manage persistent memfd enforcement"
```

### Task 5: Daemon Response State Machine and Health

**Files:**
- Modify: `include/memspy/health.h`
- Modify: `src/daemon/health.c`
- Modify: `src/daemon/app.h`
- Modify: `src/daemon/app.c`
- Modify: `src/daemon/main.c`
- Modify: `tests/unit/test_daemon.c`

**Interfaces:**
- Produces health fields `response_supported`, `response_requested`, `response_active`, `blocked_execs`, `lost_block_events`, and `response_reason`.
- Produces: `bool ms_app_set_response(struct ms_app *app, bool enabled, struct ms_error *error)`.
- Consumes: Task 2 state/allowlist APIs and Task 4 enforcer APIs.

- [ ] **Step 1: Write failing daemon transition tests**

Cover unsupported startup, disabled startup, persisted-enabled startup, invalid state defaulting disabled/degraded, invalid allowlist entries being omitted/degraded, blocked-alert insertion/publishing, storage failure while denial remains active, and enforcer counter health updates. For both enable and disable, inject a persistence failure after the map update and assert the map rolls back to the prior confirmed state.

- [ ] **Step 2: Run the daemon tests and confirm failure**

Run: `meson test -C build daemon --print-errorlogs`

Expected: FAIL because response state is absent.

- [ ] **Step 3: Wire enforcer ownership into the daemon**

Extend `ms_app_config` with response-state, response-allowlist and pin-directory paths. Read configuration before attach, keep detection startup independent, poll blocked events without delaying the existing sensor loop, and publish blocked alerts through the same bounded storage queue.

- [ ] **Step 4: Implement confirmed transitions and health**

Serialize state changes. Change the kernel map, persist the new state, and roll the map back if persistence fails. Publish health after each confirmed transition or failure. Never label response active from the requested value alone.

- [ ] **Step 5: Add CLI defaults and support probe**

Add defaults `/var/lib/memspy/response-mode`, `/etc/memspy/response-allowlist.conf`, and `/sys/fs/bpf/memspy`. Add `--check-response` to perform a disabled attach/pin/unpin probe and return success for available, exit 3 for unavailable, without changing persisted state.

- [ ] **Step 6: Run daemon and API tests**

Run: `meson test -C build daemon --print-errorlogs`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add include/memspy/health.h src/daemon/health.c src/daemon/app.c src/daemon/app.h src/daemon/main.c tests/unit/test_daemon.c
git commit -m "Integrate response mode with memspyd"
```

### Task 6: Polkit-Authorized Control API

**Files:**
- Create: `src/daemon/authorizer.h`
- Create: `src/daemon/authorizer.c`
- Modify: `src/daemon/api.h`
- Modify: `src/daemon/api.c`
- Modify: `src/daemon/app.c`
- Modify: `include/memspy/protocol.h`
- Modify: `src/ui/client.h`
- Modify: `src/ui/client.c`
- Modify: `meson.build`
- Modify: `tests/unit/test_api.c`

**Interfaces:**
- Produces: `struct ms_peer_identity { pid_t pid; uid_t uid; uint64_t start_time; }` captured from `SO_PEERCRED` and `/proc/<pid>/stat`.
- Produces: protocol constant `MS_PROTOCOL_VERSION 2`.
- Produces: `bool ms_authorizer_check(struct ms_authorizer *authorizer, const struct ms_peer_identity *peer, struct ms_error *error)` for `org.memspy.response.configure`.
- Produces callback: `bool (*set_response)(const struct ms_peer_identity *, bool enabled, void *userdata, struct ms_error *)` in `ms_api_callbacks`.
- Produces client call: `bool ms_client_set_response(struct ms_client *, bool enabled, struct ms_health *confirmed, struct ms_error *)`.

- [ ] **Step 1: Write failing API tests**

Assert status includes every response field; `set_response` is rejected before hello, on protocol v1, with non-boolean input, failed authorization, cancelled authorization, missing agent, timeout, and changed process start time. Assert a successful callback returns confirmed health and two simultaneous requests are serialized.

- [ ] **Step 2: Run API tests and confirm failure**

Run: `meson test -C build api --print-errorlogs`

Expected: FAIL because protocol v2 control is absent.

- [ ] **Step 3: Store immutable peer identity per API session**

Read credentials and start time at accept; never accept PID, UID or start time from JSON. Close the session if identity capture fails. Preserve the existing test-only `socketpair` fallback without using it on a production listener.

- [ ] **Step 4: Implement Polkit authorization and request routing**

Use `polkit_unix_process_new_for_owner()` and allow user interaction. Map denial, cancellation, missing agent and timeout to distinct bounded error codes. Invoke `ms_app_set_response` only after authorization succeeds.

- [ ] **Step 5: Add the client request and health decoding**

Send one v2 `set_response` request with an `enabled` boolean and require the daemon's confirmed health object in the response.

- [ ] **Step 6: Run API tests**

Run: `meson test -C build api --print-errorlogs`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/daemon/authorizer.c src/daemon/authorizer.h src/daemon/api.c src/daemon/api.h src/daemon/app.c src/ui/client.c src/ui/client.h include/memspy/protocol.h meson.build tests/unit/test_api.c
git commit -m "Authorize response changes with Polkit"
```

### Task 7: Response Switch and Process Details UI

**Files:**
- Modify: `src/ui/window.h`
- Modify: `src/ui/window.c`
- Modify: `src/ui/main.c`
- Modify: `data/memspy-ui.css`
- Modify: `DESIGN.md`
- Modify: `tests/ui/test_ui.c`
- Modify: `tests/unit/test_ui_state.c`

**Interfaces:**
- Produces: `void ms_window_set_response_handler(struct ms_window *, void (*handler)(bool, void *), void *userdata)`.
- Produces: `void ms_window_set_response_pending(struct ms_window *, bool pending)`.
- Consumes: response fields in `struct ms_health` and `ms_client_set_response()` from Task 6.

- [ ] **Step 1: Write failing UI tests**

Assert exact switch copy for off, on, pending and unavailable states; accessible name/state; disabled interaction while pending; restoration after cancelled/failed requests; and one handler invocation per deliberate toggle. Assert blocked and detected badges plus conditional identity, execution, target, detection and truncation fields.

- [ ] **Step 2: Run UI tests under a display and confirm failure**

Run: `dbus-run-session -- xvfb-run -a meson test -C build ui --print-errorlogs`

Expected: FAIL because the switch and expanded evidence are absent.

- [ ] **Step 3: Implement the compact response control**

Place a labelled `GtkSwitch` in the status banner, reserve its layout width across states, and use text plus existing semantic icons. Suppress programmatic `notify::active` callbacks while applying daemon health.

- [ ] **Step 4: Perform mode changes off the GTK thread**

Open a separate short-lived client connection for each toggle so the subscribed connection remains single-reader. Marshal pending and confirmed/error states back through `g_idle_add`; discard results during shutdown.

- [ ] **Step 5: Implement grouped process details**

Keep rows compact. Rename the expander to `Process details`, omit meaningless fields, make values selectable/wrapping, and render all evidence with plain `gtk_label_set_text` semantics. Add `Blocked`/`Detected` outcome text without relying on color.

- [ ] **Step 6: Update design tokens and run UI tests**

Run: `dbus-run-session -- xvfb-run -a meson test -C build ui --print-errorlogs && meson test -C build ui-state --print-errorlogs`

Expected: both PASS.

- [ ] **Step 7: Commit**

```bash
git add src/ui/window.c src/ui/window.h src/ui/main.c data/memspy-ui.css DESIGN.md tests/ui/test_ui.c tests/unit/test_ui_state.c
git commit -m "Add response control and process evidence UI"
```

### Task 8: Packaging, Installation and Documentation

**Files:**
- Create: `packaging/common/org.memspy.response.policy`
- Create: `packaging/common/cleanup-bpf.sh`
- Create: `uninstall.sh`
- Modify: `meson.build`
- Modify: `install.sh`
- Modify: `packaging/common/memspyd.service`
- Modify: `.github/workflows/ci.yml`
- Modify: `README.md`
- Modify: `docs/memspyd.8`
- Modify: `docs/memspyd.8.md`
- Modify: `docs/memspy-ui.1`
- Modify: `docs/memspy-ui.1.md`
- Modify: `tests/package/test_install.sh`
- Modify: `tests/package/test_ubuntu_installer.sh`
- Modify: `tests/package/test_ci_dependencies.sh`

**Interfaces:**
- Consumes: `memspyd --check-response` from Task 5.
- Installs: enforcement object, response allowlist, Polkit action and exact-scope cleanup helper.

- [ ] **Step 1: Write failing package contract tests**

Assert every new artifact and dependency is installed by the source installer on Debian/Ubuntu, Fedora and Arch; config files are preserved; Polkit action ID is exact; the service has `CAP_BPF`, `CAP_PERFMON` and a narrow `/sys/fs/bpf/memspy` writable path; cleanup refuses any path outside that directory.

- [ ] **Step 2: Run package tests and confirm failure**

Run: `meson test -C build installer ci-dependencies --print-errorlogs && sh tests/package/test_install.sh build`

Expected: FAIL because response artifacts are not packaged.

- [ ] **Step 3: Add Polkit and service integration**

Install `org.memspy.response.configure` with `auth_admin_keep` defaults. Add `polkit-gobject-1` build/runtime packages. Preserve the existing hardening directives and grant only capabilities and paths demonstrated by the enforcement tests.

- [ ] **Step 4: Update install and uninstall flows**

After installation and before starting the final service, run the support probe and print the exact available/unavailable result without failing detection-only installation. On uninstall, disable the map and remove only `/sys/fs/bpf/memspy` pins before removing binaries; keep history unless `--remove-data` is explicitly passed.

- [ ] **Step 5: Update user documentation**

Replace “detection-only” absolutes with precise default/optional behavior. Document supported states, Polkit prompts, launcher allowlist risk, BPF LSM checks, recovery commands and the fact that MemSpy is not a complete endpoint-protection product. Update both Markdown man-page sources and their installed roff counterparts.

- [ ] **Step 6: Run package and documentation checks**

Run: `meson test -C build installer migration ci-dependencies build-portability --print-errorlogs && sh tests/package/test_install.sh build`

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add packaging/common packaging/ubuntu config uninstall.sh install.sh meson.build .github/workflows/ci.yml README.md docs tests/package
git commit -m "Package and document response mode"
```

### Task 9: Privileged Enforcement Matrix and Final Verification

**Files:**
- Modify: `test-samples/memfd_exec.c`
- Create: `tests/integration/enforcer_harness.c`
- Create: `tests/integration/test_enforcer.sh`
- Modify: `tests/integration/test_sensor.sh`
- Modify: `tests/vm/run_matrix.sh`
- Modify: `tests/meson.build`

**Interfaces:**
- Consumes: the complete daemon, BPF objects and package artifacts from Tasks 1–8.

- [ ] **Step 1: Make the memfd fixture prove whether its payload started**

Add an optional inherited result descriptor. The child writes one byte only after successful memfd execution; the parent reports `EACCES` distinctly when the LSM denies `execveat`.

- [ ] **Step 2: Write the privileged enforcement test**

Assert detection-only execution succeeds and triggers `MEMFD_EXEC`; enabled response returns `EACCES`, produces no child byte and stores one `BLOCKED_MEMFD_EXEC`; ordinary execution succeeds; an allowlisted launcher succeeds; disable restores detection-only behavior.

- [ ] **Step 3: Add lifecycle and unsupported-host cases**

Restart `memspyd` while enabled and assert the pinned program remains active. Reboot in the VM matrix and assert state restoration. Test stale compatible adoption, incompatible replacement and exact-scope uninstall cleanup. When BPF LSM is unavailable, assert the test reports a capability skip while the detector suite still passes.

- [ ] **Step 4: Run the complete non-privileged suite**

Run: `meson setup --wipe build --buildtype=debug -Db_sanitize=address,undefined -Dintegration_tests=true && meson compile -C build && meson test -C build --no-suite privileged --print-errorlogs`

Expected: zero failures; UI may skip only when no display is installed.

- [ ] **Step 5: Run GTK and strict design checks**

Run: `dbus-run-session -- xvfb-run -a meson test -C build ui --print-errorlogs`

Run: `python /home/mrn1gativ3/.codex/plugins/cache/openai-curated-remote/frontend-design-premium/1.4.0/skills/frontend-design-premium/scripts/audit_project.py . --mode strict`

Expected: UI PASS; design audit reports zero errors and zero warnings.

- [ ] **Step 6: Run the privileged VM matrix**

Run in disposable Ubuntu/Debian, Fedora and Arch x86_64 guests: `sudo sh tests/vm/run_matrix.sh build-vm`

Expected: detection suite PASS everywhere; enforcement tests PASS where BPF LSM is active and report an explicit capability skip elsewhere.

- [ ] **Step 7: Run release install verification**

Run: `meson setup --wipe build-package --prefix=/usr --buildtype=release -Dintegration_tests=false && meson compile -C build-package && sh tests/package/test_install.sh build-package`

Expected: PASS with all installed response artifacts and hardened service settings.

- [ ] **Step 8: Commit**

```bash
git add test-samples/memfd_exec.c tests/integration tests/vm/run_matrix.sh tests/meson.build
git commit -m "Verify memfd prevention across supported hosts"
```
