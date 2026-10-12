# MemSpy Server Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a headless MemSpy CLI, precise `/proc/<pid>/mem` write detection, bounded server process context, and structured journald alert output while retaining the GTK dashboard.

**Architecture:** Keep `memspyd` as the sole privileged sensor, store writer, and response authority. Advance the local protocol and alert schema once, share one Unix-socket client between GTK and CLI, enrich accepted observations in userspace, and treat optional `/proc` and journald failures as visible degradation rather than detector failure.

**Tech Stack:** C17, libbpf CO-RE eBPF, GLib/GIO, json-c, SQLite, GTK 3, libsystemd, Meson/Ninja, systemd/PolicyKit.

**Spec:** `docs/superpowers/specs/2026-10-12-server-operations-design.md`

## Global Constraints

- Support x86_64 Linux 5.4+ with readable `/sys/kernel/btf/vmlinux`.
- Keep `memspyd` as the only privileged component; add no TCP/UDP listener or network capability.
- Keep GTK primary for desktop users and make it optional for headless builds.
- Emit `PROC_MEM_WRITE` only after a positive write result and confirmed canonical cross-process `/proc/<pid>/mem` descriptor resolution.
- Never collect written bytes, process memory, environment variables, credentials, or packet contents.
- Preserve every supported prior SQLite schema transactionally; never replace a failed database.
- Keep all kernel events, procfs strings, API messages, database values, and CLI arguments bounded and validated.
- Response changes continue through `org.memspy.response.configure`; neither client handles passwords.
- Existing detection, 30-day retention, response, allowlist, and UI behavior must remain green.

## Review Focus

- A descriptor that closes or is reused before daemon resolution must produce no `PROC_MEM_WRITE`, not a stale-target alert; pin in Task 4 sensor tests.
- A schema 1, 2, or 3 database containing existing rows must migrate to schema 4 without losing or reinterpreting fields; pin in Task 1 store tests.
- JSON mode must emit only one valid document on stdout while connection and authorization diagnostics stay on stderr; pin in Task 2 CLI tests.
- Unknown/truncated cgroup formats and vanished processes must retain the alert with empty context plus `enrichment_incomplete`; pin in Task 3 evidence tests.
- A journald write failure must not prevent storage or API publication and must be rate-limited; pin in Task 5 daemon tests.

---

### Task 1: Alert Contract, Schema 4, and API v3

**Files:**
- Modify: `include/memspy/protocol.h`
- Modify: `include/memspy/alert.h`
- Modify: `include/memspy/observation.h`
- Modify: `include/memspy/health.h`
- Modify: `src/common/alert_json.c`
- Modify: `src/daemon/store.h`
- Modify: `src/daemon/store.c`
- Modify: `src/daemon/api.c`
- Modify: `src/ui/client.c`
- Modify: `tests/unit/test_alert_json.c`
- Modify: `tests/unit/test_store.c`
- Modify: `tests/unit/test_api.c`

**Interfaces:**
- Produces: protocol version `3`; schema version `4`; extended `struct ms_alert`/`struct ms_observation`; health counters `incomplete_observations` and `journal_errors`; `bool ms_store_get(struct ms_store *, int64_t, struct ms_alert *, struct ms_error *)`; API operation `{"v":3,"op":"alert","id":N}` returning `alert_not_found` when absent.
- Consumes: existing bounded alert codec, pagination, hostile-client handling, and transactional migrations.

- [ ] **Step 1: Write failing alert-codec tests**

Add `/alert-json/server-context-roundtrip` and bounds/type cases for `grandparent_pid`, `grandparent_comm`, `grandparent_exe`, `systemd_unit`, `cgroup_path`, `container_id`, `container_runtime`, `tty`, `ssh_origin`, `pid_namespace`, `mount_namespace`, `target_namespace_pid`, and `bytes_written`. Assert a full literal fixture round-trips and invalid types/oversized strings fail. Extend health API/client tests to require non-negative `incomplete_observations` and `journal_errors`.

- [ ] **Step 2: Write failing schema and lookup tests**

Extend `/store/schema`, add migration fixtures for schema versions 1, 2, and 3, and add `/store/get-by-id`. Assert `PRAGMA user_version=4`, old fields survive, new fields use safe defaults, an inserted full alert is identical when fetched, and absent IDs return `store_not_found` without modifying the output.

- [ ] **Step 3: Write failing API v3 tests**

Update literals to version 3 and add `/api/single-alert`: an existing ID returns exactly one canonical alert, zero/negative/non-integer IDs return `invalid_request`, and an absent positive ID returns `alert_not_found`.

- [ ] **Step 4: Run the focused tests and verify RED**

Run: `meson compile -C build tests/test-alert-json tests/test-store tests/test-api && meson test -C build alert-json store api --print-errorlogs`

Expected: compile/test failures for missing fields, schema 4, store lookup, and API operation.

- [ ] **Step 5: Implement the contract and migration**

Use these fixed string capacities in `alert.h`: unit `256`, cgroup `1024`, container ID `129`, runtime `32`, and TTY `64` bytes. Add the fields named in Step 1 to both alert and observation models, add the two health counters, update the one canonical JSON codec and health encoder/decoder, migrate schema 1/2/3 transactionally to 4, and implement `ms_store_get` with the same row decoder as pagination.

- [ ] **Step 6: Implement API v3 single-alert handling**

Add strict positive `int64` parsing for `id`, call `ms_store_get`, and return the canonical codec output. Do not expose database messages or introduce a second serializer.

- [ ] **Step 7: Run focused and regression tests**

Run the Step 4 command. Expected: all three test executables pass with no sanitizer findings.

- [ ] **Step 8: Commit**

```bash
git add include/memspy src/common/alert_json.c src/daemon/store.c src/daemon/store.h src/daemon/api.c src/ui/client.c tests/unit/test_alert_json.c tests/unit/test_store.c tests/unit/test_api.c
git commit -m "Add server context to alert protocol"
```

### Task 2: Shared Local Client and `memspyctl`

**Files:**
- Create: `src/common/client.h`
- Create: `src/common/client.c`
- Create: `src/cli/main.c`
- Create: `src/cli/output.h`
- Create: `src/cli/output.c`
- Create: `tests/unit/test_cli_output.c`
- Create: `tests/integration/test_cli.sh`
- Modify: `src/ui/main.c`
- Delete: `src/ui/client.h`
- Delete: `src/ui/client.c`
- Modify: `tests/unit/test_api.c`
- Modify: `meson.build`
- Modify: `tests/meson.build`

**Interfaces:**
- Consumes: API v3 and `ms_store_get` from Task 1.
- Produces: shared existing `ms_client_*` API plus `bool ms_client_get_alert(struct ms_client *, int64_t, struct ms_alert *, struct ms_error *)`; installed `/usr/bin/memspyctl`; output functions `ms_cli_print_status`, `ms_cli_print_alert`, and `ms_cli_print_alerts` accepting `FILE *` and `bool json`.

- [ ] **Step 1: Write failing shared-client and output tests**

Add a client round-trip for one existing/missing alert to `test_api.c`. Add `test_cli_output.c` asserting human output contains rule, process, response state, and context labels; JSON output parses as exactly one document and equals the canonical alert/status values.

- [ ] **Step 2: Write failing CLI integration tests**

Run a fixture API socket and assert `status`, `alerts --limit 1`, `show ID --json`, invalid usage, unavailable socket, missing alert, and authorization failure return `0`, `2`, `3`, `5`, and `4` as specified. Capture stdout/stderr separately and assert JSON-mode stdout has no diagnostics.

- [ ] **Step 3: Run focused tests and verify RED**

Run: `meson compile -C build tests/test-api tests/test-cli-output memspyctl && meson test -C build api cli-output cli-integration --print-errorlogs`

Expected: missing target/source/API failures.

- [ ] **Step 4: Move the client without behavior changes**

Move `src/ui/client.*` to `src/common/client.*`, update UI/test include paths and Meson sources, and first verify existing API/UI compilation before adding CLI behavior.

- [ ] **Step 5: Implement the single-alert client and CLI**

Implement exact commands and exits from the spec: `status`, `alerts`, `show`, `export`, `response`, and `version`. `export ALERT_ID` is the script-oriented alias for `show ALERT_ID --json`. Bound `--limit` to `1..200`; accept only `high|medium`; parse alert IDs with full-string positive `int64` validation; keep JSON on stdout and diagnostics on stderr.

- [ ] **Step 6: Run focused tests**

Run the Step 3 command. Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add src/common/client.c src/common/client.h src/cli src/ui/main.c tests/unit/test_api.c tests/unit/test_cli_output.c tests/integration/test_cli.sh meson.build tests/meson.build
git rm src/ui/client.c src/ui/client.h
git commit -m "Add memspyctl local administration client"
```

### Task 3: Bounded Server Process Context and GTK Details

**Files:**
- Modify: `src/daemon/process_evidence.h`
- Modify: `src/daemon/process_evidence.c`
- Modify: `src/daemon/sensor.c`
- Modify: `src/daemon/enforcer.c`
- Modify: `src/daemon/policy.c`
- Create: `tests/unit/test_process_evidence.c`
- Modify: `tests/unit/test_sensor.c`
- Modify: `tests/unit/test_enforcer.c`
- Modify: `tests/unit/test_policy.c`
- Modify: `src/ui/window.c`
- Modify: `tests/ui/test_ui.c`
- Modify: `tests/meson.build`

**Interfaces:**
- Consumes: extended observation/alert fields from Task 1.
- Produces: `struct ms_process_evidence`; `bool ms_process_evidence_read_at(const char *proc_root, pid_t pid, struct ms_process_evidence *)`; production wrapper `bool ms_process_evidence_read(pid_t, struct ms_process_evidence *)`; parser `bool ms_process_cgroup_parse(const char *, struct ms_process_evidence *)`.

- [ ] **Step 1: Write failing procfs fixture tests**

Create temporary proc-root fixtures for a normal systemd service, SSH ancestry, Docker-style cgroup, Podman/libpod cgroup, containerd/Kubernetes-style scope, unknown cgroup, oversized cgroup, missing grandparent, and invalid UTF-8. Assert exact fields and that incomplete inputs return usable partial evidence with `complete=false`.

- [ ] **Step 2: Extend sensor/policy tests**

Assert an alert candidate copies parent and grandparent identity, unit, cgroup/container, TTY/SSH, and namespace IDs through observation to alert. Assert ordinary exec events retain the existing cheap enrichment behavior and do not hash additional ancestors.

- [ ] **Step 3: Add failing GTK detail tests**

Assert populated server context appears under `Identity` and `Workload`, empty workload sections are absent, and long cgroup values remain selectable/wrapping without changing compact or wide allocations.

- [ ] **Step 4: Run focused tests and verify RED**

Run: `meson compile -C build tests/test-process-evidence tests/test-sensor tests/test-policy tests/test-enforcer tests/test-ui && meson test -C build process-evidence sensor policy enforcer ui --print-errorlogs`

Expected: missing model/parser/UI failures.

- [ ] **Step 5: Implement bounded evidence reading**

Refactor the current parent reader behind `struct ms_process_evidence`. Use `openat` relative to a proc directory, cap every read, resolve parent then grandparent, parse `/proc/<pid>/cgroup`, `/proc/<pid>/stat`, `/proc/<pid>/status`, and namespace symlinks, and invoke no external command. Preserve the existing 128 MiB immediate-parent hash limit.

- [ ] **Step 6: Wire policy and GTK presentation**

Copy the new fields through sensor/enforcer/policy once. Add only conditional detail fields and omit an empty `Workload` section.

- [ ] **Step 7: Run focused tests**

Run the Step 4 command. Expected: all pass under a graphical test session; report UI skip explicitly when no display is available.

- [ ] **Step 8: Commit**

```bash
git add src/daemon/process_evidence.c src/daemon/process_evidence.h src/daemon/sensor.c src/daemon/enforcer.c src/daemon/policy.c src/ui/window.c tests/unit/test_process_evidence.c tests/unit/test_sensor.c tests/unit/test_enforcer.c tests/unit/test_policy.c tests/ui/test_ui.c tests/meson.build
git commit -m "Add server process context to alerts"
```

### Task 4: Successful `/proc/<pid>/mem` Write Detection

**Files:**
- Modify: `src/bpf/memspy_shared.h`
- Modify: `src/bpf/memspy.bpf.c`
- Modify: `src/daemon/process_evidence.h`
- Modify: `src/daemon/process_evidence.c`
- Modify: `src/daemon/sensor.c`
- Modify: `src/daemon/policy.c`
- Modify: `tests/unit/test_sensor_abi.c`
- Modify: `tests/unit/test_sensor.c`
- Modify: `tests/unit/test_policy.c`
- Create: `test-samples/proc_mem_write.c`
- Modify: `tests/integration/sensor_harness.c`
- Modify: `tests/integration/test_sensor.sh`
- Modify: `tests/meson.build`

**Interfaces:**
- Consumes: target/context fields from Tasks 1 and 3.
- Produces: kernel ABI version `2`, `MS_KERNEL_FILE_WRITE`, `MS_OBSERVATION_PROC_MEM_WRITE`, and rule `PROC_MEM_WRITE`; `bool ms_proc_mem_target_read(const char *proc_root, pid_t source_pid, int fd, pid_t *namespace_pid, pid_t *host_pid, char *target_exe, size_t capacity)`.

- [ ] **Step 1: Write failing ABI and syscall-correlation tests**

Assert `MS_KERNEL_EVENT_ABI == 2`. File-write events carry source PID, the non-negative fd in `aux`, and successful bytes in `result`; `target_pid` remains zero until userspace resolution. Cover `write`, `pwrite64`, `writev`, and `pwritev2`; failed and zero-byte returns emit nothing.

- [ ] **Step 2: Write failing descriptor-resolution tests**

Using a temporary proc-root fixture, assert canonical numeric mem targets resolve, self/non-mem/ordinary/reused/disappeared descriptors do not, numeric overflow fails, and namespace-to-host mapping either returns the literal host PID or explicitly incomplete evidence.

- [ ] **Step 3: Write failing policy tests**

Assert only a confirmed cross-process positive write produces medium `PROC_MEM_WRITE`, `bytes_written` equals the successful result, and the observation participates in the existing 30-second `INJECTION_CHAIN` correlation exactly like other cross-process writes.

- [ ] **Step 4: Add the privileged positive and negative fixture cases**

The benign fixture forks a target, opens its canonical proc mem path, performs a harmless successful write to an agreed writable address, keeps the descriptor alive until observation, and exits cleanly. Add open-only, failed-write, self-write, ordinary-file, inherited-fd, and duplicated-fd cases with exact expected rule counts.

- [ ] **Step 5: Run unit tests and verify RED**

Run: `meson compile -C build tests/test-sensor-abi tests/test-sensor tests/test-policy && meson test -C build sensor-abi sensor policy --print-errorlogs`

Expected: failures for missing event, resolver, and policy branch.

- [ ] **Step 6: Implement the minimal kernel event path**

Reuse the current pending-call LRU map. Add entry/exit handlers for the four write syscall variants, emit only on `result > 0`, store fd in `aux`, and never read user buffers or iovec contents.

- [ ] **Step 7: Confirm descriptors in userspace and apply policy**

Resolve the live fd under the source proc directory, reject self/unconfirmed targets, enrich the target when possible, and increment `health.incomplete_observations` when resolution loses the close/exit race. Add the policy branch and injection correlation.

- [ ] **Step 8: Run unit and privileged VM tests**

Run unit command from Step 5, then in a disposable supported VM: `sudo sh tests/integration/test_sensor.sh build`

Expected: all prior fixtures plus the exact positive/negative proc-memory cases pass.

- [ ] **Step 9: Commit**

```bash
git add src/bpf src/daemon/process_evidence.c src/daemon/process_evidence.h src/daemon/sensor.c src/daemon/policy.c test-samples/proc_mem_write.c tests/unit/test_sensor_abi.c tests/unit/test_sensor.c tests/unit/test_policy.c tests/integration/sensor_harness.c tests/integration/test_sensor.sh tests/meson.build
git commit -m "Detect successful proc memory writes"
```

### Task 5: Structured Journald Alert Output

**Files:**
- Create: `src/daemon/journal.h`
- Create: `src/daemon/journal.c`
- Modify: `src/daemon/app.h`
- Modify: `src/daemon/app.c`
- Modify: `meson.build`
- Create: `tests/unit/test_journal.c`
- Modify: `tests/unit/test_daemon.c`
- Modify: `tests/meson.build`
- Modify: `packaging/common/memspyd.service`

**Interfaces:**
- Consumes: canonical `ms_alert_to_json` from Task 1.
- Produces: `bool ms_journal_alert(const struct ms_alert *, struct ms_error *)`; injectable `journal_alert` dependency in `struct ms_app_dependencies` for failure tests.

- [ ] **Step 1: Write failing journal-field tests**

Assert high maps to `LOG_ALERT`, medium maps to `LOG_WARNING`, and fields exactly include `MESSAGE`, `MEMSPY_ALERT_ID`, `MEMSPY_RULE`, `MEMSPY_SEVERITY`, `MEMSPY_ACTION`, `MEMSPY_PID`, `MEMSPY_UID`, and one parseable canonical `MEMSPY_ALERT_JSON`. Assert newline/control characters cannot create extra fields.

- [ ] **Step 2: Write failing daemon failure-path tests**

Inject a journal writer that fails repeatedly. Assert storage and publication still occur once, `health.journal_errors` increments, health degrades, and only one warning is requested within a 60-second rate-limit window.

- [ ] **Step 3: Run focused tests and verify RED**

Run: `meson compile -C build tests/test-journal tests/test-daemon && meson test -C build journal daemon --print-errorlogs`

Expected: missing module/dependency failures.

- [ ] **Step 4: Implement the journal adapter and daemon call**

Use `sd_journal_send` directly, the canonical JSON serializer, decimal buffers with checked bounds, and no shell. Call it only after storage assigns the alert ID and before/after API publication without making either depend on journal success.

- [ ] **Step 5: Verify service sandbox access**

In a disposable VM, restart the installed unit, trigger one fixture, and assert `journalctl -u memspyd -o json` contains the stable `MEMSPY_*` fields while `PrivateNetwork=yes` remains enabled.

- [ ] **Step 6: Run tests and commit**

Run the Step 3 command. Expected: pass.

```bash
git add src/daemon/journal.c src/daemon/journal.h src/daemon/app.c src/daemon/app.h meson.build tests/unit/test_journal.c tests/unit/test_daemon.c tests/meson.build packaging/common/memspyd.service
git commit -m "Publish structured alerts to journald"
```

### Task 6: Optional GTK and Headless Installer Profile

**Files:**
- Create: `meson_options.txt`
- Modify: `meson.build`
- Modify: `tests/meson.build`
- Modify: `install.sh`
- Modify: `packaging/ubuntu/install-test-vm.sh`
- Modify: `tests/package/test_ubuntu_installer.sh`
- Modify: `tests/package/test_install.sh`
- Modify: `tests/package/test_ci_dependencies.sh`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Consumes: `memspyctl` and libsystemd dependency from Tasks 2 and 5.
- Produces: Meson feature option `desktop_ui` (`auto|enabled|disabled`); installer profile argument `gnome|kde|headless`; desktop/full and headless staged-install checks.

- [ ] **Step 1: Write failing installer-profile tests**

Exercise installer detection with command shims: no desktop selects headless; explicit headless skips GTK/AppIndicator/libnotify packages and desktop user requirement; GNOME/KDE retain current validation; dual desktop remains explicit. Assert all distributions include their libsystemd development package.

- [ ] **Step 2: Write failing staged-install tests**

Configure once with `-Ddesktop_ui=enabled` and once with `disabled`. Assert both install `memspyd`, `memspyctl`, BPF/config/systemd/PolicyKit/man files; only enabled installs `memspy-ui`, CSS, icons, applications, and autostart files.

- [ ] **Step 3: Run package tests and verify RED**

Run: `meson test -C build installer ci-dependencies --print-errorlogs` plus both `tests/package/test_install.sh` staged profiles.

Expected: missing feature option/profile/dependency failures.

- [ ] **Step 4: Make UI dependencies and targets conditional**

Define `desktop_ui` as a Meson feature. Require GTK/AppIndicator/libnotify only when enabled, auto-enable when found in `auto`, and gate UI executable/assets/man page/tests together. Daemon/CLI builds must not reference UI dependencies.

- [ ] **Step 5: Implement installer profile selection**

Update usage to `[reader-user] [gnome|kde|headless]`. Auto-select headless when neither desktop exists, install only profile dependencies, pass the exact Meson feature state, add only a supplied/trusted reader user to `memspy-ui`, and print the selected profile and correct post-install instructions.

- [ ] **Step 6: Run package and full non-privileged tests**

Run both staged builds and `meson test -C build --no-suite privileged --print-errorlogs`. Expected: all enabled/disabled package assertions and non-privileged tests pass.

- [ ] **Step 7: Commit**

```bash
git add meson_options.txt meson.build tests/meson.build install.sh packaging/ubuntu/install-test-vm.sh tests/package .github/workflows/ci.yml
git commit -m "Support headless MemSpy installation"
```

### Task 7: Documentation and Release Verification

**Files:**
- Create: `docs/memspyctl.1.md`
- Create: `docs/memspyctl.1`
- Modify: `docs/memspyd.8.md`
- Modify: `docs/memspyd.8`
- Modify: `docs/memspy-ui.1.md`
- Modify: `docs/memspy-ui.1`
- Modify: `README.md`
- Modify: `DESIGN.md`
- Modify: `tests/package/test_install.sh`

**Interfaces:**
- Consumes: completed commands, fields, installer profiles, limitations, and journal fields from Tasks 1-6.
- Produces: accurate user/contributor documentation and final verification evidence.

- [ ] **Step 1: Update README and man pages**

Document desktop/server profiles, full `memspyctl` examples and exits, `PROC_MEM_WRITE` precision boundary and close-race limitation, server context, journald JSON queries, trusted reader-group access, privacy/retention impact, headless installation, dependencies, architecture diagram, detection table, limitations, and repository layout.

- [ ] **Step 2: Update the design context and install assertions**

Record CLI/headless ownership in `DESIGN.md` without changing the GTK visual identity. Assert the new man page and profile-specific installed files in `test_install.sh`.

- [ ] **Step 3: Run fresh release verification**

Run:

```bash
meson setup build-final --wipe --buildtype=debug -Db_sanitize=address,undefined -Ddesktop_ui=enabled
meson compile -C build-final
ASAN_OPTIONS=detect_leaks=0 meson test -C build-final --no-suite privileged --print-errorlogs
meson setup build-headless --wipe --buildtype=release -Ddesktop_ui=disabled
meson compile -C build-headless
meson test -C build-headless --no-suite privileged --print-errorlogs
sh tests/package/test_install.sh build-final desktop
sh tests/package/test_install.sh build-headless headless
```

Expected: zero failures; graphical tests may skip only when no display is present and must pass under the CI Xvfb job.

- [ ] **Step 4: Run the privileged VM matrix**

Run: `sudo sh tests/vm/run_matrix.sh build-vm`

Expected: every legacy fixture and the new `/proc/<pid>/mem` positive/negative matrix passes; structured journal record is queryable; detection and response capability checks retain their expected results.

- [ ] **Step 5: Audit the final diff**

Run `git diff --check`, search for protocol version 2/schema version 3 stale assumptions, inspect installed-file manifests, and confirm no network capability, payload logging, environment capture, or arbitrary privileged output path was introduced.

- [ ] **Step 6: Commit**

```bash
git add README.md DESIGN.md docs tests/package/test_install.sh
git commit -m "Document MemSpy server operations"
```

