# Expanded Response Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the single Response-mode switch reliably deny every currently detected fileless execution and injection primitive, with rule-scoped exemptions and truthful blocked alerts.

**Architecture:** Extend the existing separate BPF-LSM response object instead of changing the observational sensor. Keep one enabled map and one daemon lifecycle, add fixed enforcement kinds and rule-scoped device/inode allowlist keys, and activate only after all links plus the ptrace relationship barrier succeed.

**Tech Stack:** C17, libbpf CO-RE, BPF LSM, GLib, json-c, Meson, systemd/PolicyKit.

**Spec:** `docs/superpowers/specs/2026-10-14-expanded-response-and-evidence-design.md`

## Global Constraints

- Linux x86_64, kernel 5.x and newer where each required BPF-LSM hook is supported.
- Detection remains operational when Response mode is unavailable.
- Response is off by default and all-or-nothing when enabled.
- No new runtime dependency or protocol-version bump.
- Old path-only allowlist lines remain MEMFD_EXEC-only exemptions.
- A denied operation stays denied if its perf event is lost.

## Review Focus

- A malformed or disappearing `/proc/<pid>/status` during activation must roll back, never report On.
- An allowlist path replaced after parsing must not broaden policy; device/inode identity is authoritative.
- A PID reused between syscall intent and LSM authorization must not be denied as the old target.
- Self-directed memory access must not be blocked.
- Partial hook/pin compatibility must be rejected rather than adopted.

---

### Task 1: Rule-scoped response configuration

**Files:**
- Modify: `src/bpf/memspy_enforce_shared.h`
- Modify: `src/daemon/response_config.h`
- Modify: `src/daemon/response_config.c`
- Modify: `tests/unit/test_response_config.c`
- Modify: `config/response-allowlist.conf`

**Interfaces:**
- Produces: `enum ms_response_rule`, `struct ms_allowlist_key { __u32 rule; __u32 reserved; __u64 device; __u64 inode; }`.
- Produces: unchanged `ms_response_allowlist_load(...)`, now returning `GArray<struct ms_allowlist_key>`.

- [ ] Write parser tests for all five rule names, multiple paths per rule, the same path under multiple rules, legacy path-only MEMFD_EXEC mapping, duplicates, unknown rules, relative paths, and unsafe files.
- [ ] Run `meson test -C build-install response-config --print-errorlogs`; expect the new format assertions to fail.
- [ ] Add the rule enum/key and minimally update parsing, deduplication, limits, and warnings.
- [ ] Run the response-config test; expect PASS.
- [ ] Record the verified task in the execution ledger; commit if repository metadata is writable.

### Task 2: Enforcement ABI and pure policy predicates

**Files:**
- Modify: `src/bpf/memspy_enforce_shared.h`
- Modify: `tests/unit/test_enforce_abi.c`

**Interfaces:**
- Consumes: `enum ms_response_rule`, `struct ms_allowlist_key` from Task 1.
- Produces: ABI v2 event kinds for all five blocked rules, actor/target fields, fixed per-kind counters, and pure deny predicates used by BPF and unit tests.

- [ ] Add failing ABI/predicate tests covering disabled response, exact rule exemption, self access, missing target identity, each deny kind, and counter layout.
- [ ] Run `meson test -C build-install enforce-abi --print-errorlogs`; expect failures against ABI v1.
- [ ] Implement the minimal shared ABI and predicates without kernel-only helpers.
- [ ] Run the enforce-abi test; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 3: Complete BPF-LSM policy

**Files:**
- Modify: `src/bpf/memspy_enforce.bpf.c`
- Modify: generated skeleton inputs in `meson.build` only if required by existing generation rules.
- Modify: `tests/unit/test_build_portability.sh`

**Interfaces:**
- Consumes: ABI v2 and rule-scoped keys from Tasks 1-2.
- Produces: required LSM programs/tracepoint intent tracking and perf events for memfd, deleted exec, process_vm_writev, ptrace admission, and `/proc/<pid>/mem` writes.

- [ ] Add a portability assertion that the object exposes every required program and map; run it and expect failure.
- [ ] Implement the smallest verifier-safe hooks, using task identity and inode/superblock data rather than userspace path trust.
- [ ] Compile with `meson compile -C build-install memspy_enforce.bpf.o`; expect success without verifier-independent compiler warnings.
- [ ] Run build-portability and enforce-abi tests; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 4: Daemon lifecycle, blocked alerts, and health

**Files:**
- Modify: `src/daemon/enforcer.h`
- Modify: `src/daemon/enforcer.c`
- Modify: `include/memspy/health.h`
- Modify: `src/daemon/health.c`
- Modify: `src/daemon/api.c`
- Modify: `src/common/client.c`
- Modify: `src/cli/output.c`
- Modify: `tests/unit/test_enforcer.c`
- Modify: `tests/unit/test_daemon.c`
- Modify: `tests/unit/test_cli_output.c`
- Modify: `tests/api/test_api.c`

**Interfaces:**
- Consumes: all BPF programs/maps and ABI v2.
- Produces: `blocked_operations`, compatible `blocked_execs`, all-or-nothing response status, and conversion to the five `BLOCKED_*` alerts.

- [ ] Add failing tests for every event conversion, malformed kinds, complete-link adoption rejection, aggregate/execution counters, and additive health JSON.
- [ ] Run `meson test -C build-install enforcer daemon cli-output api --print-errorlogs`; expect new assertions to fail.
- [ ] Update the enforcer backend map/link tables, configuration, polling, status, API/client parsing, and CLI rendering.
- [ ] Run the focused tests; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 5: Ptrace activation barrier

**Files:**
- Create: `src/daemon/ptrace_barrier.h`
- Create: `src/daemon/ptrace_barrier.c`
- Create: `tests/unit/test_ptrace_barrier.c`
- Modify: `src/daemon/daemon.c`
- Modify: `meson.build`
- Modify: `tests/meson.build`

**Interfaces:**
- Produces: `bool ms_ptrace_barrier_check(const char *proc_root, const GArray *allowlist, struct ms_error *error)`.
- Consumes: PTRACE_WRITE allowlist identities and existing response enable/rollback path.

- [ ] Add fixture-proc tests for no tracers, exempt tracer, non-exempt tracer, malformed status, disappearing PID, and PID identity change.
- [ ] Run `meson test -C build-install ptrace-barrier --print-errorlogs`; expect missing implementation failure.
- [ ] Implement the procfs scan and integrate enable → barrier → persist, rolling the map back on any failure.
- [ ] Run ptrace-barrier, daemon, and API tests; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 6: Privileged fixtures, documentation, and full verification

**Files:**
- Modify: `tests/integration/` fixtures and harnesses for the five primitives.
- Modify: `tests/vm/run_matrix.sh`
- Modify: `README.md`
- Modify: `docs/memspyd.8`
- Modify: `docs/memspy-ui.1`

**Interfaces:**
- Consumes: complete Response policy.
- Produces: reproducible off/on/exempt validation and administrator guidance.

- [ ] Add matrix checks for detected-off, blocked-on, exact-rule exemption, disablement, restart/adoption, event loss, and active LSM coexistence.
- [ ] Run all non-privileged tests with `meson test -C build-install --no-suite privileged --print-errorlogs`; expect PASS.
- [ ] Document exact blocked primitives, ptrace admission semantics/barrier, config examples, and kernel requirements.
- [ ] Run `meson compile -C build-install` and the full available non-privileged suite again; expect PASS without GTK/libbpf warnings.
- [ ] Record unrun privileged cases explicitly; commit if possible.
