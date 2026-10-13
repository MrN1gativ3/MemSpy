# Expanded Response and Executable Evidence Design

Date: 2026-10-14
Status: Approved design

## Purpose

Expand MemSpy's optional Response mode from memfd-only prevention to prevention of every currently detected fileless-execution and process-injection primitive that has a reliable pre-operation kernel decision point. At the same time, improve incident evidence so an administrator can identify the actor, executed payload, target, pre-exec launcher, and parent process using complete executable paths and MD5/SHA-256 hashes when those images remain available.

The primary users are Linux server administrators and desktop analysts. Detection must remain available when prevention is unsupported, disabled, or fails to initialize.

## Goals

- Keep one PolicyKit-authorized Response-mode switch.
- Deny memfd execution, deleted-image execution, `process_vm_writev`, ptrace access, and writes through `/proc/<pid>/mem` when Response mode is active.
- Record every successful denial as a distinct blocked alert.
- Preserve the existing detection rules when Response mode is off.
- Support rule-specific executable exemptions without silently broadening existing exemptions.
- Store and display full executable identities, MD5, SHA-256, and precise evidence-failure reasons.
- Preserve existing alert history through an additive database migration.
- Make response capability all-or-nothing rather than claiming partial protection.

## Non-goals

- Killing or quarantining a process after an operation succeeds.
- Hashing memory contents directly inside eBPF.
- Recovering bytes that no longer have an open kernel or procfs representation.
- Network containment, payload scanning, or malware-family classification.
- Per-rule response switches in the GTK application.

## Enforcement architecture

The existing response eBPF object remains separate from the observational sensor. A single `response_enabled` map controls all enforcement programs. The daemon stages, validates, pins, and promotes the complete response object using the existing all-or-nothing pin lifecycle.

| Detected behavior | Enforcement decision | Blocked rule |
| --- | --- | --- |
| `MEMFD_EXEC` | Deny at `bprm_check_security` when the executable is a confirmed memfd image | `BLOCKED_MEMFD_EXEC` |
| `DELETED_EXEC` | Deny at `bprm_check_security` when the executable dentry is unlinked | `BLOCKED_DELETED_EXEC` |
| `PROCESS_VM_WRITE` | Mark `process_vm_writev` intent at syscall entry and deny the matching cross-process `ptrace_access_check` | `BLOCKED_PROCESS_VM_WRITE` |
| `PTRACE_WRITE` | Deny ptrace attachment and `PTRACE_TRACEME` before a tracing relationship is established | `BLOCKED_PTRACE_ACCESS` |
| `PROC_MEM_WRITE` | Deny write permission on a sensor-equivalent, canonical `/proc/<pid>/mem` file | `BLOCKED_PROC_MEM_WRITE` |
| `INJECTION_CHAIN` | No separate hook; prevent the chain by denying its injection or suspicious-execution stage | Underlying blocked rule |

Ptrace enforcement is intentionally broader than the detection rule. Linux does not provide an LSM decision at each modifying `PTRACE_POKEDATA` operation after attachment, so reliable prevention requires rejecting ptrace admission for non-exempt callers. The UI and documentation must describe this behavior explicitly.

Enabling Response mode uses an activation barrier for pre-existing ptrace relationships. The daemon first enables kernel enforcement so no new non-exempt relationship can be created, then scans `/proc/*/status` for `TracerPid`. Allowlisted tracers are accepted. If a non-allowlisted relationship exists, or either process cannot be verified safely, activation is rolled back and the daemon reports `Cannot enable response mode while PID X is traced by PID Y`. Response mode is reported On only after this scan succeeds. This avoids claiming protection while an already-attached tracer could still modify memory.

Kernel decisions use task, file, inode, superblock, and syscall-intent data. They must not trust a userspace path string. A denied operation remains denied if event publication fails.

Self-directed memory operations are not blocked. Cross-process target identity must be validated before denial so PID reuse or an incomplete target lookup does not produce a guessed attribution.

## Response allowlist

`/etc/memspy/response-allowlist.conf` gains a rule-specific format:

```text
MEMFD_EXEC /usr/bin/trusted-runtime
DELETED_EXEC /usr/lib/example/updater
PROCESS_VM_WRITE /usr/bin/trusted-profiler
PTRACE_WRITE /usr/bin/gdb
PROC_MEM_WRITE /usr/lib/example/diagnostic-agent
```

Paths must remain absolute, canonical, root-controlled regular executable files. The daemon resolves accepted entries into device/inode keys and loads rule-scoped keys into the BPF allowlist map.

For backward compatibility, an existing line containing only an absolute path is treated as a `MEMFD_EXEC` exemption. It must not exempt the executable from any newly added blocker. Unknown rules, duplicate entries, unsafe files, and malformed lines are rejected and reported through degraded health; they do not disable the remaining response policy.

## Enforcement events and health

The response event ABI gains a denial kind for each blocked primitive plus the fields needed to identify the actor and target. The ABI version, map compatibility checks, pin names, and tests change together so old pinned objects cannot be adopted as the new policy.

Every accepted event becomes an alert with:

- `action: blocked`
- high severity
- the corresponding `BLOCKED_*` rule
- actor PID/UID/command context
- target PID for cross-process operations
- the kernel decision point as evidence

Health adds `blocked_operations` as the total of all denial kinds. The existing `blocked_execs` field remains the execution-denial count for compatibility. A fixed-size per-kind counter array supplies both values without an unbounded map. Perf-buffer loss increments lost-block-event health while the kernel denial remains in force.

Response is reported as supported only after every required program, map, and link is loaded and configured. Missing BPF LSM support or a missing required hook leaves detection active and Response mode unavailable with an exact reason. There is no partial-active state.

## Executable evidence model

Incident evidence distinguishes five roles:

- **Actor:** process initiating injection or another non-exec suspicious operation.
- **Payload/executed image:** image involved in memfd or deleted-image execution.
- **Target:** process receiving a cross-process memory modification.
- **Pre-exec launcher:** current process image replaced by a denied execution attempt.
- **Parent:** parent of the actor, payload process, or pre-exec launcher.

The alert schema adds:

```text
exe_md5
exe_sha256
exe_hash_status
launcher_md5
launcher_sha256
launcher_hash_status
parent_md5
parent_sha256
parent_hash_status
target_md5
target_sha256
target_hash_status
```

Existing `exe`, `launcher_exe`, `parent_exe`, and `target_exe` fields hold complete paths or truthful kernel identities such as `/memfd:name (deleted)`. MemSpy must not invent a filesystem path for an anonymous or deleted image.

Hash statuses are stable string values:

- `complete`
- `not_collected`
- `process_exited`
- `image_unavailable`
- `no_filesystem_path`
- `too_large`
- `read_error`
- `identity_changed`
- `blocked_before_open`

The daemon opens executable images through procfs while the process identity is known, verifies process start identity to prevent PID-reuse attribution, and calculates MD5 and SHA-256 in one streaming pass. The current 128 MiB maximum applies to every role. Hash failure never blocks alert storage.

For successful execution alerts, the executed image and parent are collected. For injection alerts, the actor and target are collected. For a denied execution, the pre-exec launcher and parent are collected. A denied memfd payload may not be recoverable in userspace; its image is stored with `blocked_before_open`, while the pre-exec launcher is hashed when available.

MD5 is provided only for compatibility with external IOC collections. SHA-256 remains the primary integrity identifier.

## Storage and API compatibility

SQLite receives additive nullable columns for the new hash and status fields. Startup migration runs transactionally and preserves existing rows. Historical rows map empty hash fields to `not_collected` rather than generic incomplete evidence.

Canonical JSON adds the new fields without removing or renaming existing fields. Parsing accepts older records with absent new fields and assigns `not_collected`. Because the additions are optional and backward-compatible, the local protocol version remains unchanged. Daemon, CLI, and UI continue to reject malformed types and oversized strings.

`memspyctl show` and `memspyctl export` expose every new field. The compact `alerts` listing remains unchanged.

## GTK presentation

Expanded incident details retain the current single-scroll layout and add role-oriented evidence groups:

- Actor executable
- Payload/executed image
- Target executable
- Pre-exec launcher
- Parent process

Each available group shows full path, MD5, SHA-256, and status. Values are selectable and copyable. Long values wrap in the expanded card; collapsed summaries may ellipsize with the full value in a tooltip.

The UI replaces the generic “some process details are missing” evidence message with the exact status explanation for each role. It uses `Unavailable` only when the absence matters and hides roles that are not applicable to that rule. Severity and outcome remain separate: a denied event displays a `Blocked` outcome badge and its actual severity.

The Response-mode switch remains pending until the daemon confirms the complete policy. It never displays On based solely on the requested state.

## Failure and recovery behavior

- Detection sensor failure follows the existing detector-health behavior.
- Response-object load or attachment failure leaves detection running and Response mode unavailable.
- Invalid exemptions are omitted rather than converted into broad exemptions.
- A non-exempt or unverifiable ptrace relationship present during activation rolls Response mode back to Off with the actor and target PIDs in the reason.
- Missing evidence records the exact failure status and still stores the alert.
- Event-publication failure does not permit an operation that the kernel policy denied.
- Disabling Response mode updates the shared enabled map and immediately stops new denials.
- The cleanup helper continues to remove only MemSpy-owned pins while the daemon is stopped.
- A daemon restart adopts only a completely compatible response object; otherwise it performs the existing staged replacement.

## Validation

### Non-privileged tests

- Pure deny-predicate tests for each primitive and allowlist outcome.
- Activation-barrier tests for no tracers, allowlisted tracers, non-allowlisted tracers, disappearing processes, and malformed `TracerPid` records.
- Response-allowlist parsing, rule scoping, unsafe-entry rejection, and legacy-path behavior.
- Enforcement ABI validation, malformed events, rule conversion, and pin compatibility.
- Database creation and migration from the previous schema with history preservation.
- JSON round-trip tests for complete and legacy evidence.
- Hashing tests for normal, deleted-but-open, oversized, vanished, unreadable, and identity-changed images.
- UI tests for blocked/detected outcomes, all applicable evidence roles, missing evidence reasons, selectable values, and long paths.
- CLI JSON output tests for new fields.

### Privileged disposable-VM tests

For every primitive:

1. Response off: harmless fixture succeeds and generates the existing detected alert.
2. Response on: fixture fails with the expected permission error and generates the matching blocked alert.
3. Exact rule/path exemption: fixture succeeds for the exempt launcher without exempting other rules or launchers.

The matrix also verifies all-or-nothing response reporting, event-loss health, daemon restart/pin adoption, response disablement, and coexistence with the distribution's active LSMs.

## Documentation and rollout

README and man pages will list the exact blocked primitives, broader ptrace semantics, rule-specific allowlist format, evidence limits, kernel capability requirements, and recovery commands. The installer continues enabling BPF LSM where supported but does not claim response availability until the daemon's complete probe succeeds.

The feature remains off by default. Administrators must explicitly authenticate to enable it and should add narrowly reviewed exemptions before enabling Response mode on a production server.

## Success criteria

- All five primitive behaviors are denied before successful modification or execution when Response mode is active.
- Each denial produces the correct blocked rule when event delivery succeeds.
- The injection chain is prevented by at least one underlying denial.
- Exact exemptions affect only their configured rule and launcher.
- Response mode is never reported active while a non-exempt pre-existing ptrace relationship can continue modifying memory.
- Detection behavior is unchanged when Response mode is off or unsupported.
- Existing alert history survives upgrade.
- The UI shows complete paths and both hashes when collectable, and a precise reason otherwise.
- Full non-privileged and supported-kernel privileged test matrices pass without GTK or libbpf warnings.
