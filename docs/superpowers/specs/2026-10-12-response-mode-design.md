# MemSpy Response Mode and Process Evidence Design

**Date:** 2026-10-12  
**Status:** Approved  
**Target:** MemSpy 0.2.x on x86_64 Linux

## Purpose

MemSpy currently detects and records fileless execution and process-injection behavior. This change adds an optional response mode that prevents memory-backed `memfd` images from executing, while preserving detection-only operation on hosts that cannot support BPF LSM enforcement. It also expands alert details so an operator can understand which user and process attempted the execution, the executable involved, and the bounded argument list.

Success means:

- a supported host can enable response mode through the desktop UI after Polkit administrator authentication;
- an attempted `memfd` execution is denied before the new image starts and creates a high-severity `BLOCKED_MEMFD_EXEC` alert;
- the enabled state survives daemon restarts and reboots;
- ordinary executable images continue to run;
- unsupported hosts retain all existing detection behavior and explain why response mode is unavailable;
- existing alert history is preserved during upgrade.

## Scope

Response mode denies only memory-backed `memfd` execution. Deleted-image execution, `ptrace`, and `process_vm_writev` remain detection-only because blocking them would disrupt common debuggers, profilers, runtimes, and package-update flows.

This version does not dump process memory, quarantine content, hash anonymous payloads, block networking, edit bootloader configuration, or provide a general endpoint-prevention policy engine.

## Architecture

Detection and enforcement remain separate:

```text
tracepoint BPF programs -> observations -> policy -> stored alerts -> UI

execve/execveat capture -> BPF LSM bprm_check_security
                                 |
                                 +-> allow ordinary image
                                 +-> allow approved launcher
                                 +-> deny memfd image and emit blocked event

UI response switch -> local API -> Polkit authorization -> enforcement map
                                                   |
                                                   +-> persistent root-only state
```

The existing tracepoint object remains loadable on all currently supported kernels. A second CO-RE BPF object contains the enforcement programs and is loaded only after a runtime capability probe succeeds. Failure to load or attach this object must not prevent the detector, alert store, or read-only API operations from starting.

The daemon remains the only process that loads BPF programs, changes enforcement maps, writes response state, or publishes alerts. The UI remains unprivileged.

## Kernel Enforcement

### Eligibility

The daemon reports response mode as supported only when all of the following are true:

- kernel BTF is readable at `/sys/kernel/btf/vmlinux`;
- BPF LSM is compiled into and active in the running kernel;
- the enforcement object loads and its LSM link attaches successfully;
- the daemon can create and pin its map and link under `/sys/fs/bpf/memspy`.

Static configuration checks are diagnostic. A successful load-and-attach probe is authoritative. The installer reports missing prerequisites but never changes kernel command-line or bootloader settings.

### Decision

The enforcement object attaches an LSM program to `bprm_check_security`. The program identifies a `memfd` image from kernel file metadata: the shmem/tmpfs superblock and the kernel-created `memfd:` dentry name must both match. Checking both avoids treating every executable stored on tmpfs as a memfd image.

When response mode is disabled, the program returns success without changing execution. When enabled, it checks the launcher allowlist. An unmatched memfd image is denied with `-EACCES` before the new executable image starts. Denial is independent of userspace event delivery, so a full or unavailable event buffer cannot accidentally allow execution.

The LSM program emits a bounded blocked-execution event containing the process identity, user identity, attempted filename, captured arguments, launcher identity, timestamp, and truncation flags. A daemon-side lost-event counter exposes cases where enforcement occurred but an alert could not be delivered.

### Argument capture

Tracepoint programs on `execve` and `execveat` capture the attempted filename and a fixed upper bound of argument strings into a per-process BPF map. The LSM program consumes this entry during the same execution attempt and removes it after the decision. The verifier-safe implementation uses a fixed argument count and byte budget; it does not perform an unbounded loop or allocate a large BPF stack object.

Userspace converts the captured argument vector to a shell-escaped display string. Argument boundaries therefore remain visible even when an argument contains spaces. Truncated data is explicitly marked in the alert instead of being presented as complete.

### Lifecycle and crash behavior

The enforcement map and link are pinned under `/sys/fs/bpf/memspy`. If `memspyd` crashes while response mode is enabled, the attached LSM program remains active. On restart, the daemon validates the pinned object ABI before adopting it. Incompatible objects are replaced by attaching the new program before detaching the old one, avoiding an intentional enforcement gap.

The bpffs state is recreated from the persistent setting after reboot. Disabling response mode updates the kernel map before persisting the disabled state. Enabling persists the requested state only after the kernel map confirms it is active. Failed transitions leave the last confirmed state intact and return an error to the UI.

The uninstall path first disables the MemSpy enforcement map, then removes only objects below `/sys/fs/bpf/memspy`. It must not recursively remove or alter other bpffs objects.

## Authorization and Persistent State

The API gains a privileged response-mode operation while alert history and health operations remain read-only. The daemon records Unix peer credentials when accepting a connection and builds the Polkit process subject from the peer PID, UID, and process start time to avoid PID-reuse authorization errors.

The Polkit action is `org.memspy.response.configure`. Both enable and disable requests require an administrator challenge. The desktop Polkit agent owns the credential dialog; neither `memspy-ui` nor `memspyd` reads, transmits, or stores a password. Cancellation, missing authentication agents, denied authorization, and timeout are distinct errors returned to the UI.

Confirmed mode is stored atomically in a root-owned, mode `0600` file below `/var/lib/memspy`. The daemon writes a temporary file, syncs it, renames it over the prior state, and syncs the containing directory. Invalid or insecure state files are rejected and response mode defaults to disabled.

Membership in `memspy-ui` permits connecting to the local socket but does not authorize response-mode changes. Every state change still passes Polkit authorization.

## Enforcement Allowlist

A separate root-owned response allowlist contains one absolute launcher executable path per line. It is empty by default. The daemon opens each entry without following a final symlink, validates that it refers to a regular executable file, and populates a BPF map keyed by filesystem device and inode. The LSM program compares the current task's pre-exec image with this map.

Allowlisting a launcher permits that launcher to execute memfd images and therefore weakens response coverage. Invalid entries fail closed and are reported through daemon health. The existing detection allowlist remains independent and continues to suppress only stored alerts; it cannot authorize kernel execution.

## Alert Data

The alert model and database schema advance together. Schema version 2 adds fields without deleting or rewriting existing rows:

- `action`: `detected` or `blocked`;
- `username`: the name resolved for the observed UID at alert time, when available;
- `launcher_exe`: the executable that requested a blocked exec;
- `parent_exe`: the observed parent executable;
- `arguments_truncated`: whether the displayed command line is incomplete.

Existing rows migrate with `action=detected`, empty enrichment fields, and `arguments_truncated=false`. The existing `exe` and `cmdline` fields continue to mean the executed image and its arguments for detected events. For a denied event they mean the attempted memfd image and attempted arguments.

`BLOCKED_MEMFD_EXEC` is high severity and uses explanation “MemSpy blocked a memory-backed executable image.” Its evidence states that the BPF LSM hook denied execution. An alert remains valid when enrichment races with process exit; unavailable fields are labelled as unavailable and `enrichment_incomplete` is set.

The JSON protocol version advances to 2. The handshake rejects mismatched versions clearly so an old UI cannot silently misrepresent response status. Alert and status strings remain length-bounded, UTF-8 validated, and rendered as plain selectable text.

## Desktop UI

The existing GTK window remains a compact alert viewer. It does not become a general policy editor.

The status banner gains a labelled `Response mode` switch with four explicit presentations:

- **Off — Detection only**;
- **On — Blocking memfd execution**;
- **Pending — Waiting for administrator authentication**;
- **Unavailable —** followed by the daemon-provided capability reason.

The switch is disabled while a request is pending. Authentication cancellation or a daemon error restores the last confirmed state and shows the specific failure. Status is never conveyed by color alone. The top-panel indicator remains monochrome.

Alert rows add an outcome badge, `Blocked` or `Detected`, ahead of the rule, process name/PID, and timestamp. The existing expander is renamed `Process details` and groups selectable fields:

- **Identity:** username and UID, process name, PID, parent PID;
- **Execution:** executable or attempted executable, shell-escaped command line, launcher executable for blocked attempts;
- **Target:** target PID and executable when present;
- **Detection:** action, rule, evidence, timestamp, and any enrichment or truncation warning.

Fields with no meaning for an alert are omitted rather than filled with zeroes. Technical values use the existing monospace style. The 440-pixel default width is retained, long values wrap, and keyboard focus and screen-reader names cover the switch, error state, rows, and details.

## Daemon Health and Failure Handling

Health status exposes enforcement support, requested state, confirmed active state, capability reason, denial count, and lost blocked-event count. The UI says “Blocking active” only when the kernel map confirms the enabled state.

Failure modes behave as follows:

- unsupported BPF LSM: detection healthy, response unavailable;
- enforcement attach failure: detection healthy or degraded as appropriate, response unavailable with the loader error;
- invalid response state: response disabled and health degraded;
- invalid allowlist entry: entry omitted, response remains enabled, health degraded with the configuration error;
- Polkit denial or cancellation: no state change;
- alert-store failure: kernel enforcement continues and health reports storage failure;
- daemon crash: pinned enforcement remains active and systemd restarts the daemon.

Logs must not contain argument contents by default. They may contain rule IDs, numeric process identifiers, transition results, and sanitized error descriptions.

## Packaging and Installation

Meson builds and installs a separate enforcement BPF object and skeleton, the Polkit action, the response allowlist, and updated documentation. The source installer adds the Polkit development/runtime dependency and required BPF build inputs for Ubuntu/Debian, Fedora, and Arch.

The systemd unit receives only the capabilities and writable paths required to load, attach, pin, and manage the BPF programs. Existing filesystem, network, namespace, and syscall restrictions remain unless a verified enforcement operation requires a narrowly scoped exception.

The installer prints one of two results:

- `Detection and response available`; or
- `Detection available; response unavailable: [specific reason]`.

Installation succeeds in both cases. Re-running `install.sh` preserves `/etc/memspy` configuration, `/var/lib/memspy` state and alert history. `uninstall.sh` removes installed files and MemSpy-owned pinned BPF objects but does not remove alert history unless the user explicitly requests data removal.

## Verification

Unit and component tests cover:

- schema 1 to schema 2 migration with existing alert preservation;
- alert JSON round trips, missing fields, bounds, invalid UTF-8, and protocol mismatch;
- shell escaping and truncation markers;
- response-state file validation and atomic persistence;
- allowlist validation and map-key construction;
- authorization allowed, denied, cancelled, unavailable, timed out, and PID-reuse-safe subjects;
- API status and state transitions, including concurrent requests;
- UI off, on, pending, unavailable, cancelled, and failed states;
- accessible labels and conditional alert fields.

Privileged disposable-VM tests cover:

- response disabled: the memfd fixture executes and is detected;
- response enabled: the memfd fixture receives `EACCES`, its payload never starts, and one `BLOCKED_MEMFD_EXEC` alert is stored;
- ordinary executable execution succeeds in both modes;
- an allowlisted launcher can execute its fixture;
- mode and enforcement survive daemon restart;
- stale pinned objects are safely adopted or replaced;
- response state is restored after reboot;
- unsupported BPF LSM falls back to detection-only;
- uninstall detaches and removes only MemSpy-owned BPF objects.

The supported-kernel matrix runs on current Ubuntu/Debian, Fedora, and Arch x86_64 images where CI infrastructure permits. A release cannot claim response support for a distribution/kernel combination until its privileged test passes there.

## Security Boundaries

- Kernel events and process metadata are untrusted input and remain bounded and validated.
- UI strings are plain text, never Pango markup or shell commands.
- API clients cannot select arbitrary filesystem paths for privileged writes.
- Polkit authorization is bound to the connected process identity, not a caller-supplied PID or UID.
- Persistent state and allowlists reject group- or world-writable ownership/modes.
- BPF pins are confined to the exact MemSpy bpffs directory.
- The response switch controls one fixed policy; it cannot inject rules or BPF bytecode.

## Documentation Changes

The README, man pages, installer output, and UI help text must distinguish detection from prevention. They must state that response mode blocks memfd execution only, is off by default, may affect legitimate memory-backed runtimes, requires BPF LSM, and does not make MemSpy a complete endpoint-protection product.
