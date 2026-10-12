# MemSpy Server Operations and `/proc` Memory Injection Design

**Date:** 2026-10-12  
**Status:** Approved  
**Target:** MemSpy 0.2.x on x86_64 Linux 5.4+

## Purpose

MemSpy currently provides a privileged local detector and an optional GTK interface. This release makes the same detector practical on headless servers without weakening the individual-user dashboard. It adds four bounded capabilities: a native command-line client, high-confidence `/proc/<pid>/mem` write detection, server-oriented process context, and journald JSON alert output.

Success means:

- a server administrator can inspect health and alerts without installing or launching the GTK UI;
- a successful cross-process write through a tracked `/proc/<pid>/mem` descriptor produces one `PROC_MEM_WRITE` alert;
- stored and live alerts identify the responsible service, container/cgroup, terminal or SSH origin, and bounded process lineage when those facts are available;
- each accepted alert is available as a structured journald record and as JSON from the CLI;
- existing alert history survives the schema upgrade;
- unsupported or incomplete kernel coverage is reported explicitly and never presented as full protection.

## Scope

This release contains only:

1. `memspyctl` for status, alert listing/detail, JSON export, and response control;
2. successful cross-process `/proc/<pid>/mem` write detection;
3. bounded server process context;
4. structured journald alert output.

It does not add fleet management, a network listener, automatic process killing, packet capture, memory dumping, cloud submission, threat-intelligence lookup, or generic writable/executable-memory heuristics.

## Architecture

The existing privilege boundary remains unchanged:

```text
kernel tracepoints
      |
      v
eBPF observation sensor -> daemon correlation/enrichment -> SQLite
                                      |                     |
                                      |                     +-> local API
                                      |                              |-> memspy-ui
                                      |                              +-> memspyctl
                                      |
                                      +-> structured journald alert
```

`memspyd` remains the only privileged component and the only writer of alerts or response state. `memspyctl` and `memspy-ui` are unprivileged clients of the same root-owned Unix socket. No TCP or UDP listener is introduced.

The API client implementation moves from the UI directory to a shared internal client module used by both front ends. Protocol parsing, bounds, UTF-8 validation, connection behavior, and response authorization therefore have one owner.

## `memspyctl`

### Commands

The first CLI surface is intentionally small:

```text
memspyctl status [--json]
memspyctl alerts [--severity high|medium] [--limit N] [--json]
memspyctl show ALERT_ID [--json]
memspyctl export ALERT_ID
memspyctl response on|off
memspyctl version
```

`status` reports detector health, event loss, storage availability, and response support/requested/active state. `alerts` lists newest-first bounded history. `show` renders all evidence for one alert. `export` writes the canonical single-alert JSON document to standard output; it does not create a root-owned file on behalf of the caller. `response` uses the existing PolicyKit action and never accepts credentials on stdin or the command line.

Human-readable output is the default. `--json` emits one complete JSON document to stdout and sends diagnostics to stderr. Successful commands return `0`; invalid usage returns `2`; unavailable detector/API returns `3`; authorization failure returns `4`; a missing alert returns `5`. Output is non-interactive and stable enough for shell consumption only in JSON mode.

### Access and authorization

Socket access continues to require membership in `memspy-ui`. The group name is retained for compatibility even though it now grants both UI and CLI read access. README text will clearly describe it as trusted local alert-reader access.

Read operations require only socket access. Every `response on` and `response off` request independently passes the connected CLI process PID, UID, and start time through the existing PolicyKit authorization path. Running `memspyctl` with `sudo` is unnecessary and not recommended.

## Local API and compatibility

The protocol advances from version 2 to version 3 because alerts gain fields and the API gains a single-alert operation. The handshake continues to reject mismatched versions rather than allowing an old client to misrepresent evidence.

New operation:

```json
{"v":3,"op":"alert","id":42}
```

The response contains one canonical alert object or `alert_not_found`. Existing status, paginated alert-list, subscription, and response operations retain their current semantics.

All numeric identifiers are range-checked. Strings remain length-bounded and valid UTF-8. Unknown fields are not trusted, and malformed messages close the session according to the existing hostile-client policy.

## `/proc/<pid>/mem` Detection

### Rule semantics

`PROC_MEM_WRITE` is a medium-severity detection for a successful write by one process into another process through a tracked `/proc/<pid>/mem` file descriptor. Opening the file, attempting a zero-byte write, or receiving a failed write result does not produce an alert.

The alert contains:

- source process PID, UID, executable, command line, and lineage;
- target PID as named in the source process's PID namespace;
- resolved host target PID and executable when available;
- successfully written byte count, capped to numeric metadata only;
- evidence naming the `/proc` memory-write path;
- `enrichment_incomplete` when the target cannot be resolved before it exits.

No written bytes or target memory are copied into the event or database.

### Kernel event flow

The sensor records the file descriptor on entry to `write`, `pwrite64`, `writev`, and `pwritev2`, then emits an observation only after a positive syscall return. The existing bounded pending-operation LRU map provides entry/exit correlation; no payload bytes or iovec contents are read.

On receipt, the daemon resolves `/proc/<source-host-pid>/fd/<descriptor>` and accepts the observation only when the live descriptor identifies a canonical `/proc/<numeric-pid>/mem` target. Descriptor duplication and inheritance therefore need no separate kernel bookkeeping. If the source closes the descriptor or exits before userspace can resolve it, MemSpy omits the alert and increments an incomplete-observation counter rather than guessing from stale state.

The initial portable implementation recognizes canonical numeric procfs targets. Bind-mounted aliases and noncanonical textual aliases are reported as uncovered rather than guessed. `/proc/self/mem` and `/proc/thread-self/mem` are excluded from this cross-process rule. This precision-first boundary and the short-lived-descriptor race are documented in health/capability output and the README.

Map pressure and lost events increment existing health counters. Failure to attach a required write tracepoint marks `PROC_MEM_WRITE` unavailable while preserving other supported rules.

### Namespace resolution

The numeric PID in a procfs path belongs to the source process's PID namespace. Userspace records that namespace identifier and resolves the target through the source process's procfs view when possible, then maps it to the host PID using `NSpid` metadata. If resolution races with process exit, the original namespace PID remains visible and host target fields remain empty.

## Server Process Context

Enrichment remains a bounded snapshot taken when the daemon accepts an observation. The following fields are added to every alert when meaningful:

- grandparent process name, PID, and executable path;
- systemd unit parsed from the process cgroup;
- full bounded cgroup path;
- container/runtime identifier when a known cgroup form can be parsed without invoking an external command;
- TTY name;
- SSH-origin boolean derived from bounded ancestry (`sshd`), without claiming the remote address;
- PID and mount namespace identifiers.

The immediate parent evidence and SHA-256 fields remain unchanged. Lineage is limited to parent and grandparent for this release. Container detection is evidence-based: an unknown cgroup format yields empty container fields instead of a guessed runtime or image name. MemSpy does not call Docker, Podman, containerd, Kubernetes, systemd, or login services during enrichment.

Every `/proc` read has a strict size bound. Paths and identifiers are validated before storage. Races, permission failures, oversized values, and vanished processes set `enrichment_incomplete`; they do not discard an otherwise valid detection.

## Alert Model and Storage

The fixed alert ABI, JSON codec, SQLite schema, daemon store, UI model, shared client, and test fixtures advance together. The next schema version adds columns for:

- grandparent PID, name, and executable;
- systemd unit;
- cgroup path;
- container ID and runtime;
- TTY;
- SSH origin;
- PID and mount namespace identifiers;
- target namespace PID;
- successful write byte count.

Existing rows migrate transactionally with safe empty or zero defaults. No existing column is deleted or reinterpreted. A failed migration rolls back and prevents the daemon from opening the store; it never creates a replacement database or discards history.

Store reads apply the same length and UTF-8 validation as live events. The JSON representation uses explicit field names and omits no security-relevant boolean merely because it is false.

## Journald Output

After an alert is accepted by policy and assigned its database ID, the daemon writes one structured journal entry. High severity uses `LOG_ALERT`, medium severity uses `LOG_WARNING`, and the entry includes stable fields:

```text
MESSAGE=MemSpy high alert: PROC_MEM_WRITE
MEMSPY_ALERT_ID=42
MEMSPY_RULE=PROC_MEM_WRITE
MEMSPY_SEVERITY=high
MEMSPY_ACTION=detected
MEMSPY_PID=1234
MEMSPY_UID=1000
MEMSPY_ALERT_JSON={...canonical alert JSON...}
```

The existing JSON codec produces `MEMSPY_ALERT_JSON`; journald code does not maintain a second serializer. Journal write failure does not block detection, storage, or local API publication. It increments a bounded health/error counter and writes a rate-limited ordinary daemon warning.

The implementation uses the systemd journal API already present on all supported target distributions and adds only the corresponding build dependency. It does not spawn `logger` or a shell.

Journald may retain command lines and process paths contained in the canonical alert JSON. The README documents this local disclosure boundary and shows how administrators can control journal access and retention. No memory contents, environment variables, or packet data are logged.

## GTK Dashboard

The dashboard remains the primary interface for individual users. Existing alert rows and filters do not gain new permanent columns. The `Process details` disclosure adds conditional server-context fields grouped under:

- **Identity:** user, process, parent, grandparent, TTY, and SSH origin;
- **Execution:** executable and command line;
- **Workload:** systemd unit, container/runtime, cgroup, and namespaces;
- **Target:** namespace/host target identity and successful byte count;
- **Detection:** outcome, rule, evidence, and completeness.

Empty sections are omitted. Long values wrap and remain selectable. The compact default size, wide-window maximum width, keyboard behavior, and accessibility naming remain unchanged.

## Health and Failure Behavior

Health/capability reporting distinguishes each probe instead of treating all coverage as one boolean. Relevant states include:

- required core sensor unavailable: detector failed;
- `/proc` memory probe unavailable: detector degraded, other rules continue;
- descriptor/pending map pressure: detector degraded and loss counter visible;
- process context unavailable: alert retained with incomplete evidence;
- journald unavailable: storage and API continue, logging health degraded;
- SQLite unavailable: existing bounded in-memory queue behavior continues;
- CLI cannot connect: deterministic exit status and stderr message;
- PolicyKit denied/cancelled/unavailable: response state remains unchanged.

No failure path silently upgrades an uncertain observation to a high-confidence alert.

## Packaging and Installation

Meson builds and installs `/usr/bin/memspyctl` and its man page. GTK, AppIndicator, libnotify, desktop entries, icons, and `memspy-ui` become one optional build/install feature. Daemon, CLI, eBPF, PolicyKit, systemd, storage, configuration, and man-page components remain available without desktop development libraries.

`install.sh` selects one of two profiles:

- **Desktop:** when GNOME or KDE is detected or explicitly selected, install daemon, CLI, GTK dashboard, indicator, notifications, and desktop integration.
- **Headless:** when neither desktop is present or `headless` is explicitly selected, install daemon, CLI, and system integration without GTK packages or desktop files.

The installer prints the selected profile before package installation. Ambiguous dual-desktop systems retain the existing explicit GNOME/KDE selection behavior. Headless selection is never treated as an installation failure. Package dependency tests cover Ubuntu/Debian, Fedora, and Arch for both profiles, including the systemd development library required for structured journald output.

The existing `memspy-ui` group remains the trusted local alert-reader group in this release to avoid an unsafe group migration. A headless administrator may add a specific trusted account to that group for unprivileged `memspyctl` access; the installer never grants every local account access. Renaming the group is outside this release.

Installation preserves `/etc/memspy`, `/var/lib/memspy`, and the response state. The service sandbox retains no network access. Any journal-socket access required by the structured logger is verified under the installed systemd unit.

## README and Documentation

`README.md` is updated in the same implementation changeset to include:

- individual desktop and server-administrator usage profiles;
- `memspyctl` command examples and exit-status expectations;
- desktop and headless installation examples;
- the `PROC_MEM_WRITE` rule and its precision-first coverage boundary;
- new server/context alert fields;
- journald JSON query and export examples;
- the alert-reader group security boundary;
- updated dependencies, architecture diagram, privacy statement, limitations, and repository layout.

The `memspyd`, `memspy-ui`, and new `memspyctl` man pages receive equivalent operational facts without duplicating implementation detail.

## Verification

Unit and component tests cover:

- canonical `/proc/<pid>/mem` descriptor resolution, invalid paths, self targets, numeric overflow, and descriptor-disappearance races;
- write entry-exit correlation, failed and zero-byte writes, all supported write syscall variants, LRU pressure, and event validation;
- namespace target resolution and process-exit races;
- process context parsing with systemd, Docker, Podman, containerd/Kubernetes-style, unknown, and truncated cgroups;
- schema migration from every supported prior version with history preservation;
- alert JSON round trips and all new bounds;
- API version rejection, single-alert found/not-found, hostile inputs, and concurrent clients;
- every CLI command, JSON stdout purity, error stderr, exit statuses, and PolicyKit error mapping;
- journald field construction and nonfatal journal-write failure;
- GTK conditional fields, wrapping, accessibility, compact and wide layouts.

Privileged disposable-VM tests cover:

- a benign fixture successfully writes to another fixture through `/proc/<pid>/mem` and produces one `PROC_MEM_WRITE` alert;
- open-only, failed-write, self-write, ordinary file write, disappeared descriptors, and unrelated descriptor reuse produce no alert;
- inherited and duplicated live descriptors are detected through their resolved procfs target;
- existing memfd, deleted-exec, `ptrace`, `process_vm_writev`, injection-chain, and response tests still pass;
- `memspyctl` works as a trusted unprivileged group member on a headless session;
- the installed service writes a queryable structured journal record without gaining network access;
- Ubuntu/Debian, Fedora, and Arch dependency installation and builds remain valid.
- desktop and headless installer profiles select only their required dependencies and files.

Release verification reports unsupported tracepoints per kernel. A distribution/kernel combination does not claim `PROC_MEM_WRITE` coverage until its privileged fixture passes there.

## Security and Privacy Boundaries

- Kernel event fields, procfs data, API messages, database text, and CLI arguments are untrusted and bounded.
- `/proc` paths are parsed as data and never passed to a shell.
- `memspyctl export` writes only to stdout; it does not provide a privileged arbitrary-file-write primitive.
- Response changes remain PolicyKit-authorized and bound to peer credentials.
- Journald receives alert metadata but never payload bytes, memory, environment variables, or credentials.
- Container identity is local evidence, not an authorization boundary.
- The daemon does not contact remote services or acquire network access.

## Delivery Order

Implementation proceeds in dependency order:

1. shared alert model, schema migration, JSON, and API v3;
2. shared client module and `memspyctl`;
3. server process-context enrichment and GTK detail rendering;
4. `/proc/<pid>/mem` kernel events, correlation, policy, and fixtures;
5. structured journald output;
6. installer, man pages, README, and full supported test matrix.

Each stage leaves the non-privileged suite green. Kernel-facing stages require the privileged VM fixture before being considered complete.
