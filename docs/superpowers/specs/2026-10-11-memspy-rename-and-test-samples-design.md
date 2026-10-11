# MemSpy Rename, Migration, and Test Samples Design

## Purpose

Rename the Fileless Detector project to **MemSpy**, replace every legacy product identifier, migrate existing installations without losing configuration or alerts, and expose the detector's benign integration fixtures as a documented `test-samples/` collection.

The product remains a local, detection-only Linux security monitor. The rename does not expand collection, prevention, networking, or remediation behavior.

## Naming Contract

The installed and source-level identity becomes:

| Capability | New identifier |
| --- | --- |
| Product and source project | `MemSpy` / `memspy` |
| Daemon binary | `memspyd` |
| Desktop binary | `memspy-ui` |
| systemd service | `memspyd.service` |
| Authorized UI group | `memspy-ui` |
| Configuration directory | `/etc/memspy` |
| Alert state directory | `/var/lib/memspy` |
| Runtime directory | `/run/memspy` |
| Unix socket | `/run/memspy/memspy.sock` |
| BPF installation directory | `/usr/libexec/memspy` |
| Shared UI data directory | `/usr/share/memspy` |
| Desktop application ID | `org.memspy.MemSpyUI` |
| Desktop entry | `org.memspy.MemSpyUI.desktop` |
| C symbols and macros | `ms_` and `MS_` prefixes |

Source files, generated BPF skeleton names, icons, CSS, manual pages, packaging files, tests, journal messages, temporary names, and documentation follow the same identity. The word “fileless” remains where it describes the security behavior; it is no longer used as a product, executable, service, path, application ID, or source-symbol prefix.

The package version remains `0.1.0` because this rename occurs before a qualified public release.

## Detection Rule IDs

Rule IDs have no product mnemonic:

| Previous ID | New ID |
| --- | --- |
| `FL-MEMFD-EXEC` | `MEMFD_EXEC` |
| `FL-DELETED-EXEC` | `DELETED_EXEC` |
| `FL-PROCESS-VM-WRITE` | `PROCESS_VM_WRITE` |
| `FL-PTRACE-WRITE` | `PTRACE_WRITE` |
| `FL-INJECTION-CHAIN` | `INJECTION_CHAIN` |

The policy engine, serialized alerts, API responses, allowlist parser, UI labels, tests, samples, documentation, and default configuration use only the new IDs. Existing database rows retain their historical text if migrated; migrations do not rewrite alert evidence. Existing allowlist entries using old IDs are converted during migration so policy behavior is preserved.

## Installation Migration

### Persistent data

An existing installation migrates:

- `/etc/filelessd/allowlist.conf` to `/etc/memspy/allowlist.conf`;
- `/var/lib/filelessd/alerts.db` to `/var/lib/memspy/alerts.db`; and
- matching SQLite `alerts.db-wal` and `alerts.db-shm` files when present.

The migration preserves contents, ownership, and restrictive modes. After migration, MemSpy enforces root ownership, mode `0600` on the database and sidecars, and the package-defined mode on the allowlist. The database schema does not change.

The allowlist migration replaces only complete, recognized legacy rule IDs in the rule field. Paths and comments remain byte-for-byte unchanged. Unknown or malformed entries remain invalid and prevent daemon startup under the existing fail-closed policy.

### Runtime state

The old service is stopped before persistent state moves. `/run/filelessd/filelessd.sock` is not migrated because it is ephemeral. `memspyd.service` creates `/run/memspy` and a new socket at startup. The old service is disabled after the new installation succeeds.

### Collision and rollback rules

Migration performs a complete read-only preflight before stopping services or moving data:

1. Old-only data is eligible for migration.
2. New-only data is preserved and no migration is needed.
3. If old and new configuration or database data both exist, installation stops with an actionable conflict message and modifies neither location.
4. A repeated migration after success is a no-op.

Moves within `/etc` and `/var/lib` use same-parent atomic renames where possible. If a later migration step fails, completed moves are rolled back before the old service is restarted. The migration never deletes a non-empty old or new directory. Cleanup removes only empty legacy runtime/state directories after successful verification.

### Package transitions

The Ubuntu source installer and Debian, RPM, and Arch lifecycle metadata use the same migration contract. Package metadata declares the legacy package as replaced/obsolete and conflicting so two daemons cannot own the old and new sensors simultaneously. Removal preserves `/var/lib/memspy`; explicit supported purge removes it.

The source installer continues preserving a locally edited allowlist across build or install failure. It performs migration before enabling `memspyd.service`, adds the selected desktop user to `memspy-ui`, and verifies the new service is active.

## Safe Test Samples

The top-level `test-samples/` directory owns the intentional behavior fixtures. It contains:

| Sample | Expected result | Safe behavior |
| --- | --- | --- |
| `memfd_exec.c` | `MEMFD_EXEC` | Copies its own executable into a memfd and executes that copy |
| `deleted_exec.c` | `DELETED_EXEC` | Copies itself to a temporary file, unlinks it, and executes its open descriptor |
| `process_vm_write.c` | `PROCESS_VM_WRITE` | Writes the integer `42` into a child process created by the sample |
| `ptrace_write.c` | `PTRACE_WRITE` | Uses `PTRACE_POKEDATA` only against its own traced child |
| `injection_chain.c` | `INJECTION_CHAIN` | Writes only into its own child, then directs that child to execute a self-copy from memfd |
| `ordinary_exec.c` | no alert | Executes `/usr/bin/true` as a negative control |

Samples have no embedded payload, persistence, networking, privilege escalation, evasion, arbitrary target PID, arbitrary write value, or user-supplied command execution. Each positive sample operates only on itself or a child it creates, exits promptly, and returns nonzero when the intended syscall sequence fails.

`test-samples/README.md` explains every syscall sequence, expected rule, prerequisites, and the disposable-VM requirement. Users run samples through the existing privileged VM matrix rather than against production workstations.

## Build and Test Integration

Meson builds the samples without installing them. The sensor harness runs each sample under the real eBPF sensor and policy engine, accepts observations only for the fixture process or its direct child, and requires the exact expected rule. The ordinary execution control must produce no alert.

Implementation follows test-driven development:

1. Update package, CLI, path, rule-ID, and install-layout contract tests to require MemSpy identifiers and observe them fail against the legacy tree.
2. Add migration tests using isolated temporary roots. Cover old-only migration, new-only no-op, old/new conflict, recognized allowlist conversion, idempotence, and preservation of database bytes and modes.
3. Add the `INJECTION_CHAIN` fixture expectation and observe it fail before adding the sample and direct-child harness support.
4. Rename and implement only enough code and packaging to satisfy those contracts.
5. Run all sanitized and release non-privileged tests, install staging, desktop validation, packaging checks, and the strict UI audit.
6. Run the privileged sensor suite on disposable x86_64 GNOME and KDE VMs with supported kernels before claiming release support.

A final source scan must find no legacy product identifiers: `filelessd`, `fileless-ui`, `org.fileless`, `FL-`, or `fl_`. Generic prose describing “fileless malware” is expected and remains valid.

## Documentation

The GitHub README, man pages, durable design context, architecture specification, installer messages, desktop launchers, and package descriptions identify the project as MemSpy. Commands and paths use only the new interface. Documentation prominently distinguishes the harmless test samples from malware and warns that they intentionally trigger security telemetry.

## Compatibility and Release Risk

This is an intentional breaking rename. Scripts calling the old binaries or service must change. Clients using the old socket path must change. Allowlist IDs are migrated, but third-party integrations matching old rule IDs must update.

The migration is not considered release-ready until collision, rollback, preservation, and idempotence tests pass and an actual upgrade from the legacy build succeeds on each packaged distribution. Existing alerts remain readable but keep the rule ID originally stored with them, so a migrated database can contain both historical and new rule identifiers.
