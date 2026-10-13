# Executable Evidence and GTK Presentation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve and present role-specific executable paths plus MD5/SHA-256 evidence with precise failure reasons for detected and blocked incidents.

**Architecture:** Extend the existing alert value object, JSON, and SQLite schema additively. Reuse the daemon's procfs enrichment path to stream both hashes in one pass, then render role-oriented selectable fields in the existing GTK3 incident card.

**Tech Stack:** C17, GLib/GIO, json-c, SQLite3, OpenSSL EVP already used by the project, GTK3, Meson.

**Spec:** `docs/superpowers/specs/2026-10-14-expanded-response-and-evidence-design.md`

## Global Constraints

- Preserve existing alerts and protocol compatibility.
- Maximum hashed image size remains 128 MiB.
- SHA-256 is primary; MD5 exists only for IOC compatibility.
- Never invent a filesystem path for anonymous or deleted images.
- Hash failure must not prevent alert storage.
- GTK updates remain on the main thread and keep one primary scroll region.

## Review Focus

- A PID-reused process must return `identity_changed`, not another process's hash.
- A path containing spaces or invalid display bytes must remain safely selectable and serializable.
- A file changed while hashing must not be reported `complete`.
- Old database rows and JSON without new fields must map to `not_collected`.
- A long path or hash must wrap in details without widening the dashboard.

---

### Task 1: Alert and JSON evidence contract

**Files:**
- Modify: `include/memspy/alert.h`
- Modify: `src/common/alert_json.c`
- Modify: `tests/unit/test_alert_json.c`

**Interfaces:**
- Produces: `MS_MD5_BYTES`, `enum ms_hash_status` string contract, and role fields named in the spec.
- Produces: additive canonical JSON with legacy defaults of `not_collected`.

- [ ] Add failing complete/legacy/malformed round-trip tests for every new hash and status field.
- [ ] Run `meson test -C build-install alert-json --print-errorlogs`; expect missing-field failures.
- [ ] Add fields, validation, serialization, and legacy defaults with no protocol bump.
- [ ] Run alert-json; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 2: One-pass executable hashing

**Files:**
- Modify: `src/daemon/process_evidence.h`
- Modify: `src/daemon/process_evidence.c`
- Modify: `tests/unit/test_process_evidence.c`

**Interfaces:**
- Produces: a role-neutral evidence helper returning full path, MD5, SHA-256, and exact status after start-identity verification.
- Consumes: existing procfs root injection/test seams and the 128 MiB cap.

- [ ] Add failing tests for complete, deleted-but-open, oversized, vanished, unreadable, no-filesystem-path, and identity-changed images.
- [ ] Run `meson test -C build-install process-evidence --print-errorlogs`; expect failures.
- [ ] Stream MD5 and SHA-256 together through existing GLib checksum support, verifying file/process identity before accepting results.
- [ ] Run process-evidence; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 3: Role-aware daemon enrichment

**Files:**
- Modify: `include/memspy/observation.h`
- Modify: `src/daemon/daemon.c`
- Modify: `src/daemon/policy.c` only if role selection currently belongs there.
- Modify: `tests/unit/test_daemon.c`
- Modify: `tests/integration/test_daemon.c`

**Interfaces:**
- Consumes: role-neutral evidence helper and expanded alert fields.
- Produces: executed-image/parent evidence for exec alerts, actor/target for injection, launcher/parent plus `blocked_before_open` for denied exec.

- [ ] Add failing tests for each alert family and exact status propagation when a role is unavailable.
- [ ] Run daemon tests; expect failures on missing evidence.
- [ ] Populate only applicable roles and derive `enrichment_incomplete` from exact role statuses for backward compatibility.
- [ ] Run daemon tests; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 4: Additive SQLite migration and CLI exposure

**Files:**
- Modify: `src/daemon/store.c`
- Modify: `tests/unit/test_store.c`
- Modify: `tests/integration/test_cli.sh`

**Interfaces:**
- Consumes: expanded `struct ms_alert` and canonical JSON.
- Produces: next schema version with nullable hash/status columns and preserved rows.

- [ ] Add a failing migration test from schema v4 plus insert/read tests for all new fields.
- [ ] Run `meson test -C build-install store cli-integration --print-errorlogs`; expect failures.
- [ ] Add one transactional migration and bind/read the new fields, defaulting historical rows to `not_collected`.
- [ ] Run store and CLI integration tests; expect PASS.
- [ ] Record the verified task; commit if possible.

### Task 5: GTK role-oriented evidence details

**Files:**
- Modify: `src/ui/window.c`
- Modify: `data/memspy-ui.css` only for reusable evidence group spacing/styles.
- Modify: `tests/ui/test_ui.c`

**Interfaces:**
- Consumes: expanded alert fields/status strings.
- Produces: applicable Actor, Payload/executed image, Target, Pre-exec launcher, and Parent groups with selectable full values and precise status copy.

- [ ] Add failing UI tests for complete roles, `blocked_before_open`, `identity_changed`, hidden non-applicable roles, selectable labels, long wrapping paths, and blocked/detected badges.
- [ ] Run `dbus-run-session -- xvfb-run -a meson test -C build-install ui --print-errorlogs`; expect new assertions to fail.
- [ ] Refactor only the detail-body builder into small role-group helpers; retain existing card/list/filter behavior.
- [ ] Run the UI test; expect PASS without GTK warnings.
- [ ] Record the verified task; commit if possible.

### Task 6: Documentation and full verification

**Files:**
- Modify: `README.md`
- Modify: `docs/memspyd.8`
- Modify: `docs/memspy-ui.1`

**Interfaces:**
- Consumes: final evidence behavior.
- Produces: administrator documentation for roles, hash limits, and status meanings.

- [ ] Document exact roles, MD5/SHA-256 purpose, the 128 MiB limit, and failure statuses.
- [ ] Run `meson compile -C build-install`; expect success.
- [ ] Run `meson test -C build-install --no-suite privileged --print-errorlogs`; expect all available tests PASS or documented environment-only skips.
- [ ] Inspect `git diff --check`; expect no whitespace errors.
- [ ] Record final verification; commit if possible.
