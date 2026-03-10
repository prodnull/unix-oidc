---
phase: 02-storage-backend-wiring
plan: "03"
subsystem: storage
tags: [rust, keyring, keyutils, secret-service, dpop, oidc-agent, status, migration]

# Dependency graph
requires:
  - phase: 02-storage-backend-wiring plan 01
    provides: StorageRouter with BackendKind/MigrationStatus, probe-based detection
  - phase: 02-storage-backend-wiring plan 02
    provides: maybe_migrate() with atomic rollback, StorageRouter wired throughout

provides:
  - AgentResponseData::Status with storage_backend and migration_status fields
  - AgentResponse::status() constructor with two new Option<String> params
  - AgentState with storage_backend and migration_status fields (set at daemon startup)
  - run_status() prints "Storage: ..." and "Migration: ..." lines (daemon + non-daemon paths)
  - unix-oidc-agent/tests/headless_storage.rs with two #[ignore] keyutils integration tests
  - docs/storage-architecture.md covering backend selection, migration, headless deployment, security

affects:
  - phase-03-hardware-keys (status command API)
  - operators deploying to headless servers (keyutils fallback documented)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Option<String> for status fields set at daemon startup — avoids coupling protocol layer to enum types"
    - "TDD RED/GREEN for protocol changes — write failing tests before adding struct fields"
    - "#[serde(skip_serializing_if = Option::is_none)] for backward-compatible optional JSON fields"
    - "Non-daemon status path calls StorageRouter::detect() locally — no daemon needed for storage info"

key-files:
  created:
    - unix-oidc-agent/tests/headless_storage.rs
    - docs/storage-architecture.md
  modified:
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/main.rs
    - CLAUDE.md

key-decisions:
  - "storage_backend and migration_status stored as Option<String> in AgentState (not enum) — follows mlock_status precedent, avoids protocol-layer coupling to storage enum types"
  - "Non-daemon status path (agent not running) calls StorageRouter::detect() to show current storage info — ensures operators can see which backend is active even without the daemon"
  - "headless_storage.rs tests use #[cfg(target_os = linux)] guard — macOS never compiles or runs these tests; CI Docker (Linux) runs them with --ignored flag"

patterns-established:
  - "Protocol optional fields: add Option<String> with skip_serializing_if = Option::is_none; update all constructor call sites"
  - "Daemon startup captures StorageRouter kind and migration_status as strings after migration, stores in AgentState for status response"

requirements-completed: [STOR-04, STOR-06, STOR-07]

# Metrics
duration: 5min
completed: 2026-03-10
---

# Phase 02 Plan 03: Storage Status Reporting and Documentation Summary

**Storage backend and migration status added to `unix-oidc-agent status` output, with keyutils headless integration tests and full storage architecture documentation.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-10T15:04:07Z
- **Completed:** 2026-03-10T15:09:02Z
- **Tasks:** 2
- **Files modified:** 5 (+ 2 created)

## Accomplishments

- Status command now shows `Storage: keyring (Secret Service)` and `Migration: n/a` on both daemon-connected and standalone paths
- `AgentResponseData::Status` extended with `storage_backend` and `migration_status` optional JSON fields (backward-compatible with `skip_serializing_if`)
- Two `#[ignore]` integration tests in `headless_storage.rs` validate the keyutils fallback and credential persistence across daemon restart (CI Docker)
- `docs/storage-architecture.md` covers the full probe chain, migration semantics, headless deployment guide, container considerations, troubleshooting, and security advisories (CoW/SSD)
- `CLAUDE.md` updated with Storage Backend Invariants section (10 invariants covering probe contract, migration atomicity, forced backend semantics, fallback safety)

## Task Commits

1. **Task 1: Extend status command with storage backend and migration status** - `0be39d1` (feat)
2. **Task 2: Headless CI integration test and storage architecture documentation** - `59998e2` (feat)

## Files Created/Modified

- `unix-oidc-agent/src/daemon/protocol.rs` - Added `storage_backend` and `migration_status` fields to `AgentResponseData::Status`; updated `AgentResponse::status()` constructor; added 3 TDD tests
- `unix-oidc-agent/src/daemon/socket.rs` - Added same fields to `AgentState`; updated Debug impl; updated Status handler; updated struct literal tests
- `unix-oidc-agent/src/main.rs` - Updated `run_serve()` to capture storage info from `StorageRouter` post-migration; updated `run_status()` to display Storage and Migration lines; updated `load_agent_state()`
- `unix-oidc-agent/tests/headless_storage.rs` - Created with `test_headless_fallback_to_keyutils` and `test_headless_credentials_persist_across_restart` (both `#[ignore]`, Linux-only)
- `docs/storage-architecture.md` - Created: backend selection diagram, probe chain, migration semantics, headless deployment guide, container notes, troubleshooting, security considerations
- `CLAUDE.md` - Added "Storage Backend Invariants" section with 10 invariants

## Decisions Made

- `storage_backend` and `migration_status` stored as `Option<String>` in `AgentState` (not enum) — follows `mlock_status` precedent; avoids protocol-layer coupling to storage enum types. Callers call `display_name()` at the storage layer boundary.
- Non-daemon `run_status()` path calls `StorageRouter::detect()` locally to show current storage info. Operators can see which backend is active even when the daemon is not running.
- `headless_storage.rs` tests are `#[cfg(target_os = "linux")]` — ensures macOS builds never compile or attempt to run them; CI Docker calls with `--ignored`.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- Phase 02 storage backend wiring is complete: backend detection, migration, status reporting, documentation.
- Phase 03 (hardware keys — PKCS#11/cryptoki spike) can proceed; `StorageRouter` and `AgentState` APIs are stable.
- Headless CI integration tests in `headless_storage.rs` are ready for Linux CI Docker job.

---
*Phase: 02-storage-backend-wiring*
*Completed: 2026-03-10*
