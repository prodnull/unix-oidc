---
phase: 02-storage-backend-wiring
plan: "02"
subsystem: storage
tags: [rust, keyring, dpop, oauth, migration, storage-router]

# Dependency graph
requires:
  - phase: 02-storage-backend-wiring/02-01
    provides: StorageRouter with probe-based backend detection, BackendKind, MigrationStatus enums

provides:
  - maybe_migrate() and maybe_migrate_from() on StorageRouter with atomic rollback
  - All 7 FileStorage::new() call sites replaced with StorageRouter::detect()
  - load_or_create_signer accepts &dyn SecureStorage (generalized)
  - Auto-migration triggered at daemon startup (run_serve) and login (run_login)

affects:
  - phase-03 (hardware signer wiring — storage interface now fully trait-based)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "StorageRouter::detect() as the single entry point for all storage access"
    - "maybe_migrate_from(&FileStorage) for testable, injected migration; maybe_migrate() for production"
    - "Atomic migration: write + read-back verify; rollback all on any failure"
    - "Best-effort secure delete of source files post-migration (WARN on failure, do not abort)"
    - "&dyn SecureStorage as parameter type for storage-consuming functions"

key-files:
  created: []
  modified:
    - unix-oidc-agent/src/storage/router.rs
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/daemon/socket.rs

key-decisions:
  - "maybe_migrate_from(&FileStorage) takes explicit source — enables two-tempdir tests without interactive keychain prompts"
  - "maybe_migrate() is the public API; creates FileStorage::new() internally for production use"
  - "detect_forced_with_dir() test helper uses non-File BackendKind with file backend — allows migration to run without real keyring in CI"
  - "Migration called in both run_serve() (primary trigger) and run_login() (upgrade trigger)"
  - "FailOnSecondStore uses AtomicUsize not Cell<usize> — SecureStorage requires Send+Sync"

patterns-established:
  - "StorageRouter::detect() replaces FileStorage::new() at every call site — uniform storage acquisition"
  - "Rollback semantics: per-key best-effort (log WARN, continue remaining rollback keys)"
  - "TDD structure: failing tests added before implementation; tests use FileStorage tempdir pairs to avoid keyring prompts"

requirements-completed: [STOR-02, STOR-03, STOR-05]

# Metrics
duration: 13min
completed: 2026-03-10
---

# Phase 2 Plan 02: Storage Backend Wiring Summary

**StorageRouter wired into all 7 agent command paths with atomic file-to-keyring migration, rollback, and secure-delete of migrated source files**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-10T14:38:37Z
- **Completed:** 2026-03-10T14:51:57Z
- **Tasks:** 2 (TDD + wiring)
- **Files modified:** 3

## Accomplishments

- `maybe_migrate()` / `maybe_migrate_from()` implemented with write+verify atomicity and rollback on any failure
- All 7 `FileStorage::new()` call sites in main.rs and socket.rs replaced with `StorageRouter::detect()`
- `load_or_create_signer` generalized from `&FileStorage` to `&dyn SecureStorage`
- Migration triggered at daemon startup (`run_serve`) and interactive login (`run_login`)
- 78/78 tests pass; 0 clippy warnings with `-D warnings`

## Task Commits

1. **Task 1: maybe_migrate() with atomic rollback and unit tests** - `ae086e3` (feat)
2. **Task 2: Replace all FileStorage::new() with StorageRouter::detect()** - `86ad563` (feat)

**Plan metadata:** (this commit)

_Task 1 was TDD: failing tests added first, then implementation._

## Files Created/Modified

- `unix-oidc-agent/src/storage/router.rs` - Added `maybe_migrate()`, `maybe_migrate_from()`, `rollback_migration()`, and 5 TDD migration tests; imported `KEY_*` constants and `warn!` macro
- `unix-oidc-agent/src/main.rs` - Replaced 6 `FileStorage::new()` calls; changed import; `load_or_create_signer` → `&dyn SecureStorage`; migration calls in `run_serve` and `run_login`
- `unix-oidc-agent/src/daemon/socket.rs` - Replaced 1 `FileStorage::new()` in `perform_token_refresh`; updated import

## Decisions Made

- `maybe_migrate_from(&FileStorage)` takes explicit source instead of calling `FileStorage::new()` internally — this enables two-tempdir test patterns (source + destination as separate file stores) without interactive keychain prompts on macOS.
- `detect_forced_with_dir()` test helper creates a `StorageRouter` with `kind = BackendKind::SecretService` but a `FileStorage` backend — avoids the `kind == File` guard that would skip migration, while also avoiding any real keyring access.
- `FailOnSecondStore` in rollback test uses `AtomicUsize` instead of `Cell<usize>` because `SecureStorage: Send + Sync`.
- Migration called in both `run_serve` (primary trigger per CONTEXT.md) and `run_login` (upgrade trigger for users who don't run daemon first).

## Deviations from Plan

**1. [Rule 1 - Bug] Fixed Cell<usize> not implementing Sync in FailOnSecondStore test struct**
- **Found during:** Task 1 (TDD GREEN phase)
- **Issue:** `FailOnSecondStore.call_count: Cell<usize>` — `SecureStorage` requires `Send + Sync`, `Cell<T>` is not `Sync`
- **Fix:** Changed to `AtomicUsize` with `fetch_add(1, SeqCst)` in store()
- **Files modified:** unix-oidc-agent/src/storage/router.rs
- **Verification:** `cargo test` passes
- **Committed in:** ae086e3 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug)
**Impact on plan:** Necessary for test code to compile. No scope change.

## Issues Encountered

None.

## Next Phase Readiness

- Storage interface is now fully trait-object-based (`&dyn SecureStorage` everywhere)
- Phase 3 hardware signer wiring can proceed — storage API is stable
- All agent command paths (login, logout, refresh, reset, serve, status, get-proof) use the router

---
*Phase: 02-storage-backend-wiring*
*Completed: 2026-03-10*
