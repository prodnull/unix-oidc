---
phase: 02-storage-backend-wiring
verified: 2026-03-10T15:30:00Z
status: passed
score: 7/7 must-haves verified
re_verification: false
---

# Phase 02: Storage Backend Wiring Verification Report

**Phase Goal:** The agent defaults to OS keyring storage, falls back to kernel keyutils on headless Linux, migrates existing file-stored credentials transparently, and reports its active backend on status
**Verified:** 2026-03-10T15:30:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | StorageRouter::detect() probes backends in order and selects the first working one | VERIFIED | `detect_auto()` in router.rs lines 445-545: Secret Service → keyutils → macOS Keychain → file, each with write/read/delete probe |
| 2  | Probe mechanism uses full write/read/delete cycle, not just constructor success | VERIFIED | `probe_backend()` in router.rs lines 304-329: stores PROBE_VALUE, reads back, deletes, returns Err on any step failure |
| 3  | keyring crate has sync-secret-service, linux-native, and apple-native features enabled | VERIFIED | `unix-oidc-agent/Cargo.toml` line 46: `keyring = { version = "3", features = ["sync-secret-service", "linux-native", "apple-native"] }` |
| 4  | UNIX_OIDC_STORAGE_BACKEND env var forces backend; probe failure returns Err, does NOT fall through | VERIFIED | `detect_forced()` in router.rs lines 332-442: each branch returns Err on probe failure; no fallthrough path exists |
| 5  | FileStorage is the last-resort fallback when all keyring probes fail | VERIFIED | `detect_auto()` lines 534-544: `FileStorage::new()` called only after all platform-gated blocks have failed |
| 6  | All 7 FileStorage::new() call sites replaced with StorageRouter::detect() | VERIFIED | grep confirms zero `FileStorage::new()` in main.rs and socket.rs; 8 `StorageRouter::detect` call sites found in main.rs, 1 in socket.rs |
| 7  | Migration is atomic with rollback; source files secure-deleted after success | VERIFIED | `maybe_migrate_from()` in router.rs lines 178-264: write+verify per key, `rollback_migration()` on any failure, `src.delete()` for each key post-success |

**Score:** 7/7 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/storage/router.rs` | StorageRouter, BackendKind, MigrationStatus, probe functions, detect() | VERIFIED | All types present; 979 lines; substantive implementation with 10+ unit tests |
| `unix-oidc-agent/src/storage/mod.rs` | pub mod router; re-exports; Migration variant | VERIFIED | Line 10: `pub mod router;`, line 50: `pub use router::{BackendKind, MigrationStatus, StorageRouter};`, line 45: `Migration(String)` variant |
| `unix-oidc-agent/Cargo.toml` | keyring features: sync-secret-service, linux-native, apple-native | VERIFIED | Line 46: all three features present |
| `.github/workflows/ci.yml` | libdbus-1-dev in all apt-get install steps | VERIFIED | 7 occurrences found (lines 35, 126, 188, 246, 266, 290, 341) |
| `unix-oidc-agent/src/main.rs` | StorageRouter::detect() at all command paths; migration at startup and login | VERIFIED | 8 call sites; `maybe_migrate()` called in run_serve() (line 177) and run_login() (line 356) |
| `unix-oidc-agent/src/daemon/socket.rs` | StorageRouter in socket handler | VERIFIED | Line 416: `StorageRouter::detect()` replaces FileStorage |
| `unix-oidc-agent/src/daemon/protocol.rs` | storage_backend and migration_status fields in AgentResponseData::Status | VERIFIED | Lines 80-84: both fields with `skip_serializing_if = "Option::is_none"` |
| `unix-oidc-agent/tests/headless_storage.rs` | Integration test for headless fallback (keyutils) | VERIFIED | Both `test_headless_fallback_to_keyutils` and `test_headless_credentials_persist_across_restart` present, `#[ignore]`, Linux-only |
| `docs/storage-architecture.md` | Backend Selection section | VERIFIED | Exists; section "Backend Selection" at line 22; covers probe chain, migration, headless, troubleshooting |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `storage/router.rs` | keyring crate | `keyring::set_default_credential_builder` + `keyring::secret_service/keyutils/macos::default_credential_builder()` | VERIFIED | Lines 351, 382, 412, 450, 480, 508 in router.rs |
| `storage/router.rs` | `storage/file_store.rs` | `FileStorage::new()` as fallback | VERIFIED | Lines 335, 535: FileStorage used in forced file path and auto-detection fallback |
| `main.rs` | `storage/router.rs` | `StorageRouter::detect()` calls | VERIFIED | 8 call sites; import at top of file |
| `storage/router.rs` | `storage/file_store.rs` | `file.delete()` for migrated files; `FileStorage::new()` in `maybe_migrate()` | VERIFIED | Lines 151, 254: `FileStorage::new()` in `maybe_migrate()`; `src.delete(key)` at line 254 |
| `main.rs` | `load_or_create_signer` | `&dyn SecureStorage` parameter | VERIFIED | Line 858: `fn load_or_create_signer(storage: &dyn SecureStorage)`; called at lines 361 and 816 |
| `daemon/socket.rs` | `daemon/protocol.rs` | `AgentResponse::status()` with `storage_backend` and `migration_status` params | VERIFIED | socket.rs line 271: `state_read.storage_backend.clone()` and line 272: `state_read.migration_status.clone()` passed to `AgentResponse::status()` |
| `main.rs` | `daemon/protocol.rs` | `run_status()` displays storage_backend and migration_status | VERIFIED | Lines 257-261: prints "Storage: {}" and "Migration: {}"; lines 278-279: non-daemon path also prints both |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| STOR-01 | 02-01 | Runtime keyring backend detection via probe write/read/delete at daemon startup | SATISFIED | `probe_backend()` in router.rs; called from `detect_auto()` and `detect_forced()` |
| STOR-02 | 02-01, 02-02 | KeyringStorage activated as default backend when available; FileStorage as fallback | SATISFIED | `detect_auto()` in router.rs; FileStorage only reached when all keyring probes fail |
| STOR-03 | 02-02 | File-to-keyring migration for existing file credentials (detect on startup, migrate transparently, log) | SATISFIED | `maybe_migrate()` in router.rs; called in `run_serve()` and `run_login()`; `info!` at line 261 |
| STOR-04 | 02-01, 02-03 | Linux headless support via keyutils user keyring (@u) when D-Bus Secret Service unavailable | SATISFIED | `BackendKind::KeyutilsUser` in router.rs; headless_storage.rs integration test; docs section |
| STOR-05 | 02-01, 02-02 | File deletion uses random-overwrite + unlink (secure delete); CoW/SSD limitation documented | SATISFIED | `src.delete()` calls post-migration; docs/storage-architecture.md has "Security Considerations" with CoW/SSD advisory |
| STOR-06 | 02-03 | `unix-oidc-agent status` reports active storage backend and migration status | SATISFIED | protocol.rs: `storage_backend` and `migration_status` fields; main.rs prints "Storage:" and "Migration:" in both daemon and non-daemon paths |
| STOR-07 | 02-03 | Documentation updated with storage architecture, backend selection, migration, headless deployment guide | SATISFIED | `docs/storage-architecture.md` exists with all required sections |

All 7 STOR requirements covered. No orphaned requirements found (STOR-01 through STOR-07 are the only Phase 2 storage requirements in REQUIREMENTS.md traceability table).

### Anti-Patterns Found

No anti-patterns detected in key phase files.

| File | Pattern | Result |
|------|---------|--------|
| router.rs | TODO/FIXME/placeholder | None found |
| protocol.rs | TODO/FIXME/placeholder | None found |
| headless_storage.rs | TODO/FIXME/placeholder | None found |
| router.rs | Empty implementations (return null/empty) | None — all methods delegate to `self.backend` |
| router.rs | Unhandled probe failures | None — WARN logged with actionable message per plan spec |

### Human Verification Required

#### 1. Keyutils probe on headless Linux

**Test:** On a headless Linux host (no D-Bus session), run `cargo test --test headless_storage -- --ignored --nocapture`
**Expected:** `test_headless_fallback_to_keyutils` passes; `StorageRouter::detect()` returns `BackendKind::KeyutilsUser`; credential round-trip succeeds
**Why human:** Test is `#[ignore]` and requires the Linux kernel keyutils subsystem; cannot verify on macOS dev machine

#### 2. Status output format in live daemon

**Test:** Start the daemon (`unix-oidc-agent serve &`), then run `unix-oidc-agent status`
**Expected:** Output includes lines `Storage: keyring (macOS Keychain)` and `Migration: n/a` (or the appropriate values for the running environment)
**Why human:** Real daemon interaction; requires observing actual CLI output

#### 3. Migration path: file credentials auto-promoted to keyring

**Test:** Pre-seed file credentials in `~/.local/share/unix-oidc-agent/` (or platform equivalent), then start the daemon on a machine with a working keyring
**Expected:** Daemon startup logs "Migrated N credentials to keyring backend"; file credentials are absent after startup; keyring contains the credentials
**Why human:** Requires orchestrating a real credential state transition across daemon restarts

### Gaps Summary

No gaps. All must-haves verified, all 7 STOR requirements satisfied, no blocker anti-patterns.

---

## Summary

Phase 02 goal is fully achieved. The implementation is substantive — not stubs — at all three verification levels:

1. **Exists:** All planned artifacts are present in the codebase with correct paths
2. **Substantive:** `router.rs` is 979 lines with complete probe-based detection, forced-backend logic, atomic migration with rollback, and 10+ passing unit tests; `protocol.rs` has real field wiring; `headless_storage.rs` has two real integration tests
3. **Wired:** `StorageRouter::detect()` replaces all 7 former `FileStorage::new()` call sites; `load_or_create_signer` accepts `&dyn SecureStorage`; status fields flow from `StorageRouter` through `AgentState` to `AgentResponse::status()` to CLI output

Test suite passes: 80 passed, 0 failed, 5 ignored (headless + interactive keychain tests). Clippy passes with `-D warnings`.

---

_Verified: 2026-03-10T15:30:00Z_
_Verifier: Claude (gsd-verifier)_
