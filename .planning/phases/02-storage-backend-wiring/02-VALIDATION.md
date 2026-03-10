---
phase: 2
slug: storage-backend-wiring
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in (`cargo test`), edition 2021 |
| **Config file** | none — `[dev-dependencies]` in `Cargo.toml` |
| **Quick run command** | `cargo test -p unix-oidc-agent` |
| **Full suite command** | `cargo test --all-features` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p unix-oidc-agent`
- **After every plan wave:** Run `cargo test --all-features`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 02-01-01 | 01 | 1 | STOR-01 | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_probe_cycle` | ❌ W0 | ⬜ pending |
| 02-01-02 | 01 | 1 | STOR-01 | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_probe_failure` | ❌ W0 | ⬜ pending |
| 02-01-03 | 01 | 1 | STOR-02 | unit (mock) | `cargo test -p unix-oidc-agent storage::router::tests::test_fallback_to_file` | ❌ W0 | ⬜ pending |
| 02-02-01 | 02 | 2 | STOR-02 | compile | `cargo build -p unix-oidc-agent` | ✅ existing | ⬜ pending |
| 02-02-02 | 02 | 2 | STOR-03 | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_success` | ❌ W0 | ⬜ pending |
| 02-02-03 | 02 | 2 | STOR-03 | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_rollback` | ❌ W0 | ⬜ pending |
| 02-02-04 | 02 | 2 | STOR-03 | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_noop` | ❌ W0 | ⬜ pending |
| 02-02-05 | 02 | 2 | STOR-05 | unit | `cargo test -p unix-oidc-agent storage::router::tests::test_migration_uses_secure_delete` | ❌ W0 | ⬜ pending |
| 02-03-01 | 03 | 3 | STOR-04 | integration | `cargo test -p unix-oidc-agent --test headless_storage -- --ignored` | ❌ W0 | ⬜ pending |
| 02-03-02 | 03 | 3 | STOR-06 | unit | `cargo test -p unix-oidc-agent daemon::protocol::tests::test_status_storage_backend` | ❌ W0 | ⬜ pending |
| 02-03-03 | 03 | 3 | STOR-07 | manual | inspect `docs/` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `unix-oidc-agent/src/storage/router.rs` — `StorageRouter` struct, `detect()`, migration logic stubs
- [ ] `unix-oidc-agent/src/storage/router.rs` tests — unit test stubs for probe, fallback, migration, rollback
- [ ] `unix-oidc-agent/tests/headless_storage.rs` — integration test stub with `#[ignore]` for CI Docker path
- [ ] `unix-oidc-agent/Cargo.toml` — add `sync-secret-service`, `linux-native`, `apple-native` features to `keyring`
- [ ] `.github/workflows/ci.yml` — add `libdbus-1-dev` to apt install step

*Existing infrastructure covers dev-dependencies (tempfile already present).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Documentation exists in `docs/` | STOR-07 | Doc content quality not automatable | Inspect `docs/` for storage architecture docs |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
