---
phase: 6
slug: pam-panic-elimination-security-mode-infrastructure
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 6 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in `cargo test` |
| **Config file** | Workspace `Cargo.toml` |
| **Quick run command** | `cargo test -p pam-unix-oidc 2>&1` |
| **Full suite command** | `cargo test --workspace 2>&1` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc 2>&1`
- **After every plan wave:** Run `cargo test --workspace && cargo clippy -p pam-unix-oidc -- -D clippy::unwrap_used -D clippy::expect_used`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 06-01-01 | 01 | 1 | SEC-01 | unit | `cargo test -p pam-unix-oidc -- parking_lot` | ❌ W0 | ⬜ pending |
| 06-01-02 | 01 | 1 | SEC-01 | unit | `cargo test -p pam-unix-oidc -- getrandom` | ❌ W0 | ⬜ pending |
| 06-01-03 | 01 | 1 | SEC-01 | unit | `cargo test -p pam-unix-oidc -- device_flow` | ❌ W0 | ⬜ pending |
| 06-02-01 | 02 | 2 | SEC-03 | unit | `cargo test -p pam-unix-oidc -- test_jti_strict` | ❌ W0 | ⬜ pending |
| 06-02-02 | 02 | 2 | SEC-03 | unit | `cargo test -p pam-unix-oidc -- test_jti_warn` | ❌ W0 | ⬜ pending |
| 06-02-03 | 02 | 2 | SEC-03 | unit | `cargo test -p pam-unix-oidc -- test_dpop_strict` | ❌ W0 | ⬜ pending |
| 06-02-04 | 02 | 2 | SEC-04 | unit | `cargo test -p pam-unix-oidc -- test_v1_policy` | ❌ W0 | ⬜ pending |
| 06-02-05 | 02 | 2 | SEC-04 | unit | `cargo test -p pam-unix-oidc -- test_invalid_enforcement` | ❌ W0 | ⬜ pending |
| 06-02-06 | 02 | 2 | SEC-07 | build | `grep -r "MAX_ENTRIES\|MAX_JTI_CACHE" pam-unix-oidc/src/ \| grep -v 100_000 \| wc -l` | ✅ | ⬜ pending |
| 06-03-01 | 03 | 3 | SEC-02 | build | `cargo clippy -p pam-unix-oidc -- -D clippy::unwrap_used -D clippy::expect_used 2>&1` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/src/policy/config.rs` — tests for v1.0 backward compat load, invalid mode rejection, figment env override
- [ ] `pam-unix-oidc/src/oidc/validation.rs` — tests for enforcement mode paths (strict/warn/disabled for JTI, DPoP, ACR)
- [ ] `pam-unix-oidc/src/security/session.rs` — tests for getrandom error propagation
- [ ] Adversarial tests: malformed tokens, corrupt config, JTI cache at capacity

*If none: "Existing infrastructure covers all phase requirements."*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| v1.0 migration notice logged at INFO | SEC-04 | Log output inspection | Load v1.0 policy.yaml, verify INFO log mentioning "v1.0 defaults" |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
