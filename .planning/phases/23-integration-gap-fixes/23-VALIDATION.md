---
phase: 23
slug: integration-gap-fixes
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-13
---

# Phase 23 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust) |
| **Config file** | Cargo.toml (workspace) |
| **Quick run command** | `cargo test -p pam-unix-oidc -- --test-threads=1 nonce_consume` |
| **Full suite command** | `cargo test -p pam-unix-oidc --features test-mode` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc -- --test-threads=1 nonce_consume`
- **After every plan wave:** Run `cargo test -p pam-unix-oidc --features test-mode`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 23-01-01 | 01 | 1 | MIDP-02 | integration | `cargo test -p pam-unix-oidc -- nonce_consume_multi_issuer` | ❌ W0 | ⬜ pending |
| 23-01-02 | 01 | 1 | MIDP-02 | unit | `cargo test -p pam-unix-oidc -- apply_per_issuer_dpop` | ✅ | ⬜ pending |
| 23-01-03 | 01 | 1 | ENTR-01 | integration | `cargo test -p pam-unix-oidc -- policy_entra_yaml_deserialize` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Nonce replay test in `tests/multi_idp_integration.rs` — stub for MIDP-02 nonce consumption
- [ ] Policy deserialization test in `tests/entra_integration.rs` — stub for ENTR-01 fixture loading

*Existing test infrastructure (cargo test, test-mode feature flag) covers framework needs.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
