---
phase: 21
slug: multi-idp-configuration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-13
---

# Phase 21 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust) + shell integration tests |
| **Config file** | `pam-unix-oidc/Cargo.toml` |
| **Quick run command** | `cargo test -p pam-unix-oidc` |
| **Full suite command** | `cargo test --workspace && bash test/tests/test_multi_idp.sh` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 45 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 21-01-01 | 01 | 1 | MIDP-01 | unit | `cargo test -p pam-unix-oidc issuer_config` | ❌ W0 | ⬜ pending |
| 21-01-02 | 01 | 1 | MIDP-06 | unit | `cargo test -p pam-unix-oidc issuer_routing` | ❌ W0 | ⬜ pending |
| 21-01-03 | 01 | 1 | MIDP-07 | unit | `cargo test -p pam-unix-oidc jwks_registry` | ❌ W0 | ⬜ pending |
| 21-02-01 | 02 | 1 | MIDP-02 | unit | `cargo test -p pam-unix-oidc dpop_enforcement` | ❌ W0 | ⬜ pending |
| 21-02-02 | 02 | 1 | MIDP-03 | unit | `cargo test -p pam-unix-oidc claim_mapping` | ❌ W0 | ⬜ pending |
| 21-02-03 | 02 | 1 | MIDP-04 | unit | `cargo test -p pam-unix-oidc acr_mapping` | ❌ W0 | ⬜ pending |
| 21-02-04 | 02 | 1 | MIDP-05 | unit | `cargo test -p pam-unix-oidc group_mapping` | ❌ W0 | ⬜ pending |
| 21-03-01 | 03 | 2 | MIDP-08 | integration | `bash test/tests/test_multi_idp.sh` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/src/policy/issuer_config.rs` — IssuerConfig struct + deserialization tests
- [ ] `pam-unix-oidc/tests/multi_idp.rs` — integration test stubs for multi-issuer routing
- [ ] `test/tests/test_multi_idp.sh` — shell integration test stubs

*Existing cargo test infrastructure covers unit testing; Wave 0 adds multi-issuer-specific fixtures.*

---

## Manual-Only Verifications

*All phase behaviors have automated verification.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 45s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
