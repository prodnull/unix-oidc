---
phase: 11
slug: implementation-completion
status: draft
nyquist_compliant: true
wave_0_complete: false
created: 2026-03-11
---

# Phase 11 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test + shell integration tests + CI workflow validation |
| **Config file** | `.github/workflows/ci.yml` (CI), `docker-compose.token-exchange.yaml` (Docker) |
| **Quick run command** | `cargo test -p unix-oidc-agent --test daemon_lifecycle && bash test/tests/test_token_exchange.sh --dry-run` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~60 seconds (unit tests); CI jobs ~5-10 min |

---

## Sampling Rate

- **After every task commit:** Run `cargo test --workspace`
- **After every plan wave:** Run full suite + validate CI workflow YAML syntax (`yq eval ci.yml`)
- **Before `/gsd:verify-work`:** Full suite must be green; CI workflow must parse without errors
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | Status |
|---------|------|------|-------------|-----------|-------------------|--------|
| 11-01-T1 | 01 | 1 | TEST-01 | CI workflow + shell | `yq eval .github/workflows/ci.yml && bash -n test/tests/test_token_exchange.sh` | ⬜ pending |
| 11-01-T2 | 01 | 1 | TEST-02 | integration | `cargo test --workspace` (after realm config change) | ⬜ pending |
| 11-02-T1 | 02 | 1 | TEST-03 | CI workflow | `yq eval .github/workflows/ci.yml` (dpop-interop job) | ⬜ pending |
| 11-02-T2 | 02 | 1 | TEST-04 | integration (Rust) | `cargo test -p unix-oidc-agent --test daemon_lifecycle` | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `unix-oidc-agent/tests/daemon_lifecycle.rs` — integration test scaffold for TEST-04
- [ ] `test/tests/test_dpop_binding.sh` — DPoP-bound token E2E test script for TEST-02

*Existing infrastructure covers TEST-01 (files exist) and TEST-03 (runner exists).*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| CI jobs pass on GitHub Actions | ALL | Requires push to remote + GitHub Actions runner | Push branch, check `gh run list`, verify all jobs green |

---

## Validation Sign-Off

- [x] All tasks have automated verify
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references
- [x] No watch-mode flags
- [x] Feedback latency < 60s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ready
