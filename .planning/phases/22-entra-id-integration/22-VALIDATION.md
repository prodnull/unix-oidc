---
phase: 22
slug: entra-id-integration
status: approved
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-13
---

# Phase 22 -- Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test + `cargo test` |
| **Config file** | `pam-unix-oidc/Cargo.toml` (features: `test-mode`) |
| **Quick run command** | `cargo test -p pam-unix-oidc --features test-mode -- entra` |
| **Full suite command** | `cargo test --workspace --features test-mode -- --test-threads=1` |
| **Estimated runtime** | ~30 seconds (unit/mock); live Entra tests ~10s additional |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc --features test-mode -- --test-threads=1`
- **After every plan wave:** Run `cargo test --workspace --features test-mode -- --test-threads=1`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 22-01-T1 | 01 | 1 | ENTR-03, ENTR-04 | unit | `cargo test -p pam-unix-oidc --features test-mode -- expected_audience allow_unsafe collision_safety` | Created inline | pending |
| 22-01-T2 | 01 | 1 | ENTR-01 | manual | N/A (documentation) | Created inline | pending |
| 22-02-T1 | 02 | 2 | ENTR-02, ENTR-03, ENTR-04, ENTR-05 | integration | `cargo test --release -p pam-unix-oidc --test entra_integration -- --ignored --test-threads=1` | Created inline | pending |
| 22-03-T1 | 03 | 3 | CI-03 | shell | `bash -n test/scripts/get-entra-token.sh` | Created inline | pending |
| 22-03-T2 | 03 | 3 | CI-03, ENTR-05 | CI | `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/provider-tests.yml'))"` | Created inline | pending |

*Status: pending / green / red / flaky*

---

## Wave 0 Note

Wave 0 files (test files, fixtures, scripts, documentation) are created inline within
Wave 1/2/3 tasks rather than in a separate Wave 0 plan. Each task creates its own
artifacts:

- **22-01-T1:** Creates tests in `multi_idp_integration.rs` (existing file, new tests)
- **22-01-T2:** Creates `test/fixtures/policy/policy-entra.yaml`, `docs/entra-setup-guide.md`
- **22-02-T1:** Creates `pam-unix-oidc/tests/entra_integration.rs`
- **22-03-T1:** Creates `test/scripts/get-entra-token.sh`
- **22-03-T2:** Modifies `.github/workflows/provider-tests.yml`

This approach is valid because each plan's tasks are sequential within the plan, and
cross-plan dependencies (22-02 depends on 22-01; 22-03 depends on 22-01 and 22-02)
ensure files exist before they are referenced.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| App registration guide completeness | ENTR-01 | Documentation deliverable | Review `docs/entra-setup-guide.md` against App Registration Checklist in RESEARCH.md (6 items: public client flag, single-tenant, redirect URI, Allow public client flows, API permissions with admin consent, optional claims) |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or inline artifact creation
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 artifacts created inline within plan tasks (no separate Wave 0 plan needed)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** approved
