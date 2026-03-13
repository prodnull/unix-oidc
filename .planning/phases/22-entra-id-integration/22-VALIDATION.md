---
phase: 22
slug: entra-id-integration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-13
---

# Phase 22 — Validation Strategy

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
| TBD | 01 | 1 | ENTR-01 | manual | N/A (documentation) | N/A | pending |
| TBD | 01 | 1 | ENTR-02 | integration | `cargo test -p pam-unix-oidc -- entra_rs256_token_validates` | Wave 0 | pending |
| TBD | 01 | 1 | ENTR-03 | integration | `cargo test -p pam-unix-oidc -- entra_rs256_token_validates` | Wave 0 | pending |
| TBD | 01 | 1 | ENTR-04 | integration | `cargo test -p pam-unix-oidc -- entra_upn_strip_domain_maps` | Wave 0 | pending |
| TBD | 01 | 1 | ENTR-05 | integration | `cargo test -p pam-unix-oidc -- entra_bearer_auth_audit_trail` | Wave 0 | pending |
| TBD | 02 | 2 | CI-03 | CI | Inspect `provider-tests.yml` diff | Wave 0 | pending |

*Status: pending · green · red · flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/tests/entra_integration.rs` — stubs for ENTR-02, ENTR-03, ENTR-04, ENTR-05
- [ ] `test/fixtures/policy/policy-entra.yaml` — Entra issuer fixture
- [ ] `test/scripts/get-entra-token.sh` — ROPC token acquisition for CI
- [ ] `docs/entra-setup-guide.md` — step-by-step app registration guide (ENTR-01)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| App registration guide completeness | ENTR-01 | Documentation deliverable | Review `docs/entra-setup-guide.md` against App Registration Checklist in RESEARCH.md |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
