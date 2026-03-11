---
phase: 10
slug: ciba-step-up-fido2-acr-delegation
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-11
---

# Phase 10 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test + integration tests via Docker Compose |
| **Config file** | None (unit tests inline; integration: `docker-compose.test.yaml`) |
| **Quick run command** | `cargo test -p pam-unix-oidc --lib -- ciba && cargo test -p unix-oidc-agent --lib -- ciba` |
| **Full suite command** | `cargo test --workspace` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc --lib -- ciba && cargo test -p unix-oidc-agent --lib -- ciba`
- **After every plan wave:** Run `cargo test --workspace`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | Status |
|---------|------|------|-------------|-----------|-------------------|--------|
| 10-01-T1 | 01 | 1 | STP-02, STP-03, STP-04 | unit (inline TDD) | `cargo test -p pam-unix-oidc --lib -- ciba::types && cargo test -p pam-unix-oidc --lib -- oidc::jwks` | ⬜ pending |
| 10-01-T2 | 01 | 1 | STP-02, STP-03 | unit (inline TDD) | `cargo test -p pam-unix-oidc --lib -- ciba` | ⬜ pending |
| 10-02-T1 | 02 | 1 | STP-05 | unit (inline TDD) | `cargo test -p unix-oidc-agent --lib -- daemon::protocol` | ⬜ pending |
| 10-02-T2 | 02 | 1 | STP-06 | unit (inline TDD) | `cargo test -p pam-unix-oidc --lib -- device_flow` | ⬜ pending |
| 10-03-T1 | 03 | 2 | STP-01 | unit (inline TDD) | `cargo test -p unix-oidc-agent --lib -- daemon::socket && cargo test -p unix-oidc-agent --lib -- ciba` | ⬜ pending |
| 10-03-T2 | 03 | 2 | STP-07 | unit (inline TDD, mock IPC) | `cargo test -p pam-unix-oidc --lib -- sudo` | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Strategy

All plans in Phase 10 use inline TDD (`tdd="true"` on each task). Tests are written as part of each task's RED-GREEN-REFACTOR cycle, not in a separate Wave 0 step. This satisfies the Nyquist requirement because:

1. Each task's `<behavior>` block defines testable expectations before implementation.
2. The `<verify>` command runs the tests written during the task.
3. No task produces code without a corresponding test in the same commit.

Wave 0 file scaffolds (module skeletons) are created as Step 1 within each task's action — they exist before tests are written.

---

## Adversarial Tests (Mandatory per ROADMAP testing mandate)

| Scenario | Test Type | Plan-Task | Reason |
|----------|-----------|-----------|--------|
| CIBA response with wrong ACR — hard-fail, never warn | unit | 10-01-T1 | Security invariant |
| auth_req_id expired before poll completes | unit | 10-03-T1 | `expired_token` error code path |
| slow_down response increases interval | unit | 10-03-T1 | Spec compliance |
| IdP returns access_denied | unit | 10-03-T1 | User denial path |
| No `backchannel_authentication_endpoint` in discovery | unit | 10-01-T2 | Config error, not panic |
| binding_message > 64 chars truncated | unit | 10-01-T2 | UI safety |
| Concurrent StepUp requests for same user | unit | 10-03-T1 | Guard against double-initiation |
| PAM poll loop timeout expiry | unit (mock IPC) | 10-03-T2 | StepUpTimedOut(timeout) branch |
| PAM poll loop user denial | unit (mock IPC) | 10-03-T2 | StepUpTimedOut(denied) branch |
| PAM IPC connection refused | unit (mock IPC) | 10-03-T2 | SudoError::StepUp branch |

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Push notification arrives on phone | STP-01, STP-02 | Requires real IdP + mobile device | Configure Keycloak CIBA, trigger sudo, verify notification text |
| FIDO2 authenticator prompt | STP-04 | Requires hardware authenticator | Configure fido2 step-up, trigger sudo, tap YubiKey when prompted |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify — inline TDD approach satisfies Nyquist
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covered by inline TDD (tests written before implementation in each task)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** ready
