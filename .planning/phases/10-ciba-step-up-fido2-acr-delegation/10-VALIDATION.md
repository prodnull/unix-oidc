---
phase: 10
slug: ciba-step-up-fido2-acr-delegation
status: draft
nyquist_compliant: false
wave_0_complete: false
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

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 10-01-01 | 01 | 1 | STP-01 | unit (mock IdP) | `cargo test -p unix-oidc-agent -- ciba::poll` | ❌ W0 | ⬜ pending |
| 10-01-02 | 01 | 1 | STP-02 | unit | `cargo test -p pam-unix-oidc -- ciba::binding_message` | ❌ W0 | ⬜ pending |
| 10-01-03 | 01 | 1 | STP-03 | unit (mock discovery) | `cargo test -p pam-unix-oidc -- ciba::discovery` | ❌ W0 | ⬜ pending |
| 10-01-04 | 01 | 1 | STP-04 | unit | `cargo test -p pam-unix-oidc -- ciba::acr` | ❌ W0 | ⬜ pending |
| 10-02-01 | 02 | 1 | STP-05 | unit | `cargo test -p unix-oidc-agent -- daemon::protocol::step_up` | ❌ W0 | ⬜ pending |
| 10-02-02 | 02 | 1 | STP-06 | unit (regression) | `cargo test -p pam-unix-oidc -- device_flow::discovery` | ❌ W0 | ⬜ pending |
| 10-02-03 | 02 | 1 | STP-07 | unit | `cargo test -p unix-oidc-agent -- ciba::timeout` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/src/ciba/mod.rs` + `client.rs` + `types.rs` — new module skeleton (STP-01, STP-02, STP-03, STP-04)
- [ ] `pam-unix-oidc/src/ciba/tests/` — unit test fixtures (mock CIBA responses for each error code)
- [ ] `unix-oidc-agent/src/daemon/protocol.rs` — StepUp/StepUpPending/StepUpComplete/StepUpTimedOut variants (STP-05)
- [ ] `unix-oidc-agent/src/daemon/socket.rs` — handle_step_up() handler function (STP-01, STP-05)
- [ ] No new framework install required — cargo test is already in CI

---

## Adversarial Tests (Mandatory per ROADMAP testing mandate)

| Scenario | Test Type | Reason |
|----------|-----------|--------|
| CIBA response with wrong ACR — hard-fail, never warn | unit | Security invariant |
| auth_req_id expired before poll completes | unit | `expired_token` error code path |
| slow_down response increases interval | unit | Spec compliance |
| IdP returns access_denied | unit | User denial path |
| No `backchannel_authentication_endpoint` in discovery | unit | Config error, not panic |
| binding_message > 64 chars truncated | unit | UI safety |
| Concurrent StepUp requests for same user | unit | Guard against double-initiation |

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Push notification arrives on phone | STP-01, STP-02 | Requires real IdP + mobile device | Configure Keycloak CIBA, trigger sudo, verify notification text |
| FIDO2 authenticator prompt | STP-04 | Requires hardware authenticator | Configure fido2 step-up, trigger sudo, tap YubiKey when prompted |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
