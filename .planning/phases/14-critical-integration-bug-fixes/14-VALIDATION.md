---
phase: 14
slug: critical-integration-bug-fixes
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-11
---

# Phase 14 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test (`cargo test`) |
| **Config file** | none (inline `#[test]` and `#[tokio::test]`) |
| **Quick run command** | `cargo test -p pam-unix-oidc -- --test-threads=1` |
| **Full suite command** | `cargo test --workspace -- --test-threads=1` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc -- --test-threads=1` and `cargo test -p unix-oidc-agent -- --test-threads=1`
- **After every plan wave:** Run `cargo test --workspace -- --test-threads=1 && cargo clippy --workspace -- -D warnings`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 14-01-01 | 01 | 0 | SES-08 | integration | `cargo test -p unix-oidc-agent --test daemon_lifecycle -- session_closed` | ❌ W0 | ⬜ pending |
| 14-01-02 | 01 | 0 | SES-07 | unit | `cargo test -p unix-oidc-agent -- test_cleanup_session_fires` | ❌ W0 | ⬜ pending |
| 14-01-03 | 01 | 0 | SEC-05 | unit | `cargo test -p unix-oidc-agent -- test_ssh_askpass_nonce_flow` | ❌ W0 | ⬜ pending |
| 14-01-04 | 01 | 0 | OPS-09 | unit | `cargo test -p pam-unix-oidc -- test_clock_skew_from_policy_config` | ❌ W0 | ⬜ pending |
| 14-01-05 | 01 | 0 | OPS-09 | unit | `cargo test -p pam-unix-oidc -- test_validation_config_clock_skew_from_policy` | ❌ W0 | ⬜ pending |
| 14-01-06 | 01 | 0 | cleanup | unit | `cargo test -p unix-oidc-agent -- test_step_up_result_toctou_safe` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] Test for SessionClosed IPC newline fix — verify `cleanup_session()` dispatch timing
- [ ] Unit test for `run_ssh_askpass()` nonce store/retrieve flow (mock filesystem ops)
- [ ] Unit test for `PamTimeoutsConfig` deserialization and clock_skew threading
- [ ] Unit test for socket.rs safe HashMap get (no panic on missing key)

*All tests are new — existing infrastructure does not cover these specific integration points.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| SSH login with `dpop_required=Strict` E2E | SEC-05 | Requires live SSH connection with SSH_ASKPASS + running agent | 1. Start agent daemon. 2. Configure `SSH_ASKPASS=unix-oidc-agent ssh-askpass`. 3. SSH to target with `dpop_required=Strict`. 4. Verify authentication succeeds. |
| SessionClosed cleanup fires within 100ms | SES-08 | Timing validation requires real IPC over Unix socket | 1. Establish SSH session. 2. Disconnect. 3. Check agent logs for `cleanup_session` within 100ms of `SessionClosed` receipt. |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
