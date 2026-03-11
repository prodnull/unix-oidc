---
phase: 13
slug: operational-hardening
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-11
---

# Phase 13 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in tests + integration tests |
| **Config file** | `Cargo.toml` workspace; no separate test config |
| **Quick run command** | `cargo test -p unix-oidc-agent 2>&1 \| tail -20` |
| **Full suite command** | `cargo test --workspace 2>&1 \| tail -40` |
| **Estimated runtime** | ~30 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p unix-oidc-agent 2>&1 | tail -20`
- **After every plan wave:** Run `cargo test --workspace 2>&1 | tail -40`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 13-01-01 | 01 | 1 | OPS-01 | manual | `systemd-analyze verify contrib/systemd/unix-oidc-agent.service` | ❌ W0 | ⬜ pending |
| 13-01-02 | 01 | 1 | OPS-02 | unit | `cargo test -p unix-oidc-agent test_socket_activation_standalone_fallback` | ❌ W0 | ⬜ pending |
| 13-01-03 | 01 | 1 | OPS-03 | unit | `cargo test -p unix-oidc-agent test_plist_generation` | ❌ W0 | ⬜ pending |
| 13-01-04 | 01 | 1 | OPS-04 | unit | `cargo test -p unix-oidc-agent test_readiness_gate_order` | ❌ W0 | ⬜ pending |
| 13-02-01 | 02 | 1 | OPS-05 | unit | `cargo test -p unix-oidc-agent test_peer_credential_uid_check` | ❌ W0 | ⬜ pending |
| 13-02-02 | 02 | 1 | OPS-06 | unit | `cargo test -p unix-oidc-agent test_ipc_idle_timeout` | ❌ W0 | ⬜ pending |
| 13-03-01 | 03 | 1 | OPS-07 | unit | `cargo test -p unix-oidc-agent test_config_timeouts_defaults` | ❌ W0 | ⬜ pending |
| 13-03-02 | 03 | 1 | OPS-08 | unit | (same test) | ❌ W0 | ⬜ pending |
| 13-03-03 | 03 | 1 | OPS-09 | unit | (same test) | ❌ W0 | ⬜ pending |
| 13-03-04 | 03 | 1 | OPS-10 | unit | `cargo test -p unix-oidc-agent test_jwks_cache_ttl_env_override` | ❌ W0 | ⬜ pending |
| 13-04-01 | 04 | 2 | OPS-11 | unit | `cargo test -p unix-oidc-agent test_request_span_fields` | ❌ W0 | ⬜ pending |
| 13-04-02 | 04 | 2 | OPS-12 | unit | `cargo test -p pam-unix-oidc test_get_hostname_syscall` | ❌ W0 | ⬜ pending |
| 13-04-03 | 04 | 2 | OPS-13 | integration | `cargo test -p unix-oidc-agent --test daemon_lifecycle test_getproof_logging` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `unix-oidc-agent/tests/ops_hardening.rs` — stubs for OPS-02 through OPS-13
- [ ] `unix-oidc-agent/src/daemon/peer_cred.rs` — new module for `get_peer_credentials()` (unit-testable via mock fd)
- [ ] Inline tests in `unix-oidc-agent/src/config.rs` for TimeoutsConfig validation
- [ ] `tracing-test = "0.2"` dev-dependency for span field assertions (OPS-11)
- [ ] `pam-unix-oidc/src/audit.rs` test for updated `get_hostname()` (OPS-12)

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| systemd unit file valid syntax and hardening | OPS-01 | Requires systemd tooling | `systemd-analyze verify contrib/systemd/unix-oidc-agent.service` |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
