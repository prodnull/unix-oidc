---
phase: 9
slug: token-introspection-session-lifecycle-token-refresh
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 9 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness (`cargo test`) |
| **Config file** | Cargo.toml `[dev-dependencies]` + `#[cfg(test)]` modules in-source |
| **Quick run command** | `cargo test -p pam-unix-oidc --features test-mode && cargo test -p unix-oidc-agent 2>&1 \| tail -20` |
| **Full suite command** | `cargo test --workspace --features test-mode 2>&1 \| tail -30` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc --features test-mode && cargo test -p unix-oidc-agent`
- **After every plan wave:** Run `cargo test --workspace --features test-mode`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 09-01-01 | 01 | 1 | SES-01 | unit | `cargo test -p pam-unix-oidc --features test-mode session::tests` | ❌ W0 | ⬜ pending |
| 09-01-02 | 01 | 1 | SES-02 | unit | `cargo test -p pam-unix-oidc --features test-mode session::tests::test_close_session` | ❌ W0 | ⬜ pending |
| 09-01-03 | 01 | 1 | SES-03 | unit | `cargo test -p pam-unix-oidc --features test-mode lib::tests::test_session_id_correlation` | ❌ W0 | ⬜ pending |
| 09-02-01 | 02 | 1 | SES-05 | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests` | ❌ W0 | ⬜ pending |
| 09-02-02 | 02 | 1 | SES-06 | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests::test_cache_hit` | ❌ W0 | ⬜ pending |
| 09-03-01 | 03 | 2 | SES-04 | unit | `cargo test -p unix-oidc-agent daemon::tests::test_refresh_threshold` | ❌ W0 | ⬜ pending |
| 09-03-02 | 03 | 2 | SES-07 | unit | `cargo test -p unix-oidc-agent daemon::tests::test_revocation_best_effort` | ❌ W0 | ⬜ pending |
| 09-03-03 | 03 | 2 | SES-08 | unit | `cargo test -p unix-oidc-agent daemon::tests::test_session_closed_ack` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/src/session/mod.rs` — new module with test stubs for SES-01, SES-02, SES-03
- [ ] `pam-unix-oidc/src/oidc/introspection.rs` — new module with test stubs for SES-05, SES-06
- [ ] `unix-oidc-agent/src/daemon/socket.rs` — test additions for SES-04, SES-07, SES-08

*Existing infrastructure covers framework and config — no new framework install needed.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Server restart orphan cleanup | SES-01/SES-02 | Requires actual tmpfs loss + daemon restart | 1. Open SSH session 2. Kill agent daemon 3. Restart agent 4. Verify orphan scan logs |
| End-to-end introspection with live IdP | SES-05 | Requires Keycloak with introspection endpoint | Use Docker Compose integration test with Keycloak |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
