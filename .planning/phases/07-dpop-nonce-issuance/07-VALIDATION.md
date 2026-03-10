---
phase: 7
slug: dpop-nonce-issuance
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-10
---

# Phase 7 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | Rust built-in test harness (`cargo test`) |
| **Config file** | none — inline `#[cfg(test)]` modules per crate convention |
| **Quick run command** | `cargo test -p pam-unix-oidc --lib 2>&1 \| tail -20` |
| **Full suite command** | `cargo test --workspace 2>&1 \| tail -30` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p pam-unix-oidc --lib 2>&1 | tail -20`
- **After every plan wave:** Run `cargo test --workspace 2>&1 | tail -30`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 07-01-01 | 01 | 0 | SEC-06 | unit | `cargo test -p pam-unix-oidc security::nonce_cache -x` | ❌ W0 | ⬜ pending |
| 07-01-02 | 01 | 0 | SEC-05 | unit | `cargo test -p pam-unix-oidc generate_dpop_nonce` | ❌ W0 | ⬜ pending |
| 07-01-03 | 01 | 1 | SEC-06 | unit | `cargo test -p pam-unix-oidc nonce_consume_single_use` | ❌ W0 | ⬜ pending |
| 07-01-04 | 01 | 1 | SEC-06 | unit | `cargo test -p pam-unix-oidc nonce_expired_rejected` | ❌ W0 | ⬜ pending |
| 07-01-05 | 01 | 1 | SEC-06 | unit | `cargo test -p pam-unix-oidc nonce_replay_always_hard_fail` | ❌ W0 | ⬜ pending |
| 07-01-06 | 01 | 1 | SEC-06 | unit | `cargo test -p pam-unix-oidc nonce_missing_strict_rejects` | ❌ W0 | ⬜ pending |
| 07-01-07 | 01 | 1 | SEC-06 | unit | `cargo test -p pam-unix-oidc nonce_missing_warn_allows` | ❌ W0 | ⬜ pending |
| 07-01-08 | 01 | 1 | SEC-06 | unit | `cargo test -p pam-unix-oidc nonce_cache_capacity_exhaustion` | ❌ W0 | ⬜ pending |
| 07-02-01 | 02 | 1 | SEC-05 | unit | `cargo test -p unix-oidc-agent dpop_proof_includes_nonce` | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `pam-unix-oidc/src/security/nonce_cache.rs` — nonce cache module with `#[cfg(test)]` block
- [ ] `moka = { version = "0.12", features = ["sync"] }` added to `pam-unix-oidc/Cargo.toml`
- [ ] Tests stubs for all SEC-05 and SEC-06 behaviors in nonce_cache tests

*Existing infrastructure covers agent-side tests — `unix-oidc-agent` already has test harness.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Two-round PAM conversation works over SSH keyboard-interactive | SEC-05 | Requires live sshd + PAM stack | 1. Start Keycloak Docker compose 2. SSH to test server with agent 3. Verify nonce prompt appears then proof prompt 4. Verify auth succeeds |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
