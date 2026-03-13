---
phase: 17
slug: p2-enhancements
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-03-13
---

# Phase 17 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | cargo test (Rust) |
| **Config file** | Cargo.toml workspace |
| **Quick run command** | `cargo test -p unix-oidc-agent --lib` |
| **Full suite command** | `cargo test --workspace && cargo clippy --workspace -- -D warnings` |
| **Estimated runtime** | ~45 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p unix-oidc-agent --lib`
- **After every plan wave:** Run `cargo test --workspace && cargo clippy --workspace -- -D warnings`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 60 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 17-01-01 | 01 | 1 | MEM-07 | unit | `cargo test -p unix-oidc-agent --features pqc -- pqc_signer` | ❌ W0 | ⬜ pending |
| 17-02-01 | 02 | 1 | SES-09 | unit | `cargo test -p unix-oidc-agent -- sweep` | ❌ W0 | ⬜ pending |
| 17-02-02 | 02 | 1 | SES-09 | build | `cargo build --workspace` | ✅ | ⬜ pending |
| 17-03-01 | 03 | 2 | OBS-1, OBS-3 | unit | `cargo test -p unix-oidc-agent -- protocol` | ✅ | ⬜ pending |
| 17-03-02 | 03 | 2 | OBS-1 | build+grep | `cargo build --workspace && grep -c "unix_oidc_audit" unix-oidc-agent/src/daemon/socket.rs` | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- Existing infrastructure covers all phase requirements. No new test frameworks or fixtures needed.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| mlock succeeds on ML-DSA allocation | MEM-07 | Requires root or elevated RLIMIT_MEMLOCK | Run agent with `sudo` and check WARN-free startup logs |
| Audit events appear in journald JSON | OBS-1 | Requires systemd journal | `journalctl -u unix-oidc-agent -o json --since "1 min ago"` |
| Session sweep reaps orphaned files | SES-09 | Requires /run/unix-oidc/sessions/ | Create stale session file, wait for sweep interval, verify removal |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 60s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
