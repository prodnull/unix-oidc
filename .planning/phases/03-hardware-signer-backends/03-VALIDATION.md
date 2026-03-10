---
phase: 3
slug: hardware-signer-backends
status: draft
nyquist_compliant: true
wave_0_complete: true
created: 2026-03-10
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | `cargo test` (Rust built-in) |
| **Config file** | `unix-oidc-agent/Cargo.toml` (dev-dependencies: tempfile, tokio-test) |
| **Quick run command** | `cargo test -p unix-oidc-agent --lib` |
| **Full suite command** | `cargo test -p unix-oidc-agent` |
| **Estimated runtime** | ~15 seconds |

---

## Sampling Rate

- **After every task commit:** Run `cargo test -p unix-oidc-agent --lib`
- **After every plan wave:** Run `cargo test -p unix-oidc-agent`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 15 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | Status |
|---------|------|------|-------------|-----------|-------------------|--------|
| 3-01-01 | 01 | 1 | HW-01 | unit (mock session) | `cargo test -p unix-oidc-agent --features yubikey crypto::yubikey_signer` | pending |
| 3-01-02 | 01 | 1 | HW-01 | integration (#[ignore]) | `cargo test -p unix-oidc-agent --features yubikey -- --ignored yubikey` | pending |
| 3-02-01 | 02 | 1 | HW-02 | unit (mock context) | `cargo test -p unix-oidc-agent --features tpm crypto::tpm_signer` | pending |
| 3-02-02 | 02 | 1 | HW-02 | integration (#[ignore]) | `cargo test -p unix-oidc-agent --features tpm -- --ignored tpm` | pending |
| 3-03-01 | 03 | 1 | HW-03 | build test | `cargo build -p unix-oidc-agent` | pending |
| 3-01-03 | 01 | 1 | HW-04 | unit (verify session not stored) | `cargo test -p unix-oidc-agent --features yubikey no_held_session` | pending |
| 3-02-03 | 02 | 1 | HW-05 | unit (mock capability response) | `cargo test -p unix-oidc-agent --features tpm p256_capability_probe` | pending |
| 3-03-02 | 03 | 2 | HW-06 | unit | `cargo test -p unix-oidc-agent hardware::factory` | pending |
| 3-03-03 | 03 | 2 | HW-07 | manual | n/a | pending |

*Status: pending / green / red / flaky*

---

## Wave 0 Note

All test files are created inline by their respective plan tasks during execution. There are no
separate pre-execution test stubs required. Each plan task's `<action>` section specifies the tests
to write alongside the production code, and each task's `<verify>` section has a concrete
`<automated>` command (no MISSING references). Wave 0 is satisfied by design.

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Hardware key setup docs present and accurate | HW-07 | Documentation content review | Review `docs/hardware-key-setup.md` covers: YubiKey PIV provisioning, TPM enrollment, PCSC daemon, PIN lockout, pcscd not running, TPM not present |

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify — no MISSING references
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 satisfied: test files created inline by plan tasks
- [x] No watch-mode flags
- [x] Feedback latency < 15s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
