---
phase: 3
slug: hardware-signer-backends
status: draft
nyquist_compliant: false
wave_0_complete: false
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

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| 3-01-01 | 01 | 1 | HW-01 | unit (mock session) | `cargo test -p unix-oidc-agent --features yubikey crypto::yubikey_signer` | ❌ W0 | ⬜ pending |
| 3-01-02 | 01 | 1 | HW-01 | integration (#[ignore]) | `cargo test -p unix-oidc-agent --features yubikey -- --ignored yubikey` | ❌ W0 | ⬜ pending |
| 3-02-01 | 02 | 1 | HW-02 | unit (mock context) | `cargo test -p unix-oidc-agent --features tpm crypto::tpm_signer` | ❌ W0 | ⬜ pending |
| 3-02-02 | 02 | 1 | HW-02 | integration (#[ignore]) | `cargo test -p unix-oidc-agent --features tpm -- --ignored tpm` | ❌ W0 | ⬜ pending |
| 3-03-01 | 03 | 1 | HW-03 | build test | `cargo build -p unix-oidc-agent` | ✅ | ⬜ pending |
| 3-01-03 | 01 | 1 | HW-04 | unit (verify session not stored) | `cargo test -p unix-oidc-agent --features yubikey no_held_session` | ❌ W0 | ⬜ pending |
| 3-02-03 | 02 | 1 | HW-05 | unit (mock capability response) | `cargo test -p unix-oidc-agent --features tpm p256_capability_probe` | ❌ W0 | ⬜ pending |
| 3-03-02 | 03 | 2 | HW-06 | unit | `cargo test -p unix-oidc-agent hardware::factory` | ❌ W0 | ⬜ pending |
| 3-03-03 | 03 | 2 | HW-07 | manual | n/a | ❌ W0 | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

- [ ] `unix-oidc-agent/src/crypto/yubikey_signer.rs` — stubs + unit tests for HW-01, HW-04
- [ ] `unix-oidc-agent/src/crypto/tpm_signer.rs` — stubs + unit tests for HW-02, HW-05
- [ ] `unix-oidc-agent/src/hardware/mod.rs` — HardwareSignerFactory stubs for HW-06
- [ ] `unix-oidc-agent/src/hardware/pin_cache.rs` — PIN cache stubs
- [ ] `unix-oidc-agent/tests/hardware_integration.rs` — `#[ignore]` test stubs for HW-01, HW-02

*Existing infrastructure covers build test (HW-03) via CI.*

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| Hardware key setup docs present and accurate | HW-07 | Documentation content review | Review `docs/hardware-signer-guide.md` covers: YubiKey PIV provisioning, TPM enrollment, PCSC daemon, PIN lockout, pcscd not running, TPM not present |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 15s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
