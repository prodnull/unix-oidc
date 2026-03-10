---
phase: 03-hardware-signer-backends
verified: 2026-03-10T18:30:00Z
status: passed
score: 7/7 must-haves verified
re_verification: false
---

# Phase 03: Hardware Signer Backends Verification Report

**Phase Goal:** Add YubiKey (PKCS#11) and TPM signer implementations behind optional Cargo features
**Verified:** 2026-03-10T18:30:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | DPoP proof generation works with both software signer and external raw r\|\|s bytes | VERIFIED | `build_dpop_message` + `assemble_dpop_proof` implemented in `dpop.rs`; unit tests pass for both paths |
| 2 | YubiKeySigner implements DPoPSigner trait and compiles behind `--features yubikey` | VERIFIED | `impl DPoPSigner for YubiKeySigner` in `yubikey_signer.rs`; `cargo build --features yubikey` succeeds |
| 3 | Building without `--features yubikey` or `--features tpm` succeeds with no hardware deps | VERIFIED | `cargo build -p unix-oidc-agent` (no features) finishes cleanly; no cryptoki or tss-esapi in base dep graph |
| 4 | YubiKey PCSC session is opened and closed per `sign_proof()` call — no persistent session | VERIFIED | `sign_proof` opens `open_rw_session`, signs, calls `drop(session)` explicitly before `assemble_dpop_proof` |
| 5 | TPM probes P-256 capability at provisioning time with clear error if unsupported | VERIFIED | `TpmSigner::probe_p256()` calls `get_capability(EccCurves)` and returns `TpmSignerError::P256NotSupported` on failure; `provision()` calls `probe_p256()` first |
| 6 | `unix-oidc-agent login --signer yubikey\|tpm\|software` CLI flag selects the correct backend | VERIFIED | `Commands::Login { signer: String }` with `default_value = "software"` in `main.rs`; `build_signer()` dispatches by spec |
| 7 | Hardware key setup documentation covers YubiKey PIV provisioning, TPM enrollment, PCSC daemon, and troubleshooting | VERIFIED | `docs/hardware-key-setup.md` exists (301 lines); covers YubiKey PIV slots, TPM setup, PCSC daemon, PIN lockout recovery, cloud vTPM matrix, troubleshooting table |

**Score:** 7/7 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `unix-oidc-agent/src/crypto/dpop.rs` | `build_dpop_message`, `assemble_dpop_proof`, `generate_dpop_proof`, `InvalidSignatureLength`, `HardwareSigner` error variants | VERIFIED | All functions present and tested; both new error variants declared |
| `unix-oidc-agent/src/crypto/yubikey_signer.rs` | `YubiKeySigner` implementing `DPoPSigner` via cryptoki PKCS#11, with `open()` and `provision()` constructors | VERIFIED | 790 lines; full implementation with error types, helpers, and both hardware (#[ignore]) and software unit tests |
| `unix-oidc-agent/src/hardware/pin_cache.rs` | `PinCache` with `SecretString`, configurable timeout, `clear()` | VERIFIED | `PinCache` struct with `Mutex<Option<CacheEntry>>`, `timeout_secs`, `get_or_prompt`, `clear`; rpassword cfg-gated |
| `unix-oidc-agent/src/hardware/mod.rs` | `SignerConfig`, `YubiKeyConfig`, `TpmConfig`, `build_signer()`, `provision_signer()`, `SignerConfig::load()` | VERIFIED | All types present; both factory functions dispatch by spec with feature-flag guards |
| `unix-oidc-agent/src/crypto/tpm_signer.rs` | `TpmSigner` implementing `DPoPSigner` via tss-esapi; `pad_to_32`; `probe_p256` | VERIFIED | `pad_to_32` at module root (cross-platform); `TpmSigner` in `linux_impl` behind `cfg(target_os = "linux")`; 5 `pad_to_32` unit tests |
| `unix-oidc-agent/Cargo.toml` | `[features]` with `yubikey` and `tpm`; cryptoki optional; rpassword optional; tss-esapi Linux-only optional | VERIFIED | `yubikey = ["dep:cryptoki", "dep:rpassword"]`; `tpm = ["dep:tss-esapi", "dep:rpassword"]`; tss-esapi under `[target.'cfg(target_os = "linux")'.dependencies]` |
| `unix-oidc-agent/src/main.rs` | `Commands::Provision`, `--signer` flag on `Login`, `run_provision()`, `format_signer_type()`, signer_type in metadata, hardware restore in `load_agent_state()` | VERIFIED | All present and wired |
| `unix-oidc-agent/src/daemon/socket.rs` | `AgentState.signer_type: Option<String>`, passed through Status response | VERIFIED | Field at line 50; passed to `AgentResponse::status()` at line 278 |
| `unix-oidc-agent/src/daemon/protocol.rs` | `AgentResponseData::Status.signer_type: Option<String>`, `AgentResponse::status()` 8-parameter version | VERIFIED | Field at line 88; constructor at line 123 |
| `docs/hardware-key-setup.md` | 300+ line setup guide | VERIFIED | 301 lines covering YubiKey PIV, TPM 2.0, PCSC, PIN management, cloud vTPMs, config file, troubleshooting table, security considerations |

---

### Key Link Verification

#### Plan 03-01 Key Links

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `yubikey_signer.rs` | `dpop.rs` | `build_dpop_message` + `assemble_dpop_proof` | WIRED | Line 29: `use crate::crypto::dpop::{assemble_dpop_proof, build_dpop_message, DPoPError};`; called in `sign_proof()` at lines 276 and 324 |
| `yubikey_signer.rs` | `hardware/pin_cache.rs` | `PinCache::get_or_prompt` | WIRED | Line 31: `use crate::hardware::{PinCache, SignerConfig};`; `pin_cache.get_or_prompt("YubiKey PIN: ")` in `sign_proof()` at line 281 |
| `signer.rs` (SoftwareSigner) | `dpop.rs` | `generate_dpop_proof` | WIRED | SoftwareSigner::sign_proof calls `generate_dpop_proof`; refactoring preserved this path |

#### Plan 03-02 Key Links

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `tpm_signer.rs` | `dpop.rs` | `build_dpop_message` + `assemble_dpop_proof` | WIRED | Line 77-78 in `linux_impl`: `use crate::crypto::dpop::{assemble_dpop_proof, build_dpop_message, DPoPError};`; called in `sign_proof()` at lines 312 and 388 |
| `tpm_signer.rs` | `hardware/pin_cache.rs` | `PinCache` | WIRED | Line 80: `use crate::hardware::{PinCache, SignerConfig};`; `PinCache::new(pin_timeout)` in `TpmSigner::load()` |

#### Plan 03-03 Key Links

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `main.rs` | `hardware/mod.rs` | `build_signer` + `provision_signer` | WIRED | Line 16: `use unix_oidc_agent::hardware::{build_signer, provision_signer, SignerConfig};`; called in `run_login()` at line 402 and `run_provision()` at line 700 |
| `hardware/mod.rs` | `crypto/yubikey_signer.rs` | `YubiKeySigner::provision()` | WIRED | `provision_signer` at line 210: `crate::crypto::YubiKeySigner::provision(slot, config)?` |
| `main.rs` | token metadata JSON | `signer_type` field persisted | WIRED | Line 651: `"signer_type": signer_type_for_storage` in metadata JSON |
| `load_agent_state()` | `build_signer()` | reads `signer_type` from metadata, constructs correct signer | WIRED | Lines 939-978: reads `signer_type` from metadata; dispatches to `build_signer(hw_spec, &hw_config)` for hardware specs; ERROR logged with no fallback if unavailable |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| HW-01 | 03-01 | `YubiKeySigner` implementing `DPoPSigner` via `cryptoki` 0.7 (PKCS#11) with P-256 ECDSA signing | SATISFIED | `yubikey_signer.rs`: full implementation with `open()`, `provision()`, and `impl DPoPSigner for YubiKeySigner`; structurally complete; integration test stubs for real hardware |
| HW-02 | 03-02 | `TpmSigner` implementing `DPoPSigner` via `tss-esapi` 7.6 with P-256 ECDSA signing | SATISFIED | `tpm_signer.rs` `linux_impl`: full implementation with `probe_p256()`, `provision()`, `load()`, and `impl DPoPSigner for TpmSigner`; integration test stubs for real TPM |
| HW-03 | 03-01 | Both backends gated behind optional cargo features (`yubikey`, `tpm`) | SATISFIED | `Cargo.toml` features declared; base build (`cargo build -p unix-oidc-agent`) succeeds without PKCS#11 or TPM deps; confirmed with build verification |
| HW-04 | 03-01 | YubiKey uses open-sign-close PCSC pattern (no persistent handle) | SATISFIED | `sign_proof()` opens `open_rw_session(slot)`, signs, calls `drop(session)` explicitly before returning; no session stored in struct |
| HW-05 | 03-02 | TPM probes P-256 capability at provisioning time with clear error if unsupported | SATISFIED | `TpmSigner::probe_p256()` queries `CapabilityType::EccCurves`, checks for `EccCurve::NistP256`; `provision()` calls `probe_p256()` before any key creation |
| HW-06 | 03-03 | `unix-oidc-agent login --signer yubikey\|tpm\|software` CLI flag for backend selection; `provision` subcommand | SATISFIED | `Commands::Login { signer: String, default_value = "software" }` and `Commands::Provision { signer: String }` both present and wired to `build_signer()`/`provision_signer()` |
| HW-07 | 03-03 | Documentation updated with hardware key setup guides (YubiKey PIV provisioning, TPM enrollment, PCSC daemon, troubleshooting) | SATISFIED | `docs/hardware-key-setup.md` (301 lines) covers all required areas including YubiKey PIV slots, TPM 2.0 setup, PCSC daemon, PIN lockout recovery, cloud vTPM advisory, config file format, troubleshooting table |

**All 7 requirements satisfied.**

---

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | — | — | — | No TODO/FIXME/placeholder comments, empty returns, or stub implementations found |

Scanned: `yubikey_signer.rs`, `tpm_signer.rs`, `hardware/mod.rs`, `main.rs`, `docs/hardware-key-setup.md`

---

### Human Verification Required

#### 1. YubiKey Sign-Proof Round-Trip

**Test:** With a YubiKey 5 series inserted and pcscd running, run:
```
cargo build --features yubikey
# Set PIN to known value, provision slot 9a
./target/debug/unix-oidc-agent provision --signer yubikey:9a
./target/debug/unix-oidc-agent login --signer yubikey:9a --issuer https://your-idp.com
```
**Expected:** Provisioning succeeds, login completes with DPoP thumbprint printed, signer type shown as "yubikey (slot 9a)" in status output.
**Why human:** Requires physical YubiKey hardware; no mock PKCS#11 in test suite.

#### 2. TPM Sign-Proof Round-Trip

**Test:** On a Linux machine with TPM 2.0 and `tpm2-abrmd` running:
```
cargo build --features tpm
./target/debug/unix-oidc-agent provision --signer tpm
./target/debug/unix-oidc-agent login --signer tpm --issuer https://your-idp.com
```
**Expected:** Provisioning probes P-256 capability, generates key at handle 0x81000001, login completes, status shows "Signer: tpm".
**Why human:** Requires real TPM 2.0 hardware or swtpm daemon; CI does not have TPM available.

#### 3. Hardware Unavailable at Daemon Restart

**Test:** Login with `--signer yubikey:9a`, start daemon (`serve`), then unplug the YubiKey and restart the daemon.
**Expected:** Daemon logs ERROR "Hardware signer 'yubikey:9a' unavailable — re-login required", starts without signing capability, no silent fallback to software signer.
**Why human:** Requires physical YubiKey to verify the error behavior and absence of fallback.

#### 4. PIN Cache Behavior

**Test:** Login with `--signer yubikey:9a`, sign several proofs — PIN should only be prompted once. Then intentionally enter a wrong PIN; verify PIN cache is cleared and next attempt re-prompts.
**Expected:** Cache hit behavior: no re-prompt within 8 hours. CKR_PIN_INCORRECT clears cache and next call prompts again.
**Why human:** Requires real YubiKey; timeout and cache clearing behavior is functionally implemented but cannot be verified without hardware.

---

### Gaps Summary

No gaps found. All seven HW requirements are structurally implemented and their key links are wired. The only limitation is that full end-to-end signing verification requires real hardware (YubiKey or TPM), which is documented via `#[ignore]` integration tests in the codebase. This is the expected state for hardware backends.

**Note on cryptoki version:** Plans specified cryptoki 0.12; the implementation uses cryptoki 0.7.0 (the version that actually resolved from crates.io at implementation time). The API surface used is identical. This deviation was documented in the 03-01-SUMMARY and is not a gap.

**Note on tss-esapi platform scope:** tss-esapi is declared as a Linux-only optional dep (`[target.'cfg(target_os = "linux")'.dependencies.tss-esapi]`). `TpmSigner` compiles on Linux only; `pad_to_32` and its tests run on all platforms. This is the correct architecture for a Linux-only hardware backend.

---

_Verified: 2026-03-10T18:30:00Z_
_Verifier: Claude (gsd-verifier)_
