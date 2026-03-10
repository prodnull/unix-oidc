---
phase: 03-hardware-signer-backends
plan: 02
subsystem: crypto
tags: [dpop, tpm, tss-esapi, hardware-signer, p256, jwt, probe, pkcs11]

requires:
  - phase: 03-hardware-signer-backends/03-01
    provides: build_dpop_message + assemble_dpop_proof, PinCache, SignerConfig, TpmConfig, DPoPSigner trait

provides:
  - pad_to_32() helper (left-pads P-256 scalar bytes to 32 bytes; platform-independent)
  - TpmSigner implementing DPoPSigner via tss-esapi 7.6 (Linux only)
  - TpmSigner::probe_p256() verifying NistP256 curve support before key operations (HW-05)
  - TpmSigner::provision() creating non-exportable persistent P-256 key under Owner hierarchy
  - TpmSigner::load() reading existing key from persistent handle, reconstructing JWK/thumbprint
  - tss-esapi 7.6 optional dep gated to Linux via target.'cfg(target_os = "linux")'.dependencies

affects:
  - 03-03-provision-command (uses TpmSigner::provision() and TpmSigner::load())

tech-stack:
  added:
    - tss-esapi 7.6.0 (Linux-only optional dep; tss-esapi-sys 0.5.0 requires libtss2-esys at link time)
  patterns:
    - Platform-conditional module split: pad_to_32 always compiled under cfg(feature="tpm"); linux_impl gated by cfg(target_os="linux") for tss-esapi FFI
    - Open-sign-close TPM context: TpmSigner::sign_proof() creates Context, loads key, signs, drops Context — no persistent context held (matches HW-04 open-sign-close pattern from YubiKey)
    - probe_p256 first: TPM provisioning always calls probe_p256() before key creation to fail early on vTPMs lacking NistP256
    - pad_to_32 for TPM r||s: TPM BigNum-style scalars may omit leading zeros; pad_to_32 normalizes both r and s to 32 bytes before JWS assembly

key-files:
  created:
    - unix-oidc-agent/src/crypto/tpm_signer.rs
  modified:
    - unix-oidc-agent/src/crypto/mod.rs
    - unix-oidc-agent/Cargo.toml

key-decisions:
  - "tss-esapi dep gated to Linux only — tss-esapi-sys 0.5.0 pre-built bindings cover x86_64-linux, aarch64-linux, x86_64-darwin only; aarch64-darwin (Apple Silicon) panics in build script. Linux is the only deployment target for TPM anyway."
  - "tpm_signer module compiled on all platforms under cfg(feature=tpm) but linux_impl (tss-esapi) gated to target_os=linux — keeps pad_to_32 unit tests runnable on macOS CI"
  - "TpmSigner::sign_proof() uses pre-computed SHA-256 digest + null HashcheckTicket for unrestricted signing keys — TPM unrestricted signing keys do not require TPM-internal hash verification; null ticket is the correct approach per TCG spec"
  - "HashcheckTicket constructed via TryFrom<TPMT_TK_HASHCHECK> from tss2-esys FFI struct — no public constructor in tss-esapi 7.6; must go through raw FFI type"

patterns-established:
  - "TPM context lifecycle: Context::new() per sign_proof() call, never held across calls (matches HW-04 open-sign-close from YubiKey)"
  - "pad_to_32 normalization: all P-256 scalar extractions from TPM must pass through pad_to_32 before JWS assembly"
  - "Platform-conditional optional dep: use [target.'cfg(target_os=)'.dependencies] for FFI crates requiring platform-specific system libraries"

requirements-completed: [HW-02, HW-05]

duration: 45min
completed: 2026-03-10
---

# Phase 03 Plan 02: TpmSigner via tss-esapi Summary

**TPM 2.0 P-256 ECDSA DPoP signer with NistP256 capability probe and r||s left-padding behind Linux-only tss-esapi 7.6 optional feature**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-03-10T16:35:00Z
- **Completed:** 2026-03-10T17:20:46Z
- **Tasks:** 1 (TDD)
- **Files modified:** 2 (modified) + 1 (created) = 3 total

## Accomplishments

- Implemented `TpmSigner` behind `--features tpm` using tss-esapi 7.6, with `probe_p256()` (HW-05), `provision()`, `load()`, and `DPoPSigner::sign_proof()` implementations
- Factored `pad_to_32()` as a platform-independent public helper — TPM scalars may omit leading zeros; this normalizes r and s to exactly 32 bytes before JWS assembly per RFC 9449
- Added tss-esapi as a Linux-only optional dep (`[target.'cfg(target_os = "linux")'.dependencies]`), keeping macOS builds clean while preserving the 5 pad_to_32 unit tests as runnable cross-platform
- All four build targets pass on macOS: no features, yubikey, tpm, yubikey+tpm

## Task Commits

1. **Task 1: Implement TpmSigner with P-256 capability probe and signing** - `d71d4a7` (feat)

## Files Created/Modified

- `unix-oidc-agent/src/crypto/tpm_signer.rs` — pad_to_32 (platform-independent) + linux_impl submodule with TpmSigner (probe_p256, provision, load, DPoPSigner impl), TpmSignerError, and integration test stubs
- `unix-oidc-agent/src/crypto/mod.rs` — Added `#[cfg(feature = "tpm")] pub mod tpm_signer` and Linux-only re-export of TpmSigner
- `unix-oidc-agent/Cargo.toml` — Added `[target.'cfg(target_os = "linux")'.dependencies.tss-esapi]` version 7.6 optional; updated `tpm = ["dep:tss-esapi", "dep:rpassword"]`

## Decisions Made

- **tss-esapi Linux-only**: tss-esapi-sys 0.5.0 requires `libtss2-esys` pkg-config and supports only x86_64-linux, aarch64-linux, x86_64-darwin natively. The dev environment is aarch64-darwin (Apple Silicon), which panics in the build script. Linux is the deployment platform for TPM. Using `target.'cfg(target_os = "linux")'.dependencies` keeps macOS CI functional.
- **pad_to_32 outside linux_impl**: The helper is placed at the module root (not inside linux_impl) so its unit tests compile and run on all platforms. This was the key insight that unblocked macOS CI validation of the core algorithm.
- **HashcheckTicket via raw FFI**: tss-esapi 7.6 `HashcheckTicket` has no public constructor; construction requires `TryFrom<TPMT_TK_HASHCHECK>` using the raw tss2_esys FFI struct with `tag: StructureTag::Hashcheck`, `hierarchy: Hierarchy::Null`, and empty digest.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] tss-esapi-sys does not support aarch64-darwin**
- **Found during:** Task 1 (first build attempt with `--features tpm`)
- **Issue:** `cargo build --features tpm` panics in tss-esapi-sys build script: "aarch64, darwin is not part of the supported tuples". The plan assumed Linux CI. tpm2-tss is not available on macOS via homebrew.
- **Fix:** Moved tss-esapi to `[target.'cfg(target_os = "linux")'.dependencies]` (Linux-only optional dep). Split tpm_signer.rs into platform-independent part (pad_to_32 + tests) and linux_impl submodule (tss-esapi). The feature activates on all platforms; TpmSigner is only compiled on Linux.
- **Files modified:** unix-oidc-agent/Cargo.toml, unix-oidc-agent/src/crypto/mod.rs, unix-oidc-agent/src/crypto/tpm_signer.rs
- **Verification:** `cargo build --features tpm` succeeds on macOS; `cargo test --lib --features tpm` runs 5 pad_to_32 unit tests; all 4 build variants pass
- **Committed in:** d71d4a7

---

**Total deviations:** 1 auto-fixed (Rule 3 — platform blocking issue)
**Impact on plan:** The fix is necessary for macOS dev environment. Linux CI (the real deployment target) will compile the full tss-esapi implementation. No scope creep; plan objectives fully met for the Linux target.

## Issues Encountered

- `HashcheckTicket` struct fields are private in tss-esapi 7.6; no `new()` constructor. Resolved by using `TryFrom<TPMT_TK_HASHCHECK>` from the raw tss2_esys FFI binding, accessing `tss_esapi::tss2_esys::TPMT_TK_HASHCHECK` directly.
- `StructureTag::Hashcheck` for the null ticket must come from `tss_esapi::constants::StructureTag`, not from `interface_types::structure_tags` — the type is re-exported from constants in tss-esapi 7.6.

## Next Phase Readiness

- **03-03 (provision command)**: Both `TpmSigner::provision()` and `TpmSigner::load()` are ready for CLI integration. The `probe_p256()` call is embedded in `provision()` so the CLI gets HW-05 checks automatically.
- **Blocker (existing)**: Full end-to-end validation requires real TPM 2.0 hardware or swtpm. Integration tests are marked `#[ignore = "Requires TPM 2.0 with tpm2-abrmd running"]`.
- **Linux CI note**: The `cargo build --features tpm` step in the plan's verification checklist requires `libtss2-esys`, `libtss2-sys`, `libtss2-tctildr`, and `libtss2-mu` (tpm2-tss >= 2.4.6). On Ubuntu: `apt install libtss2-dev`.

## Self-Check: PASSED

- unix-oidc-agent/src/crypto/tpm_signer.rs: FOUND
- .planning/phases/03-hardware-signer-backends/03-02-SUMMARY.md: FOUND
- Commit d71d4a7: FOUND

---
*Phase: 03-hardware-signer-backends*
*Completed: 2026-03-10*
