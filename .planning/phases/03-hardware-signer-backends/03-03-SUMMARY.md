---
phase: 03-hardware-signer-backends
plan: 03
subsystem: cli+docs
tags: [cli, hardware-signer, provision, yubikey, tpm, dpop, signer-type, metadata]

requires:
  - phase: 03-hardware-signer-backends/03-01
    provides: YubiKeySigner::open + YubiKeySigner::provision, DPoPSigner trait, build/assemble DPoP
  - phase: 03-hardware-signer-backends/03-02
    provides: TpmSigner::provision + TpmSigner::load, probe_p256

provides:
  - build_signer() factory: constructs DPoPSigner from spec string (software/yubikey:slot/tpm)
  - provision_signer() factory: generates key on hardware, returns (signer_type, Arc<dyn DPoPSigner>)
  - provision subcommand: `unix-oidc-agent provision --signer yubikey:9a` or tpm
  - login --signer flag: selects hardware or software signer at login time
  - signer_type persisted in token metadata JSON and restored on daemon restart
  - Hardware unavailable at restart: ERROR logged, signer=None, no silent fallback
  - Status shows signer type: "software", "yubikey (slot 9a)", "tpm"
  - docs/hardware-key-setup.md: YubiKey PIV + TPM 2.0 setup guide

affects:
  - daemon/protocol.rs: signer_type added to AgentResponseData::Status
  - daemon/socket.rs: signer_type field in AgentState
  - main.rs: provision subcommand, login --signer, load_agent_state() hardware restore

tech-stack:
  added: []
  patterns:
    - build_signer/provision_signer: spec-string dispatch (yubikey:slot → YubiKeySigner::open/provision, tpm → TpmSigner::load/provision)
    - signer_type persistence: stored in token metadata JSON, key "signer_type"
    - No silent fallback: hardware unavailable → signer=None + ERROR log, re-login required

key-files:
  created:
    - docs/hardware-key-setup.md
  modified:
    - unix-oidc-agent/src/hardware/mod.rs
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/daemon/protocol.rs

key-decisions:
  - "build_signer takes #[allow(unused_variables)] config param — on base build (no hardware features) the config arg goes unused; #[cfg]-gated branches in the hardware feature paths use it"
  - "Hardware signer login skips KEY_DPOP_PRIVATE storage — key lives on device; comment in code makes audit boundary explicit"
  - "load_agent_state() reads signer_type from metadata before constructing signer — single source of truth for backend selection"
  - "format_signer_type() helper for user-facing display: 'yubikey:9a' → 'yubikey (slot 9a)'"

requirements-completed: [HW-06, HW-07]

duration: 10m
completed: 2026-03-10
---

# Phase 03 Plan 03: Provision Command + CLI Integration + Hardware Key Docs Summary

**Hardware signers wired into CLI via provision subcommand, --signer login flag, signer_type metadata persistence, and daemon restart recovery, plus comprehensive hardware key setup guide**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-10T17:23:53Z
- **Completed:** 2026-03-10T17:34:24Z
- **Tasks:** 2
- **Files modified:** 4 (modified) + 1 (created) = 5 total

## Accomplishments

- Implemented `build_signer()` and `provision_signer()` factory functions in `hardware/mod.rs` — spec-string dispatch to YubiKeySigner or TpmSigner, with clear errors when hardware features are not compiled in
- Added `Provision` subcommand to the CLI (`unix-oidc-agent provision --signer yubikey:9a`), routing to YubiKeySigner::provision() or TpmSigner::provision()
- Added `--signer` flag to `login` subcommand (default: `software`); hardware specs open the pre-provisioned device key via `build_signer()`
- Persisted `signer_type` in token metadata JSON; `load_agent_state()` reads it at daemon startup and reconstructs the correct backend — no silent fallback if hardware is unavailable (ERROR logged, signer set to None)
- Added `signer_type` field to `AgentState`, `AgentResponseData::Status`, and `AgentResponse::status()`; status output shows "Signer: yubikey (slot 9a)" etc.
- Wrote `docs/hardware-key-setup.md` (301 lines) covering YubiKey PIV provisioning, TPM 2.0 enrollment, PCSC daemon requirements, PIN management and lockout recovery, cloud vTPM matrix, configuration file format, troubleshooting table, and security considerations

## Task Commits

1. **Task 1: Wire build_signer factory, provision command, --signer flag, signer persistence, and status** — `a0739fe` (feat)
2. **Task 2: Write hardware key setup documentation** — `415ed22` (docs)

## Files Created/Modified

- `unix-oidc-agent/src/hardware/mod.rs` — Added `build_signer()` and `provision_signer()` public factory functions; added `use crate::crypto::DPoPSigner; use std::sync::Arc;` imports
- `unix-oidc-agent/src/main.rs` — Added `Provision` subcommand, `--signer` flag on `Login`, `run_provision()`, `format_signer_type()` helper, updated `run_login()` for hardware signer selection and `signer_type` metadata, updated `load_agent_state()` for hardware restore
- `unix-oidc-agent/src/daemon/socket.rs` — Added `signer_type: Option<String>` to `AgentState`, updated Debug impl, `new()`, all struct literal construction sites, and `handle_request` Status arm
- `unix-oidc-agent/src/daemon/protocol.rs` — Added `signer_type: Option<String>` to `AgentResponseData::Status`, updated `AgentResponse::status()` signature (with `#[allow(clippy::too_many_arguments)]`), updated all test call sites and added new `test_status_response_hardware_signer_type` test
- `docs/hardware-key-setup.md` — New: YubiKey PIV and TPM 2.0 setup guide (301 lines)

## Decisions Made

- **`build_signer` config param with `#[allow(unused_variables)]`**: Without hardware features the `config` arg is unused (all branches behind `#[cfg(feature = "yubikey")]` and `#[cfg(feature = "tpm")]`). Using `#[allow(unused_variables)]` keeps a clean API while avoiding a lint error on base builds.
- **Hardware login skips KEY_DPOP_PRIVATE**: For hardware signers, `run_login()` does not write `KEY_DPOP_PRIVATE`. The comment in the code makes this audit boundary explicit: hardware keys never leave the device.
- **`load_agent_state()` as single source of truth**: All signer backend selection happens in `load_agent_state()` based on `signer_type` from metadata. This is the only place that decides software vs. hardware — no duplicated logic.
- **`format_signer_type()` for display**: The raw spec `"yubikey:9a"` is not user-friendly. `format_signer_type()` maps it to `"yubikey (slot 9a)"` for status output and login completion messages.
- **`#[allow(clippy::too_many_arguments)]` on `AgentResponse::status()`**: The function now has 8 parameters (exceeding clippy's default limit of 7). A builder pattern would be over-engineered for this internal API; the allow attribute is the pragmatic choice.

## Deviations from Plan

None — plan executed exactly as written. All verification steps passed on first attempt.

## Issues Encountered

- Clippy `-D warnings` flagged `AgentResponse::status()` with 8 parameters as exceeding the `too_many_arguments` limit (7). Fixed with `#[allow(clippy::too_many_arguments)]` per plan step 7 guidance.
- `unused_variables` warning for `config` param in `build_signer()` / `provision_signer()` on base builds (no hardware features compiled). Fixed with `#[allow(unused_variables)]` on the parameter.

## Self-Check: PASSED

- unix-oidc-agent/src/hardware/mod.rs: FOUND
- docs/hardware-key-setup.md: FOUND (301 lines)
- .planning/phases/03-hardware-signer-backends/03-03-SUMMARY.md: FOUND
- Commit a0739fe: FOUND
- Commit 415ed22: FOUND

---
*Phase: 03-hardware-signer-backends*
*Completed: 2026-03-10*
