---
phase: 23-integration-gap-fixes
plan: 01
subsystem: auth
tags: [dpop, nonce-cache, replay-protection, multi-issuer, entra, yaml-deserialization, security-fix]

requires:
  - phase: 21-multi-idp
    provides: authenticate_multi_issuer + apply_per_issuer_dpop
  - phase: 22-entra-id-integration
    provides: policy-entra.yaml fixture + entra_integration.rs test suite

provides:
  - Cache-backed nonce consumption in apply_per_issuer_dpop() (replay-window fix)
  - Nonce replay rejection tests for multi-issuer path (MIDP-02 integration fix)
  - Non-ignored CI test for Entra policy fixture deserialization (ENTR-01 integration fix)

affects:
  - Any future phase touching apply_per_issuer_dpop or DPoP nonce enforcement
  - CI: entra_integration now has one always-run test (no secrets required)

tech-stack:
  added: []
  patterns:
    - "validate_and_enforce_nonce closure pattern: cache-backed nonce consumption lives in the DPoP validation closure, not at the call site"
    - "Non-ignored fixture test pattern: always-run structural assertion test alongside ignored live-credential tests"

key-files:
  created:
    - .planning/phases/23-integration-gap-fixes/23-01-SUMMARY.md
  modified:
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/tests/multi_idp_integration.rs
    - pam-unix-oidc/tests/entra_integration.rs

key-decisions:
  - "dpop_nonce_enforcement passed as EnforcementMode from policy.effective_security_modes().dpop_required — consistent with how JTI enforcement is plumbed through authenticate_multi_issuer"
  - "Nonce consumption block placed inside validate_and_enforce_nonce closure (not at call sites) to ensure both DPoP-bound and unbound-with-proof paths consume nonces unconditionally"
  - "Replay test uses enforcement=Warn so unbound token + proof flows through nonce consumption without requiring cnf.jkt — simpler test setup, same code path coverage"
  - "Entra fixture test is NOT gated by cfg(feature = test-mode) — pure deserialization, no signature bypass needed"

requirements-completed:
  - "MIDP-02 (integration fix)"
  - "ENTR-01 (integration fix)"

duration: 12min
completed: 2026-03-14
---

# Phase 23 Plan 01: Integration Gap Fixes Summary

**Cache-backed DPoP nonce consumption added to multi-issuer auth path (replay-window closed) and non-ignored Entra fixture YAML deserialization test added to CI**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-14T00:48:01Z
- **Completed:** 2026-03-14T01:00:00Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Fixed replay-window vulnerability: `apply_per_issuer_dpop()` now calls `global_nonce_cache().consume()` in the cache-backed nonce path, matching the behavior of `authenticate_with_dpop()`
- Added two adversarial tests that verify nonce replay is rejected and nonce is absent from cache after auth
- Added `test_policy_entra_yaml_deserializes` to `entra_integration.rs` — runs in every CI build without any Entra secrets, catching YAML schema regressions

## Task Commits

1. **Task 1: Nonce consumption + replay tests** - `57bfd51` (fix + test)
2. **Task 2: Entra fixture deserialization test** - `9479066` (test)

## Files Created/Modified

- `pam-unix-oidc/src/auth.rs` - Added `dpop_nonce_enforcement` param to `apply_per_issuer_dpop()`, refactored `validate_proof` closure to `validate_and_enforce_nonce` with cache-backed nonce consumption block
- `pam-unix-oidc/tests/multi_idp_integration.rs` - Added `make_test_dpop_proof` helper (real ES256 proofs), `test_multi_issuer_dpop_nonce_replay_rejected`, `test_multi_issuer_dpop_nonce_consumed`
- `pam-unix-oidc/tests/entra_integration.rs` - Added `test_policy_entra_yaml_deserializes` (non-ignored)

## Decisions Made

- `dpop_nonce_enforcement` sourced from `policy.effective_security_modes().dpop_required` — consistent with the existing JTI enforcement plumbing pattern in `authenticate_multi_issuer`
- Nonce block placed inside the `validate_and_enforce_nonce` closure so both DPoP-bound and unbound-with-proof paths go through identical consumption logic
- Replay test uses `enforcement=Warn` with an unbound token to keep test setup minimal while still exercising the `validate_and_enforce_nonce` closure
- Entra fixture test needs no `cfg(feature = "test-mode")` gate because it only exercises YAML deserialization, not signature verification

## Deviations from Plan

None — plan executed exactly as written. The `validate_and_enforce_nonce` closure approach is equivalent to the plan's instruction to "add the cache-backed nonce consumption block after each `validate_proof()` call" — the closure was the idiomatic Rust way to do that without duplicating the block at two call sites.

## Issues Encountered

None.

## Next Phase Readiness

- Multi-issuer DPoP nonce path is now on parity with the single-issuer path — both consume nonces from the global cache
- Entra fixture YAML schema is now regression-tested in CI
- Phase 23 Plan 02 (if any) can proceed without DPoP replay concerns in the multi-issuer path

---
*Phase: 23-integration-gap-fixes*
*Completed: 2026-03-14*
