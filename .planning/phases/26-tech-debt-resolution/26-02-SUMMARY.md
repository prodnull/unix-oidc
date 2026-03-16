---
phase: 26-tech-debt-resolution
plan: 02
subsystem: auth
tags: [pam, dead-code, serde, group-resolution, multi-idp]

requires:
  - phase: 26-01
    provides: ACR enforcement wiring and per-issuer JWKS config
provides:
  - Smaller GroupSource enum (NssOnly only) with no dead TokenClaim variant
  - Removed effective_issuers() backward-compat shim; issuer_by_url() is sole lookup path
  - Regression tests for NssOnly serde, issuer_by_url resolution, token_claim rejection
affects: [27-multi-idp-advanced, 28-e2e-tests]

tech-stack:
  added: []
  patterns: [single-variant-enum-with-default, dead-code-removal-with-regression-tests]

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/tests/multi_idp_integration.rs

key-decisions:
  - "GroupMappingConfig.claim field kept for forward compatibility but doc updated to note NssOnly-only support"
  - "Removed effective_issuers() entirely including legacy OIDC_ISSUER env var synthesis path"

patterns-established:
  - "Dead code removal paired with positive regression tests and negative rejection tests"

requirements-completed: [DEBT-03, DEBT-04]

duration: 4min
completed: 2026-03-16
---

# Phase 26 Plan 02: Dead Code Removal Summary

**Removed GroupSource::TokenClaim enum variant and effective_issuers() shim with 4 regression tests confirming NssOnly serde, issuer_by_url resolution, and token_claim rejection**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T03:46:13Z
- **Completed:** 2026-03-16T03:50:34Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments
- Removed GroupSource::TokenClaim dead variant from security-critical PAM module (DEBT-03)
- Removed effective_issuers() backward-compat method that was never called in production auth path (DEBT-04)
- Removed 5 tests exercising removed code, added 4 positive/negative regression tests
- Verified serde correctly rejects "token_claim" as invalid GroupSource value

## Task Commits

Each task was committed atomically:

1. **Task 1: Remove GroupSource::TokenClaim and effective_issuers() dead code** - `e5a0160` (refactor)

## Files Created/Modified
- `pam-unix-oidc/src/policy/config.rs` - Removed TokenClaim variant, effective_issuers() method, 3 unit tests; added 4 regression tests; updated doc comments
- `pam-unix-oidc/tests/multi_idp_integration.rs` - Removed effective_issuers and TokenClaim tests; updated module doc comments

## Decisions Made
- GroupMappingConfig.claim field retained for forward compatibility (field has no current consumer but keeping it avoids breaking YAML configs that include it)
- effective_issuers() removed entirely including the OIDC_ISSUER env var legacy synthesis path; auth pipeline exclusively uses issuer_by_url()

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- GroupSource enum is now single-variant, simplifying downstream match arms
- issuer_by_url() is the sole issuer lookup method, clarifying the API surface
- Ready for Phase 26-03 (Entra token helper) and Phase 27 (multi-IdP advanced features)

---
*Phase: 26-tech-debt-resolution*
*Completed: 2026-03-16*
