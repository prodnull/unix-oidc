---
phase: 26-tech-debt-resolution
plan: 01
subsystem: auth
tags: [acr, jwks, oidc, pam, multi-idp, config]

requires:
  - phase: 21-multi-idp-configuration
    provides: IssuerConfig with acr_mapping and multi-issuer auth pipeline
  - phase: 24-bug-fixes-lint
    provides: Clean lint baseline for config.rs and auth.rs modifications
provides:
  - ACR enforcement wired from IssuerConfig.acr_mapping.required_acr into ValidationConfig
  - Per-issuer JWKS cache TTL and HTTP timeout configurable via policy.yaml
  - required_acr field on AcrMappingConfig for operator-specified ACR requirements
affects: [27-multi-idp-advanced, 28-e2e-conformance]

tech-stack:
  added: []
  patterns:
    - "Per-issuer config fields with serde defaults and Default impl alignment"
    - "Structured log at INFO for non-default per-issuer values"

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/tests/multi_idp_integration.rs

key-decisions:
  - "required_acr added to AcrMappingConfig (not IssuerConfig) to keep ACR config co-located"
  - "JWKS defaults 300s/10s preserved via serde default functions for backward compatibility"

patterns-established:
  - "Per-issuer tuning via IssuerConfig fields with serde(default) and matching Default impl"

requirements-completed: [DEBT-02, DEBT-05]

duration: 3min
completed: 2026-03-16
---

# Phase 26 Plan 01: ACR Enforcement Wiring + Per-Issuer JWKS Config Summary

**ACR mapping enforcement wired from IssuerConfig into auth pipeline; JWKS cache TTL and HTTP timeout configurable per-issuer with 300s/10s defaults**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-16T03:39:36Z
- **Completed:** 2026-03-16T03:42:54Z
- **Tasks:** 1 (TDD: RED + GREEN)
- **Files modified:** 3

## Accomplishments
- ACR enforcement active when issuer has acr_mapping.required_acr set; tokens with wrong or missing ACR rejected
- Backward compatibility preserved: issuers without acr_mapping pass tokens without ACR checks
- Per-issuer JWKS cache TTL and HTTP timeout replace hardcoded constants in auth.rs
- Structured INFO log emitted when non-default JWKS values are used
- 9 new tests, 42 total tests passing, clippy clean

## Task Commits

Each task was committed atomically (TDD):

1. **Task 1 (RED): Failing tests for ACR enforcement and JWKS config** - `a84e936` (test)
2. **Task 1 (GREEN): Wire ACR enforcement and per-issuer JWKS config** - `4be4d65` (feat)

## Files Created/Modified
- `pam-unix-oidc/src/policy/config.rs` - Added required_acr to AcrMappingConfig; added jwks_cache_ttl_secs/http_timeout_secs to IssuerConfig with serde defaults
- `pam-unix-oidc/src/auth.rs` - Replaced hardcoded required_acr: None with issuer_config.acr_mapping.required_acr; replaced JWKS constants with per-issuer config values
- `pam-unix-oidc/tests/multi_idp_integration.rs` - Added 9 tests for ACR enforcement wiring and JWKS config serde

## Decisions Made
- `required_acr` added to `AcrMappingConfig` (not `IssuerConfig`) to keep all ACR configuration co-located in the acr_mapping block
- JWKS defaults (300s TTL, 10s timeout) preserved via `fn default_jwks_cache_ttl()` and `fn default_http_timeout()` serde default functions for zero-behavior-change upgrade

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed existing AcrMappingConfig direct constructions in tests**
- **Found during:** Task 1 (RED phase)
- **Issue:** Two existing tests constructed AcrMappingConfig directly without the new required_acr field
- **Fix:** Added `..AcrMappingConfig::default()` to existing test constructions
- **Files modified:** pam-unix-oidc/tests/multi_idp_integration.rs
- **Committed in:** a84e936 (RED phase commit)

---

**Total deviations:** 1 auto-fixed (1 bug fix)
**Impact on plan:** Minimal - existing test construction needed update for new struct field. No scope creep.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- ACR enforcement and per-issuer JWKS config are wired and tested
- Phase 27 (multi-IdP advanced) can build on these wired config paths
- Phase 28 (E2E conformance) can validate ACR enforcement end-to-end

---
*Phase: 26-tech-debt-resolution*
*Completed: 2026-03-16*
