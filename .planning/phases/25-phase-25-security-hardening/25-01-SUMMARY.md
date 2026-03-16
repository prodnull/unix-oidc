---
phase: 25-phase-25-security-hardening
plan: 01
subsystem: auth
tags: [jwt, algorithm-confusion, https-enforcement, syslog, audit, oidc]

# Dependency graph
requires:
  - phase: 24-security-bug-fixes
    provides: "BreakGlassAuth severity wiring (SBUG-02), clippy-clean baseline"
provides:
  - "key_algorithm_to_algorithm() exhaustive enum match for JWKS-to-JWT algorithm conversion"
  - "DEFAULT_ALLOWED_ALGORITHMS constant and parse_algorithm_names() for per-issuer config"
  - "allowed_algorithms field on IssuerConfig and ValidationConfig"
  - "validate_https_url() shared function for URL scheme enforcement"
  - "HTTPS enforcement at PolicyConfig::load_from() for issuer URLs"
  - "cfg-gated allow_insecure_http_for_testing for test-mode builds"
  - "SHRD-03 regression guard documentation on existing break-glass tests"
affects: [25-phase-25-security-hardening, 28-e2e-testing]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Exhaustive enum match for cross-crate type conversion (orphan rule workaround)"
    - "Allowlist-based security (replace blocklist with explicit permitted set)"
    - "cfg-gated test-only struct fields for insecure bypasses"
    - "Shared URL validator reused across config and device flow modules"

key-files:
  created: []
  modified:
    - "pam-unix-oidc/src/oidc/validation.rs"
    - "pam-unix-oidc/src/policy/config.rs"
    - "pam-unix-oidc/src/device_flow/types.rs"
    - "pam-unix-oidc/src/auth.rs"
    - "pam-unix-oidc/src/sudo.rs"
    - "pam-unix-oidc/src/audit.rs"
    - "pam-unix-oidc/tests/entra_integration.rs"

key-decisions:
  - "Used standalone function key_algorithm_to_algorithm() instead of TryFrom due to orphan rule (both KeyAlgorithm and Algorithm are external types)"
  - "Allowlist approach (DEFAULT_ALLOWED_ALGORITHMS) instead of blocklist -- fails-safe when new algorithms are added to jsonwebtoken crate"
  - "SHRD-03 verified by existing Phase 24 SBUG-02 tests rather than adding duplicate test code"
  - "HTTPS validation placed in config.rs as public function for reuse by device_flow::types"

patterns-established:
  - "Algorithm safety via allowlist: new algorithms must be explicitly added to DEFAULT_ALLOWED_ALGORITHMS to be accepted"
  - "HTTPS enforcement at config load time: insecure URLs rejected before any network I/O"
  - "Test-mode struct fields use #[cfg(any(test, feature = 'test-mode'))] to guarantee absence in production binaries"

requirements-completed: [SHRD-01, SHRD-02, SHRD-03, SHRD-04]

# Metrics
duration: 14min
completed: 2026-03-16
---

# Phase 25 Plan 01: Security Hardening (Algorithm Allowlist + HTTPS Enforcement) Summary

**Algorithm confusion prevention via exhaustive enum-match allowlist, HTTPS enforcement for all OIDC issuer URLs at config load time, and break-glass syslog severity regression guard**

## Performance

- **Duration:** 14 min
- **Started:** 2026-03-16T02:03:46Z
- **Completed:** 2026-03-16T02:17:38Z
- **Tasks:** 3
- **Files modified:** 7

## Accomplishments

- Replaced fragile serde-based algorithm comparison with exhaustive `key_algorithm_to_algorithm()` enum match, closing the HS256-with-RSA-public-key algorithm confusion attack vector (SHRD-01)
- Replaced blocklist with configurable per-issuer allowlist (`DEFAULT_ALLOWED_ALGORITHMS`), failing safe when new algorithms are added to the jsonwebtoken crate (SHRD-02)
- Added HTTPS enforcement at `PolicyConfig::load_from()` so HTTP issuer URLs are rejected before any network I/O occurs (SHRD-04)
- Refactored device flow URI validation to reuse shared `validate_https_url()` function
- Verified break-glass syslog severity mapping (SHRD-03) with regression guard documentation

## Task Commits

Each task was committed atomically:

1. **Task 1: Algorithm enum match and configurable per-issuer allowlist** - `eec0649` (feat) -- committed by parallel session as part of 25-02 work
2. **Task 2: HTTPS enforcement for issuer URLs and device flow URIs** - `bdcbf0a` (feat)
3. **Task 3: Break-glass syslog severity verification** - `7fd1287` (test)

## Files Created/Modified

- `pam-unix-oidc/src/oidc/validation.rs` - Added `key_algorithm_to_algorithm()`, `DEFAULT_ALLOWED_ALGORITHMS`, `parse_algorithm_names()`, `allowed_algorithms` field in `ValidationConfig`, replaced serde comparison with enum match, replaced blocklist with allowlist
- `pam-unix-oidc/src/policy/config.rs` - Added `validate_https_url()`, `allowed_algorithms` field on `IssuerConfig`, `allow_insecure_http_for_testing` cfg-gated field, HTTPS validation in `load_from()`
- `pam-unix-oidc/src/device_flow/types.rs` - Refactored `validate_uris()` to use shared `validate_https_url()`
- `pam-unix-oidc/src/auth.rs` - Wired per-issuer `allowed_algorithms` from `IssuerConfig` through `parse_algorithm_names()` into `ValidationConfig`
- `pam-unix-oidc/src/sudo.rs` - Added `allowed_algorithms: None` to `ValidationConfig` construction
- `pam-unix-oidc/src/audit.rs` - Added SHRD-03 regression guard documentation comment
- `pam-unix-oidc/tests/entra_integration.rs` - Added `allowed_algorithms: None` to `ValidationConfig` constructions

## Decisions Made

- Used standalone function `key_algorithm_to_algorithm()` instead of `TryFrom` impl due to Rust orphan rule (both `KeyAlgorithm` and `Algorithm` are external types from the `jsonwebtoken` crate)
- Chose allowlist over blocklist: `DEFAULT_ALLOWED_ALGORITHMS` contains only the 9 asymmetric signing algorithms. New algorithms added to the crate are automatically rejected until explicitly added, which is the secure default
- SHRD-03 was already fully implemented by Phase 24 SBUG-02; added regression guard documentation rather than duplicate test code
- `validate_https_url()` placed as a public function in `config.rs` for reuse by `device_flow::types.rs`, avoiding code duplication

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Task 1 committed by parallel 25-02 session**
- **Found during:** Task 1 commit
- **Issue:** The algorithm allowlist changes (validation.rs, config.rs, auth.rs, sudo.rs, entra_integration.rs) were already committed in `eec0649` by a parallel session executing 25-02
- **Fix:** Verified all Task 1 code changes are present in HEAD, ran tests to confirm correctness, proceeded with Task 2/3
- **Files modified:** None (already committed)
- **Verification:** All 393 tests pass including new algorithm tests

---

**Total deviations:** 1 (commit ordering due to parallel session)
**Impact on plan:** No impact on correctness. All code changes are present and verified.

## Issues Encountered

None -- all tests pass, clippy clean, production build (without test-mode) succeeds.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Security hardening plan 01 complete: algorithm confusion and HTTPS enforcement in place
- Plan 02 (terminal sanitization, D-Bus encryption enforcement) already partially committed
- Ready for Phase 25 Plan 03+ or Phase 26 multi-IdP work

---
*Phase: 25-phase-25-security-hardening*
*Completed: 2026-03-16*
