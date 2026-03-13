---
phase: 21-multi-idp-configuration
plan: "02"
subsystem: pam-unix-oidc/auth
tags: [multi-idp, auth-routing, dpop, jti-cache, claim-mapping, midp]
dependency_graph:
  requires:
    - phase: 21-01
      provides: IssuerConfig, IssuerJwksRegistry, PolicyConfig.effective_issuers(), PolicyConfig.issuer_by_url()
  provides:
    - extract_iss_for_routing() (pam-unix-oidc/src/auth.rs)
    - authenticate_multi_issuer() (pam-unix-oidc/src/auth.rs)
    - AuthError::UnknownIssuer variant (pam-unix-oidc/src/auth.rs)
    - apply_per_issuer_dpop() (pam-unix-oidc/src/auth.rs)
    - JWKS_REGISTRY static (pam-unix-oidc/src/lib.rs)
    - Multi-issuer PAM dispatch (pam-unix-oidc/src/lib.rs)
  affects:
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs
tech_stack:
  added: []
  patterns:
    - Caller-side JTI key scoping ("iss:jti" prefix) — no struct modification
    - Pre-validation iss extraction for routing (payload decode only, no sig verify)
    - Static Lazy<IssuerJwksRegistry> for PAM cross-call cache persistence
    - ENV_MUTEX pattern for serializing env-var test isolation (carried from Plan 01)
key_files:
  created: []
  modified:
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs
key_decisions:
  - "JTI scoping at call site (format! macro) — JtiCache struct unchanged. Per-issuer collision prevention is a calling-convention, not a cache invariant."
  - "JWKS_REGISTRY is static in lib.rs (not a field in a struct) because PAM modules are loaded as shared libraries and there is no long-lived struct to hold it"
  - "Unknown issuer → AuthError::UnknownIssuer (new variant) mapped to PamError::AUTH_ERR — consistent with token validation failures"
  - "apply_per_issuer_dpop() extracted as a separate function — makes per-issuer enforcement policy explicit and independently testable"
  - "JWKS TTL/timeout hardcoded to 300s/10s for now — future work can add per-issuer cache tuning to PolicyConfig"
requirements-completed:
  - MIDP-06
  - MIDP-07

duration: 10min
completed: "2026-03-13"
---

# Phase 21 Plan 02: Multi-Issuer Auth Routing Summary

**`extract_iss_for_routing()` + `authenticate_multi_issuer()` dispatch tokens to per-issuer JWKS, DPoP enforcement, and claim mapping, with issuer-scoped JTI cache keys and a static JWKS_REGISTRY for cross-call cache persistence.**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-13T19:09:36Z
- **Completed:** 2026-03-13T19:18:xx Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- `extract_iss_for_routing()` decodes JWT payload (no sig verify) to extract `iss` for pre-validation routing; trailing-slash normalized
- `authenticate_multi_issuer()` dispatches to per-issuer `ValidationConfig`, `JwksProvider`, DPoP enforcement, and `UsernameMapper` — covers MIDP-06 and MIDP-07
- `apply_per_issuer_dpop()` implements Disabled / Warn / Strict enforcement modes per-issuer (MIDP-02), allowing Entra-like issuers to opt out of DPoP entirely
- JTI cache keys scoped as `"{iss}:{jti}"` at call site — no cross-issuer replay false positives (MIDP-07)
- Static `JWKS_REGISTRY` in `lib.rs` ensures JWKS cache survives across consecutive PAM authentication calls
- PAM entry point branches on `policy.issuers.is_empty()`: non-empty → multi-issuer dispatch; empty → unmodified legacy path (zero behavior change)

## Task Commits

1. **Task 1: extract_iss_for_routing() + authenticate_multi_issuer() + JTI scoping** - `598e54e` (feat)
2. **Task 2: Wire PAM entry points in lib.rs** - `b24e973` (feat)

## Files Created/Modified

- `pam-unix-oidc/src/auth.rs` — Added `AuthError::UnknownIssuer`, `extract_iss_for_routing()`, `authenticate_multi_issuer()`, `apply_per_issuer_dpop()`; 10 new unit tests
- `pam-unix-oidc/src/lib.rs` — Added `JWKS_REGISTRY` static, multi-issuer dispatch branching, `UnknownIssuer` PAM error mapping; 3 new unit tests

## Decisions Made

- JTI cache scoping is caller-side only: the `JtiCache` struct remains unchanged. The `format!("{iss}:{jti}")` pattern creates distinct namespace buckets without requiring a schema change in the cache internals. This is a convention, not an invariant enforced by the type system — documented in code comments.
- `JWKS_REGISTRY` is a module-level static in `lib.rs` (not a struct field) because PAM modules are `cdylib` without a persistent daemon object to hold state between calls.
- JWKS TTL (300 s) and HTTP timeout (10 s) are hardcoded constants in `authenticate_multi_issuer()` with a comment noting future per-issuer config is possible. This avoids premature API design while still being operationally reasonable.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added `AuthError::UnknownIssuer` match arm to lib.rs error handler**
- **Found during:** Task 1 (build after adding `UnknownIssuer` variant)
- **Issue:** Adding `UnknownIssuer` to `AuthError` made the existing `match &e` in `lib.rs` non-exhaustive, blocking compilation
- **Fix:** Added the `AuthError::UnknownIssuer(iss)` arm with WARN log + audit event + `PamError::AUTH_ERR` — the correct production behavior, aligning with Task 2 requirements
- **Files modified:** `pam-unix-oidc/src/lib.rs`
- **Verification:** `cargo build -p pam-unix-oidc --features test-mode` succeeded
- **Committed in:** `598e54e` (noted in Task 1 commit; formally part of Task 2 behavior)

**2. [Rule 3 - Blocking] Replaced `policy.cache.jwks_cache_ttl_secs` and `policy.timeouts.http_timeout_secs` with hardcoded constants**
- **Found during:** Task 1 (plan specified these fields but they don't exist in `CacheConfig`/`PamTimeoutsConfig`)
- **Issue:** `CacheConfig` has no `jwks_cache_ttl_secs`; `PamTimeoutsConfig` has no `http_timeout_secs`
- **Fix:** Used `const JWKS_CACHE_TTL_SECS: u64 = 300` and `const JWKS_HTTP_TIMEOUT_SECS: u64 = 10` with comments about future per-issuer config
- **Files modified:** `pam-unix-oidc/src/auth.rs`
- **Verification:** `cargo build` succeeded; values are operationally reasonable defaults

---

**Total deviations:** 2 auto-fixed (both Rule 3 — blocking)
**Impact on plan:** Both were necessary compilation fixes. No scope creep; plan intent fully delivered.

## Issues Encountered

- **ENV_MUTEX race in multi-issuer tests**: Parallel test threads racing on `UNIX_OIDC_TEST_MODE` caused 3 tests to fail with JWKS fetch errors (test mode not active when validator was constructed). Fixed by adding `static MULTI_ISSUER_ENV_MUTEX: Mutex<()>` to serialize the 5 tests that set/remove the env var. Same pattern as Plan 01.

## Success Criteria Verification

- [x] Token from configured issuer authenticates through multi-issuer dispatch
- [x] Token from unknown issuer is rejected with `AuthError::UnknownIssuer` + audit log
- [x] Per-issuer DPoP enforcement works (Strict on issuer A, Disabled on issuer B)
- [x] Per-issuer claim mapping (strip_domain on A, none on B) checked via collision-safety hard-fail
- [x] JWKS cache entries are independent per issuer (IssuerJwksRegistry from Plan 01)
- [x] JTI cache keys are issuer-scoped — no cross-issuer collision
- [x] Legacy single-issuer deployments are unaffected (`policy.issuers.is_empty()` → old path)
- [x] All existing unit tests continue to pass (364 unit tests)

## Self-Check: PASSED

Files verified:
- FOUND: `pam-unix-oidc/src/auth.rs`
- FOUND: `pam-unix-oidc/src/lib.rs`
- FOUND: `.planning/phases/21-multi-idp-configuration/21-02-SUMMARY.md`

Commits verified:
- FOUND: `598e54e` — feat(21-02): add extract_iss_for_routing() and authenticate_multi_issuer()
- FOUND: `b24e973` — feat(21-02): wire PAM entry points to multi-issuer auth dispatch
