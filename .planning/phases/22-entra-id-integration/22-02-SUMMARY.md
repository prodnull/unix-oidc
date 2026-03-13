---
phase: 22-entra-id-integration
plan: "02"
subsystem: testing
tags: [entra, azure-ad, rs256, oidc, integration-tests, upn-mapping, bearer-auth, dpop]

requires:
  - phase: 22-entra-id-integration
    provides: IssuerConfig.expected_audience, IssuerConfig.allow_unsafe_identity_pipeline, Entra policy fixture

provides:
  - pam-unix-oidc/tests/entra_integration.rs — 9 live integration tests covering ENTR-02 through ENTR-05

affects:
  - 22-entra-id-integration (CI PAM chain test will use these as the integration baseline)
  - future-idp-integrations (RS256 live-test pattern reusable for other RSA-signing IdPs)

tech-stack:
  added: []
  patterns:
    - "Live integration tests use #[ignore] with descriptive message — all tests ignored by default, run with --include-ignored when env vars set"
    - "reqwest::blocking::Client for HTTP in test files — pam-unix-oidc uses blocking reqwest (no tokio)"
    - "Adversarial tamper pattern: XOR last byte of base64url payload section to flip one bit, triggering signature failure"

key-files:
  created:
    - pam-unix-oidc/tests/entra_integration.rs
  modified: []

key-decisions:
  - "reqwest blocking client used in tests (not async) — pam-unix-oidc depends on reqwest 0.11 blocking-only; no tokio in dev-dependencies"
  - "UserNotFound/IdentityMapping/UserResolution are all acceptable terminal states in bearer test — SSSD absent in test env; all three confirm pipeline reached past DPoP gate"
  - "Discovery test fetches JWKS URI and checks kty=RSA + alg=RS256 directly — proves Entra uses RSA keys before token validation is attempted"

patterns-established:
  - "ENTR-02 live test pattern: validate config → JwksProvider → TokenValidator::with_jwks_provider → real sig check (no test-mode)"
  - "ENTR-05 bearer-only pattern: authenticate_multi_issuer with dpop_proof=None, assert not DPoPRequired, assert not UnknownIssuer"

requirements-completed: [ENTR-02, ENTR-03, ENTR-04, ENTR-05]

duration: 3min
completed: "2026-03-13"
---

# Phase 22 Plan 02: Entra ID Integration Test Suite Summary

**9 live Entra integration tests (RS256 discovery, token validation, UPN strip_domain mapping, bearer-only DPoP bypass, 3 adversarial cases) — all ignored by default, activated with ENTRA_* env vars**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-13T21:09:54Z
- **Completed:** 2026-03-13T21:12:52Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Created `pam-unix-oidc/tests/entra_integration.rs` with 9 tests covering ENTR-02 through ENTR-05
- All tests are `#[ignore]` by default with descriptive reason; activated via `--include-ignored` when `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, and `ENTRA_TOKEN` are set
- Discovery test (`test_entra_discovery_returns_valid_jwks_uri`) fetches live OIDC discovery document and JWKS, asserting RS256 key presence — proves Entra infrastructure is reachable before signature tests run
- RS256 validation test (`test_entra_rs256_token_validates`) exercises real cryptographic verification against live Entra JWKS — first RS256 live signature test in the project (Keycloak uses ES256)
- UPN mapping tests verify `email → strip_domain → lowercase` pipeline and raw `preferred_username` preservation
- Bearer-only auth test asserts `authenticate_multi_issuer` with `dpop_proof=None` does not return `DPoPRequired` or `UnknownIssuer`, confirming full pipeline completion to SSSD boundary
- Three adversarial tests: wrong tenant (issuer mismatch), tampered payload (signature fail), unknown issuer (multi-issuer routing rejection)

## Task Commits

1. **Task 1: Create Entra live integration test suite** - `0b7bb44` (feat)

## Files Created/Modified

- `pam-unix-oidc/tests/entra_integration.rs` — 9 live Entra integration tests (524 lines)

## Decisions Made

- Used `reqwest::blocking::Client` instead of async — pam-unix-oidc only depends on `reqwest 0.11` with the `blocking` feature; no tokio in dev-dependencies. Initial attempt used `#[tokio::test]` which failed to compile (Rule 3 auto-fix).
- Accepted `UserResolution` error in addition to `UserNotFound` and `IdentityMapping` as valid terminal states for the bearer-only test — SSSD may fail differently depending on environment; all three prove the DPoP gate was passed.
- Discovery test checks `kty == "RSA" && alg == "RS256"` directly in the JWKS JSON rather than via the `jsonwebtoken` JWK types — keeps the test independent of internal JWK parsing and mirrors what an operator would verify manually.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Replaced `#[tokio::test]` with sync tests using `reqwest::blocking`**
- **Found during:** Task 1 (during compilation)
- **Issue:** Plan specified `#[tokio::test]` for async tests but `pam-unix-oidc` has no `tokio` dev-dependency; `reqwest 0.11` is configured with `blocking` feature only, not `full`/`async` features
- **Fix:** Changed `#[tokio::test]` annotations to `#[test]`, converted `reqwest::Client` to `reqwest::blocking::Client`, removed all `.await` calls
- **Files modified:** `pam-unix-oidc/tests/entra_integration.rs`
- **Verification:** `cargo build -p pam-unix-oidc --tests` passes; `cargo test --test entra_integration -- --list` shows all 9 tests
- **Committed in:** `0b7bb44` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Required adaptation; blocking HTTP is functionally equivalent for live integration tests that are inherently I/O-bound. No scope change.

## Issues Encountered

None beyond the async/blocking mismatch documented above as a deviation.

## User Setup Required

**Live tests require Entra tenant credentials.** See `docs/entra-setup-guide.md` for:
- `ENTRA_TENANT_ID` — Directory (tenant) ID from Azure Portal
- `ENTRA_CLIENT_ID` — Application (client) ID from App Registration
- `ENTRA_TOKEN` — Access token obtained via ROPC or device flow

Run with:
```bash
ENTRA_TENANT_ID=<tenant> ENTRA_CLIENT_ID=<client_id> ENTRA_TOKEN=<token> \
  cargo test -p pam-unix-oidc --test entra_integration -- --include-ignored
```

## Next Phase Readiness

- Entra integration test infrastructure is complete; Phase 22 integration tests exist and compile
- CI PAM chain test (provider-tests.yml) can add `ENTRA_*` secrets to run these tests in CI against a real Entra tenant
- Phase 22 plan coverage: Plan 01 = config foundation (ENTR-01, -03, -04); Plan 02 = live integration tests (ENTR-02, -03, -04, -05)

---
*Phase: 22-entra-id-integration*
*Completed: 2026-03-13*
