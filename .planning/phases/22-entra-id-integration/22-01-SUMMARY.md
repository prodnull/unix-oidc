---
phase: 22-entra-id-integration
plan: "01"
subsystem: auth
tags: [entra, azure-ad, oidc, rs256, dpop, collision-safety, identity-mapping]

requires:
  - phase: 21-multi-idp
    provides: IssuerConfig, authenticate_multi_issuer, per-issuer DPoP enforcement, IssuerJwksRegistry

provides:
  - IssuerConfig.expected_audience for Entra api:// audience URI override
  - IssuerConfig.allow_unsafe_identity_pipeline for single-tenant collision-safety bypass
  - Entra policy fixture (test/fixtures/policy/policy-entra.yaml)
  - Multi-idp fixture updated with allow_unsafe_identity_pipeline: true for Entra issuer
  - docs/entra-setup-guide.md (361-line step-by-step app registration guide)

affects:
  - 22-entra-id-integration (plans 02+: integration tests depend on this config/fixture foundation)
  - future-idp-integrations (expected_audience pattern reusable for any IdP with non-GUID audiences)

tech-stack:
  added: []
  patterns:
    - "expected_audience fallback: issuer_config.expected_audience.as_deref().unwrap_or(&issuer_config.client_id)"
    - "allow_unsafe_identity_pipeline bypass wraps check_collision_safety with tracing::warn"
    - "serde(default) on Option<String> and bool fields ensures safe deserialization without explicit defaults"

key-files:
  created:
    - test/fixtures/policy/policy-entra.yaml
    - docs/entra-setup-guide.md
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/tests/multi_idp_integration.rs
    - test/fixtures/policy/policy-multi-idp.yaml

key-decisions:
  - "expected_audience is Option<String> with serde(default) — None falls back to client_id (RFC 7519 §4.1.3 standard behavior)"
  - "allow_unsafe_identity_pipeline bypass logs tracing::warn at auth time — operator intent is auditable in logs"
  - "TDD RED/GREEN executed: 5 tests written before implementation, all green after"

patterns-established:
  - "ENTR-01: Entra config pattern — dpop: disabled, allow_unsafe: true, jti: warn, strip_domain+lowercase on email"

requirements-completed: [ENTR-01, ENTR-03, ENTR-04]

duration: 6min
completed: "2026-03-13"
---

# Phase 22 Plan 01: Entra ID Config Foundation Summary

**IssuerConfig extended with expected_audience and allow_unsafe_identity_pipeline for Entra ID, wired into the multi-issuer auth path, with Entra policy fixture and 361-line app registration setup guide**

## Performance

- **Duration:** 6 min
- **Started:** 2026-03-13T21:01:05Z
- **Completed:** 2026-03-13T21:06:47Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added `expected_audience: Option<String>` to `IssuerConfig` — lets Entra deployments with custom Application ID URIs (e.g. `api://unix-oidc`) pass audience validation without hacking `client_id`
- Added `allow_unsafe_identity_pipeline: bool` (default false) to `IssuerConfig` — bypasses collision-safety hard-fail for single-tenant Entra deployments where `strip_domain` is safe because the IdP enforces domain membership; logs `tracing::warn` when active
- Wired both fields into `authenticate_multi_issuer()` with security-annotated comments (RFC 7519 §4.1.3 reference for audience; IDN-03 reference for collision-safety)
- Created `test/fixtures/policy/policy-entra.yaml` with correct Entra defaults (dpop: disabled, jti: warn, strip_domain + lowercase, commented `expected_audience`)
- Updated `test/fixtures/policy/policy-multi-idp.yaml` — added `allow_unsafe_identity_pipeline: true` to Entra issuer so the fixture passes the now-enforced collision-safety gate
- Created `docs/entra-setup-guide.md` (361 lines) covering all 6 App Registration Checklist items, ROPC test commands, token claim verification, User.Read scope exclusion rationale, known limitations (uti vs jti, ROPC deprecation, SHR vs DPoP), and troubleshooting for common errors

## Task Commits

1. **Task 1: Add expected_audience + allow_unsafe_identity_pipeline** - `6624fa0` (feat) — TDD: 5 tests written RED, then GREEN
2. **Task 2: Entra policy fixture + multi-idp update + setup guide** - `06a84b5` (feat)

## Files Created/Modified

- `pam-unix-oidc/src/policy/config.rs` — added 2 fields to IssuerConfig + Default impl
- `pam-unix-oidc/src/auth.rs` — wired expected_audience into ValidationConfig Step 3; wrapped check_collision_safety in bypass at Step 7
- `pam-unix-oidc/tests/multi_idp_integration.rs` — 5 new ENTR-01 tests
- `test/fixtures/policy/policy-entra.yaml` — new Entra single-issuer fixture
- `test/fixtures/policy/policy-multi-idp.yaml` — added allow_unsafe_identity_pipeline: true
- `docs/entra-setup-guide.md` — comprehensive app registration and token verification guide

## Decisions Made

- `expected_audience` uses `serde(default)` so existing configs deserialize without change — backward compatible
- Bypass logs `tracing::warn` (not just a no-op) so security operators can audit when the bypass is active; this fulfills "never silently fail" from CLAUDE.md
- Setup guide documents `User.Read` scope exclusion prominently (Pitfall 3 from 22-RESEARCH.md) since this is the most common Entra integration mistake

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None. The TDD cycle was clean: tests failed for missing fields, implementation made them pass, all 402 existing tests continued to pass.

## User Setup Required

See `docs/entra-setup-guide.md` for the step-by-step Entra tenant and app registration setup. Required before running Plan 02 integration tests.

## Next Phase Readiness

- Config foundation is complete; Plan 02 can add the CI integration test that acquires a real Entra token and authenticates through the PAM path
- `test/fixtures/policy/policy-entra.yaml` is ready for use as the policy fixture in Plan 02
- The `expected_audience` field is available if the tenant's app registration uses an Application ID URI

---
*Phase: 22-entra-id-integration*
*Completed: 2026-03-13*
