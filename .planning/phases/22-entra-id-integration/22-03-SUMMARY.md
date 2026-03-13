---
phase: 22-entra-id-integration
plan: 03
subsystem: testing
tags: [entra, azure-ad, oidc, ci, ropc, github-actions, provider-tests]

# Dependency graph
requires:
  - phase: 22-entra-id-integration/22-02
    provides: entra_integration.rs tests (RS256, UPN mapping, bearer-only, adversarial)
provides:
  - ROPC token acquisition script for Entra CI (test/scripts/get-entra-token.sh)
  - Secrets-gated Entra CI job in provider-tests.yml following Auth0 pattern
affects: [22-entra-id-integration, provider-tests, ci-infra]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Secrets-gated CI job: check secret presence at start, skip all remaining steps if absent"
    - "ROPC token acquisition: curl POST to /oauth2/v2.0/token with grant_type=password"
    - "Token masking: ::add-mask:: before injecting token into GITHUB_ENV"

key-files:
  created:
    - test/scripts/get-entra-token.sh
  modified:
    - .github/workflows/provider-tests.yml

key-decisions:
  - "Scopes limited to openid+profile+email; User.Read explicitly excluded — adding User.Read changes aud to graph.microsoft.com, breaking PAM audience validation (RESEARCH.md Pitfall 3)"
  - "Entra job is optional in provider-summary — does not fail the required check if secrets are absent; matches Auth0 treatment"
  - "Cargo build scoped to -p pam-unix-oidc (not full workspace) for CI speed"

patterns-established:
  - "CI cloud provider pattern: check-secret -> install-rust -> cache -> build -> discover -> acquire-token -> run-tests -> summary"

requirements-completed: [CI-03, ENTR-05]

# Metrics
duration: 2min
completed: 2026-03-13
---

# Phase 22 Plan 03: Entra CI Automation Summary

**ROPC token script and secrets-gated Entra CI job wired into provider-tests.yml, completing the full Entra integration automation loop**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-13T21:15:28Z
- **Completed:** 2026-03-13T21:16:55Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Created `test/scripts/get-entra-token.sh` — non-interactive ROPC token acquisition for CI; scopes restricted to `openid profile email` (no User.Read) per RESEARCH.md Pitfall 3
- Added `entra` job to `.github/workflows/provider-tests.yml` following the Auth0 secrets-gating pattern exactly
- Entra job: secrets check -> Rust build -> OIDC discovery -> ROPC token (masked) -> integration tests from 22-02 -> summary
- `provider-summary` updated with `entra` in `needs` and results output; Entra is optional (non-blocking)

## Task Commits

Each task was committed atomically:

1. **Task 1: Create ROPC token acquisition script** - `06e1a4e` (feat)
2. **Task 2: Add Entra CI job to provider-tests.yml** - `382b665` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `test/scripts/get-entra-token.sh` - Bash script that POSTs ROPC grant to Entra v2.0 token endpoint; outputs access_token on stdout; fails fast with descriptive error if any required env var is absent
- `.github/workflows/provider-tests.yml` - Added entra job with 8 steps; updated workflow_dispatch input description; updated provider-summary needs/output

## Decisions Made

- Scopes are `openid profile email` — User.Read excluded because it shifts token audience to `https://graph.microsoft.com`, which would break PAM audience validation. Documented in script comments referencing 22-RESEARCH.md Pitfall 3.
- Entra CI job builds only `-p pam-unix-oidc` (not the full workspace) for faster CI execution — Keycloak job already validates the full workspace build.
- `provider-summary` treats Entra as optional (same as Auth0/Google) — CI does not fail if the tenant secrets are not configured in the repository.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

To enable the Entra CI job, configure the following GitHub Actions secrets in the repository:

| Secret | Description |
|--------|-------------|
| `ENTRA_TENANT_ID` | Azure AD tenant ID (GUID) |
| `ENTRA_CLIENT_ID` | Application (client) ID (GUID) |
| `ENTRA_TEST_USER` | UPN of test user (e.g. `ci-test@corp.example`) |
| `ENTRA_TEST_PASSWORD` | Password for test user (MFA must be disabled or excluded via Conditional Access) |

Without these secrets, the entra job will output a skip message and complete as `skipped` — it will not block the workflow.

## Next Phase Readiness

- Phase 22 (Entra ID Integration) is complete: Plan 01 (config + RS256), Plan 02 (integration tests), Plan 03 (CI automation) all done.
- The full Entra integration loop is operational: live token acquisition -> RS256 validation -> UPN claim mapping -> bearer-only (DPoP disabled) -> adversarial rejection tests.
- No blockers for milestone close.

---
*Phase: 22-entra-id-integration*
*Completed: 2026-03-13*
