---
phase: 28-documentation-e2e-test-coverage
plan: "05"
subsystem: e2e-testing
tags: [ciba, fido2, acr, e2e-test, keycloak, ci]
requirements: [E2ET-04]

dependency_graph:
  requires:
    - test/tests/test_ciba_integration.sh (base CIBA test infrastructure)
    - test/fixtures/keycloak/ciba-test-realm.json (realm config)
    - docker-compose.ciba-integration.yaml (Keycloak test environment)
    - pam-unix-oidc/src/ciba/types.rs (ACR_PHR/ACR_PHRH constants and semantics)
    - unix-oidc-agent/src/daemon/socket.rs (concurrent step-up guard impl reference)
  provides:
    - E2ET-04: Automated CIBA full flow + FIDO2 ACR delegation + concurrent step-up guard
    - test/tests/test_ciba_fido2_e2e.sh
    - test/docker/keycloak/ciba-realm-acr-patch.sh
  affects:
    - .github/workflows/ci.yml (ciba-integration job — new step added)
    - test/fixtures/keycloak/ciba-test-realm.json (LoA mapping added)

tech_stack:
  added: []
  patterns:
    - Keycloak acr.loa.map realm attribute for simulating FIDO2 LoA levels without hardware
    - Keycloak Admin API direct grant for CIBA auto-approval in CI
    - pass/fail/skip pattern inherited from test_ciba_integration.sh
    - decode_jwt_payload() helper for base64url → JSON decoding in bash

key_files:
  created:
    - test/tests/test_ciba_fido2_e2e.sh
    - test/docker/keycloak/ciba-realm-acr-patch.sh
  modified:
    - test/fixtures/keycloak/ciba-test-realm.json

decisions:
  - "Keycloak LoA mapping uses short-form keys (phr, phrh) not full URIs; token acr claim reflects the map key, not OpenID EAP ACR URN"
  - "CIBA auto-approval via Admin API direct grant: direct grant establishes a user session which Keycloak associates with pending auth_req_id"
  - "Concurrent step-up guard documented at unit level (socket.rs lines ~1559-1571); not exercisable from shell script without a running agent daemon"
  - "ciba-realm-acr-patch.sh provides runtime patch path for existing deployments; ciba-test-realm.json is the canonical import-time config"
  - "CI step E2ET-04 was pre-added by plan 28-04 execution; verified present and correct"

metrics:
  duration: "~15 minutes"
  completed_date: "2026-03-16"
  tasks_completed: 2
  tasks_total: 2
  files_created: 3
  files_modified: 2
---

# Phase 28 Plan 05: CIBA FIDO2 E2E Test Coverage Summary

Automated E2E test for CIBA backchannel auth with FIDO2 ACR delegation (Keycloak LoA simulation) and documented concurrent step-up guard coverage.

## What Was Built

**test/tests/test_ciba_fido2_e2e.sh** — Fully automated CIBA E2E test covering E2ET-04:

| Test | What it validates |
|------|-------------------|
| Test 1 | Full CIBA flow: auth_req_id obtained, auto-approved via Keycloak Admin API, token polled to completion |
| Test 2 | FIDO2 ACR delegation: `acr_values=phr` in request → `acr` claim in token validated (Keycloak LoA 3) |
| Test 3 | Concurrent CIBA requests: Keycloak issues separate auth_req_ids; agent-level guard documented at unit level |
| Test 4 | CIBA timeout behavior: unapproved request returns `authorization_pending` or `slow_down` (not a token) |
| Step 5 | Negative: invalid `auth_req_id` rejected with an error code |

**test/fixtures/keycloak/ciba-test-realm.json** — Updated with:
- `acr.loa.map`: `phr=3` (FIDO2 phishing-resistant), `phrh=4` (FIDO2 hardware-bound), `mfa=2`
- CIBA realm attributes: poll mode, `login_hint`, 120s expiry, 5s interval

**test/docker/keycloak/ciba-realm-acr-patch.sh** — Runtime patch script for existing deployments that need to add LoA mapping without re-importing the realm JSON.

## Key Design Decisions

**ACR short-form vs full URI**: The production code (`pam-unix-oidc/src/ciba/types.rs`) uses full OpenID EAP ACR URIs (`http://schemas.openid.net/pape/policies/2007/06/phishing-resistant`). Keycloak's `acr.loa.map` uses short-form keys (`phr`, `phrh`) as the map keys, and the ACR claim in tokens reflects those keys. The E2E test validates what Keycloak actually emits.

**Concurrent step-up guard**: The agent-level guard (`STEP_UP_IN_PROGRESS`) in `unix-oidc-agent/src/daemon/socket.rs handle_step_up()` cannot be triggered from a shell script without a running agent daemon. The E2E test validates the Keycloak side (both requests accepted, separate `auth_req_id`s issued); the agent-level assertion is documented with source line references and covered by unit tests.

**CIBA auto-approval**: Keycloak 26.x does not expose a dedicated "approve CIBA" Admin API endpoint. The test uses the resource owner password grant (direct access grant) to establish a user session, which Keycloak associates with the pending `auth_req_id` for the poll-mode flow.

## Deviations from Plan

### CI pre-wiring

**Found during:** Task 2 CI wiring step

**What happened:** The `E2ET-04` step (`Run CIBA FIDO2 ACR E2E (E2ET-04)`) was already present in `.github/workflows/ci.yml` — added by the previous plan (28-04, commit `6287308`) which wired several E2E tests together. My edit was a no-op since the content was identical.

**Impact:** None — the acceptance criteria (grep `test_ciba_fido2_e2e\|E2ET-04` returns >= 2 lines) is met. The CI wiring is correct and complete.

**Rule applied:** No deviation rule triggered — this is plan coordination, not a bug.

## Self-Check: PASSED

| Item | Status |
|------|--------|
| test/tests/test_ciba_fido2_e2e.sh | FOUND |
| test/docker/keycloak/ciba-realm-acr-patch.sh | FOUND |
| test/fixtures/keycloak/ciba-test-realm.json (acr.loa.map) | FOUND |
| .planning/phases/28-documentation-e2e-test-coverage/28-05-SUMMARY.md | FOUND |
| Task 1 commit (3aa60e3 — realm config) | FOUND |
| Task 2 commit (8187e84 — test script) | FOUND |
| CI wiring (E2ET-04 in ci.yml HEAD) | FOUND |
