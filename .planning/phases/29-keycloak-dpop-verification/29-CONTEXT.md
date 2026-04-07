# Phase 29: Keycloak DPoP Verification - Context

**Gathered:** 2026-04-07
**Status:** Ready for planning

<domain>
## Phase Boundary

Explicitly prove that the existing Keycloak CI stack issues DPoP-bound tokens (`cnf.jkt` claim present) via Device Authorization Grant, and that the PAM module validates them correctly. Establishes the reference PoP implementation before testing commercial IdPs (Phases 30-31).

This is verification and documentation of existing capability, not new feature development.

</domain>

<decisions>
## Implementation Decisions

### CI Assertion Strategy (Claude's Discretion)
- **D-01:** Promote existing `test/tests/test_dpop_binding.sh` cnf.jkt validation into the keycloak-e2e CI job as a hard gate — job fails if `cnf.jkt` is absent from device-flow-acquired tokens.
- **D-02:** Reuse existing test infrastructure extensively. The device flow E2E (`test/e2e/run-device-flow-e2e.sh`) and DPoP binding test (`test/tests/test_dpop_binding.sh`) already validate cnf.jkt. New work should be additive assertions, not parallel test suites.

### PAM Audit Log Verification (Claude's Discretion)
- **D-03:** Integration test sends a Keycloak device-flow-issued DPoP-bound token through PAM validation and verifies the OCSF audit event confirms `cnf` binding. Structured assertion (parse audit JSON), not grep.

### Reference Documentation
- **D-04:** Operator quickstart format — 1-2 pages. Assumes reader has Keycloak experience. Covers: required realm settings for DPoP + Device Auth Grant, what to verify (cnf.jkt), what it proves.
- **D-05:** Reference `docker-compose.e2e.yaml` as the canonical runnable example AND include key Keycloak config snippets inline for operators who want to understand without running the compose stack.
- **D-06 (HARD CONSTRAINT):** Every command, config snippet, Keycloak setting, and factual claim in the documentation MUST be verified against the actual running Keycloak instance (26.5.5) and current Keycloak documentation. No assumptions from training data. Researcher and executor agents must validate every claim by running commands or reading primary sources. No excuses about versions or dated training data.

### Claude's Discretion
- CI job structure (which existing job to extend vs. new job)
- Integration test implementation details (test harness, assertion format)
- Doc file location within `docs/`

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Existing Test Infrastructure
- `test/tests/test_dpop_binding.sh` — Existing DPoP binding validation (cnf.jkt check against Keycloak)
- `test/tests/test_dpop_e2e.sh` — DPoP E2E with PAM validation path
- `test/e2e/run-device-flow-e2e.sh` — Full device flow E2E with Playwright + DPoP
- `docker-compose.e2e.yaml` — Keycloak 26.5.5 E2E stack (DPoP GA)
- `test/fixtures/keycloak/e2e/` — Keycloak realm import fixtures

### CI Configuration
- `.github/workflows/ci.yml` — Main CI workflow
- `.github/workflows/provider-tests.yml` — Provider-specific test jobs

### DPoP Implementation
- `pam-unix-oidc/src/oidc/dpop.rs` — Server-side DPoP validation (cnf.jkt verification)
- `rust-oauth-dpop/src/server.rs` — DPoP server library (thumbprint comparison)
- `pam-unix-oidc/src/oidc/token.rs` — Token claims including `cnf` confirmation claim

### Standards
- RFC 9449 (DPoP) — Demonstrating Proof of Possession
- RFC 8628 — OAuth 2.0 Device Authorization Grant

### Keycloak Documentation (MUST be fetched fresh, not from training data)
- Keycloak 26.x DPoP configuration docs — verify against running instance
- Keycloak realm client configuration for device flow + DPoP

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `test/tests/test_dpop_binding.sh` — Already validates cnf.jkt presence and thumbprint match against Keycloak. Core logic can be promoted to CI gate.
- `test/e2e/run-device-flow-e2e.sh` — Full Playwright-coordinated device flow with DPoP. Already checks cnf.jkt.
- `docker-compose.e2e.yaml` — Keycloak 26.5.5 with realm auto-import, OpenLDAP, test host. Production-ready E2E stack.
- OCSF audit events (v2.2, Phase 27) — 16 event variants with HMAC chain. Authentication events carry DPoP binding info.

### Established Patterns
- Shell-based E2E tests with `pass`/`fail` helpers and structured output
- Playwright device flow automation via `test/e2e/` TypeScript
- Keycloak realm fixtures as JSON import files
- Secrets-gated CI with graceful skip-if-absent

### Integration Points
- keycloak-e2e CI job in `.github/workflows/ci.yml` — where the hard gate assertion goes
- OCSF audit event JSON — where PAM audit log verification reads from

</code_context>

<specifics>
## Specific Ideas

- User explicitly requires triple-validation of all commands and claims in documentation — no training-data assumptions, verify against running Keycloak 26.5.5 instance and primary docs
- Existing test coverage is extensive; phase is about making implicit verification explicit and gated

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 29-keycloak-dpop-verification*
*Context gathered: 2026-04-07*
