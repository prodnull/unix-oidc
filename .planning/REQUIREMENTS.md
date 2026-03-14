# Requirements: unix-oidc v2.1 Integration Testing Infrastructure

**Defined:** 2026-03-13
**Core Value:** DPoP private keys must be protected at rest, in memory, and on deletion — and integration tests must verify this with real cryptographic validation, not TEST_MODE bypasses.

## v2.1 Requirements

### Blocker Fixes

- [x] **BFIX-01**: Keycloak issuer URL aligned between token `iss` claim and PAM `OIDC_ISSUER` validation
- [x] **BFIX-02**: `unix-oidc-agent` binary installed and startable in test-host container
- [x] **BFIX-03**: Device flow token polling sends DPoP proof header per RFC 9449 §4.2
- [x] **BFIX-04**: IPC `notify_agent_session_closed()` sends newline terminator to prevent `read_line` hang

### E2E Infrastructure

- [x] **INFR-01**: New `docker-compose.e2e.yaml` with Keycloak 26.4+, no `UNIX_OIDC_TEST_MODE`, aligned issuer URLs
- [x] **INFR-02**: Keycloak health check uses `/health/ready` endpoint (not TCP port check)
- [x] **INFR-03**: Sentinel assertion at CI job start verifying `UNIX_OIDC_TEST_MODE` is NOT set
- [x] **INFR-04**: Realm JSON fixes (`deviceAuthorizationGrantEnabled` boolean, DPoP GA settings for Keycloak 26.4+)

### Playwright Automation

- [x] **PLAY-01**: Playwright spec automates Keycloak device flow consent (navigate to verification URI, fill credentials, grant)
- [x] **PLAY-02**: Tmpfile coordination between Playwright spec and shell poll loop for token handoff
- [x] **PLAY-03**: CI-compatible headless execution on GitHub Actions runners

### SSH E2E Test

- [x] **E2E-01**: Full auth chain: `agent login` → `agent serve` → SSH with `SSH_ASKPASS` → PAM conversation (3 rounds) → JWKS signature verification → shell access
- [x] **E2E-02**: Auth log verification confirms structured audit event for successful authentication
- [x] **E2E-03**: Negative tests: expired token rejected, wrong issuer rejected, replayed DPoP proof rejected

### CI Integration

- [x] **CI-01**: `keycloak-e2e` GitHub Actions job depending on build-matrix artifact
- [x] **CI-02**: Parallel Playwright + shell test execution within the job
- [x] **CI-03**: Entra ID secrets-gated CI job (`entra-integration`)

### Multi-IdP Configuration

- [x] **MIDP-01**: `issuers[]` array in policy.yaml with per-issuer config blocks (issuer_url, client_id, client_secret)
- [x] **MIDP-02**: Per-issuer DPoP enforcement mode (strict/warn/disabled)
- [x] **MIDP-03**: Per-issuer claim mapping rules (username extraction, strip-domain, regex)
- [x] **MIDP-04**: Per-issuer ACR value mapping (e.g., Keycloak `urn:keycloak:acr:loa2` vs Entra `c1`/`c2`)
- [x] **MIDP-05**: Per-issuer group mapping (token claim path vs NSS-only, group name translation)
- [x] **MIDP-06**: PAM module matches incoming token `iss` to configured issuer; rejects unknown issuers
- [x] **MIDP-07**: JWKS cache keyed by issuer URL (multi-issuer concurrent caching)
- [x] **MIDP-08**: Graceful degradation: missing optional per-issuer fields fall back to safe defaults with WARN logging

### Entra ID Integration

- [x] **ENTR-01**: Entra app registration with device code flow enabled (public client)
- [x] **ENTR-02**: OIDC discovery + JWKS endpoint validation against live Entra tenant
- [x] **ENTR-03**: RS256 token signature verification through PAM module (not just ES256)
- [x] **ENTR-04**: UPN claim mapping (`alice@corp.com` → `alice`) validated end-to-end
- [x] **ENTR-05**: Bearer-only mode (DPoP disabled) produces successful auth with full audit trail

## Testing Coverage Requirements

Every requirement above must have corresponding tests that cover:
- **Happy path**: Feature works as designed
- **Negative/adversarial**: Malformed input, expired tokens, wrong issuers, replayed proofs, forged claims
- **Degraded mode**: IdP unreachable, missing optional claims, clock skew, partial config
- **Cross-IdP**: Features that interact with multi-IdP config tested with at least 2 issuers
- **Observability**: All auth events (success AND failure) produce structured audit events

## Future Requirements (v2.2+)

### Additional IdP Integrations

- **IDPX-01**: Okta integration tests (CIBA push-only mode detection)
- **IDPX-02**: Auth0 integration tests (device flow + token validation)
- **IDPX-03**: Google Cloud Identity integration tests

### Multi-IdP Advanced

- **MIDP-09**: IdP priority ordering (try issuers in configured order)
- **MIDP-10**: IdP health monitoring (mark issuer degraded if JWKS fetch fails)
- **MIDP-11**: Hot-reload of issuer config without daemon restart

## Out of Scope

| Feature | Reason |
|---------|--------|
| Multi-IdP federation (Keycloak federating Entra) | Deployment architecture, not unix-oidc config — documented in ops guide |
| SAML integration | unix-oidc is OIDC-only by design |
| DPoP with Entra ID | Entra uses proprietary SHR, not RFC 9449 — no interop path exists |
| reqwest 0.11→0.13 upgrade | Separate hardening task, not integration testing |
| SCIM provisioning | Separate provisioning milestone |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| BFIX-01 | Phase 18 | Complete |
| BFIX-02 | Phase 18 | Complete |
| BFIX-03 | Phase 18 | Complete |
| BFIX-04 | Phase 18 | Complete |
| INFR-01 | Phase 18 | Complete |
| INFR-02 | Phase 18 | Complete |
| INFR-03 | Phase 18 | Complete |
| INFR-04 | Phase 18 | Complete |
| PLAY-01 | Phase 19 | Complete |
| PLAY-02 | Phase 19 | Complete |
| PLAY-03 | Phase 19 | Complete |
| E2E-01 | Phase 20 | Complete |
| E2E-02 | Phase 20 | Complete |
| E2E-03 | Phase 20 | Complete |
| CI-01 | Phase 20 | Complete |
| CI-02 | Phase 20 | Complete |
| CI-03 | Phase 22 | Complete |
| MIDP-01 | Phase 21 | Complete |
| MIDP-02 | Phase 21 | Complete |
| MIDP-03 | Phase 21 | Complete |
| MIDP-04 | Phase 21 | Complete |
| MIDP-05 | Phase 21 | Complete |
| MIDP-06 | Phase 21 | Complete |
| MIDP-07 | Phase 21 | Complete |
| MIDP-08 | Phase 21 | Complete |
| ENTR-01 | Phase 22 | Complete |
| ENTR-02 | Phase 22 | Complete |
| ENTR-03 | Phase 22 | Complete |
| ENTR-04 | Phase 22 | Complete |
| ENTR-05 | Phase 22 | Complete |

**Coverage:**
- v2.1 requirements: 30 total
- Complete: 30 (all requirements satisfied)
- Pending: 0
- Unmapped: 0

---
*Requirements defined: 2026-03-13*
*Last updated: 2026-03-14 after Phase 20+23 completion*
