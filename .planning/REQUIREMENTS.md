# Requirements: unix-oidc v2.1 Integration Testing Infrastructure

**Defined:** 2026-03-13
**Core Value:** DPoP private keys must be protected at rest, in memory, and on deletion — and integration tests must verify this with real cryptographic validation, not TEST_MODE bypasses.

## v2.1 Requirements

### Blocker Fixes

- [ ] **BFIX-01**: Keycloak issuer URL aligned between token `iss` claim and PAM `OIDC_ISSUER` validation
- [ ] **BFIX-02**: `unix-oidc-agent` binary installed and startable in test-host container
- [ ] **BFIX-03**: Device flow token polling sends DPoP proof header per RFC 9449 §4.2
- [ ] **BFIX-04**: IPC `notify_agent_session_closed()` sends newline terminator to prevent `read_line` hang

### E2E Infrastructure

- [ ] **INFR-01**: New `docker-compose.e2e.yaml` with Keycloak 26.4+, no `UNIX_OIDC_TEST_MODE`, aligned issuer URLs
- [ ] **INFR-02**: Keycloak health check uses `/health/ready` endpoint (not TCP port check)
- [ ] **INFR-03**: Sentinel assertion at CI job start verifying `UNIX_OIDC_TEST_MODE` is NOT set
- [ ] **INFR-04**: Realm JSON fixes (`deviceAuthorizationGrantEnabled` boolean, DPoP GA settings for Keycloak 26.4+)

### Playwright Automation

- [ ] **PLAY-01**: Playwright spec automates Keycloak device flow consent (navigate to verification URI, fill credentials, grant)
- [ ] **PLAY-02**: Tmpfile coordination between Playwright spec and shell poll loop for token handoff
- [ ] **PLAY-03**: CI-compatible headless execution on GitHub Actions runners

### SSH E2E Test

- [ ] **E2E-01**: Full auth chain: `agent login` → `agent serve` → SSH with `SSH_ASKPASS` → PAM conversation (3 rounds) → JWKS signature verification → shell access
- [ ] **E2E-02**: Auth log verification confirms structured audit event for successful authentication
- [ ] **E2E-03**: Negative tests: expired token rejected, wrong issuer rejected, replayed DPoP proof rejected

### CI Integration

- [ ] **CI-01**: `keycloak-e2e` GitHub Actions job depending on build-matrix artifact
- [ ] **CI-02**: Parallel Playwright + shell test execution within the job
- [ ] **CI-03**: Entra ID secrets-gated CI job (`entra-integration`)

### Multi-IdP Configuration

- [ ] **MIDP-01**: `issuers[]` array in policy.yaml with per-issuer config blocks (issuer_url, client_id, client_secret)
- [ ] **MIDP-02**: Per-issuer DPoP enforcement mode (strict/warn/disabled)
- [ ] **MIDP-03**: Per-issuer claim mapping rules (username extraction, strip-domain, regex)
- [ ] **MIDP-04**: Per-issuer ACR value mapping (e.g., Keycloak `urn:keycloak:acr:loa2` vs Entra `c1`/`c2`)
- [ ] **MIDP-05**: Per-issuer group mapping (token claim path vs NSS-only, group name translation)
- [ ] **MIDP-06**: PAM module matches incoming token `iss` to configured issuer; rejects unknown issuers
- [ ] **MIDP-07**: JWKS cache keyed by issuer URL (multi-issuer concurrent caching)
- [ ] **MIDP-08**: Graceful degradation: missing optional per-issuer fields fall back to safe defaults with WARN logging

### Entra ID Integration

- [ ] **ENTR-01**: Entra app registration with device code flow enabled (public client)
- [ ] **ENTR-02**: OIDC discovery + JWKS endpoint validation against live Entra tenant
- [ ] **ENTR-03**: RS256 token signature verification through PAM module (not just ES256)
- [ ] **ENTR-04**: UPN claim mapping (`alice@corp.com` → `alice`) validated end-to-end
- [ ] **ENTR-05**: Bearer-only mode (DPoP disabled) produces successful auth with full audit trail

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
| BFIX-01 | — | Pending |
| BFIX-02 | — | Pending |
| BFIX-03 | — | Pending |
| BFIX-04 | — | Pending |
| INFR-01 | — | Pending |
| INFR-02 | — | Pending |
| INFR-03 | — | Pending |
| INFR-04 | — | Pending |
| PLAY-01 | — | Pending |
| PLAY-02 | — | Pending |
| PLAY-03 | — | Pending |
| E2E-01 | — | Pending |
| E2E-02 | — | Pending |
| E2E-03 | — | Pending |
| CI-01 | — | Pending |
| CI-02 | — | Pending |
| CI-03 | — | Pending |
| MIDP-01 | — | Pending |
| MIDP-02 | — | Pending |
| MIDP-03 | — | Pending |
| MIDP-04 | — | Pending |
| MIDP-05 | — | Pending |
| MIDP-06 | — | Pending |
| MIDP-07 | — | Pending |
| MIDP-08 | — | Pending |
| ENTR-01 | — | Pending |
| ENTR-02 | — | Pending |
| ENTR-03 | — | Pending |
| ENTR-04 | — | Pending |
| ENTR-05 | — | Pending |

**Coverage:**
- v2.1 requirements: 30 total
- Mapped to phases: 0
- Unmapped: 30

---
*Requirements defined: 2026-03-13*
*Last updated: 2026-03-13 after initial definition*
