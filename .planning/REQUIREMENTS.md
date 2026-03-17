# Requirements: unix-oidc v3.0

**Defined:** 2026-03-16
**Core Value:** DPoP private keys must be protected at rest, in memory, and on deletion

## v3.0 Requirements

Requirements for External IdP Integration & PoP Landscape milestone.

### Entra ID Integration

- [ ] **ENTRA-01**: Agent daemon completes Device Authorization Grant flow against live Entra ID tenant
- [ ] **ENTRA-02**: PAM module validates Entra-issued tokens via real JWKS endpoint (RS256)
- [ ] **ENTRA-03**: UPN-to-Unix username mapping works correctly with Entra `preferred_username`
- [ ] **ENTRA-04**: Missing `jti` claim (Entra uses `uti`) triggers warn-and-allow path, not rejection
- [ ] **ENTRA-05**: Both v1.0 and v2.0 issuer URL formats are handled correctly in config
- [ ] **ENTRA-06**: Secrets-gated CI job runs Entra E2E tests on push to main
- [ ] **ENTRA-07**: Entra E2E tests run locally when env vars are set, skip gracefully when absent
- [ ] **ENTRA-08**: Step-by-step Entra tenant setup guide for app registration, API permissions, and test user configuration

### Auth0 Integration

- [ ] **AUTH0-01**: Agent daemon completes Device Authorization Grant flow against live Auth0 tenant
- [ ] **AUTH0-02**: PAM module validates Auth0-issued tokens via real JWKS endpoint
- [ ] **AUTH0-03**: Auth0 namespaced custom claims are mapped correctly to Unix identity
- [ ] **AUTH0-04**: Bearer-only operation works with per-issuer `dpop_required = false`
- [ ] **AUTH0-05**: Secrets-gated CI job runs Auth0 E2E tests on push to main
- [ ] **AUTH0-06**: Auth0 E2E tests run locally when env vars are set, skip gracefully when absent
- [ ] **AUTH0-07**: Step-by-step Auth0 tenant setup guide for application config, API creation, and device flow enablement

### Keycloak DPoP Verification

- [ ] **KCDPOP-01**: Existing Keycloak CI explicitly verifies tokens issued via device flow carry `cnf` claim
- [ ] **KCDPOP-02**: DPoP proof validation succeeds against Keycloak device-flow-issued tokens
- [ ] **KCDPOP-03**: Keycloak DPoP + device flow documented as reference implementation for full PoP

### Documentation

- [ ] **DOC-01**: PoP landscape document covering provider DPoP matrix and three deployment patterns
- [ ] **DOC-02**: Token Exchange (RFC 8693) bridge reference architecture for commercial IdPs
- [ ] **DOC-03**: Provider quirks guide for operators (Entra, Auth0, Keycloak specifics)

## Future Requirements

### v3.1+ Deferred

- **AUTHC-01**: Auth Code + PKCE with local loopback redirect (RFC 8252) for workstation DPoP
- **TXEXCH-01**: Token Exchange (RFC 8693) bridge implementation with Keycloak as internal STS
- **OKTA-01**: Live Okta integration test (Device Auth Grant + DPoP if confirmed)
- **GCP-01**: Live Google Cloud Identity integration test
- **CATTP-01**: Client Attestation PoP (draft-ietf-oauth-attestation-based-client-auth) when RFC published

## Out of Scope

| Feature | Reason |
|---------|--------|
| Auth Code + PKCE flow | Keycloak covers DPoP better; narrow use case (workstation-only) |
| Token Exchange bridge implementation | Document architecture in v3.0, build in v3.1 |
| Okta/Google Cloud Identity testing | Deferred to v3.2; Entra + Auth0 prove multi-IdP story |
| DPoP + Device Flow per IETF draft | Draft not standardized, no implementations; test what Keycloak does natively |
| Proxy DPoP injection | Security theater, prohibited by RFC 9449 §7.1 |
| mTLS token binding (RFC 8705) | Incompatible with SSH/PAM transport — no TLS layer |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| ENTRA-01 | — | Pending |
| ENTRA-02 | — | Pending |
| ENTRA-03 | — | Pending |
| ENTRA-04 | — | Pending |
| ENTRA-05 | — | Pending |
| ENTRA-06 | — | Pending |
| ENTRA-07 | — | Pending |
| ENTRA-08 | — | Pending |
| AUTH0-01 | — | Pending |
| AUTH0-02 | — | Pending |
| AUTH0-03 | — | Pending |
| AUTH0-04 | — | Pending |
| AUTH0-05 | — | Pending |
| AUTH0-06 | — | Pending |
| AUTH0-07 | — | Pending |
| KCDPOP-01 | — | Pending |
| KCDPOP-02 | — | Pending |
| KCDPOP-03 | — | Pending |
| DOC-01 | — | Pending |
| DOC-02 | — | Pending |
| DOC-03 | — | Pending |

**Coverage:**
- v3.0 requirements: 21 total
- Mapped to phases: 0
- Unmapped: 21 ⚠️

---
*Requirements defined: 2026-03-16*
*Last updated: 2026-03-16 after initial definition*
