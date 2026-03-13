# Phase 22: Entra ID Integration - Context

**Gathered:** 2026-03-13
**Status:** Ready for planning

<domain>
## Phase Boundary

Azure Entra ID tokens (RS256, bearer-only, v2.0 endpoint, tenant-specific issuer, UPN claim) authenticate successfully through the PAM module using the multi-issuer infrastructure from Phase 21. The integration test runs the full PAM auth chain in Docker and is gated on Entra secrets in CI.

Out of scope: DPoP with Entra (Entra uses proprietary SHR, not RFC 9449), v1.0 token endpoint, SAML.

</domain>

<decisions>
## Implementation Decisions

### App Registration Setup
- Device code flow grant type (public client) — matches real-world unix-oidc usage
- ROPC (password grant) bootstrap in CI to avoid browser automation against Entra login pages — ROPC exchanges test user credentials for a refresh token, then refresh token exchanges for access tokens
- v2.0 endpoint only — issuer format: `https://login.microsoftonline.com/{tenant}/v2.0`
- **Scopes for PAM validation tokens:** `openid profile email` (NOT `User.Read`)
  - **Revision (planning phase):** The original locked decision specified `openid profile email User.Read`. Research (22-RESEARCH.md, Pitfall 3) confirmed that including `User.Read` (a Microsoft Graph permission) causes Entra to set the token audience to `https://graph.microsoft.com` instead of the app's client ID. This makes the token fail PAM audience validation. The scope is revised to `openid profile email` only for tokens used in PAM authentication. `User.Read` may still be configured in the app registration for other purposes (e.g., Graph API calls with a separate token).
- Planning phase must produce a **step-by-step Entra tenant/app registration guide** the user can follow to set up their tenant

### UPN Claim Mapping
- Primary username claim: `preferred_username` (standard OIDC, populated with UPN in Entra v2.0)
- Hard-fail if `preferred_username` is absent — no silent fallback to other claims; log "missing claim: preferred_username for issuer X" and reject auth
- Transform chain: `strip_domain` then `lowercase` (e.g., `Alice@Corp.Example` → `alice`)
- Test both configurations: with strip_domain (UPN → bare username) AND without strip_domain (raw UPN used as-is)

### CI Test Strategy
- Entra job added to existing `provider-tests.yml` (same trigger pattern: push, PR, daily schedule)
- Secrets-gated: job runs only when Entra secrets are configured (follows Auth0 pattern)
- Full PAM chain in Docker — comprehensive test using test-host container with pam_unix_oidc installed, Entra token passed through actual PAM conversation (may depend on Phase 20 E2E infrastructure)
- Structured audit event verified in auth log for successful Entra authentication

### RS256 Validation
- Explicit RS256 integration test with real Entra JWKS — first real RS256 validation test (Keycloak tests use ES256)
- Ignore Entra's nonce-in-JWT-header quirk — irrelevant for access tokens (only affects ID tokens in implicit/hybrid flows)
- Existing JWKS cache + refresh-on-miss is sufficient for Entra's ~6-week key rotation cycle
- Add optional `expected_audience` field to `IssuerConfig` — supports custom audience URIs (e.g., `api://unix-oidc`) that differ from `client_id`; falls back to `client_id` if not set

### Claude's Discretion
- Exact CI secrets set (tenant ID, client ID, test user creds, optional client secret)
- Negative test selection (wrong tenant, expired token, tampered signature — adversarial coverage per testing mandate)
- Infrastructure details for full PAM chain Docker setup
- Whether to document Entra-specific operational notes in security guide

</decisions>

<specifics>
## Specific Ideas

- User wants a step-by-step guide for setting up the Entra tenant/app registration — they haven't done this yet and want Claude to guide them through it
- "As comprehensive as technically possible, even if it means additional infrastructure" — user explicitly chose depth over simplicity for test coverage
- User wants max claim coverage — `User.Read` scope added specifically for richer profile data
  - **Note:** `User.Read` is still configured as an API permission in the app registration (Step 5 of setup guide), but is NOT included in ROPC token request scopes for PAM validation tokens. Including it in the token request changes the audience to Microsoft Graph, breaking PAM validation. See 22-RESEARCH.md Pitfall 3.
- Existing `test/fixtures/policy/policy-multi-idp.yaml` already has an Entra-like issuer entry — use as reference but update with real tenant values

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `IssuerConfig` (policy/config.rs): Per-issuer config struct with `dpop_enforcement`, `claim_mapping`, `acr_mapping`, `group_mapping` — Entra adds as another entry
- `IssuerJwksRegistry` (oidc/jwks.rs): Per-issuer JWKS caching with independent entries — handles RS256 keys from Entra JWKS alongside ES256 keys from Keycloak
- `UsernameMapper` with `strip_domain` + `lowercase` transforms (identity/mapper.rs): Already exists from Phase 8/21
- `authenticate_multi_issuer()` (auth.rs): Multi-issuer routing with per-issuer DPoP enforcement — Entra issuer uses `dpop_enforcement: disabled`
- `provider-tests.yml`: Existing CI workflow with secrets-gated jobs (Auth0 pattern) — Entra job follows same structure
- `policy-multi-idp.yaml` fixture: Already has Entra-like issuer entry with `dpop_enforcement: disabled`, `strip_domain` transform

### Established Patterns
- Algorithm enforcement: `verify_and_decode()` in validation.rs pins token header alg to JWKS-advertised alg, blocks HS* symmetric algorithms — RS256 passes through cleanly
- `DecodingKey::from_jwk()`: jsonwebtoken library handles RSA JWK → decoding key conversion — no custom RSA handling needed
- Secrets-gated CI: Auth0 job uses `if: secrets.AUTH0_DOMAIN` pattern — Entra follows same approach

### Integration Points
- `IssuerConfig` needs optional `expected_audience: Option<String>` field
- `authenticate_multi_issuer()` Step 3 (`ValidationConfig` construction) needs to use `expected_audience` when set, falling back to `client_id`
- `provider-tests.yml` gets a new `entra` job and updated `provider-summary`
- PAM Docker test infrastructure from Phase 20 (dependency — may need to build if Phase 20 not yet complete)

</code_context>

<deferred>
## Deferred Ideas

- v1.0 token endpoint support (different issuer format `sts.windows.net/{tenant}/`, different claim names) — future phase if enterprise demand
- Entra Conditional Access policy testing (device compliance, location-based) — separate compliance phase
- Microsoft Graph API integration for richer user metadata — separate provisioning milestone
- Entra group overage handling (>200 groups) — already decided in Phase 8: groups from SSSD/NSS only, not token claims

</deferred>

---

*Phase: 22-entra-id-integration*
*Context gathered: 2026-03-13*
