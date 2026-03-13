# Phase 22: Entra ID Integration - Research

**Researched:** 2026-03-13
**Domain:** Azure Entra ID OIDC / RS256 token validation / PAM CI integration
**Confidence:** HIGH (all critical claims verified against Microsoft official docs)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **App Registration:** Device code flow grant type (public client); ROPC bootstrap in CI for
  credential-based token acquisition without browser automation
- **Endpoint:** v2.0 only — issuer format `https://login.microsoftonline.com/{tenant}/v2.0`
- **Scopes:** `openid profile email User.Read`
- **Username claim:** `preferred_username` (hard-fail if absent, no silent fallback)
- **Transform chain:** `strip_domain` then `lowercase` (e.g. `Alice@Corp.Example` → `alice`)
- **CI job:** Added to existing `provider-tests.yml`; secrets-gated; full PAM chain in Docker
- **RS256 validation:** Explicit integration test with real Entra JWKS (first RS256 test in project)
- **DPoP:** `dpop_enforcement: disabled` — Entra uses SHR not RFC 9449; no `cnf.jkt` assertions
- **nonce-in-JWT-header quirk:** Ignore (irrelevant for access tokens)
- **JWKS cache:** Existing refresh-on-miss sufficient for Entra's ~6-week key rotation cycle
- **IssuerConfig change:** Add optional `expected_audience: Option<String>`; falls back to
  `client_id` if not set
- **Planning phase deliverable:** Step-by-step Entra tenant / app registration guide

### Claude's Discretion

- Exact CI secrets set (tenant ID, client ID, test user creds, optional client secret)
- Negative test selection (wrong tenant, expired token, tampered signature)
- Infrastructure details for full PAM chain Docker setup
- Whether to document Entra-specific operational notes in security guide

### Deferred Ideas (OUT OF SCOPE)

- v1.0 token endpoint (`sts.windows.net/{tenant}/`, different claim names)
- Entra Conditional Access policy testing (device compliance, location-based)
- Microsoft Graph API integration for richer user metadata
- Entra group overage handling (>200 groups) — groups come from SSSD/NSS only (Phase 8 decision)
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| ENTR-01 | Entra app registration with device code flow enabled (public client) | App registration procedure documented; public client flag + device code grant needed |
| ENTR-02 | OIDC discovery + JWKS endpoint validation against live Entra tenant | Discovery URL format confirmed; JWKS URI format confirmed; RS256 key structure confirmed |
| ENTR-03 | RS256 token signature verification through PAM module (not just ES256) | `DecodingKey::from_jwk()` + jsonwebtoken already handle RSA; algorithm pin logic in `verify_and_decode()` passes RS256 through cleanly |
| ENTR-04 | UPN claim mapping (`alice@corp.com` → `alice`) validated end-to-end | `preferred_username` presence confirmed for v2.0 + `profile` scope; collision safety analysis documents the required `email` claim workaround |
| ENTR-05 | Bearer-only mode (DPoP disabled) produces successful auth with full audit trail | `dpop_enforcement: disabled` path already exercised in Phase 21 MIDP-02 tests; audit event shape confirmed |
| CI-03 | Entra ID secrets-gated CI job (`entra-integration`) | Auth0 pattern in `provider-tests.yml` is the template; required secrets identified |
</phase_requirements>

---

## Summary

Phase 22 adds Azure Entra ID as a second real-world identity provider alongside Keycloak. The
multi-issuer infrastructure built in Phase 21 is the enabling layer — Entra is simply a new
`IssuerConfig` entry. The Rust implementation requires only a small, targeted change: add
`expected_audience: Option<String>` to `IssuerConfig` and thread it through the
`ValidationConfig` construction in `authenticate_multi_issuer()`. Everything else — JWKS
caching, RS256 key handling, `strip_domain` + `lowercase` transforms, bearer-mode DPoP bypass,
and structured audit events — is already in the codebase.

The critical research finding is the **`preferred_username` claim hazard**: Microsoft's official
documentation states this claim is only present when the `profile` scope is requested, and is
only available in v2.0 tokens. ROPC tokens issued without `profile` scope may omit it. The
locked decision to use `preferred_username` as the primary claim and hard-fail if absent is
correct, but the test user token acquisition script MUST include `profile` in the scope list.
A second finding concerns the audience (`aud`) claim: for v2.0 access tokens issued to a custom
API, `aud` equals the API's client ID (GUID), not the application ID URI (`api://...`). The
`expected_audience` field in `IssuerConfig` handles cases where the operator registered a
custom Application ID URI.

The existing collision-safety gatekeeper (`check_collision_safety()`) will hard-fail any Entra
issuer config that uses `strip_domain` on `preferred_username`. The fixture workaround is to
use `email` as the `username_claim` with `strip_domain + lowercase` transforms — exactly what
`policy-multi-idp.yaml` already does. The planner must note that `preferred_username` is the
primary claim per the locked decision but the collision-safety rule forces the transform config
to use `email` as the claim source.

**Primary recommendation:** Wire the existing Phase 21 infrastructure to a real Entra tenant;
add `expected_audience` to `IssuerConfig`; write the CI job following the Auth0 pattern.

---

## Standard Stack

### Core (no new dependencies required)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `jsonwebtoken` | existing (workspace) | RS256 token decode/verify | `DecodingKey::from_jwk()` handles RSA JWK natively; already used for ES256 |
| `reqwest` | 0.11 (pinned) | JWKS HTTP fetch | Already in `JwksProvider`; Entra JWKS is a standard HTTPS GET |
| `serde` + `figment` | existing | `IssuerConfig` YAML deserialization | `expected_audience: Option<String>` is a trivial serde field addition |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `jq` (CI shell dep) | system | Parse token claims in CI scripts | Already used in Keycloak and Auth0 CI steps |
| `curl` (CI shell dep) | system | ROPC token fetch, discovery validation | Already used in CI scripts |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| ROPC for CI token acquisition | Browser automation (Playwright) | ROPC is simpler for CI; Playwright requires display server; ROPC acceptable for test-only credentials |
| `email` claim as username source | `preferred_username` directly | `preferred_username` triggers collision-safety hard-fail when paired with `strip_domain`; `email` avoids that (see Pitfall 1) |

**Installation:** No new packages needed.

---

## Architecture Patterns

### Recommended Project Structure (Phase 22 additions)

```
pam-unix-oidc/
├── src/policy/config.rs          # Add expected_audience: Option<String> to IssuerConfig
├── src/auth.rs                   # Thread expected_audience into ValidationConfig
├── tests/
│   └── entra_integration.rs      # New: live Entra integration test (ignored by default)
test/
├── fixtures/policy/
│   └── policy-entra.yaml         # New: Entra-only issuer fixture
├── scripts/
│   └── get-entra-token.sh        # New: ROPC token acquisition script for CI
docs/
└── entra-setup-guide.md          # New: Step-by-step app registration guide (planning deliverable)
.github/workflows/
└── provider-tests.yml            # Add entra job + update provider-summary
```

### Pattern 1: `expected_audience` field in `IssuerConfig`

**What:** Optional override for the audience claim validation. When set, the PAM module
validates `aud == expected_audience` instead of `aud == client_id`.

**When to use:** Entra app registrations that expose an Application ID URI
(`api://unix-oidc` or `api://{client_id}`). The `aud` in the access token will be the URI, not
the bare GUID client_id.

**Code change in `config.rs`:**
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssuerConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub dpop_enforcement: EnforcementMode,
    pub claim_mapping: IdentityConfig,
    pub acr_mapping: Option<AcrMappingConfig>,
    pub group_mapping: Option<GroupMappingConfig>,
    /// Optional audience URI override.
    ///
    /// When set, the token `aud` claim is validated against this value instead
    /// of `client_id`. Required when the Entra app registration exposes an
    /// Application ID URI (e.g. `api://unix-oidc`) that differs from the client
    /// ID GUID. Falls back to `client_id` if None.
    pub expected_audience: Option<String>,
}
```

**Code change in `auth.rs` Step 3:**
```rust
let validation_config = ValidationConfig {
    issuer: issuer_config.issuer_url.trim_end_matches('/').to_string(),
    // Use expected_audience when set; fall back to client_id.
    client_id: issuer_config.expected_audience
        .as_deref()
        .unwrap_or(&issuer_config.client_id)
        .to_string(),
    // ... rest unchanged
};
```

### Pattern 2: Entra-specific `policy-entra.yaml` fixture

```yaml
issuers:
  - issuer_url: "https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0"
    client_id: "${ENTRA_CLIENT_ID}"
    dpop_enforcement: disabled
    # expected_audience: "api://unix-oidc"  # uncomment if custom App ID URI is set
    claim_mapping:
      username_claim: email
      transforms:
        - strip_domain
        - lowercase
    acr_mapping:
      enforcement: warn
    group_mapping:
      source: nss_only
```

### Pattern 3: ROPC token acquisition script

```bash
#!/usr/bin/env bash
# test/scripts/get-entra-token.sh
# Acquires an Entra access token via ROPC for CI use.
# Requires: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_TEST_USER, ENTRA_TEST_PASSWORD
set -euo pipefail

SCOPE="openid profile email User.Read"
RESPONSE=$(curl -s -X POST \
  "https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=${ENTRA_CLIENT_ID}" \
  -d "username=${ENTRA_TEST_USER}" \
  -d "password=${ENTRA_TEST_PASSWORD}" \
  -d "scope=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${SCOPE}'))")")

echo "$RESPONSE" | jq -r '.access_token'
```

### Pattern 4: CI job (following Auth0 pattern in `provider-tests.yml`)

```yaml
entra:
  name: Entra ID Integration
  runs-on: ubuntu-latest
  if: |
    (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) &&
    (github.event.inputs.provider == 'all' || github.event.inputs.provider == 'entra' || github.event.inputs.provider == '')
  steps:
    - uses: actions/checkout@v6

    - name: Check Entra Configuration
      id: check-entra
      run: |
        if [ -z "${{ secrets.ENTRA_TENANT_ID }}" ]; then
          echo "ENTRA_TENANT_ID secret not configured - skipping Entra tests"
          echo "skip=true" >> $GITHUB_OUTPUT
        else
          echo "skip=false" >> $GITHUB_OUTPUT
        fi

    # ... build steps (skip if check-entra.outputs.skip == 'true') ...

    - name: Acquire Entra Token (ROPC)
      if: steps.check-entra.outputs.skip != 'true'
      env:
        ENTRA_TENANT_ID: ${{ secrets.ENTRA_TENANT_ID }}
        ENTRA_CLIENT_ID: ${{ secrets.ENTRA_CLIENT_ID }}
        ENTRA_TEST_USER: ${{ secrets.ENTRA_TEST_USER }}
        ENTRA_TEST_PASSWORD: ${{ secrets.ENTRA_TEST_PASSWORD }}
      run: |
        TOKEN=$(./test/scripts/get-entra-token.sh)
        echo "::add-mask::$TOKEN"
        echo "ENTRA_TOKEN=$TOKEN" >> $GITHUB_ENV

    - name: Validate RS256 Token Against Entra JWKS
      if: steps.check-entra.outputs.skip != 'true'
      env:
        ENTRA_TENANT_ID: ${{ secrets.ENTRA_TENANT_ID }}
        ENTRA_CLIENT_ID: ${{ secrets.ENTRA_CLIENT_ID }}
      run: |
        cargo test --release -p pam-unix-oidc --features "" \
          -- --test-threads=1 entra_integration

    - name: Negative Test: Token From Wrong Tenant Rejected
      if: steps.check-entra.outputs.skip != 'true'
      # Uses a token signed by a different tenant's JWKS key — must reject
      run: |
        cargo test --release -p pam-unix-oidc \
          -- --test-threads=1 entra_wrong_tenant_rejected
```

### Anti-Patterns to Avoid

- **Using `preferred_username` as `username_claim` with `strip_domain` transform:** This
  triggers `check_collision_safety()` hard-fail. Use `email` as the claim source instead.
- **Requesting tokens with `client_credentials` grant in CI:** Client credential tokens do not
  carry `preferred_username` or `email` (they are app-only tokens). Always use ROPC or device
  code flow for user context.
- **Hardcoding tenant IDs in fixture files committed to the repo:** Use environment variable
  substitution in CI scripts. The fixture YAML should use placeholders or separate per-tenant
  fixture files excluded from the repo.
- **Mixing Microsoft Graph scopes with custom API scopes in a single token request:** Entra
  issues one token per audience; Graph-scoped tokens have `aud=https://graph.microsoft.com`,
  which will fail PAM validation. Request custom API scopes only.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| RSA JWK to DecodingKey conversion | Custom RSA key parser | `jsonwebtoken::DecodingKey::from_jwk()` | Already handles RSA (n/e) JWK keys; tested |
| JWKS HTTP fetch + cache | Custom HTTP layer | Existing `JwksProvider` + `IssuerJwksRegistry` | Per-issuer cache with TTL + refresh-on-miss already handles Entra's key rotation |
| Audience validation | Custom `aud` check | `jsonwebtoken::Validation::set_audience()` | Library handles the comparison; our `expected_audience` field feeds the right value in |
| CI secrets masking | Custom log filter | `echo "::add-mask::$TOKEN"` GitHub Actions command | Prevents token from appearing in CI logs |

---

## Common Pitfalls

### Pitfall 1: `strip_domain` on `preferred_username` triggers collision-safety hard-fail

**What goes wrong:** The `check_collision_safety()` gatekeeper hard-fails any pipeline using
`strip_domain` on any claim (including `preferred_username`) because it is statically
non-injective (two users from different domains map to the same bare username).

**Why it happens:** The locked decision says "use `preferred_username`" but Phase 21 already
exercised this exact failure mode in `test_strip_domain_issuer_a_collision_safety_fires()`. The
production auth path calls `check_collision_safety()` unconditionally.

**How to avoid:** Configure Entra issuers with `username_claim: email` + `strip_domain` +
`lowercase` transforms. The `email` claim with `strip_domain` is still non-injective in theory,
but the collision-safety function checks the transform presence, not the claim name. Wait —
re-reading the collision module: `check_collision_safety()` fires whenever `strip_domain` is
present, regardless of which claim is used. This means BOTH `preferred_username` and `email`
with `strip_domain` will hard-fail in the collision-safety check.

**Resolution:** The planner must choose one of:
1. Use a `regex` transform that captures only the local-part of a verified-domain email
   (still advisory-warns but passes `check_collision_safety` — no, it also hard-fails regex).
2. Use `preferred_username` with no transforms and configure the Entra app to issue
   bare usernames (no UPN format). This requires Entra custom attribute mapping.
3. Relax `check_collision_safety` for the `email` claim case when the operator has configured
   a single-tenant Entra app (the single-tenant constraint makes the pipeline injective in
   practice). The planner should pick the safest option: **confirm whether `strip_domain` on
   `email` should be allowed for single-domain IdPs** and add a config bypass or
   document the existing fixture passes because it never reaches `authenticate_multi_issuer`.

**Confirmed:** Looking at `policy-multi-idp.yaml` — the fixture uses `email` + `strip_domain`
and the Phase 21 `test_entra_issuer_has_strip_domain_on_email_in_fixture` test only checks the
config deserialization, not the full auth path. In a real auth call, this config WOULD trigger
`check_collision_safety()` and return `AuthError::Config`. The planner needs to address this.

**Warning signs:** Integration test returns `AuthError::Config` (not `UserNotFound`) on a
valid Entra token.

### Pitfall 2: `preferred_username` absent in ROPC token without `profile` scope

**What goes wrong:** The locked decision says hard-fail if `preferred_username` is absent. If
the CI ROPC call omits the `profile` scope, the token won't contain `preferred_username`, and
auth always fails with a claim-mapping error.

**Why it happens:** Microsoft's documentation: "The preferred_username claim... To receive this
claim, use the `profile` scope." (Source: Microsoft Learn, access-token-claims-reference)

**How to avoid:** Always include `openid profile email User.Read` in ROPC scope. Verify the
decoded token claims in the CI script before passing to the PAM validator.

**Warning signs:** CI ROPC step succeeds but PAM auth fails immediately with "missing claim:
preferred_username".

### Pitfall 3: Audience claim mismatch for tokens requested for Microsoft Graph

**What goes wrong:** If the ROPC scope list includes a Graph scope like `User.Read` without
also specifying the custom API scope, Entra issues the token with `aud=https://graph.microsoft.com`
instead of `aud={client_id}`. PAM validation rejects with `InvalidAudience`.

**Why it happens:** Entra issues one token per audience resource. `User.Read` is a Graph
permission; including it alongside `openid profile email` (which default to the identity
platform) can cause the token's audience to target Graph.

**How to avoid:** Scope the token to the custom API explicitly. For the test token, use
`openid profile email` only (without `User.Read`), or expose a custom scope on the app
registration (`api://{client_id}/access_as_user`) and request that scope. The simplest safe
approach: request `openid profile email` only for the PAM validation token; use a separate
token for Graph if needed.

**Confirmed:** The access token claims reference states: "In v2.0 tokens, this value is always
the client ID of the API." If the resource is the custom app itself, `aud` = `client_id` GUID.

**Warning signs:** Token decodes correctly, but `aud` is `https://graph.microsoft.com` or
`00000003-0000-0000-c000-000000000000`.

### Pitfall 4: ROPC blocked by MFA policy on the test user account

**What goes wrong:** If the Entra tenant has a Conditional Access policy requiring MFA for all
users, ROPC authentication fails with `invalid_grant` even with correct credentials. ROPC is
incompatible with MFA by design.

**Why it happens:** Microsoft docs: "If users need to use multi-factor authentication (MFA) to
log in to the application, they will be blocked instead."

**How to avoid:** Create a dedicated CI test user with MFA excluded from their Conditional
Access policy scope, or create a named location policy that excludes GitHub Actions runner IPs.
Document this requirement in the Entra setup guide.

**Warning signs:** ROPC returns `{"error":"invalid_grant","error_description":"AADSTS50076:...
MFA required"}`.

### Pitfall 5: `uti` claim ≠ `jti` claim — replay protection gap

**What goes wrong:** Entra access tokens use `uti` (a proprietary claim) as the unique token
identifier, not `jti` (the standard JWT ID claim). The PAM module's JTI replay protection
checks `claims.jti`. If `jti` is absent, behavior depends on `jti_enforcement` mode.

**Why it happens:** Microsoft documentation: "Token identifier claim, equivalent to `jti` in
the JWT specification." But they emit it as `uti`, not `jti`. With `jti_enforcement: warn`
(the default), authentication succeeds with a warning. With `jti_enforcement: strict`, it fails.

**How to avoid:** Ensure `jti_enforcement` for the Entra issuer is set to `warn` or `disabled`
(not `strict`). Document in the Entra setup guide that Entra does not emit standard `jti`
claims. Optionally, extend `TokenClaims` to also read `uti` as an alias for `jti`, but this
is out of scope for Phase 22 per current design.

**Confirmed risk:** HIGH — this will cause auth failures in strict-JTI-mode Entra configs.
The policy fixture must set `jti_enforcement: warn` at the global or per-issuer level.

**Warning signs:** Auth succeeds in `warn` mode but fails in `strict` mode; log shows "Token
missing JTI claim".

---

## Code Examples

### Adding `expected_audience` to `IssuerConfig` default

```rust
// Source: pam-unix-oidc/src/policy/config.rs
impl Default for IssuerConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: "unix-oidc".to_string(),
            client_secret: None,
            dpop_enforcement: EnforcementMode::Strict,
            claim_mapping: IdentityConfig::default(),
            acr_mapping: None,
            group_mapping: None,
            expected_audience: None,  // NEW FIELD
        }
    }
}
```

### Threading `expected_audience` through `authenticate_multi_issuer` (Step 3)

```rust
// Source: pam-unix-oidc/src/auth.rs — Step 3, ValidationConfig construction
let validation_config = ValidationConfig {
    issuer: issuer_config.issuer_url.trim_end_matches('/').to_string(),
    // Security: Use expected_audience override when configured; this supports
    // Entra app registrations with custom Application ID URIs (api://...) that
    // differ from the GUID client_id. Falls back to client_id (OIDC standard).
    client_id: issuer_config
        .expected_audience
        .as_deref()
        .unwrap_or(&issuer_config.client_id)
        .to_string(),
    required_acr: None,
    max_auth_age: None,
    jti_enforcement: EnforcementMode::Disabled, // scoped JTI handled at Step 8
    clock_skew_tolerance_secs: clock_skew,
};
```

### Entra OIDC Discovery verification (CI script step)

```bash
# Verify discovery returns valid JWKS URI
# Source: Microsoft Learn, v2-protocols-oidc
DISCOVERY=$(curl -sf \
  "https://login.microsoftonline.com/${ENTRA_TENANT_ID}/v2.0/.well-known/openid-configuration")
JWKS_URI=$(echo "$DISCOVERY" | jq -r '.jwks_uri')
echo "JWKS URI: $JWKS_URI"
# Expected: https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys
curl -sf "$JWKS_URI" | jq '.keys | length' | xargs -I {} echo "Found {} keys"
```

### Live Entra integration test (Rust, ignored by default)

```rust
// Source: pam-unix-oidc/tests/entra_integration.rs
#[tokio::test]
#[ignore = "Requires ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_TOKEN env vars"]
async fn test_entra_rs256_token_validates() {
    let tenant_id = std::env::var("ENTRA_TENANT_ID").expect("ENTRA_TENANT_ID required");
    let client_id = std::env::var("ENTRA_CLIENT_ID").expect("ENTRA_CLIENT_ID required");
    let token = std::env::var("ENTRA_TOKEN").expect("ENTRA_TOKEN required");

    let issuer = format!(
        "https://login.microsoftonline.com/{}/v2.0",
        tenant_id
    );

    let config = ValidationConfig {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        required_acr: None,
        max_auth_age: None,
        jti_enforcement: EnforcementMode::Warn,
        clock_skew_tolerance_secs: 60,
    };

    let jwks_provider = Arc::new(JwksProvider::new(&issuer));
    let validator = TokenValidator::with_jwks_provider(config, jwks_provider);
    let result = validator.validate(&token);

    assert!(result.is_ok(), "Entra RS256 token must validate: {:?}", result);
    let claims = result.unwrap();
    assert!(
        claims.preferred_username.is_some(),
        "preferred_username must be present (requires profile scope)"
    );
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| ES256-only tests | RS256 real-world validation | Phase 22 | First real RSA token path exercised |
| Single-issuer JWKS cache | Per-issuer `IssuerJwksRegistry` | Phase 21 | Entra and Keycloak caches independent |
| Global `dpop_required` | Per-issuer `dpop_enforcement` | Phase 21 | Entra gets `disabled`; Keycloak keeps `strict` |
| `client_id`-only audience | Optional `expected_audience` | Phase 22 | Supports `api://` URI registrations |

**Deprecated/outdated for this phase:**
- v1.0 Entra token endpoint (`sts.windows.net`) — explicitly out of scope

---

## Open Questions

1. **`strip_domain` + `email` collision-safety block**
   - What we know: `check_collision_safety()` hard-fails any pipeline containing `strip_domain`,
     regardless of which claim is used. The existing `policy-multi-idp.yaml` fixture uses
     `email + strip_domain` but is never run through `authenticate_multi_issuer()` in the
     Phase 21 tests (they use the fixture only for deserialization tests).
   - What's unclear: The correct production behavior — should single-tenant Entra configs be
     exempt from the collision-safety hard-fail? Should `strip_domain` on `email` be treated
     differently from `strip_domain` on `preferred_username`?
   - Recommendation: Planner must decide before writing implementation tasks. Options:
     (a) Allow `strip_domain` when `username_claim == "email"` with a single-issuer Entra
     config (requires a new `allow_collision_unsafe: bool` override field or a domain-constraint
     assertion); (b) use a `regex` transform instead (`^(?P<u>[^@]+)@corp\.example$`) which
     also warns but is more explicit about domain constraint; (c) require operator to set UPN
     prefix-only attribute in Entra (no `@domain` suffix). The fixture needs to match whatever
     is decided.

2. **`uti` vs `jti` for Entra tokens**
   - What we know: Entra emits `uti` (not `jti`). With `jti_enforcement: warn` this is
     harmless. With `strict`, it blocks authentication.
   - What's unclear: Should Phase 22 extend `TokenClaims` to alias `uti` as `jti` for Entra?
   - Recommendation: Out of scope for Phase 22. Document the limitation. Set
     `jti_enforcement: warn` in the Entra policy fixture. A future hardening phase can add
     `uti` aliasing.

3. **ROPC deprecation trajectory**
   - What we know: Microsoft warns ROPC will be blocked when MFA is required; they recommend
     migrating to service principal auth for CI. ROPC still works for public client apps on
     accounts without MFA.
   - What's unclear: Whether GitHub Actions IP ranges can reliably bypass Conditional Access.
   - Recommendation: The CI test user must have MFA disabled (or excluded via named location
     policy). Document this in the setup guide. Monitor Microsoft's deprecation announcements.

---

## Entra ID Technical Reference

### Endpoints (v2.0, tenant-specific)

| Endpoint | URL |
|----------|-----|
| OIDC Discovery | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` |
| JWKS | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| Token (ROPC/device) | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token` |
| Device Authorization | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` |

### Key Claims in v2.0 Access Tokens

| Claim | Presence | Value | Notes |
|-------|----------|-------|-------|
| `iss` | Always | `https://login.microsoftonline.com/{tid}/v2.0` | Must match `issuer_url` config |
| `aud` | Always | Client ID GUID of target API | May be `api://...` URI if custom App ID URI set |
| `preferred_username` | When `profile` scope requested | UPN (`alice@corp.example`) | v2.0 only; mutable; hard-fail if absent per locked decision |
| `email` | When `email` scope requested | UPN or email address | Use as `username_claim` to avoid `preferred_username` |
| `sub` | Always | Pairwise identifier (app-specific) | Immutable; not suitable as username |
| `oid` | With `profile` scope | Object ID GUID | Tenant-wide immutable ID |
| `jti` | NOT present | — | Entra uses `uti` instead; JTI enforcement must be `warn` |
| `uti` | Always | Unique token identifier | Entra-proprietary; equivalent to standard `jti` |
| `tid` | Always | Tenant ID GUID | Use for multi-tenant rejection (wrong tenant negative test) |
| `ver` | Always | `"2.0"` | Confirms v2.0 token |
| `alg` (header) | Always | `"RS256"` | First RS256 token in project's test suite |
| `kid` (header) | Always | Key ID | Used by `JwksProvider.get_key()` for JWKS lookup |

### App Registration Checklist (for setup guide)

1. **App type:** Public client (no client secret required for device code / ROPC public client)
2. **Supported account types:** Accounts in this organizational directory only (single-tenant)
3. **Platform:** Mobile and desktop application → Custom redirect URI: `http://localhost`
4. **Advanced → Allow public client flows:** Enabled (required for device code + ROPC)
5. **API permissions:** `openid`, `profile`, `email`, `User.Read` (delegated, admin consent granted)
6. **Optional claims (Access token):** Enable `preferred_username` if not automatically included
   — verify by decoding a test token

### CI Secrets Required

| Secret Name | Description |
|-------------|-------------|
| `ENTRA_TENANT_ID` | Tenant ID GUID (controls job gating) |
| `ENTRA_CLIENT_ID` | Application (client) ID GUID |
| `ENTRA_TEST_USER` | UPN of CI test user (e.g. `ci-test@corp.example`) |
| `ENTRA_TEST_PASSWORD` | Password for CI test user (store in GitHub Secrets) |
| `ENTRA_EXPECTED_AUDIENCE` | Optional: custom App ID URI if `expected_audience` is set |

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test + `cargo test` |
| Config file | `pam-unix-oidc/Cargo.toml` (features: `test-mode`) |
| Quick run command | `cargo test -p pam-unix-oidc --features test-mode -- entra` |
| Full suite command | `cargo test --workspace --features test-mode -- --test-threads=1` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| ENTR-01 | App registration docs produced | manual | N/A (documentation) | ❌ Wave 0 (docs/entra-setup-guide.md) |
| ENTR-02 | OIDC discovery + JWKS validation | integration | `cargo test -p pam-unix-oidc -- entra_rs256_token_validates` | ❌ Wave 0 |
| ENTR-03 | RS256 signature verified via PAM | integration | `cargo test -p pam-unix-oidc -- entra_rs256_token_validates` | ❌ Wave 0 |
| ENTR-04 | UPN → bare username mapping e2e | integration | `cargo test -p pam-unix-oidc -- entra_upn_strip_domain_maps` | ❌ Wave 0 |
| ENTR-05 | Bearer-only auth with audit event | integration | `cargo test -p pam-unix-oidc -- entra_bearer_auth_audit_trail` | ❌ Wave 0 |
| CI-03 | Entra CI job secrets-gated | CI | Verified by inspecting `provider-tests.yml` diff | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p pam-unix-oidc --features test-mode -- --test-threads=1`
- **Per wave merge:** `cargo test --workspace --features test-mode -- --test-threads=1`
- **Phase gate:** Full suite green before `/gsd:verify-work`; live Entra tests run with real secrets in CI

### Wave 0 Gaps

- [ ] `pam-unix-oidc/tests/entra_integration.rs` — covers ENTR-02, ENTR-03, ENTR-04, ENTR-05
- [ ] `test/fixtures/policy/policy-entra.yaml` — real-tenant Entra issuer fixture
- [ ] `test/scripts/get-entra-token.sh` — ROPC token acquisition for CI
- [ ] `docs/entra-setup-guide.md` — step-by-step app registration guide (ENTR-01)

---

## Sources

### Primary (HIGH confidence)

- [Microsoft Learn: Access token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference) — `preferred_username` presence conditions, `aud` value for v2.0, `uti` vs `jti`
- [Microsoft Learn: OpenID Connect on Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) — Discovery URL format, JWKS URI, issuer format
- [Microsoft Learn: OAuth 2.0 ROPC](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth-ropc) — ROPC flow, MFA incompatibility, scope parameters
- `pam-unix-oidc/src/identity/collision.rs` — collision-safety gatekeeper behavior (code audit)
- `pam-unix-oidc/src/policy/config.rs` — `IssuerConfig` current structure (code audit)
- `pam-unix-oidc/src/auth.rs` — `authenticate_multi_issuer()` Step 3 construction (code audit)
- `pam-unix-oidc/src/oidc/validation.rs` — `verify_and_decode()` algorithm pinning (code audit)
- `.github/workflows/provider-tests.yml` — Auth0 secrets-gating pattern (code audit)
- `pam-unix-oidc/tests/multi_idp_integration.rs` — Phase 21 test precedents (code audit)

### Secondary (MEDIUM confidence)

- [Microsoft Learn: Troubleshoot signature validation errors](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/app-integration/troubleshooting-signature-validation-errors) — RS256 key rotation cadence
- [Microsoft Q&A: OIDC RSA key rotation frequency](https://learn.microsoft.com/en-us/answers/questions/1393581/how-often-azure-ad-refresh-the-oidc-rsa-public-key) — key rotation is unpredictable; use JWKS refresh-on-miss

### Tertiary (LOW confidence)

- None — all critical claims verified against official documentation.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all libraries already in codebase
- Architecture patterns: HIGH — derived from existing Phase 21 code and official Entra docs
- Pitfalls: HIGH for claims/ROPC/audience (official docs confirmed); MEDIUM for collision-safety resolution (open question)
- CI integration: HIGH — Auth0 pattern directly reusable

**Research date:** 2026-03-13
**Valid until:** 2026-06-13 (Entra API changes infrequently; ROPC deprecation to watch)
