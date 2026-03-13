# Phase 21: Multi-IdP Configuration - Research

**Researched:** 2026-03-13
**Domain:** Rust PAM module — multi-issuer OIDC routing, per-issuer config, concurrent JWKS caching
**Confidence:** HIGH (all findings grounded in direct codebase inspection)

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| MIDP-01 | `issuers[]` array in policy.yaml with per-issuer config blocks (issuer_url, client_id, client_secret) | New `IssuerConfig` struct + `Vec<IssuerConfig>` in `PolicyConfig`; backward-compat via single `issuer` → single-element migration |
| MIDP-02 | Per-issuer DPoP enforcement mode (strict/warn/disabled) | `EnforcementMode` already exists; add `dpop_enforcement: EnforcementMode` to `IssuerConfig` |
| MIDP-03 | Per-issuer claim mapping rules (username extraction, strip-domain, regex) | `IdentityConfig` + `UsernameMapper` already exist and are reusable per-issuer |
| MIDP-04 | Per-issuer ACR value mapping (e.g., Keycloak `urn:keycloak:acr:loa2` vs Entra `c1`/`c2`) | `AcrConfig` already exists; per-issuer `acr_mapping` maps IdP-specific values to canonical ACR strings |
| MIDP-05 | Per-issuer group mapping (token claim path vs NSS-only, group name translation) | `groups_enforcement: EnforcementMode` already exists; per-issuer variant controls source (NSS-only vs token claim enrichment) |
| MIDP-06 | PAM module matches incoming token `iss` to configured issuer; rejects unknown issuers | Extract `iss` from JWT header (unverified decode), look up in `HashMap<String, IssuerConfig>`; reject unknown = hard-fail |
| MIDP-07 | JWKS cache keyed by issuer URL (multi-issuer concurrent caching) | `JwksProvider` already takes `issuer` in constructor; need `HashMap<String, Arc<JwksProvider>>` |
| MIDP-08 | Graceful degradation: missing optional per-issuer fields fall back to safe defaults with WARN logging | All optional fields use `#[serde(default)]`; warning logged at `PolicyConfig::load_from()` when optional sections absent |
</phase_requirements>

---

## Summary

Phase 21 is the heaviest structural refactor in v2.1. The core task is converting the PAM module from a single-issuer model (one `ValidationConfig`, one `JwksProvider`, one `IdentityConfig`) to a multi-issuer routing model where the incoming token's `iss` claim selects the per-issuer configuration bundle.

The codebase already contains all the primitive building blocks: `EnforcementMode`, `IdentityConfig`, `UsernameMapper`, `AcrConfig`, and `JwksProvider`. Phase 21 composes these into a new `IssuerConfig` struct and wires a dispatch table (`HashMap<String, IssuerConfig>`) through `PolicyConfig`, `auth.rs`, and `jwks.rs`. No new cryptographic primitives are needed.

The critical architectural constraint is that issuer routing must happen on the raw (unverified) JWT payload. The `iss` claim must be extracted from the base64-decoded JWT body BEFORE any JWKS fetch or signature verification — the JWKS endpoint is unknown until the issuer is identified. This is safe because `iss` is only used as a routing key to select the correct `JwksProvider`; the selected validator then performs full cryptographic verification of the token including the `iss` claim again.

**Primary recommendation:** Add `IssuerConfig` to `policy/config.rs`, wire a `Vec<IssuerConfig>` into `PolicyConfig`, build a `MultiIssuerRouter` in `auth.rs` that dispatches on `iss`, and upgrade `jwks.rs` to `HashMap<String, Arc<JwksProvider>>`. Backward-compatibility is maintained by auto-converting a legacy `issuer:` / `OIDC_ISSUER` env-var config into a single-element `issuers[]` array at load time.

---

## Standard Stack

### Core (already present — no new dependencies required)

| Library | Version | Purpose | Notes |
|---------|---------|---------|-------|
| `figment` | 0.10 | Layered YAML + env config loading | Already handles `#[serde(default)]` gracefully |
| `jsonwebtoken` | 9.0 | JWT header decode for `iss` extraction | `decode_header()` does no signature check |
| `parking_lot` | 0.12 | `RwLock` on JWKS cache | Already used in `JwksProvider` |
| `std::collections::HashMap` | std | Issuer-keyed dispatch table | No external dep needed |
| `serde` | workspace | Config deserialization | `#[serde(default)]` for optional fields |
| `thiserror` | workspace | Error types | `UnknownIssuer` variant to add |
| `reqwest` | 0.11 blocking | JWKS HTTP fetch per issuer | Already in use |
| `tracing` | workspace | WARN logging for missing optional fields | Already in use |

### No New Dependencies

All required functionality exists in the current dependency set. Do NOT add new dependencies.

---

## Architecture Patterns

### Recommended Module Layout

```
pam-unix-oidc/src/
├── policy/
│   └── config.rs          ← Add IssuerConfig, issuers: Vec<IssuerConfig>
├── oidc/
│   ├── jwks.rs             ← Add IssuerJwksRegistry (HashMap<String, Arc<JwksProvider>>)
│   └── validation.rs       ← TokenValidator::new() already takes ValidationConfig
└── auth.rs                 ← Add MultiIssuerRouter, dispatch on iss claim
```

### Pattern 1: IssuerConfig Struct (new type in `policy/config.rs`)

**What:** A self-contained per-issuer configuration bundle that replaces the current global `issuer`/`OIDC_ISSUER` env-var pattern.

**When to use:** Every element of `PolicyConfig::issuers[]`.

```rust
/// Per-issuer OIDC configuration bundle (MIDP-01..05).
///
/// All fields except `issuer_url` and `client_id` are optional.
/// Missing optional fields fall back to safe defaults with WARN logging (MIDP-08).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IssuerConfig {
    /// OIDC issuer URL — used as the routing key to match the token `iss` claim.
    /// Also used as the base URL for OIDC Discovery (/.well-known/openid-configuration).
    pub issuer_url: String,

    /// OAuth client ID for this issuer. Default: "unix-oidc".
    #[serde(default = "default_client_id")]
    pub client_id: String,

    /// OAuth client secret (optional; used for token introspection).
    #[serde(default)]
    pub client_secret: Option<String>,

    /// DPoP proof-of-possession enforcement mode for this issuer (MIDP-02).
    /// Default: Strict (safest; require DPoP for DPoP-bound tokens).
    /// Use Disabled for Entra ID (bearer-only) or legacy clients.
    #[serde(default = "EnforcementMode::strict_default")]
    pub dpop_enforcement: EnforcementMode,

    /// Username claim extraction and transform pipeline (MIDP-03).
    /// Default: preferred_username, no transforms.
    #[serde(default)]
    pub claim_mapping: IdentityConfig,

    /// ACR value mapping for this issuer (MIDP-04).
    /// Maps issuer-specific ACR strings (e.g. Keycloak "urn:keycloak:acr:loa2")
    /// to canonical values used by policy rules.
    /// Default: no mapping (use raw ACR claim value).
    #[serde(default)]
    pub acr_mapping: Option<AcrMappingConfig>,

    /// Group mapping configuration for this issuer (MIDP-05).
    /// Default: NSS-only (token groups used for audit enrichment only).
    #[serde(default)]
    pub group_mapping: Option<GroupMappingConfig>,
}
```

**Key design constraint:** `issuer_url` must exactly match the `iss` claim in tokens from this IdP (after trailing-slash normalization). This is the routing key — not the OIDC discovery URL, not a display name.

### Pattern 2: ACR Mapping Config (new type)

**What:** Maps IdP-specific ACR strings to canonical values. Required for Entra (`c1`, `c2`) vs Keycloak (`urn:keycloak:acr:loa2`) interoperability.

```rust
/// Maps IdP-specific ACR claim values to canonical values used in policy rules (MIDP-04).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AcrMappingConfig {
    /// Map of {idp_acr_value: canonical_value}.
    /// e.g. {"c1": "urn:example:acr:mfa", "c2": "urn:example:acr:phishing-resistant"}
    #[serde(default)]
    pub mappings: HashMap<String, String>,
    /// ACR enforcement mode for this issuer.
    #[serde(default)]
    pub enforcement: EnforcementMode,
}
```

### Pattern 3: Group Mapping Config (new type)

**What:** Controls whether NSS groups alone are used, or whether token group claims are translated.

```rust
/// Per-issuer group mapping configuration (MIDP-05).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GroupMappingConfig {
    /// Source of group membership for access decisions.
    /// - nss_only: Use NSS/SSSD groups only (default, safest).
    /// - token_claim: Use the named token claim for audit; access still via NSS.
    #[serde(default)]
    pub source: GroupSource,
    /// OIDC claim name for group extraction (when source = token_claim).
    /// Default: "groups".
    #[serde(default = "default_groups_claim")]
    pub claim: String,
    /// Optional name translation map: {token_group_name: local_group_name}.
    #[serde(default)]
    pub name_map: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GroupSource {
    #[default]
    NssOnly,
    TokenClaim,
}
```

### Pattern 4: Multi-Issuer Router (new struct in `auth.rs`)

**What:** At auth time, extracts `iss` from the raw JWT without signature verification, looks up the matching `IssuerConfig`, then constructs the per-issuer `ValidationConfig` and `JwksProvider`.

**Critical ordering:**

```
1. Decode JWT header + payload (no sig check) → extract iss
2. Look up iss in HashMap<String, IssuerConfig> → UnknownIssuer if absent
3. Construct ValidationConfig from IssuerConfig
4. Look up or create JwksProvider for this issuer (from IssuerJwksRegistry)
5. Construct TokenValidator with IssuerConfig's JwksProvider
6. Full validate() — re-verifies iss, audience, signature, expiry, JTI
7. Apply per-issuer DPoP enforcement
8. Apply per-issuer claim_mapping (UsernameMapper)
```

Step 6 re-validates `iss` cryptographically even though step 1 used it for routing. This double-check is intentional: step 1 is routing (untrusted), step 6 is security validation (trusted after JWKS verification).

```rust
/// Resolves the issuer URL from a raw JWT (no signature verification).
///
/// Decodes the payload section and extracts the `iss` claim.
/// Only used for issuer routing — never for security decisions.
/// Security: The caller MUST pass the returned issuer into a full
/// TokenValidator that re-validates `iss` after signature verification.
pub fn extract_iss_for_routing(token: &str) -> Result<String, AuthError> {
    let claims = TokenClaims::from_token(token)
        .map_err(|e| AuthError::Config(format!("Cannot decode token for routing: {e}")))?;
    Ok(claims.iss)
}
```

### Pattern 5: JWKS Registry (new struct in `jwks.rs`)

**What:** Wraps `HashMap<String, Arc<JwksProvider>>` with thread-safe lazy initialization. Each issuer gets an independent cache; fetching one issuer's JWKS never touches another issuer's cache entry.

```rust
/// Thread-safe registry of per-issuer JWKS providers.
///
/// Invariant (MIDP-07): each issuer URL maps to an independent JwksProvider.
/// A fetch or refresh for issuer A NEVER touches the cache for issuer B.
pub struct IssuerJwksRegistry {
    // Outer RwLock covers the HashMap itself (inserts during first-use initialization).
    // Inner Arc<JwksProvider> has its own RwLock for cache TTL management.
    providers: RwLock<HashMap<String, Arc<JwksProvider>>>,
}

impl IssuerJwksRegistry {
    pub fn new() -> Self { ... }

    /// Get or create the JwksProvider for the given issuer.
    pub fn get_or_init(&self, issuer: &str, ttl_secs: u64, timeout_secs: u64) -> Arc<JwksProvider> {
        // Read path: fast path when provider already exists
        {
            let read = self.providers.read();
            if let Some(p) = read.get(issuer) {
                return Arc::clone(p);
            }
        }
        // Write path: insert new provider (may race; last-write wins, both are correct)
        let mut write = self.providers.write();
        write.entry(issuer.to_string())
            .or_insert_with(|| Arc::new(JwksProvider::with_timeouts(issuer, ttl_secs, timeout_secs)))
            .clone()
    }
}
```

### Pattern 6: Backward-Compatibility Migration

**What:** When `issuers[]` is absent and `OIDC_ISSUER` env var is set (legacy mode), synthesize a single-element `issuers[]` to avoid breaking existing deployments.

```rust
impl PolicyConfig {
    /// Build an effective issuers list, honoring legacy OIDC_ISSUER env var.
    ///
    /// Priority:
    /// 1. `issuers[]` in policy.yaml (Phase 21+ config)
    /// 2. Legacy `OIDC_ISSUER` / `OIDC_CLIENT_ID` env vars → synthesize single IssuerConfig
    pub fn effective_issuers(&self) -> Result<Vec<IssuerConfig>, PolicyError> {
        if !self.issuers.is_empty() {
            return Ok(self.issuers.clone());
        }
        // Legacy path
        let issuer = std::env::var("OIDC_ISSUER")
            .map_err(|_| PolicyError::ConfigError("No issuers[] configured and OIDC_ISSUER not set".into()))?;
        let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| "unix-oidc".into());
        tracing::warn!(
            issuer = %issuer,
            "Using legacy OIDC_ISSUER env var — migrate to issuers[] in policy.yaml"
        );
        Ok(vec![IssuerConfig {
            issuer_url: issuer,
            client_id,
            ..IssuerConfig::default()
        }])
    }
}
```

### Anti-Patterns to Avoid

- **Do NOT** use `PAM_USER` or any user-supplied input as the routing key. The routing key is ALWAYS the token's `iss` claim.
- **Do NOT** cache per-issuer `IssuerConfig` by something other than the normalized issuer URL (no trailing slash). Normalization must match `JwksProvider::new()` which calls `trim_end_matches('/')`.
- **Do NOT** share the same `JtiCache` entry namespace across issuers. JTI values are only guaranteed unique within a single issuer. The JTI cache key should include the issuer URL as a prefix: `"{issuer}:{jti}"`.
- **Do NOT** apply the collision-safety check (`check_collision_safety`) globally across issuers. Each issuer's `claim_mapping` is checked independently — `alice@keycloak.com` and `alice@entra.com` routing to the same Unix `alice` is expected and correct when each issuer has `strip_domain: true` scoped to its own domain. The collision concern is within a single issuer's transform pipeline producing non-injective mappings from that issuer's token population.
- **Do NOT** allow `issuers[]` to contain duplicate `issuer_url` values. Detect and hard-fail at load time.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| JWT payload extraction without verification | Custom base64+json parser | `TokenClaims::from_token()` | Already exists, battle-tested in test suite |
| EnforcementMode deserialization | New enum variants | Reuse existing `EnforcementMode` | Hand-rolled serde impl already rejects unknown strings |
| Per-issuer JWKS caching | Custom TTL cache | `JwksProvider::with_timeouts()` + `RwLock<HashMap>` | Existing `JwksProvider` already correct per-issuer |
| YAML config loading with defaults | Custom serde | `figment` with `Serialized::defaults()` + `Yaml::file()` | Already established pattern in `PolicyConfig::load_from()` |
| Username transform pipeline | New transform runner | `UsernameMapper::from_config()` + `mapper.map()` | Complete, tested, regex-safe |

---

## Common Pitfalls

### Pitfall 1: Issuer URL Normalization Mismatch

**What goes wrong:** Token `iss` claim is `https://keycloak:8080/realms/unix-oidc` but config `issuer_url` is `https://keycloak:8080/realms/unix-oidc/` (trailing slash). Routing lookup fails → UnknownIssuer error in production.

**Why it happens:** OIDC spec requires issuer URLs to be registered without trailing slash, but human operators often add them in YAML config, and `JwksProvider::new()` already trims them.

**How to avoid:** Normalize all issuer URLs on load:
```rust
pub fn normalized_url(url: &str) -> String {
    url.trim_end_matches('/').to_string()
}
// Apply in IssuerConfig deserialization + in extract_iss_for_routing()
```

**Warning signs:** Auth failures with "unknown issuer" even when issuer appears in config.

### Pitfall 2: JTI Cache Key Collision Across Issuers

**What goes wrong:** Two different issuers both issue tokens with JTI `"abc-123"`. The first token consumes the JTI cache slot; the second is rejected as a replay even though it's a different token from a different issuer.

**Why it happens:** The global JTI cache uses bare JTI as key. With a single issuer this is fine; with multiple issuers, JTI uniqueness is only guaranteed per-issuer (RFC 7519 §4.1.7: "The "jti" ... value ... is ... unique for each JWT").

**How to avoid:** Prefix JTI cache keys with the issuer URL: key = `format!("{issuer}:{jti}")`.

**Warning signs:** Intermittent "token replay detected" errors for valid tokens from a secondary issuer.

### Pitfall 3: Collision Safety Check Applied Globally

**What goes wrong:** `check_collision_safety()` is called with a merged IdentityConfig that combines transforms from multiple issuers, causing false-positive non-injectivity failures.

**Why it happens:** Current code calls `check_collision_safety(&policy.identity)` once globally. With per-issuer configs each have their own `claim_mapping`.

**How to avoid:** Call `check_collision_safety()` once per `IssuerConfig::claim_mapping` at load time, not on a global merged config.

### Pitfall 4: JWKS Registry Initialization Race

**What goes wrong:** Two concurrent auth attempts for the same issuer both reach the "write path" of `IssuerJwksRegistry::get_or_init()` simultaneously, causing double-initialization.

**Why it happens:** The check-then-insert pattern between read and write lock creates a TOCTOU window.

**How to avoid:** Use `HashMap::entry().or_insert_with()` under a single write lock. Both initialized providers are semantically identical (same issuer URL, same TTL); the last-write-wins outcome is correct. Alternatively, use `parking_lot::RwLock` + `HashMap::entry()` as documented in the standard pattern above.

### Pitfall 5: Missing Issuer Config for Session Records

**What goes wrong:** `pam_sm_open_session` writes `token_issuer` to the PAM environment. `pam_sm_close_session` reads it. In multi-issuer mode, the session record's issuer must be present in the current config for cleanup to work. If config is updated to remove an issuer, in-flight sessions will fail cleanup.

**Why it happens:** Session records reference issuer URLs. Config can change between open and close session.

**How to avoid:** `pam_sm_close_session` must tolerate missing issuer in current config (best-effort cleanup with WARN log). The session file deletion should proceed regardless.

### Pitfall 6: Duplicate Issuer URLs in Config

**What goes wrong:** Two `issuers[]` entries with the same `issuer_url`. The HashMap routing will silently use whichever was inserted last.

**How to avoid:** Hard-fail at `PolicyConfig::load_from()` with a clear error listing the duplicate URL.

---

## Code Examples

### Example 1: policy.yaml multi-issuer config (new format)

```yaml
# Multi-IdP configuration — Phase 21+
issuers:
  - issuer_url: "http://keycloak:8080/realms/unix-oidc"
    client_id: "unix-oidc"
    dpop_enforcement: strict
    claim_mapping:
      username_claim: preferred_username
      transforms: []
    acr_mapping:
      enforcement: warn
      mappings:
        "urn:keycloak:acr:loa1": "urn:example:acr:mfa"
        "urn:keycloak:acr:loa2": "urn:example:acr:phishing-resistant"

  - issuer_url: "https://login.microsoftonline.com/{tenant}/v2.0"
    client_id: "your-entra-client-id"
    dpop_enforcement: disabled   # Entra uses SHR, not RFC 9449 DPoP
    claim_mapping:
      username_claim: preferred_username
      transforms:
        - strip_domain             # alice@corp.example → alice
    acr_mapping:
      enforcement: warn
      mappings:
        "c1": "urn:example:acr:mfa"
        "c2": "urn:example:acr:phishing-resistant"
```

### Example 2: Issuer routing in auth.rs (dispatch pattern)

```rust
// Source: codebase — auth.rs authenticate_with_dpop() pattern adapted for multi-issuer
pub fn authenticate_multi_issuer(
    token: &str,
    dpop_proof: Option<&str>,
    dpop_config: &DPoPAuthConfig,
    policy: &PolicyConfig,
    jwks_registry: &IssuerJwksRegistry,
) -> Result<AuthResult, AuthError> {
    // Step 1: Extract iss for routing (no sig check)
    let iss = extract_iss_for_routing(token)?;

    // Step 2: Look up per-issuer config
    let issuer_config = policy.issuer_by_url(&iss)
        .ok_or_else(|| AuthError::UnknownIssuer(iss.clone()))?;

    // Step 3: Build ValidationConfig from per-issuer config
    let validation_config = ValidationConfig {
        issuer: issuer_config.issuer_url.clone(),
        client_id: issuer_config.client_id.clone(),
        jti_enforcement: policy.effective_security_modes().jti_enforcement,
        clock_skew_tolerance_secs: policy.timeouts.clock_skew_staleness_secs as i64,
        required_acr: None,  // ACR checked post-validate via acr_mapping
        max_auth_age: None,
    };

    // Step 4: Get per-issuer JWKS provider
    let jwks_provider = jwks_registry.get_or_init(
        &issuer_config.issuer_url,
        policy.cache.jwks_cache_ttl_secs,
        policy.timeouts.http_timeout_secs,
    );

    // Step 5: Full cryptographic validation (re-validates iss)
    let validator = TokenValidator::with_jwks_provider(validation_config, jwks_provider);
    let claims = validator.validate(token)?;

    // Step 6: Per-issuer DPoP enforcement
    // (use issuer_config.dpop_enforcement instead of global SecurityModes.dpop_required)

    // Step 7: Per-issuer username mapping
    let mapper = UsernameMapper::from_config(&issuer_config.claim_mapping)
        .map_err(|e| AuthError::IdentityMapping(e.to_string()))?;
    // ... rest of auth flow
}
```

### Example 3: Loading and validating issuers[] (config.rs)

```rust
impl PolicyConfig {
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        // ... existing figment loading ...

        // Validate: no duplicate issuer URLs
        let mut seen = std::collections::HashSet::new();
        for issuer in &config.issuers {
            let normalized = issuer.issuer_url.trim_end_matches('/').to_string();
            if !seen.insert(normalized.clone()) {
                return Err(PolicyError::ConfigError(
                    format!("Duplicate issuer URL in issuers[]: {normalized}")
                ));
            }
        }

        // MIDP-08: WARN for issuers with missing optional fields
        for issuer in &config.issuers {
            if issuer.acr_mapping.is_none() {
                tracing::warn!(
                    issuer = %issuer.issuer_url,
                    "Issuer config has no acr_mapping — using raw ACR claim values"
                );
            }
            if issuer.group_mapping.is_none() {
                tracing::warn!(
                    issuer = %issuer.issuer_url,
                    "Issuer config has no group_mapping — using NSS-only group resolution"
                );
            }
        }

        Ok(config)
    }
}
```

### Example 4: JTI cache key scoping (security/jti_cache.rs)

```rust
// The global JTI cache must be keyed by issuer-scoped JTI to prevent
// cross-issuer replay false positives (RFC 7519 §4.1.7).
//
// Current key: jti_value
// Required key: format!("{issuer}:{jti_value}")
//
// Change in auth.rs where check_and_record() is called:
let scoped_jti = claims.jti.as_deref().map(|jti| format!("{}:{}", claims.iss, jti));
let jti_result = global_jti_cache().check_and_record(
    scoped_jti.as_deref(),
    ...,
    ttl_seconds,
);
```

---

## State of the Art

| Old Approach | Current Approach | Notes |
|--------------|------------------|-------|
| Single `OIDC_ISSUER` env var | `issuers[]` array in policy.yaml | Phase 21 adds multi-issuer; legacy env var still works via `effective_issuers()` migration path |
| Global `ValidationConfig` | Per-issuer `ValidationConfig` built from `IssuerConfig` | No breaking change to `ValidationConfig` struct |
| Single `JwksProvider` instance | `IssuerJwksRegistry` with per-issuer `JwksProvider` | MIDP-07: independent caches |
| Global `IdentityConfig` | Per-issuer `claim_mapping: IdentityConfig` | `UsernameMapper` already stateless — reuse unchanged |
| Global DPoP enforcement | Per-issuer `dpop_enforcement` | Required for Entra (disabled) vs Keycloak (strict) |

---

## Open Questions

1. **JTI cache keying scope**
   - What we know: Current global JTI cache uses bare `jti` value as key
   - What's unclear: Whether any currently-deployed issuers in test fixtures generate JTIs that would collide between issuers
   - Recommendation: Change key to `"{issuer}:{jti}"` unconditionally — no behavior change for single-issuer setups, correct for multi-issuer. Zero performance impact.

2. **Collision safety check scope in multi-issuer mode**
   - What we know: `check_collision_safety()` is called per-policy today (single issuer)
   - What's unclear: Whether the check should detect cross-issuer collisions (e.g., two issuers both using `strip_domain` that could produce the same username)
   - Recommendation: Keep per-issuer check only. Cross-issuer collisions are intentional and expected (Keycloak `alice@corp.com` and Entra `alice@corp.com` both mapping to Unix `alice` is correct and desired). The security invariant (IDN-03) was designed for within-issuer non-injectivity.

3. **Second "mock" issuer for integration tests**
   - What we know: Phase 21 success criterion requires two live issuers
   - What's unclear: Whether a second full Keycloak instance is needed or if a simpler mock (wiremock-rs) suffices
   - Recommendation: Use wiremock-rs for the second issuer in unit/integration tests (matches existing Phase 16 pattern for step-up IPC tests). Full dual-Keycloak is not needed until Phase 22 (Entra).

4. **PolicyConfig env-var allowlist in `load_from()`**
   - What we know: Current `only(&["security_modes", "cache", ...])` filter prevents `UNIX_OIDC_*` env pollution
   - What's unclear: Whether `issuers` should be in the env-var allowlist
   - Recommendation: Add `"issuers"` to the allowlist in `load_from()` and `from_env()`. Individual issuer fields are too complex for env-var override anyway, but the key must be present to avoid figment errors if an operator tries it.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test (`#[test]`, `#[cfg(test)]`) + `cargo test` |
| Config file | `pam-unix-oidc/Cargo.toml` — `[dev-dependencies]` includes `tempfile`, `serde_yaml`, `figment` |
| Quick run command | `cargo test -p pam-unix-oidc --features test-mode 2>&1 \| grep -E "^test \|FAILED\|ok$"` |
| Full suite command | `cargo test --workspace --features test-mode` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| MIDP-01 | `issuers[]` with 2 entries loads without error | unit | `cargo test -p pam-unix-oidc test_multi_issuer_policy_loads` | ❌ Wave 0 |
| MIDP-01 | Single-entry backward-compat via `effective_issuers()` | unit | `cargo test -p pam-unix-oidc test_legacy_oidc_issuer_env_var` | ❌ Wave 0 |
| MIDP-01 | Duplicate issuer URLs hard-fail at load | unit | `cargo test -p pam-unix-oidc test_duplicate_issuer_url_rejected` | ❌ Wave 0 |
| MIDP-02 | DPoP strict on issuer A, disabled on issuer B | unit | `cargo test -p pam-unix-oidc test_per_issuer_dpop_enforcement` | ❌ Wave 0 |
| MIDP-03 | strip_domain on issuer A, no transform on issuer B | unit | `cargo test -p pam-unix-oidc test_per_issuer_claim_mapping` | ❌ Wave 0 |
| MIDP-04 | Keycloak ACR mapped to canonical; Entra ACR mapped | unit | `cargo test -p pam-unix-oidc test_acr_mapping_applied` | ❌ Wave 0 |
| MIDP-05 | group_mapping=nss_only uses NSS; token_claim enriches audit | unit | `cargo test -p pam-unix-oidc test_group_mapping_modes` | ❌ Wave 0 |
| MIDP-06 | Token from known issuer authenticates; unknown issuer rejected | unit | `cargo test -p pam-unix-oidc test_unknown_issuer_rejected` | ❌ Wave 0 |
| MIDP-07 | JWKS fetch for issuer A does not evict issuer B cache | unit | `cargo test -p pam-unix-oidc test_jwks_registry_independent_caches` | ❌ Wave 0 |
| MIDP-07 | Concurrent JWKS init race produces correct result | unit | `cargo test -p pam-unix-oidc test_jwks_registry_concurrent_init` | ❌ Wave 0 |
| MIDP-08 | Issuer without acr_mapping loads with WARN | unit | `cargo test -p pam-unix-oidc test_issuer_optional_fields_defaults` | ❌ Wave 0 |

**Adversarial tests required (per global testing mandate):**

| Req ID | Negative Behavior | Test Type | Automated Command | File Exists? |
|--------|-------------------|-----------|-------------------|-------------|
| MIDP-06 | Token with forged iss claim rejected after sig check | unit+feature=test-mode | `cargo test -p pam-unix-oidc test_forged_iss_routing_rejected` | ❌ Wave 0 |
| MIDP-07 | JTI from issuer A doesn't block issuer B's identical JTI | unit | `cargo test -p pam-unix-oidc test_jti_scoped_per_issuer` | ❌ Wave 0 |
| MIDP-01 | Empty issuers[] array rejected or falls back gracefully | unit | `cargo test -p pam-unix-oidc test_empty_issuers_array` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p pam-unix-oidc --features test-mode`
- **Per wave merge:** `cargo test --workspace --features test-mode`
- **Phase gate:** Full workspace test suite green + `cargo clippy -- -D warnings` + `cargo fmt --check` before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `pam-unix-oidc/src/policy/config.rs` — `IssuerConfig`, `AcrMappingConfig`, `GroupMappingConfig` structs with tests
- [ ] `pam-unix-oidc/src/oidc/jwks.rs` — `IssuerJwksRegistry` with tests
- [ ] `pam-unix-oidc/src/auth.rs` — `MultiIssuerRouter` / `authenticate_multi_issuer()` with tests
- [ ] `test/fixtures/policy/policy-multi-idp.yaml` — reference policy with two issuers
- [ ] All test functions listed in the requirement map above

---

## Sources

### Primary (HIGH confidence)
- Direct codebase inspection:
  - `/pam-unix-oidc/src/policy/config.rs` — `PolicyConfig`, `IdentityConfig`, `SecurityModes`, `EnforcementMode`, `AcrConfig`
  - `/pam-unix-oidc/src/oidc/jwks.rs` — `JwksProvider`, `CachedJwks`, `RwLock<Option<CachedJwks>>`
  - `/pam-unix-oidc/src/oidc/validation.rs` — `TokenValidator`, `ValidationConfig`, issuer/audience/signature flow
  - `/pam-unix-oidc/src/auth.rs` — `authenticate_with_dpop()`, `authenticate_with_token()`, DPoP enforcement wiring
  - `/pam-unix-oidc/src/identity/mapper.rs` — `UsernameMapper`, `UsernameTransform`, transform pipeline
  - `/pam-unix-oidc/src/identity/collision.rs` — `check_collision_safety()` scope
  - `/pam-unix-oidc/src/oidc/token.rs` — `TokenClaims::from_token()` — the unverified decode function
- RFC 7519 §4.1.7 — JTI uniqueness scoped to issuer
- RFC 9449 §4, §8 — DPoP binding, nonce enforcement
- OIDC Core 1.0 §2 — `iss` claim definition and URL normalization requirements
- Project `CLAUDE.md` — Security Check Decision Matrix (HARD-FAIL vs configurable)
- Project `NEXT-SESSION-PLAN.md` — Phase 21 architecture notes from prior session

### Secondary (MEDIUM confidence)
- `.planning/REQUIREMENTS.md` — MIDP-01..08 requirement text (authoritative for this project)
- `.planning/ROADMAP.md` — Phase 21 success criteria

### Tertiary (N/A)
- No external web searches performed. All findings are grounded in direct codebase inspection and RFC references.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all dependencies already in Cargo.toml; no new deps required
- Architecture: HIGH — all patterns derived from existing working code in the same module (JwksProvider, ValidationConfig, IdentityConfig)
- Pitfalls: HIGH — JTI scoping and collision-check scope pitfalls derived from direct code analysis; normalization pitfall derived from JwksProvider.new() implementation

**Research date:** 2026-03-13
**Valid until:** 2026-04-13 (stable domain — codebase is the primary source; no external API churn risk)
