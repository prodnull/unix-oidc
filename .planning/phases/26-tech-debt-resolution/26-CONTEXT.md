# Phase 26: Tech Debt Resolution - Context

**Gathered:** 2026-03-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Wire or remove dead multi-IdP config paths (ACR mapping, GroupSource::TokenClaim, effective_issuers), make JWKS TTL and HTTP timeout configurable per-issuer, improve Entra CI diagnostic messaging, and update secure_delete.rs citations from DoD 5220.22-M to NIST SP 800-88 Rev 1. Six requirements: DEBT-02 through DEBT-06, DEBT-08.

</domain>

<decisions>
## Implementation Decisions

### Dead Code Resolution Strategy (DEBT-03, DEBT-04)
- **GroupSource::TokenClaim (DEBT-03): Remove.** Phase 8 established that groups come from SSSD/NSS, not OIDC token claims. TokenClaim was an early design variant that was never wired. Keeping dead code in a security-critical PAM module is a liability — dead variants can't be tested in production, and untested security code is dangerous. Remove the variant, its match arms, and any supporting code. If token-claim groups are needed in the future, they can be re-added with proper design.
- **effective_issuers() (DEBT-04): Remove.** Phase 21 established the `issuers[]` config pattern. `effective_issuers()` is a backward-compat shim that synthesizes an `IssuerConfig` from the legacy `OIDC_ISSUER` env var. The env var path is already handled in `load_from()` (config.rs line ~951). If `effective_issuers()` is not called in any production path, remove it and its tests. If it IS called somewhere, wire it properly with a deprecation warning.

### ACR Mapping Enforcement (DEBT-02)
- **Wire acr_mapping from IssuerConfig into auth.rs.** Currently `required_acr: None` is hardcoded at auth.rs:140. Instead, read `issuer_config.acr_mapping` and set `required_acr` from it.
- **Enforcement semantics:** If `acr_mapping.required_acr` is set and the token's `acr` claim doesn't match → reject (hard fail, not warn). ACR is a security property — if an operator configured it, they need it enforced.
- **Missing acr claim:** If `required_acr` is set but the token has no `acr` claim at all → reject. An IdP that doesn't return `acr` can't satisfy the requirement.
- **No acr_mapping configured:** Behavior unchanged — no ACR enforcement for that issuer (current default).

### Per-Issuer JWKS TTL and HTTP Timeout (DEBT-05)
- **Add `jwks_cache_ttl_secs` and `http_timeout_secs` fields to IssuerConfig.** Follow the same per-issuer config pattern established in Phase 21 and extended in Phase 25.
- **Default values:** 300s (5 min) for JWKS TTL, 10s for HTTP timeout — matching current hardcoded constants in auth.rs:163-164.
- **Wire into JwksProvider:** When creating the JWKS provider for an issuer, use per-issuer values instead of the hardcoded constants.
- **Structured log at startup:** Log the effective TTL and timeout for each issuer at INFO level so operators can verify configuration took effect.

### Entra CI ROPC Diagnostic (DEBT-06)
- **Detect Conditional Access block.** When the ROPC token request fails, check the error response for common Conditional Access indicators (e.g., `AADSTS50076`, `AADSTS53003`, `interaction_required`).
- **Log actionable diagnostic.** Instead of opaque failure, log: "Entra ROPC failed — possible Conditional Access policy blocking ROPC. Check tenant Conditional Access → Named Locations → exclude CI IP range, or switch to client_credentials grant."
- **Don't change the exit code.** The test should still fail — this is about improving the error message, not masking the failure.

### Citation Update (DEBT-08)
- **Primary reference: NIST SP 800-88 Rev 1 §2.4.** Update all references in `secure_delete.rs`, doc comments, and CLAUDE.md.
- **Historical note:** Keep DoD 5220.22-M as a historical reference only ("Originally inspired by DoD 5220.22-M, which DoD retired in 2006. See NIST SP 800-88 Rev 1 §2.4 for current media sanitization guidance.").
- **No functional change.** The three-pass overwrite implementation stays the same — only the citations change.

### Claude's Discretion
- Exact error messages for ACR rejection
- Whether effective_issuers() has any callers (determines wire vs remove)
- Test organization and naming
- Order of operations within plans

</decisions>

<specifics>
## Specific Ideas

- User's guiding principle carried from Phase 25: **security first, most flexible within those parameters, maximum visibility through logs and events**
- Dead code removal is the security-first choice — untested code in a PAM module is a liability
- ACR enforcement is a hard fail because operators who configure it explicitly need it enforced
- Per-issuer JWKS config follows the established pattern from Phase 21/25 (IssuerConfig fields)

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `IssuerConfig` struct (config.rs:275-317): Add `jwks_cache_ttl_secs`, `http_timeout_secs` fields here
- `ValidationConfig.required_acr` (validation.rs:154): Already supports ACR checking — just needs wiring from IssuerConfig
- `JWKS_REGISTRY.get_or_init()` (jwks.rs): Already accepts TTL and timeout params — just hardcoded at call sites
- `AcrMappingConfig` (config.rs:234-237): Already defined but never read in auth path

### Established Patterns
- Per-issuer config fields with defaults (Phase 21/25): `allowed_algorithms`, `dpop_enforcement`, etc.
- Hardcoded constants in auth.rs:163-164: `JWKS_CACHE_TTL_SECS = 300`, `HTTP_TIMEOUT_SECS = 10`
- `effective_issuers()` at config.rs:1030 — backward-compat shim synthesizing IssuerConfig from OIDC_ISSUER

### Integration Points
- auth.rs:140 `required_acr: None` — wire from `issuer_config.acr_mapping`
- auth.rs:156 `JWKS_REGISTRY.get_or_init()` — pass per-issuer TTL/timeout instead of constants
- secure_delete.rs doc comments — update DoD citation to NIST SP 800-88
- test/scripts/ Entra ROPC script — add diagnostic error parsing

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 26-tech-debt-resolution*
*Context gathered: 2026-03-15*
