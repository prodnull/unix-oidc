---
phase: 21-multi-idp-configuration
plan: "01"
subsystem: pam-unix-oidc/policy + oidc/jwks
tags: [multi-idp, config, jwks, registry, midp]
dependency_graph:
  requires: []
  provides:
    - IssuerConfig (pam-unix-oidc/src/policy/config.rs)
    - AcrMappingConfig (pam-unix-oidc/src/policy/config.rs)
    - GroupMappingConfig (pam-unix-oidc/src/policy/config.rs)
    - GroupSource (pam-unix-oidc/src/policy/config.rs)
    - PolicyConfig.issuers (pam-unix-oidc/src/policy/config.rs)
    - PolicyConfig.effective_issuers() (pam-unix-oidc/src/policy/config.rs)
    - PolicyConfig.issuer_by_url() (pam-unix-oidc/src/policy/config.rs)
    - IssuerJwksRegistry (pam-unix-oidc/src/oidc/jwks.rs)
  affects:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/oidc/jwks.rs
tech_stack:
  added: []
  patterns:
    - Read-first RwLock pattern for registry hot path
    - serde default + #[serde(default)] for backward-compat optional fields
    - ENV_MUTEX pattern for serializing env-var test isolation
key_files:
  created:
    - test/fixtures/policy/policy-multi-idp.yaml
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/oidc/jwks.rs
decisions:
  - ENV_MUTEX (std::sync::Mutex) used to serialize OIDC_ISSUER env-var tests
    rather than adding serial_test dev-dependency
  - IssuerJwksRegistry is not global; Plan 02 will own it in the auth routing struct
  - effective_issuers() synthesizes from OIDC_ISSUER (not UNIX_OIDC_ISSUER) for legacy compat
  - dpop_enforcement defaults to Strict in IssuerConfig (most secure default)
metrics:
  duration_minutes: 6
  completed_date: "2026-03-13"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 3
requirements:
  - MIDP-01
  - MIDP-02
  - MIDP-03
  - MIDP-04
  - MIDP-05
  - MIDP-08
---

# Phase 21 Plan 01: Multi-IdP Configuration Types and JWKS Registry Summary

**One-liner:** Per-issuer config bundles (IssuerConfig + AcrMappingConfig + GroupMappingConfig) with backward-compat effective_issuers() and an independent-per-issuer IssuerJwksRegistry.

## What Was Built

### Task 1: IssuerConfig types, PolicyConfig.issuers, effective_issuers(), issuer_by_url()

Added the full per-issuer configuration type hierarchy to `pam-unix-oidc/src/policy/config.rs`:

- **`AcrMappingConfig`** — maps IdP-specific ACR values to normalized values with enforcement mode (MIDP-03)
- **`GroupSource`** — enum for NSS-only vs token-claim group resolution (MIDP-04)
- **`GroupMappingConfig`** — per-issuer group membership mapping config (MIDP-04)
- **`IssuerConfig`** — per-issuer bundle: issuer_url, client_id, client_secret, dpop_enforcement, claim_mapping, acr_mapping, group_mapping (MIDP-01, MIDP-02, MIDP-05)

Added to `PolicyConfig`:
- **`issuers: Vec<IssuerConfig>`** with `#[serde(default)]` for zero-behavior-change backward compat
- **`effective_issuers()`** — returns issuers[] if non-empty; synthesizes from OIDC_ISSUER env var (legacy path) with WARN log; errors if neither is configured
- **`issuer_by_url()`** — trailing-slash-normalized lookup in issuers[]

Validation in `load_from()`:
- Duplicate `issuer_url` hard-fails with `PolicyError::ConfigError` (normalized comparison)
- MIDP-08 WARN logging for each issuer missing acr_mapping or group_mapping

Reference fixture: `test/fixtures/policy/policy-multi-idp.yaml` — two issuers (Keycloak strict DPoP, Entra-like disabled DPoP with strip_domain transform).

### Task 2: IssuerJwksRegistry for per-issuer independent JWKS caching

Added `IssuerJwksRegistry` to `pam-unix-oidc/src/oidc/jwks.rs`:

- `RwLock<HashMap<String, Arc<JwksProvider>>>` — read-first hot path, write only on first registration
- `get_or_init(issuer, ttl_secs, timeout_secs)` — normalizes trailing slash, returns same Arc on repeat calls (idempotent), creates independent JwksProvider per issuer
- `Default` impl delegates to `new()`
- MIDP-07 invariant: cache for issuer A is fully isolated from issuer B

## Tests Added

| Test | File | Purpose |
|------|------|---------|
| test_multi_issuer_two_entries_load | config.rs | Two issuers[] deserialize to len==2 |
| test_effective_issuers_returns_configured | config.rs | effective_issuers() with non-empty issuers[] |
| test_legacy_oidc_issuer_env_var_synthesized | config.rs | Legacy OIDC_ISSUER env var synthesis |
| test_duplicate_issuer_urls_rejected | config.rs | Duplicate URL hard-fails load_from() |
| test_issuer_by_url_normalization | config.rs | Trailing-slash normalization in issuer_by_url() |
| test_issuer_optional_fields_defaults | config.rs | All optional fields have safe defaults |
| test_empty_issuers_no_env_var_errors | config.rs | Empty issuers + no env var = Err |
| test_jwks_registry_new_is_empty | jwks.rs | IssuerJwksRegistry::new() |
| test_jwks_registry_different_issuers_return_different_providers | jwks.rs | MIDP-07 independence |
| test_jwks_registry_same_issuer_returns_same_provider | jwks.rs | Idempotent get_or_init() |

## Deviations from Plan

### Auto-fixed Issues

None.

### Implementation Notes

**ENV_MUTEX over serial_test:** The `test_legacy_oidc_issuer_env_var_synthesized` and `test_empty_issuers_no_env_var_errors` tests both manipulate the `OIDC_ISSUER` env var. Rather than adding `serial_test` as a new dev-dependency, a module-level `static ENV_MUTEX: Mutex<()>` was used to serialize these two tests. This is consistent with the project's minimal-dependency philosophy.

**MIDP-08 WARN logging position:** The WARN logs for missing acr_mapping and group_mapping are emitted in `load_from()` rather than in `effective_issuers()`. This is correct — the warnings fire at config load time (startup), not at every auth decision. Tests that exercise `effective_issuers()` via figment extract don't trigger these warnings (they go through `from_env()` which uses figment directly, not `load_from()`). The duplicate-detection test uses `load_from()` and exercises the full validation path.

## Success Criteria Verification

- [x] PolicyConfig loads a multi-issuer YAML fixture with two issuers without error
- [x] Legacy single-issuer env var path still works via effective_issuers()
- [x] Duplicate issuer URLs are rejected at load time
- [x] Missing optional fields fall back to safe defaults with WARN logging
- [x] IssuerJwksRegistry provides independent JwksProvider per issuer
- [x] All existing tests continue to pass (351 unit tests + 5 integration tests)

## Self-Check

All files verified, commits confirmed below.
