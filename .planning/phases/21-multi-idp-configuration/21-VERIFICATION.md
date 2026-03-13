---
phase: 21-multi-idp-configuration
verified: 2026-03-13T19:40:00Z
status: passed
score: 14/14 must-haves verified
re_verification: false
---

# Phase 21: Multi-IdP Configuration Verification Report

**Phase Goal:** Enable PAM module to authenticate against multiple OIDC identity providers simultaneously with per-issuer DPoP enforcement, audience validation, and claim mapping.
**Verified:** 2026-03-13T19:40:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

All truths drawn directly from plan `must_haves` frontmatter across Plans 01, 02, and 03.

#### Plan 01 Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A policy.yaml with two issuers[] entries loads without error | VERIFIED | `test_two_issuer_policy_loads_from_yaml` passes; `PolicyConfig::load_from()` on `test/fixtures/policy/policy-multi-idp.yaml` succeeds with `issuers.len() == 2` |
| 2 | Legacy OIDC_ISSUER env var synthesizes a single-element issuers[] array | VERIFIED | `test_legacy_oidc_issuer_env_var_synthesized` passes; `effective_issuers()` returns single-element Vec when `OIDC_ISSUER` is set and `issuers[]` is empty |
| 3 | Duplicate issuer_url values hard-fail at load time | VERIFIED | `test_duplicate_issuer_urls_rejected_at_load` passes; `load_from()` returns `Err(PolicyError::ConfigError(...))` on duplicates |
| 4 | Missing optional per-issuer fields fall back to defaults with WARN | VERIFIED | `test_issuer_optional_fields_defaults` passes; `test_issuer_without_optional_fields_loads_with_safe_defaults` passes; `dpop_enforcement` defaults to `Strict` |
| 5 | IssuerJwksRegistry returns independent JwksProvider instances per issuer URL | VERIFIED | `test_jwks_registry_different_issuers_return_different_providers` passes; `!Arc::ptr_eq` confirmed |

#### Plan 02 Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 6 | A token from a configured issuer authenticates successfully through multi-issuer dispatch | VERIFIED | `test_known_issuer_routes_correctly` passes; `authenticate_multi_issuer()` dispatches to per-issuer config |
| 7 | A token from an unknown issuer is rejected with an UnknownIssuer error | VERIFIED | `test_unknown_issuer_rejected` passes; `AuthError::UnknownIssuer` returned and mapped to `PAM_AUTH_ERR` in lib.rs |
| 8 | DPoP enforcement is applied per-issuer (strict on one, disabled on another) | VERIFIED | `test_dpop_strict_rejects_bearer_only` and `test_dpop_disabled_accepts_bearer` both pass |
| 9 | JWKS cache entries are independent per issuer | VERIFIED | `test_jwks_registry_independent_per_issuer` passes via `Arc::ptr_eq` check |
| 10 | JTI cache keys are scoped per issuer (same JTI from different issuers does not collide) | VERIFIED | `test_jti_same_value_different_issuers_no_collision` passes; `test_jti_same_value_same_issuer_is_replay` passes; scoped key format `"{iss}:{jti}"` confirmed in `auth.rs` line 188 |
| 11 | Per-issuer claim mapping produces correct usernames | VERIFIED | `test_strip_domain_issuer_a_collision_safety_fires` and `test_no_transforms_issuer_b_preserves_raw_claim` confirm per-issuer claim pipeline |

#### Plan 03 Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 12 | Two-issuer policy loads and both issuers authenticate successfully | VERIFIED | `test_two_issuer_policy_loads_from_yaml` and `test_two_issuer_policy_dpop_enforcement_from_yaml` pass |
| 13 | Unknown issuer rejected with clear error | VERIFIED | `test_forged_iss_from_unconfigured_issuer_is_rejected` passes |
| 14 | All 8 MIDP requirements covered by integration tests | VERIFIED | 26 tests in `multi_idp_integration.rs`; all 26 pass |

**Score:** 14/14 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/policy/config.rs` | IssuerConfig, AcrMappingConfig, GroupMappingConfig, GroupSource structs; effective_issuers(); issuer_by_url(); duplicate detection | VERIFIED | All types present; methods at lines 924 and 958; duplicate check in load_from(); WARN logging for missing optional fields |
| `pam-unix-oidc/src/oidc/jwks.rs` | IssuerJwksRegistry with HashMap<String, Arc<JwksProvider>> and get_or_init() | VERIFIED | `IssuerJwksRegistry` at line 310; `get_or_init()` at line 329; read-first RwLock pattern; `Default` impl at line 356 |
| `test/fixtures/policy/policy-multi-idp.yaml` | Reference two-issuer policy fixture | VERIFIED | Present; two issuers (Keycloak strict DPoP, Entra-like disabled DPoP); ACR mapping and group mapping defined |
| `pam-unix-oidc/src/auth.rs` | extract_iss_for_routing(), authenticate_multi_issuer(), UnknownIssuer variant, apply_per_issuer_dpop() | VERIFIED | All four present; JTI scoped keys at line 188; per-issuer DPoP dispatch at line 161 |
| `pam-unix-oidc/src/lib.rs` | JWKS_REGISTRY static; multi-issuer dispatch branching; UnknownIssuer PAM error mapping | VERIFIED | `JWKS_REGISTRY` static at line 65; branching at line 218; `UnknownIssuer` → `PAM_AUTH_ERR` at line 471 |
| `pam-unix-oidc/tests/multi_idp_integration.rs` | Integration tests for all MIDP-01..08 | VERIFIED | 739 lines; 26 tests; all passing |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `pam-unix-oidc/src/policy/config.rs` | `IssuerConfig` | `PolicyConfig.issuers: Vec<IssuerConfig>` | WIRED | `pub issuers: Vec<IssuerConfig>` with `#[serde(default)]` at line 784 |
| `pam-unix-oidc/src/oidc/jwks.rs` | `JwksProvider` | `IssuerJwksRegistry.get_or_init()` returns `Arc<JwksProvider>` | WIRED | `get_or_init()` returns `Arc<JwksProvider>`; confirmed at line 329 |
| `pam-unix-oidc/src/auth.rs` | `pam-unix-oidc/src/policy/config.rs` | `authenticate_multi_issuer` reads `PolicyConfig.issuer_by_url()` | WIRED | `policy.issuer_by_url(&iss)` at auth.rs line 113 |
| `pam-unix-oidc/src/auth.rs` | `pam-unix-oidc/src/oidc/jwks.rs` | `authenticate_multi_issuer` uses `IssuerJwksRegistry.get_or_init()` | WIRED | `jwks_registry.get_or_init(...)` at auth.rs line 137 |
| `pam-unix-oidc/src/lib.rs` | `pam-unix-oidc/src/auth.rs` | PAM entry point calls `authenticate_multi_issuer` | WIRED | Import at lib.rs line 46; call at line 233 with `&JWKS_REGISTRY` |
| `pam-unix-oidc/src/auth.rs` | `pam-unix-oidc/src/security/jti_cache.rs` | JTI check passes issuer-scoped key | WIRED | `format!("{}:{}", iss, jti)` at auth.rs line 188; passed to `global_jti_cache().check_and_record()` at line 201 |
| `pam-unix-oidc/tests/multi_idp_integration.rs` | `pam-unix-oidc/src/auth.rs` | calls `authenticate_multi_issuer()` | WIRED | `authenticate_multi_issuer` called in 5+ test functions |
| `pam-unix-oidc/tests/multi_idp_integration.rs` | `pam-unix-oidc/src/policy/config.rs` | loads multi-issuer PolicyConfig from fixture YAML | WIRED | `PolicyConfig::load_from(fixture_path)` in `test_two_issuer_policy_loads_from_yaml` and others |

---

## Requirements Coverage

| Requirement | Source Plan(s) | Description | Status | Evidence |
|-------------|---------------|-------------|--------|----------|
| MIDP-01 | 01, 03 | `issuers[]` array in policy.yaml with per-issuer config blocks | SATISFIED | `IssuerConfig` struct; `PolicyConfig.issuers`; YAML fixture; integration tests pass |
| MIDP-02 | 01, 03 | Per-issuer DPoP enforcement mode (strict/warn/disabled) | SATISFIED | `IssuerConfig.dpop_enforcement`; `apply_per_issuer_dpop()` in auth.rs; `test_dpop_strict_rejects_bearer_only` and `test_dpop_disabled_accepts_bearer` pass |
| MIDP-03 | 01, 03 | Per-issuer claim mapping rules (username extraction, strip-domain, regex) | SATISFIED | `IssuerConfig.claim_mapping: IdentityConfig`; `UsernameMapper::from_config()` called per issuer; `test_no_transforms_issuer_b_preserves_raw_claim` and strip_domain tests pass |
| MIDP-04 | 01, 03 | Per-issuer ACR value mapping | SATISFIED | `AcrMappingConfig` struct; `IssuerConfig.acr_mapping`; `test_acr_mapping_lookup_translates_keycloak_loa2` passes |
| MIDP-05 | 01, 03 | Per-issuer group mapping (token claim path vs NSS-only, group name translation) | SATISFIED | `GroupMappingConfig` struct; `GroupSource` enum; `test_group_mapping_defaults_to_nss_only` and `test_group_mapping_token_claim_mode` pass |
| MIDP-06 | 02, 03 | PAM module matches incoming token `iss` to configured issuer; rejects unknown issuers | SATISFIED | `extract_iss_for_routing()` + `issuer_by_url()` dispatch; `AuthError::UnknownIssuer`; 3 routing tests pass |
| MIDP-07 | 01, 02, 03 | JWKS cache keyed by issuer URL (multi-issuer concurrent caching); JTI scoped per issuer | SATISFIED | `IssuerJwksRegistry` with `Arc::ptr_eq` independence; `"{iss}:{jti}"` scoping; 4 JWKS/JTI tests pass |
| MIDP-08 | 01, 03 | Graceful degradation: missing optional per-issuer fields fall back to safe defaults with WARN logging | SATISFIED | `#[serde(default)]` on IssuerConfig; WARN log in `load_from()` for missing acr_mapping/group_mapping; `test_issuer_without_optional_fields_loads_with_safe_defaults` passes |

No orphaned requirements. All 8 MIDP IDs claimed in plans appear in REQUIREMENTS.md mapped to Phase 21. MIDP-09, MIDP-10, and MIDP-11 are listed as future phases (not Phase 21) and are not expected here.

---

## Anti-Patterns Found

No blockers or warnings detected.

Scanned files: `pam-unix-oidc/src/policy/config.rs`, `pam-unix-oidc/src/oidc/jwks.rs`, `pam-unix-oidc/src/auth.rs`, `pam-unix-oidc/src/lib.rs`, `pam-unix-oidc/tests/multi_idp_integration.rs`

| Pattern | Result |
|---------|--------|
| TODO/FIXME/PLACEHOLDER | None found in phase-modified files |
| Empty implementations (`return null`, `return {}`) | None |
| Stub handlers | None — all functions have substantive implementations |
| Clippy warnings | Zero — `cargo clippy -p pam-unix-oidc --features test-mode -- -D warnings` clean |
| Format violations | Zero — `cargo fmt --all -- --check` clean |

One notable design note (not a blocker): JWKS TTL (300s) and HTTP timeout (10s) are hardcoded constants in `authenticate_multi_issuer()` with a comment marking future per-issuer config as a follow-on. The values are operationally reasonable and the design note is explicit.

---

## Human Verification Required

None. All behaviors are exercisable via test-mode unit and integration tests without network, SSSD, or live IdP. The implementation is fully self-contained under the `test-mode` feature flag.

---

## Test Results Summary

| Suite | Tests | Passed | Failed |
|-------|-------|--------|--------|
| `pam-unix-oidc` unit tests (--features test-mode) | 364 | 364 | 0 |
| `break_glass_integration` | 5 | 5 | 0 |
| `multi_idp_integration` | 26 | 26 | 0 |
| doc-tests | 4 | 2 (2 ignored) | 0 |
| **Total** | **399** | **397** | **0** |

---

## Summary

Phase 21 goal is fully achieved. The PAM module can now authenticate against multiple OIDC identity providers simultaneously. Every MIDP requirement is implemented, tested, and passing:

- Per-issuer config bundles (`IssuerConfig`, `AcrMappingConfig`, `GroupMappingConfig`, `GroupSource`) are defined and load from YAML
- Legacy single-issuer deployments are unaffected (backward-compatible via `effective_issuers()`)
- Duplicate issuer URLs are hard-rejected at config load time
- Per-issuer DPoP enforcement (Strict/Warn/Disabled) is applied in the auth dispatch
- Per-issuer claim mapping runs `UsernameMapper` per `IssuerConfig.claim_mapping`
- `IssuerJwksRegistry` provides independent, isolated JWKS caches per issuer URL
- JTI replay cache keys are issuer-scoped (`"{iss}:{jti}"`) — no cross-issuer false positives
- All 26 integration tests cover the full MIDP-01..08 surface including adversarial cases

---

_Verified: 2026-03-13T19:40:00Z_
_Verifier: Claude (gsd-verifier)_
