---
phase: 21-multi-idp-configuration
plan: "03"
subsystem: pam-unix-oidc/tests
tags: [multi-idp, integration-test, midp, tdd, test-mode]
dependency_graph:
  requires:
    - phase: 21-01
      provides: IssuerConfig, AcrMappingConfig, GroupMappingConfig, GroupSource, IssuerJwksRegistry, PolicyConfig.effective_issuers(), PolicyConfig.issuer_by_url()
    - phase: 21-02
      provides: authenticate_multi_issuer(), extract_iss_for_routing(), AuthError::UnknownIssuer, DPoPAuthConfig
  provides:
    - pam-unix-oidc/tests/multi_idp_integration.rs (26 integration tests, all MIDP-01..08)
  affects:
    - phase-22-entra (consumes multi-idp routing for Entra-specific issuer config)
tech_stack:
  added: []
  patterns:
    - Integration tests gated on #![cfg(feature = "test-mode")] — no production impact
    - ENV_MUTEX serialization for tests manipulating UNIX_OIDC_TEST_MODE (same as Plans 01/02)
    - GroupMappingConfig::default() vs serde deserialization distinction documented in test comments
key_files:
  created:
    - pam-unix-oidc/tests/multi_idp_integration.rs
  modified: []
key_decisions:
  - "GroupMappingConfig::default_claim() is serde-only; Rust Default yields empty string. Test verified serde path separately."
  - "Integration tests are purely code-level (no live SSSD, no network). Terminal error is UserNotFound for auth path tests."
  - "strip_domain + preferred_username is non-injective; collision-safety hard-fail fires before SSSD — verified as Config error."
requirements-completed:
  - MIDP-01
  - MIDP-02
  - MIDP-03
  - MIDP-04
  - MIDP-05
  - MIDP-06
  - MIDP-07
  - MIDP-08
duration: 3min
completed: "2026-03-13"
---

# Phase 21 Plan 03: Multi-IdP Integration Tests Summary

**26 integration tests verifying all 8 MIDP requirements end-to-end, including JTI cross-issuer non-collision, per-issuer DPoP enforcement, ACR/group mapping config, and adversarial issuer rejection.**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-13T19:22:13Z
- **Completed:** 2026-03-13T19:25:xx Z
- **Tasks:** 2
- **Files modified:** 1

## Accomplishments

- Created `pam-unix-oidc/tests/multi_idp_integration.rs` with 26 integration tests covering all 8 MIDP requirements
- All tests pass under `--features test-mode` with zero network calls (no live SSSD/IdP)
- Full workspace test suite green; clippy clean with `-D warnings`; rustfmt clean

## Task Commits

1. **Task 1: Multi-IdP integration test suite (26 tests, all MIDP-01..08)** - `6a56c81` (test)
2. **Task 2: Apply rustfmt; verify workspace green** - `471fce7` (chore)

## Files Created/Modified

- `pam-unix-oidc/tests/multi_idp_integration.rs` — 26 integration tests for multi-issuer auth path

## Test Coverage by MIDP Requirement

| Requirement | Tests | Approach |
|-------------|-------|----------|
| MIDP-01 | test_two_issuer_policy_loads_from_yaml, test_two_issuer_policy_dpop_enforcement_from_yaml, test_effective_issuers_returns_configured | Load from YAML fixture; check issuer count and URLs |
| MIDP-02 | test_dpop_strict_rejects_bearer_only, test_dpop_disabled_accepts_bearer | Call authenticate_multi_issuer() without DPoP proof; verify DPoPRequired vs UserNotFound |
| MIDP-03 | test_acr_mapping_deserialises_and_translates, test_acr_mapping_lookup_translates_keycloak_loa2, test_acr_mapping_unknown_value_returns_none | AcrMappingConfig deserialization + lookup |
| MIDP-04 | test_group_mapping_defaults_to_nss_only, test_group_mapping_token_claim_mode, test_issuer_without_group_mapping_has_none, test_group_mapping_from_yaml_fixture | GroupMappingConfig construction + YAML load |
| MIDP-05 | test_strip_domain_issuer_a_collision_safety_fires, test_no_transforms_issuer_b_preserves_raw_claim, test_entra_issuer_has_strip_domain_on_email_in_fixture | Collision safety + per-issuer pipeline |
| MIDP-06 | test_known_issuer_routes_correctly, test_unknown_issuer_rejected, test_issuer_routing_normalizes_trailing_slash | Routing to known/unknown issuers |
| MIDP-07 | test_jwks_registry_independent_per_issuer, test_jwks_registry_same_issuer_returns_same_arc, test_jti_same_value_different_issuers_no_collision, test_jti_same_value_same_issuer_is_replay | Arc::ptr_eq for JWKS; scoped JTI cache |
| MIDP-08 | test_issuer_without_optional_fields_loads_with_safe_defaults, test_issuer_missing_optional_fields_no_parse_error | Minimal IssuerConfig deserialises without error |
| Adversarial | test_duplicate_issuer_urls_rejected_at_load, test_forged_iss_from_unconfigured_issuer_is_rejected | Duplicate URLs; forged iss |

## Decisions Made

- **GroupMappingConfig serde default vs Rust Default:** `#[serde(default = "GroupMappingConfig::default_claim")]` only fires during YAML/figment deserialization. Rust's `Default::default()` yields empty string for the claim field. The test for MIDP-04 verifies the serde path explicitly (round-trip through figment). This distinction is documented in the test comment.

- **Terminal error for auth path tests:** All tests that call `authenticate_multi_issuer()` end at `UserNotFound` (no SSSD in the test environment) or at an earlier error (DPoPRequired, Config, UnknownIssuer). Tests assert the correct terminal error, not success.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] GroupMappingConfig::default() yields empty claim string, not "groups"**
- **Found during:** Task 1 (test_group_mapping_defaults_to_nss_only)
- **Issue:** Test asserted `cfg.claim == "groups"` but Rust's `Default` derive uses `String::default()` (empty). The `"groups"` default only applies through `#[serde(default = ...)]`.
- **Fix:** Updated test to verify serde path (round-trip through figment YAML parse) with explanatory comment about the Rust Default vs serde default distinction.
- **Files modified:** pam-unix-oidc/tests/multi_idp_integration.rs
- **Verification:** Test passes; behavior documented in comment for future maintainers.
- **Committed in:** `6a56c81` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — test assertion corrected to match actual implementation)
**Impact on plan:** Minor test assertion adjustment. No implementation changes. Plan intent fully delivered.

## Issues Encountered

None.

## Next Phase Readiness

- All 8 MIDP requirements have integration-level verification
- Phase 22 (Entra ID) can rely on the multi-issuer routing and per-issuer DPoP/claim config tested here
- JTI cross-issuer non-collision is verified and ready for multi-IdP production deployment

---
*Phase: 21-multi-idp-configuration*
*Completed: 2026-03-13*
