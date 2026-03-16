---
phase: 26-tech-debt-resolution
verified: 2026-03-16T04:30:00Z
status: passed
score: 13/13 must-haves verified
re_verification: false
gaps: []
---

# Phase 26: Tech Debt Resolution — Verification Report

**Phase Goal:** All dead multi-IdP wiring paths are either connected to the production auth pipeline or removed; JWKS TTL and HTTP timeout are configurable per-issuer; the Entra CI diagnostic is improved; code citations are accurate.

**Verified:** 2026-03-16
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | An issuer with required_acr set rejects tokens whose acr claim does not match | VERIFIED | `required_acr: issuer_config.acr_mapping.as_ref().and_then(|m| m.required_acr.clone())` wired in auth.rs:143-146; test `test_group_source_token_claim_rejected` passes |
| 2  | An issuer with required_acr set rejects tokens with no acr claim at all | VERIFIED | Same wiring; ValidationConfig.required_acr plumbed into validation.rs which enforces hard-fail on missing acr |
| 3  | An issuer without acr_mapping configured continues to pass tokens without ACR enforcement | VERIFIED | `and_then(|m| m.required_acr.clone())` yields None when acr_mapping is None; backward compat preserved |
| 4  | Setting jwks_cache_ttl_secs and http_timeout_secs on an issuer uses those values instead of hardcoded 300s/10s | VERIFIED | auth.rs:178-179 passes `issuer_config.jwks_cache_ttl_secs` and `issuer_config.http_timeout_secs` to `jwks_registry.get_or_init()`; no remaining hardcoded JWKS constants in auth.rs |
| 5  | Omitting jwks_cache_ttl_secs and http_timeout_secs defaults to 300s and 10s respectively | VERIFIED | config.rs Default impl sets both via `default_jwks_cache_ttl()` and `default_http_timeout()` serde functions; confirmed via test |
| 6  | GroupSource::TokenClaim variant no longer exists in the codebase | VERIFIED | grep of pam-unix-oidc/src/ returns only doc comments noting its removal; enum has single NssOnly variant |
| 7  | effective_issuers() method no longer exists in the codebase | VERIFIED | grep of pam-unix-oidc/src/ shows no method definition; doc comments at config.rs:2085 note removal |
| 8  | All code paths that referenced TokenClaim or effective_issuers are removed or updated | VERIFIED | Tests removed; integration test file has no remaining references; doc comments updated |
| 9  | cargo build and cargo test pass without referencing removed code | VERIFIED | 373+5+1+2 tests pass (381 total across all test suites), 0 failures, clippy clean with -D warnings |
| 10 | GroupSource::NssOnly still deserializes correctly after TokenClaim removal | VERIFIED | test_group_source_nss_only_serde_round_trip passes; test_group_mapping_nss_only_deserializes passes |
| 11 | Entra ROPC script logs diagnostic when Conditional Access blocks ROPC (AADSTS50076, AADSTS53003, interaction_required) | VERIFIED | check_conditional_access_error() function present; 13/13 mock test assertions pass |
| 12 | secure_delete.rs cites NIST SP 800-88 Rev 1 as primary reference | VERIFIED | Module doc lines 22-27: "NIST SP 800-88 Rev 1 (primary)"; DoD 5220.22-M is historical note only |
| 13 | CLAUDE.md citations updated to match source code | VERIFIED | MEM-05 entry now reads "three-pass overwrite per NIST SP 800-88 Rev 1 SS2.4"; DoD appears only as "Originally inspired by..." historical note |

**Score:** 13/13 truths verified

---

## Required Artifacts

### Plan 26-01 (DEBT-02, DEBT-05)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/auth.rs` | ACR enforcement wired from IssuerConfig + per-issuer JWKS TTL/timeout | VERIFIED | Lines 140-179: `required_acr` reads from `issuer_config.acr_mapping.required_acr`; JWKS registry call uses `issuer_config.jwks_cache_ttl_secs` / `issuer_config.http_timeout_secs` |
| `pam-unix-oidc/src/policy/config.rs` | `jwks_cache_ttl_secs` and `http_timeout_secs` fields on IssuerConfig; `required_acr` on AcrMappingConfig | VERIFIED | Fields present with `#[serde(default)]` and Default impl; `required_acr: Option<String>` on AcrMappingConfig |

### Plan 26-02 (DEBT-03, DEBT-04)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/policy/config.rs` | GroupSource enum with only NssOnly variant; no effective_issuers() method | VERIFIED | Enum has single NssOnly variant; effective_issuers not present in src; 4 regression tests added |
| `pam-unix-oidc/tests/multi_idp_integration.rs` | Tests updated to remove TokenClaim and effective_issuers references | VERIFIED | grep returns zero matches for these identifiers in tests/ |

### Plan 26-03 (DEBT-06, DEBT-08)

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `test/scripts/get-entra-token.sh` | Conditional Access diagnostic in ROPC error path; contains "AADSTS50076" | VERIFIED | check_conditional_access_error() function at lines 36-62; CA pattern includes AADSTS50076, AADSTS53003, AADSTS50079, interaction_required |
| `test/scripts/test-entra-diagnostic.sh` | Mock-based bash unit tests for diagnostic trigger; contains "interaction_required" | VERIFIED | 6 test cases, 13 assertions; all pass |
| `unix-oidc-agent/src/storage/secure_delete.rs` | NIST SP 800-88 Rev 1 as primary citation | VERIFIED | Lines 22-27: NIST is "primary"; DoD appears only in historical note at line 26 |
| `CLAUDE.md` | Updated citation from DoD to NIST SP 800-88 Rev 1 | VERIFIED | MEM-05 heading updated; historical DoD note preserved |

---

## Key Link Verification

### Plan 26-01

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `pam-unix-oidc/src/auth.rs` | `IssuerConfig.acr_mapping.required_acr` | `issuer_config.acr_mapping.as_ref().and_then(|m| m.required_acr.clone())` | WIRED | auth.rs:143-146 — pattern `required_acr.*acr_mapping` confirmed |
| `pam-unix-oidc/src/auth.rs` | `IssuerConfig.jwks_cache_ttl_secs` / `http_timeout_secs` | `jwks_registry.get_or_init()` call at auth.rs:176-180 | WIRED | Per-issuer values passed; INFO log emitted for non-default values at auth.rs:168-175 |

### Plan 26-02

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `pam-unix-oidc/src/policy/config.rs` | `pam-unix-oidc/src/auth.rs` | No auth.rs code references GroupSource or effective_issuers | VERIFIED | grep confirms zero production references to removed identifiers; `issuer_by_url()` is sole lookup path |

### Plan 26-03

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `test/scripts/get-entra-token.sh` | Entra ROPC endpoint error response | `curl -s` + `check_conditional_access_error()` | WIRED | Pattern `AADSTS|interaction_required` present; script exits non-zero after diagnostic |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| DEBT-02 | 26-01 | ACR mapping enforcement wired in multi-issuer auth path | SATISFIED | auth.rs:143-146 wires `issuer_config.acr_mapping.required_acr` into `ValidationConfig.required_acr` |
| DEBT-03 | 26-02 | GroupSource::TokenClaim removed | SATISFIED | Enum shrunk to NssOnly; serde rejects "token_claim" variant |
| DEBT-04 | 26-02 | effective_issuers() removed | SATISFIED | Method absent from config.rs; issuer_by_url() is sole resolution path |
| DEBT-05 | 26-01 | JWKS TTL and HTTP timeout configurable per-issuer | SATISFIED | IssuerConfig fields with 300s/10s defaults; wired into jwks_registry.get_or_init() |
| DEBT-06 | 26-03 | Entra CI ROPC diagnostic for Conditional Access | SATISFIED | check_conditional_access_error() function; all 13 mock assertions pass |
| DEBT-08 | 26-03 | secure_delete.rs citation updated to NIST SP 800-88 Rev 1 | SATISFIED | Primary citation updated; DoD historical note preserved |

**Orphaned requirements check:** DEBT-07 maps to Phase 24 (not Phase 26). No orphaned requirements for this phase.

---

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None | — | — | — | No anti-patterns found in modified files |

No TODO/FIXME/placeholder comments in modified files. No empty implementations. No stub handlers. Clippy passes with `-D warnings`.

---

## Human Verification Required

None. All must-haves are verifiable programmatically:

- ACR enforcement: verified via test pass (19 relevant tests pass)
- Dead code removal: verified via grep + build
- JWKS wiring: verified via code inspection and test
- Entra diagnostic: verified via mock test execution (13/13 assertions pass)
- Citation update: verified via grep and file read

---

## Summary

Phase 26 achieves its goal completely. All six requirements are satisfied:

- **DEBT-02/05 (Plan 26-01):** The `required_acr: None` hardcoded stub in auth.rs is replaced with live reads from `issuer_config.acr_mapping.required_acr`. The hardcoded `JWKS_CACHE_TTL_SECS`/`JWKS_HTTP_TIMEOUT_SECS` constants are removed and replaced with per-issuer `IssuerConfig` fields with 300s/10s serde defaults. 9 new tests cover all positive and negative cases. All 381 tests pass across the test suite.

- **DEBT-03/04 (Plan 26-02):** `GroupSource::TokenClaim` variant is fully removed (enum has only `NssOnly`). `effective_issuers()` is removed; `issuer_by_url()` is the sole issuer resolution path. Serde correctly rejects "token_claim" as an invalid variant. 4 regression tests guard the NssOnly serde round-trip, issuer_by_url resolution, and token_claim rejection.

- **DEBT-06 (Plan 26-03):** `check_conditional_access_error()` function detects AADSTS50076/53003/50079 and `interaction_required` errors and emits an actionable diagnostic to stderr. The script still exits non-zero on failure. 6 mock test cases with 13 assertions all pass.

- **DEBT-08 (Plan 26-03):** NIST SP 800-88 Rev 1 §2.4 is the primary citation in `secure_delete.rs` and CLAUDE.md. DoD 5220.22-M appears only as a historical note. No functional code changes.

---

_Verified: 2026-03-16_
_Verifier: Claude (gsd-verifier)_
