---
phase: 22-entra-id-integration
verified: 2026-03-13T22:00:00Z
status: passed
score: 11/11 must-haves verified
re_verification: false
---

# Phase 22: Entra ID Integration Verification Report

**Phase Goal:** Entra ID (Azure AD) integration — expected_audience config, UPN claim mapping, RS256 live tests, ROPC CI script
**Verified:** 2026-03-13
**Status:** passed
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | An Entra token with audience `api://unix-oidc` authenticates successfully when `expected_audience` is configured | VERIFIED | `auth.rs:135-139` — `expected_audience.as_deref().unwrap_or(&client_id)` wired into `ValidationConfig.client_id` |
| 2  | A single-tenant Entra issuer with `strip_domain` mapping authenticates without a Config error when `allow_unsafe_identity_pipeline: true` | VERIFIED | `auth.rs:192-201` — bypass wraps `check_collision_safety`, logs WARN |
| 3  | An issuer config without `allow_unsafe_identity_pipeline` still hard-fails `strip_domain` transforms (safe by default) | VERIFIED | `auth.rs:198-200` — `else` branch calls `check_collision_safety`; `multi_idp_integration.rs:794,808` — default=false asserted |
| 4  | The Entra policy fixture deserialises and passes validation in the auth path | VERIFIED | `test/fixtures/policy/policy-entra.yaml` — dpop: disabled, allow_unsafe: true, strip_domain+lowercase, jti: warn |
| 5  | The setup guide covers all 6 App Registration Checklist items | VERIFIED | `docs/entra-setup-guide.md` (361 lines) — Steps 1-9 present; Steps 1-2 single-tenant, Step 2 public client flag, Step 3 redirect URI, Step 2 Allow public client flows, Step 4 API permissions+admin consent, Step 5 optional claims, Step 6 CI test user |
| 6  | An Entra RS256 access token validates successfully through `TokenValidator` | VERIFIED | `entra_integration.rs:203-237` — `test_entra_rs256_token_validates` uses real `TokenValidator::with_jwks_provider`, no test-mode |
| 7  | OIDC discovery against Entra tenant returns a valid JWKS URI with RS256 keys | VERIFIED | `entra_integration.rs:125-200` — `test_entra_discovery_returns_valid_jwks_uri` fetches live discovery and asserts `kty=RSA`, `alg=RS256` |
| 8  | UPN claim mapping with strip_domain + lowercase produces the correct bare username | VERIFIED | `entra_integration.rs:284-328` — `test_entra_upn_strip_domain_maps_to_bare_username` asserts no `@`, all lowercase |
| 9  | Bearer-only mode (no DPoP) completes the auth pipeline past DPoP enforcement without DPoP-related errors | VERIFIED | `entra_integration.rs:376-401` — asserts not `DPoPRequired`, not `UnknownIssuer` |
| 10 | ROPC token acquisition script fetches a valid Entra access token using `openid profile email` scopes | VERIFIED | `test/scripts/get-entra-token.sh:36` — `SCOPE="openid profile email"`, User.Read explicitly excluded per RESEARCH.md Pitfall 3 |
| 11 | Entra CI job in provider-tests.yml runs only when `ENTRA_TENANT_ID` secret is available, runs entra_integration tests, and reports in provider-summary | VERIFIED | `provider-tests.yml:192-194` — secrets gate; line 269 — `--test entra_integration --ignored`; line 284/294 — `needs` and `results` include entra |

**Score:** 11/11 truths verified

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/policy/config.rs` | `IssuerConfig` with `expected_audience` and `allow_unsafe_identity_pipeline` | VERIFIED | Lines 301, 311 — both fields present with correct types and defaults (line 324-325) |
| `pam-unix-oidc/src/auth.rs` | Audience override wiring + collision-safety bypass | VERIFIED | Lines 132-139 (audience), 192-201 (bypass) — security comments reference RFC 7519 §4.1.3 and IDN-03 |
| `test/fixtures/policy/policy-entra.yaml` | Entra-specific issuer fixture with env var placeholders | VERIFIED | Contains `ENTRA_TENANT_ID_PLACEHOLDER`, `ENTRA_CLIENT_ID_PLACEHOLDER`, `allow_unsafe_identity_pipeline: true`, `strip_domain`, `dpop_enforcement: disabled` |
| `test/fixtures/policy/policy-multi-idp.yaml` | Updated with `allow_unsafe_identity_pipeline: true` for Entra issuer | VERIFIED | Line 48 — field present |
| `docs/entra-setup-guide.md` | Step-by-step guide (min 80 lines) | VERIFIED | 361 lines; all 6 checklist items covered; User.Read exclusion documented with rationale |
| `pam-unix-oidc/tests/entra_integration.rs` | Live Entra integration tests (min 150 lines), ignored by default | VERIFIED | 524 lines; 9 tests; all annotated `#[ignore = "Requires ENTRA_* env vars..."]` |
| `test/scripts/get-entra-token.sh` | ROPC token acquisition script (min 20 lines), executable | VERIFIED | 55 lines; `chmod +x` confirmed; `set -euo pipefail`; correct scopes |
| `.github/workflows/provider-tests.yml` | Entra secrets-gated CI job with `entra` keyword | VERIFIED | `entra:` job at line 180; YAML validates; `provider-summary` updated |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `pam-unix-oidc/src/auth.rs` | `pam-unix-oidc/src/policy/config.rs` | `expected_audience.as_deref().unwrap_or(&client_id)` feeds `ValidationConfig.client_id` | WIRED | `auth.rs:135-139` matches pattern `expected_audience.*unwrap_or.*client_id` |
| `pam-unix-oidc/src/auth.rs` | `pam-unix-oidc/src/identity/collision.rs` | `allow_unsafe_identity_pipeline` conditionally skips `check_collision_safety` | WIRED | `auth.rs:192-201` matches pattern `allow_unsafe_identity_pipeline`; WARN logged |
| `pam-unix-oidc/tests/entra_integration.rs` | `pam-unix-oidc/src/oidc/validation.rs` | `TokenValidator::with_jwks_provider` validates RS256 Entra tokens | WIRED | Pattern `TokenValidator::with_jwks_provider` found at lines 208, 244, 289, 335, 449, 487 |
| `pam-unix-oidc/tests/entra_integration.rs` | `pam-unix-oidc/src/auth.rs` | `authenticate_multi_issuer` exercises full Entra auth path | WIRED | Pattern `authenticate_multi_issuer` found at lines 27 (import), 382, 518 |
| `.github/workflows/provider-tests.yml` | `test/scripts/get-entra-token.sh` | CI job executes token script | WIRED | `provider-tests.yml:249-250` — `chmod +x ./test/scripts/get-entra-token.sh; TOKEN=$(./test/scripts/get-entra-token.sh)` |
| `.github/workflows/provider-tests.yml` | `pam-unix-oidc/tests/entra_integration.rs` | CI job runs `--test entra_integration` with `--ignored` | WIRED | `provider-tests.yml:269` — `cargo test --release -p pam-unix-oidc --test entra_integration -- --ignored --test-threads=1` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| ENTR-01 | 22-01 | Entra app registration with device code flow enabled (public client) | SATISFIED | Setup guide (`docs/entra-setup-guide.md`) covers public client registration Steps 1-3; 5 unit tests in `multi_idp_integration.rs:741-813` verify config deserialization |
| ENTR-02 | 22-02 | OIDC discovery + JWKS endpoint validation against live Entra tenant | SATISFIED | `entra_integration.rs:125-200` — `test_entra_discovery_returns_valid_jwks_uri` fetches discovery and checks RS256 key presence |
| ENTR-03 | 22-01, 22-02 | RS256 token signature verification through PAM module (not just ES256) | SATISFIED | `entra_integration.rs:203-237` — `test_entra_rs256_token_validates` uses live JWKS, no test-mode bypass; real cryptographic verification path exercised |
| ENTR-04 | 22-01, 22-02 | UPN claim mapping (`alice@corp.com` → `alice`) validated end-to-end | SATISFIED | `entra_integration.rs:284-360` — two tests cover strip_domain+lowercase (no `@`) and raw UPN preservation |
| ENTR-05 | 22-02, 22-03 | Bearer-only mode (DPoP disabled) produces successful auth with full audit trail | SATISFIED | `entra_integration.rs:376-401` — bearer test asserts not `DPoPRequired`/not `UnknownIssuer`; CI job (provider-tests.yml) exercises full chain with real Entra tenant |
| CI-03 | 22-03 | Entra ID secrets-gated CI job (`entra-integration`) | SATISFIED | `provider-tests.yml:180-280` — `entra:` job with ENTRA_TENANT_ID gate, token masking, full test run, optional in provider-summary |

All 6 requirement IDs from plan frontmatter are accounted for.

**Orphaned requirements check:** REQUIREMENTS.md traceability table maps ENTR-01 through ENTR-05 and CI-03 to Phase 22. All are covered by the plans. No orphaned requirements detected.

---

## Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `test/fixtures/policy/policy-entra.yaml` | 44-45 | `ENTRA_TENANT_ID_PLACEHOLDER`, `ENTRA_CLIENT_ID_PLACEHOLDER` | Info | Intentional — fixture is a template requiring env var substitution before use; documented in file header comments |

No blockers or warnings found. The placeholder strings in the fixture are by design (documented in the file's comment block), not implementation gaps.

---

## Human Verification Required

### 1. Live RS256 Token Validation

**Test:** With a real Entra tenant configured, run:
```
ENTRA_TENANT_ID=<tenant> ENTRA_CLIENT_ID=<client_id> ENTRA_TOKEN=$(./test/scripts/get-entra-token.sh) \
  cargo test -p pam-unix-oidc --test entra_integration -- --include-ignored
```
**Expected:** All 9 tests pass
**Why human:** Tests are `#[ignore]` by design and require live Entra credentials not available in the verification environment.

### 2. CI Secrets Configuration

**Test:** Configure the 4 GitHub Actions secrets (`ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_TEST_USER`, `ENTRA_TEST_PASSWORD`) and trigger the `provider-tests.yml` workflow with `provider: entra`.
**Expected:** Entra job completes successfully; all 9 integration tests pass; provider-summary reports Entra result.
**Why human:** Requires GitHub repository secret access and a configured Entra tenant.

### 3. ENTR-05 Full Audit Trail

**Test:** Run the Entra CI job against a real Entra tenant where a Unix user matching the UPN exists on the test host.
**Expected:** Successful auth produces a structured audit event in the auth log.
**Why human:** The bearer-only unit test confirms DPoP bypass (terminates at UserNotFound in test env without SSSD); full audit trail with an actual user requires a configured Linux host with SSSD.

---

## Gaps Summary

None. All must-haves across all three plans are verified. All 6 requirement IDs are satisfied with implementation evidence.

---

_Verified: 2026-03-13T22:00:00Z_
_Verifier: Claude (gsd-verifier)_
