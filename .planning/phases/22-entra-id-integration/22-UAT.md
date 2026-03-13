---
status: complete
phase: 22-entra-id-integration
source: [22-01-SUMMARY.md, 22-02-SUMMARY.md, 22-03-SUMMARY.md]
started: 2026-03-13T21:30:00Z
updated: 2026-03-13T21:45:00Z
---

## Current Test

[testing complete]

## Tests

### 1. Config Fields Deserialize Correctly
expected: `cargo test -p pam-unix-oidc -- entr` runs all ENTR-01 tests (expected_audience, allow_unsafe_identity_pipeline deserialization, defaults, bypass behavior). All pass.
result: pass

### 2. Entra Policy Fixture Loads
expected: `test/fixtures/policy/policy-entra.yaml` parses as valid YAML and contains correct Entra defaults: `dpop: disabled`, `jti_enforcement: warn`, transforms include `strip_domain` and `lowercase`, issuer URL uses `login.microsoftonline.com/{tenant}/v2.0` pattern.
result: pass

### 3. Integration Tests Compile and List
expected: `cargo test -p pam-unix-oidc --test entra_integration -- --list` shows 9 tests, all with `#[ignore]` status. No compilation errors.
result: pass

### 4. ROPC Token Script Structure
expected: `test/scripts/get-entra-token.sh` is executable, passes `bash -n` syntax check, requires ENTRA_TENANT_ID/ENTRA_CLIENT_ID/ENTRA_TEST_USER/ENTRA_TEST_PASSWORD env vars, uses scopes `openid profile email` (no User.Read), and outputs only the access_token to stdout.
result: pass

### 5. CI Workflow Valid
expected: `.github/workflows/provider-tests.yml` contains an `entra:` job that checks for `ENTRA_TENANT_ID` secret, builds only `-p pam-unix-oidc`, masks the token with `::add-mask::`, and runs tests with `--ignored`. `provider-summary` lists entra in `needs`.
result: pass

### 6. Full Test Suite Regression
expected: `cargo test --workspace` passes with no new failures. The 5 new ENTR-01 tests in `multi_idp_integration.rs` pass. Total test count increased from baseline.
result: pass

### 7. Entra Setup Guide Quality
expected: `docs/entra-setup-guide.md` covers: App Registration steps, API permissions (User.Read exclusion rationale), ROPC grant enablement, token claim verification commands, known limitations (uti vs jti, ROPC deprecation), troubleshooting section.
result: pass

### 8. Live Entra Token Validation
expected: With valid ENTRA_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_TOKEN env vars set, `cargo test -p pam-unix-oidc --test entra_integration -- --include-ignored` passes all 9 tests (RS256 discovery, token validation, UPN mapping, bearer-only auth, adversarial rejection).
result: pass

## Summary

total: 8
passed: 8
issues: 0
pending: 0
skipped: 0

## Gaps

[none]
