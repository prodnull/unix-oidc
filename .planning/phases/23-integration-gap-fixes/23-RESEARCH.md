# Phase 23: Integration Gap Fixes — Research

**Researched:** 2026-03-13
**Domain:** Rust / PAM authentication / DPoP nonce enforcement / YAML deserialization testing
**Confidence:** HIGH (all findings from direct source inspection)

## Summary

Phase 23 closes two cross-phase integration bugs identified by the v2.1 milestone audit. Both bugs are surgical — each requires touching a small, well-understood section of existing code and adding focused tests. Neither requires new dependencies or architectural changes.

**Bug 1 (Security, MIDP-02):** `apply_per_issuer_dpop()` in `pam-unix-oidc/src/auth.rs` validates DPoP proofs for the multi-issuer path but never calls `global_nonce_cache().consume()`. The single-issuer path (`authenticate_with_dpop`) has this call correctly wired. The gap means a DPoP proof in the multi-issuer flow can be replayed within its nonce TTL even though the nonce was issued by `global_nonce_cache().issue()` in `lib.rs`. This is a replay-window vulnerability.

**Bug 2 (Test coverage, ENTR-01):** `test/fixtures/policy/policy-entra.yaml` exists and is well-formed but is never loaded by any non-ignored test. All tests in `pam-unix-oidc/tests/entra_integration.rs` are `#[ignore]`. A deserialization regression in `IssuerConfig`, `AcrMappingConfig`, `GroupMappingConfig`, or any new Entra-relevant field would go undetected in CI.

**Primary recommendation:** Fix Bug 1 by adding cache-backed nonce consumption into `apply_per_issuer_dpop()` (mirroring the existing logic from `authenticate_with_dpop`). Fix Bug 2 by adding a non-ignored unit or integration test that calls `PolicyConfig::load_from()` with the fixture path. Both fixes are self-contained and the test surface is well-bounded.

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| MIDP-02 (integration fix) | Per-issuer DPoP enforcement must include nonce cache consumption in the multi-issuer path, preventing replay within nonce TTL | `apply_per_issuer_dpop()` is the precise location; `global_nonce_cache().consume()` is the missing call; single-issuer reference implementation exists in `authenticate_with_dpop` |
| ENTR-01 (integration fix) | A non-`#[ignore]` test must load `policy-entra.yaml` via `PolicyConfig::load_from()` | Fixture file exists at `test/fixtures/policy/policy-entra.yaml`; `load_from()` is the public entry point at `policy/config.rs:825`; placeholder strings are valid YAML strings and will deserialize fine |
</phase_requirements>

---

## Standard Stack

### Core (already in use — no new dependencies)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `moka` | (current) | TTL cache backing `DPoPNonceCache` | Already used by `global_nonce_cache()`; `remove()` is the atomic single-use primitive |
| `figment` | (current) | YAML + env layered config loading used by `PolicyConfig::load_from()` | Already the project config stack |
| `tempfile` | (current dev-dep) | Write fixture to temp path for `load_from()` test | Already used in `policy/config.rs` unit tests for `test_duplicate_issuer_urls_rejected` |

No new dependencies required for either fix.

---

## Architecture Patterns

### Existing Pattern: Nonce Consumption in Single-Issuer Path

The production reference implementation is in `authenticate_with_dpop()` (`src/auth.rs` lines 680-748):

```rust
// Cache-backed nonce enforcement path (require_nonce=true, expected_nonce=None).
// This is the primary path for server-issued nonces (RFC 9449 §8).
if dpop_config.require_nonce && dpop_config.expected_nonce.is_none() {
    match &result.nonce {
        Some(nonce) => {
            match global_nonce_cache().consume(nonce) {
                Ok(()) => {
                    tracing::debug!(
                        nonce_prefix = &nonce[..nonce.len().min(8)],
                        "DPoP nonce consumed successfully"
                    );
                }
                Err(NonceConsumeError::ConsumedOrExpired) => {
                    tracing::warn!("DPoP nonce replay or expiry detected — rejecting");
                    return Err(AuthError::DPoPValidation(DPoPValidationError::NonceMismatch));
                }
                Err(NonceConsumeError::EmptyNonce) => {
                    tracing::warn!("DPoP nonce in proof is empty — rejecting");
                    return Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce));
                }
            }
        }
        None => {
            // enforcement-mode-dependent: Strict => error, Warn => warn, Disabled => skip
        }
    }
}
```

This exact block must be added to `apply_per_issuer_dpop()` after `validate_proof()` returns `result`.

### Gap: What `apply_per_issuer_dpop()` Currently Does

`apply_per_issuer_dpop()` has an inner `validate_proof` closure (lines 355-365) that builds a `DPoPConfig` and calls `validate_dpop_proof()`. The DPoP config passed to `validate_dpop_proof` has:

```rust
require_nonce: dpop_config.require_nonce && dpop_config.expected_nonce.is_some(),
expected_nonce: dpop_config.expected_nonce.clone(),
```

This condition `&& dpop_config.expected_nonce.is_some()` means the single-value (direct) nonce path works, but the cache-backed path (where `require_nonce=true` and `expected_nonce=None`) is silently skipped. The result: `validate_proof()` returns a `DPoPProofResult` with `result.nonce = Some(...)` but that nonce is never consumed from the global cache.

### Fix Design for `apply_per_issuer_dpop()`

The function signature needs one new parameter: `dpop_nonce_enforcement: EnforcementMode` (the same value used in `authenticate_with_dpop`). After calling `validate_proof(proof)?` and getting `result`, insert the cache-backed consumption block. The call site in `authenticate_multi_issuer()` (Step 6, line 179) must pass the nonce enforcement mode from `policy.effective_security_modes().dpop_required`.

Alternatively, pass `dpop_nonce_enforcement` via `DPoPAuthConfig` — but `DPoPAuthConfig` doesn't currently carry this. Adding it to the function signature is cleaner and does not change existing call-site semantics.

**Minimal diff:**

1. Add `dpop_nonce_enforcement: EnforcementMode` parameter to `apply_per_issuer_dpop()`.
2. After `validate_proof(proof)?` returns `result`, add the cache-backed consumption block (copy from `authenticate_with_dpop`).
3. At the call site in `authenticate_multi_issuer()` (line 179), pass `policy.effective_security_modes().dpop_required`.

### Existing Pattern: `PolicyConfig::load_from()` Test

The existing `test_duplicate_issuer_urls_rejected` test at `policy/config.rs:1794` shows the tempfile pattern:

```rust
let dir = tempfile::tempdir().expect("tempdir");
let path = dir.path().join("policy.yaml");
std::fs::write(&path, yaml).expect("write");
let result = PolicyConfig::load_from(&path);
```

For the Entra fixture test, two equivalent approaches exist:

**Approach A: Load directly from the fixture path (simpler, no tempfile)**

```rust
#[test]
fn test_policy_entra_yaml_deserializes() {
    // Source: test/fixtures/policy/policy-entra.yaml
    // Placeholder strings (ENTRA_TENANT_ID_PLACEHOLDER etc.) are valid YAML strings.
    // This test confirms the YAML structure matches PolicyConfig / IssuerConfig schema.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture = std::path::Path::new(manifest_dir)
        .join("../test/fixtures/policy/policy-entra.yaml");
    let config = PolicyConfig::load_from(&fixture)
        .expect("policy-entra.yaml must deserialize without error");
    assert_eq!(config.issuers.len(), 1);
    let issuer = &config.issuers[0];
    // Verify the placeholder values survived round-trip (not empty)
    assert!(issuer.issuer_url.contains("ENTRA_TENANT_ID_PLACEHOLDER"));
    assert_eq!(issuer.dpop_enforcement, EnforcementMode::Disabled);
    assert!(issuer.allow_unsafe_identity_pipeline);
    assert_eq!(config.security_modes.as_ref().map(|m| m.jti_enforcement),
               Some(EnforcementMode::Warn));
}
```

**Approach B: Embed fixture YAML inline (no file path dependency)**

Write the YAML as a `const &str` and write to a tempfile. Less fragile if the fixture moves, but duplicates content.

Approach A is recommended: it directly validates the file that ships with the project, meaning any YAML change also updates the test coverage.

### Where to Place the Test

The test does not require `--features test-mode` (no signature verification involved). It should go in `pam-unix-oidc/tests/entra_integration.rs` as a non-ignored test so it runs in CI without secrets. The file already exists and imports `PolicyConfig`. Alternatively it can be a `#[cfg(test)]` unit test in `policy/config.rs` — same outcome.

Preferred location: `pam-unix-oidc/tests/entra_integration.rs` — this keeps Entra coverage in one file and reinforces the intent that CI verifies the Entra fixture without live credentials.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Cache-backed nonce atomicity | Custom mutex + HashSet | `global_nonce_cache().consume()` via moka | Already implemented; `remove()` is atomic test-and-delete (no TOCTOU) |
| YAML loading | Custom serde parser | `PolicyConfig::load_from()` | Already implemented with figment + duplicate detection |

---

## Common Pitfalls

### Pitfall 1: Forgetting the `nonce_enforcement` parameter thread-through

**What goes wrong:** Adding the cache-backed nonce block to `apply_per_issuer_dpop()` without adding the `dpop_nonce_enforcement: EnforcementMode` parameter, then hardcoding `EnforcementMode::Strict` or `Warn`. This changes behavior for all issuers regardless of operator config.

**How to avoid:** Mirror `authenticate_with_dpop` exactly: `dpop_nonce_enforcement` comes from `policy.effective_security_modes().dpop_required` at the call site, passed through to `apply_per_issuer_dpop()`.

### Pitfall 2: Applying nonce consumption in the `Disabled` fast path

**What goes wrong:** Adding nonce cache code before the `if enforcement == EnforcementMode::Disabled { return Ok(None); }` early exit, or inside the Disabled branch. For Entra issuers (dpop_enforcement=Disabled), DPoP proofs are intentionally ignored — attempting to consume a nonce from a proof that was never validated would be incorrect.

**How to avoid:** The nonce cache consumption block must only execute when `validate_proof()` was actually called (i.e., when a proof exists and DPoP is not disabled). The existing structure already gates proof validation on `enforcement != Disabled` at line 351.

### Pitfall 3: `policy-entra.yaml` placeholder values causing `load_from()` to fail

**What goes wrong:** Assuming that `ENTRA_TENANT_ID_PLACEHOLDER` in the issuer URL causes figment to attempt variable interpolation and fail. Figment with YAML provider does NOT interpolate shell variables or env vars in string values — placeholders are opaque strings.

**Verification:** `load_from()` reads the file, passes it through `Yaml::string()` figment provider, and extracts into `PolicyConfig`. String fields accept any value. Confirmed by reading `PolicyConfig::load_from()` source at `policy/config.rs:825`.

### Pitfall 4: Test isolation for `global_nonce_cache()` in the replay test

**What goes wrong:** The replay test for the multi-issuer nonce path calls `global_nonce_cache().issue()` and then `authenticate_multi_issuer()` twice with the same proof. Because `global_nonce_cache()` is a static singleton, if the test runs in parallel with other tests that share the same nonce value, false failures can occur.

**How to avoid:** Use a unique, test-specific nonce value (e.g., include a random suffix or use `generate_dpop_nonce()`). Do not rely on a fixed string like `"test-nonce"` that might collide across parallel tests. The same pattern appears in `nonce_cache.rs` tests which use `DPoPNonceCache::new(1_000, 60)` (a local cache) to avoid polluting the global.

For the multi-issuer replay test, use `global_nonce_cache().issue(nonce)` before calling `authenticate_multi_issuer`, since that's the realistic flow (lib.rs issues the nonce, auth.rs consumes it). Use test-mode-signed tokens.

### Pitfall 5: The `validate_proof` closure in `apply_per_issuer_dpop()` does not return `nonce`

**What goes wrong:** `validate_proof` currently returns `DPoPProofResult` (which carries `result.nonce: Option<String>`). The existing code ignores `result.nonce` after calling `verify_dpop_binding`. The nonce is present in the result but never consumed.

**How to avoid:** After `let result = validate_proof(proof)?`, access `result.nonce` and apply the same consume logic as `authenticate_with_dpop`. No changes to `DPoPProofResult` struct needed — the field already exists.

---

## Code Examples

### Reference: Nonce consumption block from `authenticate_with_dpop` (single-issuer)

Source: `pam-unix-oidc/src/auth.rs:697-745`

```rust
if dpop_config.require_nonce && dpop_config.expected_nonce.is_none() {
    match &result.nonce {
        Some(nonce) => {
            match global_nonce_cache().consume(nonce) {
                Ok(()) => {
                    tracing::debug!(
                        nonce_prefix = &nonce[..nonce.len().min(8)],
                        "DPoP nonce consumed successfully"
                    );
                }
                Err(NonceConsumeError::ConsumedOrExpired) => {
                    tracing::warn!("DPoP nonce replay or expiry detected — rejecting");
                    return Err(AuthError::DPoPValidation(
                        DPoPValidationError::NonceMismatch,
                    ));
                }
                Err(NonceConsumeError::EmptyNonce) => {
                    tracing::warn!("DPoP nonce in proof is empty — rejecting");
                    return Err(AuthError::DPoPValidation(
                        DPoPValidationError::MissingNonce,
                    ));
                }
            }
        }
        None => {
            match dpop_nonce_enforcement {
                EnforcementMode::Strict => {
                    return Err(AuthError::DPoPValidation(DPoPValidationError::MissingNonce));
                }
                EnforcementMode::Warn => { tracing::warn!(...); }
                EnforcementMode::Disabled => {}
            }
        }
    }
}
```

### Reference: `PolicyConfig::load_from()` signature

Source: `pam-unix-oidc/src/policy/config.rs:825`

```rust
pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError>
```

Returns `Err(PolicyError::NotFound(...))` if file does not exist. Returns `Err(PolicyError::ParseError(...))` if YAML is malformed. Returns `Err(PolicyError::ConfigError(...))` for post-parse validation errors (e.g., duplicate issuers).

### Reference: Test fixture path from integration test

Source: `pam-unix-oidc/tests/multi_idp_integration.rs` pattern; fixture at `test/fixtures/policy/policy-entra.yaml`

```rust
// CARGO_MANIFEST_DIR is pam-unix-oidc/ for integration tests in pam-unix-oidc/tests/
let manifest_dir = env!("CARGO_MANIFEST_DIR");
let fixture = std::path::Path::new(manifest_dir)
    .join("../test/fixtures/policy/policy-entra.yaml");
```

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in (`cargo test`) |
| Config file | `pam-unix-oidc/Cargo.toml` (features: `test-mode`) |
| Quick run command | `cargo test -p pam-unix-oidc -- nonce_multi_issuer entra_yaml` |
| Full suite command | `cargo test -p pam-unix-oidc --features test-mode` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| MIDP-02 (fix) | Replayed DPoP proof in multi-issuer path is rejected when nonce already consumed | unit (test-mode) | `cargo test -p pam-unix-oidc --features test-mode -- test_multi_issuer_dpop_nonce_replay_rejected` | Wave 0 |
| MIDP-02 (fix) | `apply_per_issuer_dpop` consumes nonce from global cache after successful validation | unit (test-mode) | `cargo test -p pam-unix-oidc --features test-mode -- test_multi_issuer_dpop_nonce_consumed` | Wave 0 |
| ENTR-01 (fix) | `policy-entra.yaml` deserializes without error via `PolicyConfig::load_from()` | integration (no secrets) | `cargo test -p pam-unix-oidc --test entra_integration -- test_policy_entra_yaml_deserializes` | Wave 0 |
| ENTR-01 (fix) | Breaking the YAML structure causes `load_from()` to fail | unit | Inline negative assertion in the same test | Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p pam-unix-oidc --features test-mode 2>&1 | tail -20`
- **Per wave merge:** `cargo test -p pam-unix-oidc --features test-mode && cargo clippy -p pam-unix-oidc -- -D warnings`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `test_multi_issuer_dpop_nonce_replay_rejected` — covers MIDP-02 (new test in `tests/multi_idp_integration.rs` or `src/auth.rs` unit tests)
- [ ] `test_multi_issuer_dpop_nonce_consumed` — covers MIDP-02 (same file)
- [ ] `test_policy_entra_yaml_deserializes` — covers ENTR-01 (new non-ignored test in `tests/entra_integration.rs`)

---

## Open Questions

1. **Where exactly to add the replay test — unit vs integration test file?**
   - What we know: `multi_idp_integration.rs` uses `#[cfg(feature = "test-mode")]` and already has MIDP-02 tests. The nonce test requires calling `global_nonce_cache().issue()` directly, which is a pub function.
   - Recommendation: Add to `tests/multi_idp_integration.rs` since it already exercises `authenticate_multi_issuer`. Import `pam_unix_oidc::security::nonce_cache::{generate_dpop_nonce, global_nonce_cache}`. The global cache is shared across tests — use a unique nonce value.

2. **Should the `validate_proof` closure in `apply_per_issuer_dpop()` be refactored into a full inner function to avoid closure capture complexity?**
   - What we know: `authenticate_with_dpop` uses a closure (which captures `dpop_config` and `dpop_nonce_enforcement`). Adding more logic to the existing `validate_proof` closure in `apply_per_issuer_dpop()` is feasible.
   - Recommendation: Keep closure form; it matches the established pattern. Pass `dpop_nonce_enforcement` as a new function parameter, capture it in the closure.

---

## Sources

### Primary (HIGH confidence)

- Direct source inspection: `pam-unix-oidc/src/auth.rs` — `apply_per_issuer_dpop()` (lines 343-401), `authenticate_with_dpop()` nonce consumption (lines 694-748), `authenticate_multi_issuer()` (lines 100-330)
- Direct source inspection: `pam-unix-oidc/src/security/nonce_cache.rs` — `global_nonce_cache()`, `DPoPNonceCache.consume()`, atomicity guarantees
- Direct source inspection: `pam-unix-oidc/src/policy/config.rs` — `PolicyConfig::load_from()` (line 825)
- Direct source inspection: `test/fixtures/policy/policy-entra.yaml` — fixture content and placeholder strings
- Direct source inspection: `pam-unix-oidc/tests/entra_integration.rs` — all tests are `#[ignore]`; `entra_single_issuer_policy()` builds equivalent config programmatically
- Direct source inspection: `pam-unix-oidc/tests/multi_idp_integration.rs` — `test_dpop_strict_rejects_bearer_only`, `test_dpop_disabled_accepts_bearer` as test pattern reference
- Project planning: `.planning/v2.1-MILESTONE-AUDIT.md` — audit findings that define the two gaps

### Secondary (MEDIUM confidence)

- `.planning/phases/21-multi-idp-configuration/21-02-SUMMARY.md` — confirms `apply_per_issuer_dpop()` was extracted as a separate function in Phase 21-02; key decision documented

---

## Metadata

**Confidence breakdown:**
- Bug 1 location and fix: HIGH — inspected the exact gap; reference implementation exists
- Bug 2 location and fix: HIGH — fixture file found; `load_from()` signature verified; existing test pattern in same file
- Test strategy: HIGH — test-mode pattern well established; `global_nonce_cache` is exported pub

**Research date:** 2026-03-13
**Valid until:** 2026-04-13 (stable codebase; no external dependencies added)
