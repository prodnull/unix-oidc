# Testing Patterns

**Analysis Date:** 2026-03-10

## Test Framework

**Runner:**
- Rust built-in test framework (no external runner needed)
- Config: No separate config file; uses Cargo test infrastructure
- Async tests use `tokio::test` for async/await support

**Assertion Library:**
- Standard Rust `assert!()`, `assert_eq!()`, `assert_ne!()`
- Custom assertions rare; standard macros preferred
- Error assertions: `assert!(result.is_err())`, `assert_eq!(error_type, expected)`

**Run Commands:**
```bash
cargo test --workspace              # Run all tests across workspace
cargo test -p pam-unix-oidc         # Test single package
cargo test -p unix-oidc-agent       # Test agent package
cargo test --lib                    # Library tests only (no integration tests)
cargo test -- --nocapture           # Show output (println! visible)
cargo test -- --test-threads=1      # Single-threaded for state-dependent tests
```

**Watch Mode (not built-in):**
- Use `cargo-watch` if needed: `cargo watch -x test`
- Manual rerun via `cargo test` in IDE or terminal

## Test File Organization

**Location:**
- Co-located with implementation: tests in `mod tests { }` block at end of file
- Example: `unix-oidc-agent/src/crypto/dpop.rs` has `mod tests { }` at end

**Naming:**
- Test module: `mod tests { }`
- Test functions: `test_[description]` e.g., `test_generate_proof_format`
- Test data fixtures: No dedicated directory; fixtures created inline or via helper functions

**Structure:**
```
src/
├── module.rs           # Implementation + test module at bottom
│   └── mod tests { }   # All tests for this module
├── module/
│   ├── submodule.rs   # Submodule implementation + tests
│   └── mod.rs         # Re-exports
```

Example from codebase:
- `unix-oidc-agent/src/config.rs`: Contains `AgentConfig` struct + `mod tests { }` with test fixtures
- `unix-oidc-agent/src/crypto/dpop.rs`: DPoP proof generation + 5 unit tests

## Test Structure

**Suite Organization:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::thumbprint::compute_ec_thumbprint;
    use p256::elliptic_curve::rand_core::OsRng;

    #[test]
    fn test_generate_proof_format() {
        // Test implementation
    }

    #[test]
    fn test_another_feature() {
        // Test implementation
    }
}
```

**Patterns:**

1. **Setup Pattern** (Arrange-Act-Assert):
```rust
#[test]
fn test_config_from_yaml() {
    // Arrange: Create temporary directory and config file
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    std::fs::write(
        &config_path,
        r#"
issuer: https://idp.example.com/realms/corp
client_id: my-agent
crypto:
  enable_pqc: true
"#,
    )
    .unwrap();

    // Act: Load configuration
    let config = AgentConfig::from_file(&config_path).unwrap();

    // Assert: Verify expected values
    assert_eq!(config.issuer, "https://idp.example.com/realms/corp");
    assert_eq!(config.client_id, "my-agent");
    assert!(config.crypto.enable_pqc);
}
```

2. **Teardown Pattern**:
- `tempfile::TempDir` automatically cleans up when dropped
- No explicit cleanup needed for file-based tests

3. **Assertion Pattern**:
- Simple equality: `assert_eq!(actual, expected)`
- Boolean predicates: `assert!(result.is_ok())`
- Error matching:
```rust
assert!(matches!(
    validator.validate(&proof),
    Err(DpopError::ReplayedProof)
));
```

## Mocking

**Framework:** None (no mocking library used)

**Patterns:**

1. **Trait-Based Mocking** - Use dependency injection:
```rust
pub trait DPoPSigner: Send + Sync {
    fn thumbprint(&self) -> String;
    fn sign_proof(&self, method: &str, target: &str, nonce: Option<&str>) -> Result<String, DPoPError>;
}

impl DPoPSigner for MockSigner {
    fn thumbprint(&self) -> String { "mock-thumb".to_string() }
    fn sign_proof(&self, ...) -> Result<String, DPoPError> { ... }
}
```

2. **Test-Only Implementations** - Feature-gated for testing:
```rust
#[cfg(feature = "test-mode")]
fn is_test_mode_enabled() -> bool {
    std::env::var("UNIX_OIDC_TEST_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false)
}
```

3. **Inline Test Data** - No external mocks:
```rust
#[test]
fn test_unique_jti_per_proof() {
    let signing_key = SigningKey::random(&mut OsRng);

    let proof1 = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();
    let proof2 = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();

    // JTIs should differ
    assert_ne!(claims1.jti, claims2.jti);
}
```

**What to Mock:**
- External HTTP calls (return fixed responses in tests)
- Time-dependent operations (use fixed timestamps)
- Random number generation (seed for determinism)

**What NOT to Mock:**
- Cryptographic functions (must use real crypto in tests)
- Error conditions that should be tested with real errors
- Replay detection logic (needs real JTI cache)

## Fixtures and Factories

**Test Data:**

1. **Temporary Files** - Using `tempfile::TempDir`:
```rust
use tempfile::TempDir;

#[test]
fn test_writes_config() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");

    // Test writes to temp_dir, auto-cleaned
}
```

2. **Cryptographic Keys** - Generated fresh:
```rust
use p256::elliptic_curve::rand_core::OsRng;
use p256::ecdsa::SigningKey;

#[test]
fn test_proof_signing() {
    let signing_key = SigningKey::random(&mut OsRng);
    // Each test gets a unique random key
}
```

3. **Configuration Objects** - Built inline:
```rust
#[test]
fn test_validation() {
    let config = ValidationConfig {
        issuer: "https://idp.example.com".into(),
        client_id: "test-client".into(),
        required_acr: None,
        max_auth_age: None,
        enforce_jti: true,
    };
}
```

**Location:**
- No separate fixture directory; fixtures created in test functions
- Test utilities in same module as tests
- Reusable test helpers as functions within `mod tests { }`

## Coverage

**Requirements:**
- No explicit coverage target enforced
- CI runs tests but does not check coverage percentage
- Security-critical paths have dedicated tests

**View Coverage:**
```bash
# Requires tarpaulin or llvm-cov
cargo tarpaulin --out Html --output-dir coverage/
# or
cargo llvm-cov --html
```

**Coverage Focus Areas (observed):**
- Cryptographic operations: Every DPoP proof variant tested
- Token validation: All error paths tested
- Configuration loading: YAML and env var paths tested
- Replay protection: JTI cache tested for duplicates and expiration

## Test Types

**Unit Tests:**
- Scope: Individual functions and methods
- Approach: Synchronous, in-process testing
- Examples:
  - `test_generate_proof_format()`: DPoP proof structure
  - `test_config_from_yaml()`: Configuration parsing
  - `test_thumbprint_is_deterministic()`: Cryptographic operations
- All located in `mod tests { }` blocks within implementation files

**Integration Tests:**
- Scope: Module interactions (token validation + SSSD lookup)
- Approach: End-to-end authentication flows
- Location: Implicit via feature tests (no separate `tests/` directory observed)
- Example: Testing token validation with JWKS caching, DPoP verification, user resolution

**E2E Tests:**
- Framework: None built-in; Docker Compose for external IdP testing
- Location: `test/` directory with shell scripts and Python tests
  - `test/tests/test_token_exchange.sh`: SSH authentication flows
  - `test/tests/test_token_exchange.py`: Python-based token exchange tests
- IdP: Keycloak via `test/fixtures/keycloak/unix-oidc-test-realm.json`

**Fuzzing Tests:**
```bash
cargo fuzz run dpop_proof      # Fuzz DPoP proof parsing
cargo fuzz run policy_parser   # Fuzz policy configuration
cargo fuzz run token_parser    # Fuzz JWT token parsing
cargo fuzz run username_mapper # Fuzz username mapping
```
- Located in: `fuzz/fuzz_targets/`
- Run: `cargo +nightly fuzz run [target]`

## Common Patterns

**Async Testing:**
```rust
#[tokio::test]
async fn test_server_handles_connection() {
    // Test async/await code
    let result = handle_connection(stream, state).await;
    assert!(result.is_ok());
}
```

**Error Testing:**
```rust
#[test]
fn test_rejects_replayed_proof() {
    let proof = create_test_proof();
    let validator = DpopValidator::new();

    // First use succeeds
    assert!(validator.validate(&proof).is_ok());

    // Second use fails (replay)
    assert!(matches!(
        validator.validate(&proof),
        Err(DpopError::ReplayedProof)
    ));
}
```

**Security-Specific Testing:**
```rust
#[test]
fn test_constant_time_comparison() {
    // Verify timing attack resistance
    use subtle::ConstantTimeEq;

    let expected = [1u8; 32];
    let actual = [1u8; 32];

    let result = expected.ct_eq(&actual);
    assert!(bool::from(result));
}
```

**Deterministic Test Data:**
```rust
#[test]
fn test_proof_format() {
    // Use fixed key for deterministic output
    let signing_key = SigningKey::random(&mut OsRng);
    let proof = generate_dpop_proof(&signing_key, "SSH", "server.example.com", None).unwrap();

    // Parse and verify structure
    let parts: Vec<&str> = proof.split('.').collect();
    assert_eq!(parts.len(), 3); // Header.Payload.Signature
}
```

## Testing Checklist

When adding new code:
- [ ] Write unit test in same file's `mod tests { }` block
- [ ] Test happy path and at least one error condition
- [ ] Test security boundaries (crypto, validation, access control)
- [ ] Run `cargo test --workspace` locally
- [ ] Run `cargo clippy -- -D warnings` to catch lint issues
- [ ] For cryptographic code: test determinism, key length, algorithm enforcement
- [ ] For async code: use `#[tokio::test]` not `#[test]`
- [ ] For temporary files: use `tempfile::TempDir`

---

*Testing analysis: 2026-03-10*
