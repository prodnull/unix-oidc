# Coding Conventions

**Analysis Date:** 2026-03-10

## Naming Patterns

**Files:**
- `snake_case` for all Rust files: `dpop.rs`, `jti_cache.rs`, `user.rs`
- Module files use `mod.rs` pattern: `src/oidc/mod.rs`, `src/policy/mod.rs`
- Submodules declared in `mod.rs` using `pub mod` statements
- Error-specific modules: `error.rs` for error types (e.g., `rust-oauth-dpop/src/error.rs`)

**Functions:**
- `snake_case` for all functions (public and private)
- Function names describe their action: `authenticate_with_token()`, `validate_dpop_proof()`, `check_and_record()`
- Test functions prefixed with `test_`: `test_generate_proof_format()`, `test_rejects_replayed_proof()`
- Helper functions use descriptive verbs: `compute_ec_thumbprint()`, `is_test_mode_enabled()`

**Variables:**
- `snake_case` for all variables and bindings
- Boolean predicates use `is_` or `has_` prefix: `is_test_mode_enabled()`, `is_logged_in()`, `is_new_jti()`
- Abbreviations acceptable in domain context: `jti`, `cnf`, `acr`, `amr`, `aud` (JWT claim abbreviations)
- Acronyms remain lowercase in variable names: `jti`, `jwk`, `dpop` (not `JTI`, `JWK`, `DPOP`)

**Types & Structures:**
- `PascalCase` for all types, enums, structs, traits
- Example: `TokenClaims`, `ValidationError`, `DPoPSigner`, `AgentConfig`
- Error enum variants use `PascalCase`: `InvalidKey`, `ClockError`, `InvalidProofFormat`
- Builder patterns and utility traits: `DPoPSigner`, `SecureStorage`, `MetricsCollector`

**Constants:**
- `UPPER_SNAKE_CASE` for module-level constants
- Examples: `MAX_JTI_CACHE_ENTRIES`, `P256_COORDINATE_LEN`, `CLOCK_SKEW_TOLERANCE`, `DEFAULT_CLEANUP_INTERVAL`

## Code Style

**Formatting:**
- Standard Rust formatting: `cargo fmt` (enforced via CI)
- Line length: standard Rust default (typically 100 chars, enforced by clippy)
- Indentation: 4 spaces (Rust standard)

**Linting:**
- `cargo clippy` with strict warnings: `clippy -- -D warnings`
- All lint warnings treated as errors in CI
- Custom deny rules for dependencies: `deny.toml` with advisory DB checks

**Dependencies:**
- Workspace dependencies defined in root `Cargo.toml` with `[workspace.dependencies]`
- Shared versions across packages via workspace inheritance
- No features enabled by default unless explicitly needed
- Security-critical crates used: `jsonwebtoken`, `ring`/`rustls`, `thiserror`, `serde`

## Import Organization

**Order:**
1. Standard library imports (`std::`)
2. External crate imports (e.g., `thiserror`, `serde`, `tokio`)
3. Internal module imports (crate-relative with `use crate::`)
4. Type-specific imports (e.g., `use pamsm::PamError`)

**Path Aliases:**
- No aliasing configured; imports use full paths
- Relative imports within modules: `use crate::oidc::validation::TokenValidator`
- Re-exports in `mod.rs`: `pub use config::*` to expose common types

**Example from `pam-unix-oidc/src/auth.rs`:**
```rust
use crate::oidc::{
    validate_dpop_proof, verify_dpop_binding, DPoPConfig, DPoPValidationError, TokenValidator,
    ValidationConfig, ValidationError,
};
use crate::security::session::generate_ssh_session_id;
use crate::sssd::{get_user_info, user_exists, UserError};
use thiserror::Error;
```

**Barrel Files:**
- Used extensively: `src/oidc/mod.rs` re-exports: `TokenValidator`, `ValidationConfig`, `DPoPValidationError`
- Reduces import depth for consumers: import from module rather than submodules

## Error Handling

**Patterns:**
- All custom error types use `#[derive(Debug, thiserror::Error)]`
- Error variants use descriptive messages with context when possible
- Errors include relevant parameters (e.g., expected vs actual values)

**Examples from codebase:**
```rust
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },

    #[error("ACR level insufficient: required {required}, got {actual:?}")]
    InsufficientAcr {
        required: String,
        actual: Option<String>,
    },

    #[error("Token replay detected: JTI '{jti}' was already used")]
    TokenReplay { jti: String },
}
```

**Error Flow:**
- Functions return `Result<T, E>` where `E` implements `std::error::Error`
- Use `?` operator for error propagation in normal paths
- No `.unwrap()` or `.expect()` in production code paths (PAM module must never panic)
- Error context added via `map_err()` when propagating from lower layers

**Security-Specific Error Handling:**
- Cryptographic failures return generic errors to users: "Authentication failed"
- Detailed error context logged internally (not exposed to client)
- Timing-sensitive comparisons use constant-time comparison: `subtle::ConstantTimeEq`

## Logging

**Framework:** `tracing` crate (structured logging)

**Patterns:**
- Macro-based: `tracing::info!()`, `tracing::warn!()`, `tracing::error()`, `tracing::debug!()`
- Structured fields included in all logs
- Example from `pam-unix-oidc/src/oidc/dpop.rs`:
```rust
tracing::warn!(
    cache_size = entries.len(),
    before_cleanup = before_cleanup,
    "DPoP JTI cache at capacity, rejecting new proof"
);
```

**Log Levels:**
- `error!()`: Authentication failures, configuration errors
- `warn!()`: Security boundaries (cache full, rate limit exceeded, warnings for optional claims)
- `info!()`: Successful auth, connection established
- `debug!()`: Detailed state (for troubleshooting only)

**Security Logging:**
- Never log full tokens, passwords, or private keys
- Log request IDs, usernames, IP addresses (audit trail)
- Log why validation failed (issuer mismatch, signature invalid) but not cryptographic material

## Comments

**When to Comment:**
- Security-critical code always has explanatory comments
- Complex algorithms documented with references to RFCs/papers
- Non-obvious design decisions explained
- Invariants that must be maintained documented

**Example from `pam-unix-oidc/src/oidc/dpop.rs`:**
```rust
// Security: Use constant-time comparison to prevent timing attacks
use subtle::ConstantTimeEq;
if !expected_hash.ct_eq(&actual_hash).into() {
    return Err(ValidationError::InvalidSignature);
}
```

**JSDoc/TSDoc:**
- Not applicable (Rust uses Rustdoc instead)
- Public types and functions have documentation comments (`///`)
- Examples provided in documentation when non-obvious
- Example from `unix-oidc-agent/src/daemon/socket.rs`:
```rust
/// Get the default socket path
pub fn default_socket_path() -> PathBuf {
    let runtime_dir = std::env::var("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"));

    runtime_dir.join("unix-oidc-agent.sock")
}
```

## Function Design

**Size:**
- Most functions stay under 50 lines
- Complex functions (auth flow, validation) can exceed 100 lines but remain focused on single responsibility
- Helper functions extract complexity: `compute_ec_thumbprint()`, `maybe_cleanup()`

**Parameters:**
- Functions take concrete types or references, not Option wrappers (use `Option<&str>` not `Option<String>`)
- Configuration passed via structs: `ValidationConfig`, `DPoPConfig`, `AgentConfig` (not 5+ boolean parameters)
- Builder pattern used for complex initialization

**Return Values:**
- All functions returning values return `Result<T, E>` unless the function cannot fail
- Functions never return `Option<Result<T, E>>` (flatten structure)
- Success values wrapped in tuples when multiple pieces of data needed:
```rust
pub async fn handle_connection(
    stream: UnixStream,
    state: Arc<RwLock<AgentState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
```

## Module Design

**Exports:**
- Each module has a clear public API defined in `mod.rs`
- Private helper functions remain in implementation files
- Re-exports from `mod.rs` make the API surface explicit

**Example from `pam-unix-oidc/src/oidc/mod.rs`:**
```rust
pub use dpop::{validate_dpop_proof, verify_dpop_binding, DPoPConfig, DPoPValidationError};
pub use token::{TokenClaims, TokenError};
pub use validation::{TokenValidator, ValidationConfig, ValidationError};
```

**Module Hierarchies:**
- `pam-unix-oidc/`: Core PAM module
  - `oidc/`: OIDC token validation and DPoP
  - `sssd/`: Unix user resolution
  - `security/`: JTI cache, rate limiting, sessions
  - `policy/`: Authorization policy enforcement
  - `audit/`: Audit logging
  - `approval/`: Webhook-based approval flows

- `unix-oidc-agent/`: Client-side agent
  - `crypto/`: DPoP proof generation, key management
  - `daemon/`: Unix socket server, protocol
  - `storage/`: Secure key storage (keyring, file-based)
  - `config/`: Configuration loading

## Testing Conventions

**Unit Test Organization:**
- Tests grouped in `mod tests { }` at end of file
- Co-located with implementation (same file)
- Use `#[test]` attribute for synchronous tests
- Use `#[tokio::test]` for async tests

**Test Naming:**
- `test_[function_name]_[scenario]`: `test_config_from_yaml()`, `test_generate_proof_format()`
- Security tests include "security" or threat: `test_rejects_replayed_proof()`

**Test Structure (Arrange-Act-Assert):**
```rust
#[test]
fn test_thumbprint_is_deterministic() {
    // Arrange
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Act
    let thumb1 = compute_ec_thumbprint(verifying_key);
    let thumb2 = compute_ec_thumbprint(verifying_key);

    // Assert
    assert_eq!(thumb1, thumb2);
}
```

## Special Patterns

**Configuration Loading:**
- Two patterns supported: environment variables and YAML files
- Environment variables take precedence over file defaults
- Example from `unix-oidc-agent/src/config.rs`:
```rust
pub fn from_env() -> Result<Self, ConfigError> {
    let issuer = std::env::var("OIDC_ISSUER")
        .map_err(|_| ConfigError::MissingEnvVar("OIDC_ISSUER".to_string()))?;
    let client_id = std::env::var("OIDC_CLIENT_ID").unwrap_or_else(|_| default_client_id());
    Ok(Self { issuer, client_id, ... })
}
```

**Feature Flags:**
- `test-mode` feature in `pam-unix-oidc`: Disables signature verification for testing
- Always documented with security warnings
- Never enabled in production builds

**Thread Safety:**
- Shared mutable state protected by `RwLock<T>` (reader-writer lock)
- Example from `unix-oidc-agent/src/daemon/socket.rs`:
```rust
pub struct AgentServer {
    socket_path: PathBuf,
    state: Arc<RwLock<AgentState>>,
}
```

**Async/Await:**
- Used for I/O operations: network requests, file operations
- Tokio runtime for async operations
- Example async function signature:
```rust
pub async fn serve(&self) -> Result<(), std::io::Error> { ... }
async fn handle_connection(stream: UnixStream, state: Arc<RwLock<AgentState>>) -> Result<()> { ... }
```

---

*Convention analysis: 2026-03-10*
