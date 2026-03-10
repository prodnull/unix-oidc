# Codebase Concerns

**Analysis Date:** 2026-03-10

## Tech Debt

### Incomplete Agent Implementation

**Issue:** `unix-oidc-agent/src/main.rs` contains stub CLI commands that lack full implementation
- Files: `unix-oidc-agent/src/main.rs`
- Impact: Core agent features (login, logout, reset) are partially functional or non-functional
- Status: Agent crypto/daemon infrastructure complete (`src/crypto/`, `src/daemon/`), but CLI integration incomplete
- Fix approach: Complete CLI command implementations with proper error handling, device flow integration, and state management

**Details:**
- `run_login()` - Device flow skeleton exists but needs full OAuth2 device authorization grant flow
- `run_logout()` - Stub implementation; needs token revocation
- `run_refresh()` - Stub implementation; needs refresh token handling
- `run_reset()` - Stub implementation; needs cleanup of all stored credentials
- `run_status()` - Functional but depends on agent daemon running
- Expected blockers: Device flow client library integration, token refresh logic

### Keyring Integration Partial

**Issue:** `unix-oidc-agent/src/storage/keyring_store.rs` is implemented but not integrated into main CLI paths
- Files: `unix-oidc-agent/src/storage/keyring_store.rs`, `unix-oidc-agent/src/main.rs`
- Impact: Tokens and DPoP keypairs currently stored in plaintext files instead of secure OS keychain
- Fix approach: Switch `FileStorage` to `KeyringStorage` in `load_agent_state()` and token storage paths
- Test gap: Tests marked `#[ignore]` due to keychain access requirements

---

## RwLock Panic Risk in PAM Critical Path

**Issue:** `.unwrap()` calls on RwLock acquisitions in security-sensitive PAM code
- Files:
  - `pam-unix-oidc/src/security/jti_cache.rs` (lines 126, 139, 172, 184, 191, 194, 202, 203, 216)
  - `pam-unix-oidc/src/security/rate_limit.rs` (lines 165, 181, 207, 228, 250, 259, 290, 300, 316, 325)
- Impact: **CRITICAL** - RwLock panic during authentication can lock users out of their systems
- Risk: Poisoned locks from panics in concurrent access patterns could cascade failures
- Fix approach: Replace `.unwrap()` with `.map_err()` returning proper PAM error codes; consider `parking_lot::RwLock` which doesn't poison on panic
- Severity: High - authentication failure = system lockout

**Example from `jti_cache.rs:126`:**
```rust
let entries = self.entries.read().unwrap();  // DANGER: Can panic if lock is poisoned
```

Should be:
```rust
let entries = self.entries.read()
    .map_err(|_| JtiCheckResult::Missing)?;  // Graceful degradation
```

---

## Session ID Generation Panic Risk

**Issue:** `getrandom::fill()` with `.expect()` in PAM path
- Files: `pam-unix-oidc/src/security/session.rs` (line 74)
- Impact: If secure RNG fails (e.g., entropy exhaustion), PAM module panics and locks out all users
- Fix approach: Return proper `SessionError` instead of panicking; implement fallback RNG or graceful rejection
- Severity: High - affects all authentication attempts

```rust
// Current - UNSAFE
getrandom::fill(&mut bytes).expect(
    "secure random number generation failed - \
     system may be misconfigured or compromised",
);

// Should return Result
getrandom::fill(&mut bytes)
    .map_err(|e| SessionError::RngFailed(e.to_string()))?;
```

---

## Session ID Validation Uses Panicking `.unwrap()`

**Issue:** `is_valid_session_id()` in `pam-unix-oidc/src/security/session.rs` uses `.last().unwrap()` without prior bounds check
- Files: `pam-unix-oidc/src/security/session.rs` (lines 99, 142, 143)
- Impact: Malformed session IDs with insufficient dashes could trigger panic
- Severity: Medium - affects validation of stored session data, not critical path
- Fix approach: Use safe indexing or iterator methods that don't panic

```rust
// Current - can panic if parsing unusual format
let random_part = parts.last().unwrap();

// Should use Option handling
let random_part = parts.last()
    .and_then(|&s| if s.len() == 16 { Some(s) } else { None })
    .ok_or(ValidationError::InvalidSessionId)?;
```

---

## Audit Logging Panics on JSON Serialization

**Issue:** `audit.rs` uses `.unwrap()` on `serde_json::to_string()` calls
- Files: `pam-unix-oidc/src/audit.rs` (lines 302, 320)
- Impact: Unusual event structures that can't serialize to JSON will panic PAM module
- Severity: Medium - affects audit trail, but shouldn't happen with valid event structures
- Fix approach: Handle serialization errors gracefully, emit plaintext fallback

```rust
// Current
let json = serde_json::to_string(&event).unwrap();

// Should handle error
let json = serde_json::to_string(&event)
    .unwrap_or_else(|e| {
        format!(r#"{{"error": "audit_serialization_failed", "reason": "{}"}}"#, e)
    });
```

---

## Missing Configurable JTI Enforcement (Issue #10)

**Issue:** Hard-coded warning behavior for missing JTI claims; no configuration option for strict enforcement
- Files: `pam-unix-oidc/src/oidc/validation.rs` (line 199)
- Impact: Enterprises needing strict compliance can't enforce JTI presence requirement
- Status: Documented in TODO comment
- Fix approach: Implement security modes from `policy.yaml`:
  - `strict` - Reject missing JTI
  - `warn` - Log warning but allow (current behavior)
  - `disabled` - Skip check entirely
- Scope: Configuration parsing, validation module update, test coverage

---

## Test Mode Security Gate Not Bulletproof

**Issue:** Test mode check relies on string comparison that could be fragile
- Files: `pam-unix-oidc/src/lib.rs` (lines 41-42), `pam-unix-oidc/src/sudo.rs` (lines 16-20)
- Impact: If environment variable parsing changes, test mode could unintentionally activate in production
- Risk: Test mode **completely bypasses JWT signature verification**
- Mitigation: Current implementation uses explicit comparison (`!= ""`) which is safe
- Recommendation: Add build-time assertion that test-mode feature is not enabled in release builds
- Severity: High - if accidentally enabled, entire security model fails

---

## Potential Deadlock in Concurrent Token Operations

**Issue:** PAM module's global state (`JTI_CACHE`, rate limiter) uses RwLock with nested locking patterns
- Files: `pam-unix-oidc/src/oidc/dpop.rs` (lines 45-92), `pam-unix-oidc/src/security/rate_limit.rs`
- Impact: Multiple authentication attempts in parallel could expose deadlock scenarios
- Likelihood: Low - read locks dominate, deadlock unlikely but not impossible
- Fix approach: Audit all lock-holding paths; use `parking_lot::RwLock` which prevents deadlock on panic; avoid holding multiple locks simultaneously
- Test coverage: Need concurrent stress testing with multiple simultaneous auth attempts

---

## DPoP JTI Cache Memory Unbounded Until Cleanup

**Issue:** `MAX_JTI_CACHE_ENTRIES` (100k) could grow to memory exhaustion before cleanup
- Files: `pam-unix-oidc/src/oidc/dpop.rs` (lines 22-24, 73-86)
- Impact: Sustained token generation attack could exhaust server memory
- Mitigation: Cleanup triggered on capacity (line 74-86), but window is large (100k entries)
- Fix approach:
  - Lower `MAX_JTI_CACHE_ENTRIES` (e.g., 10k)
  - Implement time-based cleanup independent of insertions
  - Monitor cache size in metrics
- Current TTL handling: Cleanup removes expired entries, which works for normal operation

---

## Timeout Handling in Device Flow Could Block PAM

**Issue:** Device flow polling in `pam-unix-oidc/src/sudo.rs` uses fixed timeout with no interrupt
- Files: `pam-unix-oidc/src/sudo.rs` (lines 180-291)
- Impact: User waiting for step-up approval can't easily cancel (CTRL-C may not interrupt cleanly)
- Severity: Low - affects UX more than security
- Fix approach: Check for interrupt signals; implement graceful timeout with early exit option

---

## Large Files With Multiple Responsibilities

**Issue:** Several files exceed 600 lines and combine multiple concerns
- Files:
  - `unix-oidc-agent/src/main.rs` (836 lines) - CLI + daemon setup + credential loading
  - `unix-oidc-agent/src/daemon/socket.rs` (725 lines) - Server + connection handling + protocol
  - `pam-unix-oidc/src/oidc/dpop.rs` (644 lines) - DPoP validation + JTI cache + proof verification
- Impact: Harder to understand, test, and modify; increased cognitive load for security review
- Fix approach: Extract concerns into separate modules:
  - `dpop.rs` -> `dpop/validation.rs`, `dpop/jti_cache.rs`, `dpop/proof.rs`
  - `socket.rs` -> `socket/server.rs`, `socket/client.rs`, `socket/connection.rs`
  - `main.rs` -> `cli/login.rs`, `cli/serve.rs`, `daemon/startup.rs`
- Complexity: Medium effort, improves maintainability

---

## Performance Bottleneck: Rate Limiter Implementation

**Issue:** Rate limiter uses `Vec::retain()` for cleanup on every write after N attempts
- Files: `pam-unix-oidc/src/security/rate_limit.rs` (lines 207-228)
- Impact: O(n) cleanup cost on write operations; could slow authentication under attack
- Severity: Low - only happens after failures, not normal auth path
- Fix approach:
  - Use timeout-based cleanup instead of size-based
  - Implement periodic background cleanup (e.g., every 5 minutes)
  - Consider `dashmap` crate for lock-free concurrent cleanup
- Current behavior: Acceptable for typical deployment sizes (< 1000 users)

---

## JWKS Caching Doesn't Handle IdP Key Rotation Gracefully

**Issue:** JWKS cache uses simple TTL without validation of cached keys against current tokens
- Files: `pam-unix-oidc/src/oidc/jwks.rs`
- Impact: If IdP rotates keys before cache TTL expires, new tokens won't validate (token signed with new key, cache has old keys)
- Mitigation: Current implementation refreshes cache on signature verification failure (fallback path works)
- Fix approach: Implement key rotation detection:
  - If signature fails, refresh JWKS immediately instead of waiting for TTL
  - Cache multiple key generations
- Severity: Medium - fallback works but adds latency on key rotation

---

## Testing Gaps

### No Integration Tests for Full Authentication Flow

**Issue:** Unit tests exist but no end-to-end PAM authentication flow tests
- Impact: Can't verify entire authentication path works with real Keycloak/Auth0 without manual testing
- Fix approach: Docker-based integration test suite with multiple IdP configurations
- Location: `test/` directory - partial integration tests exist but incomplete

### Incomplete Cross-Language DPoP Tests

**Issue:** DPoP validation tested in Rust, but cross-language implementation compatibility unclear
- Files: `dpop-cross-language-tests/` - tests exist but coverage incomplete
- Impact: Java/Python DPoP implementations may have compatibility issues
- Fix approach: Expand test matrices to include all DPoP signing scenarios

### No Stress/Load Testing

**Issue:** No tests verify behavior under high concurrent authentication load
- Impact: Can't verify rate limiter effectiveness or detect race conditions
- Fix approach: Create benchmark suite with tools like `criterion` for Rust, load testing for PAM

---

## Fragile Areas

### Session ID Validation Logic

**Issue:** Multiple `.unwrap()` calls make session validation fragile to unexpected formats
- Files: `pam-unix-oidc/src/security/session.rs` (lines 99, 142, 143)
- Safe modification: Always bounds-check before indexing; use iterators that return `Option`
- Test coverage: Add tests for malformed session IDs

### RwLock Usage Throughout Codebase

**Issue:** All RwLock acquisitions use `.unwrap()` despite PAM's requirement for graceful failure
- Risk: Single-threaded lock poisoning can cause cascade failures
- Safe modification: Create helper trait wrapping RwLock with proper error handling
- Example:
```rust
trait PamSafeRwLock<T> {
    fn try_read_or_default(&self) -> Result<RwLockReadGuard<T>, PamError>;
}
```

---

## Security Considerations

### Test Mode Bypasses All Signature Verification

**Risk:** Feature flag `test-mode` + environment variable `UNIX_OIDC_TEST_MODE` completely disables JWT validation
- Files: `pam-unix-oidc/src/lib.rs`, `pam-unix-oidc/Cargo.toml`
- Current mitigation:
  - Feature must be explicitly enabled at compile time (not default)
  - Environment variable must be explicitly set (not just presence)
  - PAM module prints warning when enabled
- Recommendations:
  - Add CI check to ensure test-mode feature not in release builds
  - Implement release profile that rejects test-mode compilation
  - Consider removing test-mode feature entirely in favor of mock HTTP server

### No Rate Limiting on JWKS Fetches

**Risk:** Attacker could trigger repeated JWKS refreshes by crafting invalid tokens
- Impact: Potential DoS against IdP JWKS endpoint
- Fix approach: Add rate limiting to JWKS refresh attempts (e.g., max 1 refresh per minute per endpoint)

### Audit Log Truncation

**Issue:** Very long usernames or token claims could create oversized audit log entries
- Files: `pam-unix-oidc/src/audit.rs`
- Impact: Audit log file could grow unexpectedly large
- Fix approach: Truncate sensitive fields in logs (e.g., username max 256 chars, claims summary)

---

## Scaling Limits

### Single-Server JTI Replay Cache

**Issue:** In-memory JTI cache doesn't work in distributed PAM deployments (multiple servers)
- Current capacity: 100k entries
- Limit: One server can't see tokens validated on another server
- Scaling path: Implement Redis backend option for distributed deployments
- Scope: Add `--redis` configuration option; implement trait for pluggable JTI stores

### Rate Limiter Not Distributed

**Issue:** Rate limiting is per-server; attacker can bypass by hitting different servers
- Impact: Coordinated attacks across load-balanced servers not detected
- Scaling path: Central rate limit store (Redis, shared cache)
- Current behavior: Acceptable for single-server deployments

### JWKS Caching Causes Thundering Herd

**Issue:** All PAM processes refresh JWKS cache at TTL expiration simultaneously
- Impact: Potential spike of requests to IdP at cache expiration time
- Severity: Low - unlikely to cause real problems with typical IdP load
- Fix approach: Add jitter to cache TTL expiration (e.g., 300s ± 30s)

---

## Dependencies at Risk

### `reqwest` With Default-Features Disabled

**Issue:** Custom feature set may miss critical security patches in transitive deps
- Current: `default-features = false, features = ["blocking", "json", "rustls-tls"]`
- Risk: Selective feature deps harder to maintain
- Mitigation: Feature set is conservative (rustls over OpenSSL); audit regularly
- Recommendation: Document why default features disabled; keep dependency audit in CI

### `jsonwebtoken` v9.0

**Status:** Stable, well-maintained crate with active security handling
- Security: Uses `ring` for cryptography; no known recent CVEs
- Recommendation: Continue tracking for updates; currently appropriate

### `p256` and `ecdsa` Crates

**Status:** Used for DPoP signing; critical security path
- Auditing: These are RustCrypto maintained, good track record
- Recommendation: Lock to specific versions; test on each update before deploying

---

## Deployment Configuration Risks

### No Validation of OIDC_ISSUER Format

**Issue:** `unix-oidc-agent/src/main.rs` accepts arbitrary issuer URLs without validation
- Files: `unix-oidc-agent/src/main.rs` (lines 274-278)
- Risk: Typos in OIDC_ISSUER could cause authentication to fail silently or against wrong IdP
- Fix approach: Validate issuer URL format; perform OIDC discovery to verify endpoint accessibility
- Impact: Low - caught during login, but poor UX

### Break-Glass Account Not Enforced

**Issue:** Deployment documentation recommends but doesn't require break-glass account configuration
- Impact: Production systems could be deployed without recovery path
- Severity: **CRITICAL** - system lockout risk
- Fix approach: PAM module should refuse to initialize without verified break-glass account
- Recommendation: Add `--verify-break-glass` flag to pre-deployment check tool

---

## Test Coverage Gaps

### No Tests for DPoP Nonce Binding

**Issue:** Nonce validation in DPoP proofs may not be fully tested
- Impact: Nonce reuse attacks possible if implementation has gaps
- Test needed: Verify proofs with mismatched nonce are rejected

### Insufficient Error Path Testing

**Issue:** Most tests cover happy path; error handling for network failures, malformed tokens, etc. incomplete
- Impact: Unknown behavior under adverse conditions
- Files needing coverage:
  - `pam-unix-oidc/src/oidc/jwks.rs` - JWKS fetch failures
  - `pam-unix-oidc/src/device_flow/client.rs` - Device flow timeouts/failures
  - `unix-oidc-agent/src/daemon/socket.rs` - Connection drops, protocol errors

### No Fuzzing for Token Parsing

**Issue:** JWT tokens, DPoP proofs fuzzed minimally
- Impact: Malformed but structurally valid tokens might expose panics
- Fix approach: Use `cargo fuzz` targets for:
  - JWT parsing and validation
  - DPoP proof verification
  - Configuration parsing

---

## Missing Critical Features

### No Token Revocation API

**Issue:** `run_logout()` stub doesn't implement token revocation
- Impact: Revoked tokens might still be valid until expiration
- Risk: If agent storage is stolen, tokens remain valid for their full lifetime
- Fix approach: Call OAuth2 revocation endpoint during logout
- Standards: RFC 7009 - OAuth 2.0 Token Revocation

### No Session Invalidation on Server

**Issue:** No mechanism to invalidate user's sessions across all SSH servers
- Impact: Can't force re-authentication or revoke all access at once
- Scaling path: Central session store; server-side session revocation endpoint
- Note: Out of scope for single-server deployments but needed for enterprises

### Incomplete Approval Workflow Implementation

**Issue:** Webhook approval provider exists but other promised providers (Slack, Teams, PagerDuty) not implemented
- Files: `pam-unix-oidc/src/approval/webhook.rs`
- Impact: Enterprises can't use preferred notification channels
- Documentation: Security roadmap promises these providers
- Fix approach: Implement trait-based provider system; add community contributions for each provider

---

## Known Bugs / Quirks

### Clock Skew Tolerance Hard-Coded at 60 Seconds

**Issue:** `pam-unix-oidc/src/oidc/validation.rs` uses fixed 60s clock skew tolerance
- Files: `pam-unix-oidc/src/oidc/validation.rs`
- Impact: Can't adjust for deployments with worse clock synchronization
- Fix approach: Make configurable via `policy.yaml`
- Severity: Low - 60s is reasonable for most deployments

### `utf8_lossy()` Used for Username Extraction

**Issue:** Invalid UTF-8 in token claims silently converts to replacement characters
- Files: Various validation code
- Impact: Usernames with invalid UTF-8 accepted without warning
- Severity: Low - should be rare with standard IdPs
- Fix approach: Reject tokens with invalid UTF-8 in critical claims

---

*Concerns audit: 2026-03-10*
