# CLAUDE.md - AI Assistant Guide for unix-oidc

This document provides comprehensive context for AI assistants (Claude, Copilot, Cursor, etc.) working on the unix-oidc project. It captures our philosophy, architecture decisions, security invariants, and the reasoning behind key design choices.

## Project Philosophy

### Security Should Not Be Annoying

The fundamental premise of unix-oidc is that **security and usability are not opposing forces**. When security is annoying, people circumvent it. When it's an IT burden, organizations disable it. We believe:

- **Authentication should be invisible when possible** - Single sign-on means users authenticate once and work seamlessly
- **Step-up authentication should feel natural** - When elevated privileges are needed, the flow should be quick and intuitive
- **Configuration should have sensible defaults** - Secure out of the box, with knobs for enterprise customization
- **Failure modes should be clear** - When something goes wrong, the user should understand why and how to fix it

**Important clarification**: "Security shouldn't be annoying" does NOT mean "if security is annoying, disable it." It means **find a better UX**. The response to friction is always to improve the experience while maintaining security, never to remove the security check.

### Conservative Security, Pragmatic Usability

We follow the principle of **defense in depth with graceful degradation**:

1. **Default to the most secure option** that doesn't break legitimate use cases
2. **Warn before rejecting** when encountering edge cases (e.g., missing JTI claims)
3. **Make security configurable** for enterprises with different risk profiles (see issue #10)
4. **Never silently fail** - if a security check can't be performed, log it prominently

This means we might accept a token with a missing JTI claim (with a warning) rather than lock out a user whose IdP doesn't implement that optional field - but we make it configurable so strict environments can enforce it.

### The Problem We're Solving

Traditional Unix authentication has a fundamental disconnect with modern identity:

- **SSH keys get copied, shared, and never rotated** - That key on a developer's laptop from 2019? Still works.
- **When someone leaves, finding all their access is archaeology** - authorized_keys files scattered across servers
- **Enterprise MFA stops at the browser** - You need MFA for email but not for root access to production?
- **Compliance is painful** - "Show me who accessed what" requires parsing logs from dozens of sources

unix-oidc bridges this gap by bringing OIDC (the same protocol behind "Sign in with Google/Microsoft/Okta") to Linux PAM, with DPoP token binding to prevent token theft.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User's Machine                               │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │ SSH Client  │───▶│ oidc-ssh-agent   │───▶│ Identity Provider │  │
│  └─────────────┘    │ (token + DPoP)   │    │ (Okta/Azure/etc)  │  │
│                     └──────────────────┘    └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              │ SSH with token in env/keyboard-interactive
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                         Linux Server                                 │
│  ┌─────────────┐    ┌──────────────────┐    ┌───────────────────┐  │
│  │   sshd      │───▶│  PAM Module      │───▶│ Token Validation  │  │
│  └─────────────┘    │ (pam_unix_oidc)  │    │ + DPoP Verify     │  │
│                     └──────────────────┘    └───────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Location | Purpose |
|-----------|----------|---------|
| `pam-unix-oidc` | `/pam-unix-oidc/` | Core PAM module (Rust) |
| `oidc-ssh-agent` | `/oidc-ssh-agent/` | Client-side token acquisition |
| DPoP Libraries | `/*-oauth-dpop/` | Cross-language DPoP implementation |

### Why DPoP (Demonstrating Proof of Possession)?

Standard OAuth tokens are bearer tokens - anyone who has them can use them. DPoP (RFC 9449) adds cryptographic binding:

1. Client generates an ephemeral key pair
2. Each request includes a proof signed with the private key
3. Server verifies the proof matches the token's thumbprint
4. **Even if an attacker intercepts the token, they can't use it** without the private key

This is the same protection used by banking APIs and is critical for SSH where tokens might traverse untrusted networks.

## Security Invariants

These invariants MUST be maintained. Violating them is a security vulnerability.

### DPoP Validation (`pam-unix-oidc/src/oidc/dpop.rs`)

1. **JWK thumbprint computation uses canonical values**
   ```rust
   // CORRECT: Hardcoded canonical values
   let canonical = format!(
       r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
       jwk.x, jwk.y
   );

   // WRONG: Using user-supplied kty/crv
   // An attacker could supply "kty":"oct" to change the thumbprint
   ```

2. **JTI (JWT ID) uniqueness for replay protection**
   - Each DPoP proof must have a unique `jti` claim
   - The JTI cache has a size limit (100k entries) to prevent DoS
   - Cache cleanup removes expired entries before rejecting new proofs

3. **Proof timing validation**
   - `iat` (issued at) must be recent (within clock skew tolerance)
   - `exp` (expiration) must be in the future
   - These prevent replay of old proofs

4. **HTTP method and URI binding**
   - DPoP proof is bound to specific `htm` (HTTP method) and `htu` (HTTP URI)
   - Prevents using a proof from one endpoint on another

5. **Algorithm enforcement is non-negotiable**
   - DPoP proofs MUST use ES256 (P-256 ECDSA) - never accept `alg: "none"` or symmetric algorithms
   - This prevents algorithm confusion attacks where an attacker tricks the verifier into using a weaker algorithm
   - ID tokens should be validated against the algorithm specified in JWKS, not the token header
   - Never allow user-controlled algorithm selection

### Token Validation (`pam-unix-oidc/src/oidc/validation.rs`)

1. **Issuer validation** - Token must come from configured IdP
2. **Audience validation** - Token must be intended for this service
3. **Signature verification** - Using IdP's published JWKS
4. **Expiration check** - Token must not be expired
5. **DPoP binding** - If token has `cnf` claim, DPoP proof must match

### JWKS Caching Security

The JWKS (JSON Web Key Set) cache has security implications:

1. **Cache TTL should survive IdP transient failures** - If IdP is briefly unavailable, cached keys allow continued operation
2. **Key rollover support** - Old keys should remain valid during IdP key rotation (typically IdPs publish new keys before using them)
3. **TLS validation is mandatory** - JWKS endpoint must be fetched over HTTPS with proper certificate validation to the expected issuer
4. **Cache poisoning prevention** - Only cache keys from the configured issuer URL, never from token claims

### Security Check Decision Matrix

**HARD-FAIL (Never Optional)** - These checks can NEVER be skipped or made lenient:

| Check | Reason |
|-------|--------|
| Signature verification | Attacker can forge any token |
| Issuer validation | Attacker can use token from malicious IdP |
| Audience validation | Token meant for another service accepted |
| Expiration check | Stolen tokens valid forever |
| Algorithm enforcement | Algorithm confusion attacks |

**WARN-AND-ALLOW (Configurable per Issue #10)** - These can be lenient for compatibility:

| Check | Default | Reason for flexibility |
|-------|---------|----------------------|
| JTI presence | warn | Some IdPs don't implement this optional claim |
| ACR/AMR claims | warn | Not all IdPs support authentication context |
| DPoP binding | configurable | Legacy clients may not support DPoP |

**IMPORTANT**: When adding new security checks, explicitly decide which category they belong to and document the reasoning.

### PAM Module Constraints

1. **No panics** - A panic in PAM can lock users out of their system
2. **Timeout handling** - Network calls must have timeouts
3. **Graceful degradation** - If OIDC fails, don't brick the system
4. **Audit logging** - All authentication attempts must be logged

### CRITICAL: Test Mode Security

> ⚠️ **NEVER ENABLE TEST MODE IN PRODUCTION** ⚠️

The `test-mode` feature flag and `UNIX_OIDC_TEST_MODE` environment variable **completely bypass signature verification**. This allows ANY attacker to forge tokens with arbitrary claims.

```rust
// This function exists for testing ONLY
// It skips ALL cryptographic verification
pub fn new_insecure_for_testing() -> Self { ... }
```

**Requirements:**
- Production binaries MUST be built without `--features test-mode`
- CI/CD pipelines SHOULD verify test features are not present in release builds
- Never recommend enabling test mode "for debugging" in production - use proper logging instead
- The environment variable check should use explicit string comparison (e.g., `== "1"` or `== "true"`), not just presence checking

## Coding Conventions

### Rust Idioms

```rust
// Use thiserror for error types
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("Token expired at {0}")]
    TokenExpired(DateTime<Utc>),

    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },
}

// Use tracing for structured logging
tracing::info!(
    username = %claims.preferred_username,
    issuer = %claims.iss,
    "Authentication successful"
);

// Prefer explicit error handling over unwrap/expect in production paths
let token = token_str.parse::<Token>()
    .map_err(|e| ValidationError::MalformedToken(e.to_string()))?;
```

### Error Handling Philosophy

1. **In PAM paths**: Never panic, always return PAM error codes
2. **In CLI tools**: Can panic on truly unrecoverable errors (OOM, etc.)
3. **Log before returning errors**: The caller might not log details
4. **Include context**: "Failed to validate token" is useless; include why

### Security-Sensitive Code

When modifying security-sensitive code:

1. **Add comments explaining the security rationale**
2. **Reference relevant RFCs or CVEs** when applicable
3. **Consider timing attacks** for comparison operations
4. **Use constant-time comparison** for secrets

```rust
// Security: Use constant-time comparison to prevent timing attacks
use subtle::ConstantTimeEq;
if !expected_hash.ct_eq(&actual_hash).into() {
    return Err(ValidationError::InvalidSignature);
}
```

## Testing Requirements

### Test Matrix

| Platform | Status | Notes |
|----------|--------|-------|
| Ubuntu 22.04 | ✅ CI | Primary development target |
| Ubuntu 24.04 | ✅ CI | |
| RHEL 9 / Rocky 9 | 🧪 Community | SELinux considerations |
| Debian 12 | 🧪 Community | |
| Amazon Linux 2023 | 🧪 Community | |

| Provider | Status | Notes |
|----------|--------|-------|
| Keycloak | ✅ CI | Docker-based integration tests |
| Auth0 | ✅ CI | Requires secrets |
| Google Cloud Identity | ✅ CI | Requires secrets |
| Azure AD | 🧪 Community | Needs testing |
| Okta | 🧪 Community | Needs testing |

### Writing Tests

```rust
#[test]
fn test_dpop_proof_validation() {
    // Arrange: Set up test fixtures
    let proof = create_test_proof();
    let validator = DpopValidator::new();

    // Act: Perform the operation
    let result = validator.validate(&proof);

    // Assert: Check expectations
    assert!(result.is_ok());
}

#[test]
fn test_rejects_replayed_proof() {
    // Security test: Verify replay protection works
    let proof = create_test_proof();
    let validator = DpopValidator::new();

    // First use should succeed
    assert!(validator.validate(&proof).is_ok());

    // Second use should fail (replay)
    assert!(matches!(
        validator.validate(&proof),
        Err(DpopError::ReplayedProof)
    ));
}
```

### Security Testing

- **Fuzz testing**: `cargo fuzz` targets in `/fuzz/`
- **Dependency audit**: `cargo audit` in CI
- **SAST**: CodeQL analysis
- **Secret scanning**: Prevent credential leaks

## Deployment and Operations

### Break-Glass Access is MANDATORY

> ⚠️ **Never deploy OIDC authentication as the ONLY authentication path** ⚠️

Before deploying unix-oidc to production servers:

1. **Configure a local break-glass account** - See `break_glass` in policy.yaml
2. **Test break-glass access works** when OIDC is disabled/unreachable
3. **Document credentials** in your organization's emergency procedures (secure vault, not wiki)
4. **Consider hardware tokens** (YubiKey) for break-glass authentication
5. **Regularly test break-glass** - Include in quarterly DR exercises

Getting locked out of servers because your IdP is down is a catastrophic, career-affecting failure mode. Plan for it.

### Operational Failure Modes

| Failure | Symptom | Resolution |
|---------|---------|------------|
| IdP unreachable | "Connection refused" or timeout errors | Check network, IdP status; break-glass if needed |
| JWKS endpoint error | "Failed to fetch JWKS" | IdP certificate issue or endpoint changed; check IdP config |
| Clock skew | "Token not yet valid" or "Token expired" (for fresh tokens) | Sync NTP; check server/client clocks |
| Certificate expiration | TLS errors to IdP | IdP needs to renew certs; temporary workaround via break-glass |
| User not provisioned | "User not found" after successful OIDC | Check SSSD/LDAP sync; verify username mapping |
| Rate limited | "Too many authentication attempts" | Wait for cooldown; check for brute force attacks |

### Log Locations and Troubleshooting

```bash
# PAM authentication logs (most Linux distros)
journalctl -u sshd -f
tail -f /var/log/auth.log      # Debian/Ubuntu
tail -f /var/log/secure        # RHEL/CentOS

# Check PAM module is loaded
grep pam_unix_oidc /etc/pam.d/sshd

# Verify OIDC configuration
cat /etc/unix-oidc/config.yaml

# Test IdP connectivity (from server)
curl -v https://your-idp.com/.well-known/openid-configuration

# Check for clock skew
date && curl -I https://your-idp.com 2>&1 | grep -i date
```

### Rollback Procedure

If the PAM module has issues, quickly revert:

```bash
# Option 1: Disable the PAM module (keeps it installed)
# Edit /etc/pam.d/sshd and comment out the pam_unix_oidc line
sudo sed -i 's/^auth.*pam_unix_oidc/#&/' /etc/pam.d/sshd

# Option 2: Uninstall completely
sudo rm /lib/security/pam_unix_oidc.so  # or /lib64/security/
sudo rm /etc/pam.d/unix-oidc  # if using include

# Option 3: Use break-glass account to access and fix
ssh breakglass@server  # Uses local password auth
```

**Pre-deployment checklist:**
- [ ] Break-glass account configured and tested
- [ ] Rollback procedure documented and accessible
- [ ] On-call team knows rollback steps
- [ ] Monitoring alerts for auth failures configured

### Error Message Verbosity

Security vs. debugging tradeoff for error messages:

**External-facing (returned to user/client):**
- Generic: "Authentication failed" - don't reveal why
- Never expose: internal paths, stack traces, IdP configuration details
- OK to include: request ID for correlation with logs

**Internal logs (server-side):**
- Verbose: Include full error details, token claims (excluding signatures), timing
- Structured logging: Use tracing spans for correlation
- Sensitive data: Never log full tokens, passwords, or private keys

```rust
// GOOD: Generic to user, detailed in logs
tracing::warn!(
    error = %e,
    username = %attempted_username,
    client_ip = %peer_addr,
    "Authentication failed"
);
return Err(AuthError::AuthenticationFailed);  // Generic

// BAD: Leaks information to attacker
return Err(AuthError::InvalidSignature(format!(
    "Expected key {} but got {}", expected_kid, actual_kid
)));
```

## Adding New OIDC Providers

### What's Needed

1. **Discovery endpoint** - Most providers support `/.well-known/openid-configuration`
2. **JWKS endpoint** - For token signature verification
3. **Supported claims** - `preferred_username`, `email`, `sub` at minimum
4. **DPoP support** - Check if provider supports RFC 9449 (optional but recommended)

### Integration Test Template

```rust
#[tokio::test]
#[ignore = "Requires NewProvider credentials"]
async fn test_newprovider_integration() {
    let config = ProviderConfig {
        issuer: "https://newprovider.com".into(),
        client_id: env::var("NEWPROVIDER_CLIENT_ID").unwrap(),
        // ...
    };

    // Test discovery
    let metadata = discover_metadata(&config.issuer).await.unwrap();
    assert!(metadata.token_endpoint.is_some());

    // Test token validation
    // ...
}
```

### Common Provider Quirks

| Provider | Quirk | Workaround |
|----------|-------|------------|
| Azure AD | `preferred_username` might be UPN not username | Username mapping config |
| Okta | Custom authorization server URLs | Configurable issuer |
| Google | Limited custom claims | Use `email` as identifier |
| Keycloak | Highly configurable but needs setup | Provide Docker Compose |

## Future Evolution

### OAuth/OIDC Landscape

The identity landscape is evolving. Be prepared for:

1. **IETF drafts becoming RFCs** - DPoP was draft, now RFC 9449
2. **New token binding mechanisms** - Watch for alternatives to DPoP
3. **Passkey/WebAuthn integration** - May complement OIDC flows
4. **Decentralized identity** - DIDs and verifiable credentials
5. **Post-quantum considerations** - Current EC curves may need replacement

### Configurable Security Modes (Issue #10)

We're moving toward configurable enforcement:

```toml
[security]
# strict: Reject anything suspicious
# warn: Log warnings but allow (current default)
# disabled: Skip check entirely (not recommended)
jti_enforcement = "warn"
dpop_required = "strict"
```

This allows enterprises to:
- Start permissive and tighten over time
- Accommodate IdPs with varying RFC compliance
- Meet different compliance requirements

### Planned Enhancements

- [ ] SCIM integration for user provisioning
- [ ] Group-based access policies
- [ ] Session management (revocation)
- [ ] Hardware key attestation
- [ ] Centralized audit log shipping

## Working with This Codebase

### Quick Start for Contributors

```bash
# Build everything
cargo build --workspace

# Run tests (unit + integration where possible)
cargo test --workspace

# Run specific PAM module tests
cargo test -p pam-unix-oidc

# Check for security issues
cargo audit
cargo clippy -- -D warnings

# Format code
cargo fmt --all
```

### Key Files to Understand

| File | Purpose | Security-Critical |
|------|---------|-------------------|
| `pam-unix-oidc/src/lib.rs` | PAM entry points | ⚠️ Yes |
| `pam-unix-oidc/src/oidc/dpop.rs` | DPoP validation | ⚠️ Yes |
| `pam-unix-oidc/src/oidc/validation.rs` | Token validation | ⚠️ Yes |
| `pam-unix-oidc/src/config.rs` | Configuration parsing | Moderate |
| `oidc-ssh-agent/src/main.rs` | Client CLI | Moderate |

### Common Tasks

**Adding a new configuration option:**
1. Add to `config.rs` with appropriate defaults
2. Update example configs in `examples/`
3. Document in README and man pages
4. Consider security implications

**Fixing a security issue:**
1. Create a private security advisory first (if applicable)
2. Write a test that demonstrates the vulnerability
3. Fix with minimal changes
4. Document the fix with CVE/advisory reference
5. Consider backporting to maintenance branches

**Updating dependencies:**
1. Run `cargo update` for patch updates
2. For major updates, check changelogs for breaking changes
3. Run full test suite
4. Check for new security advisories

### Dependency Evaluation Criteria

For a security-critical PAM module, new dependencies require scrutiny:

**Before adding a dependency, evaluate:**

| Criterion | Questions to Ask |
|-----------|-----------------|
| **Necessity** | Can we do this with std or existing deps? Is the complexity worth it? |
| **Maintenance** | Active maintainer? Recent commits? Responsive to issues? |
| **Security track record** | Past CVEs? How were they handled? Security policy? |
| **Supply chain** | Reputable author/org? Verified on crates.io? |
| **Transitive deps** | What does it pull in? Any known-bad dependencies? |
| **Size/complexity** | Is it minimal or kitchen-sink? More code = more attack surface |

**Trusted dependencies** (well-audited, critical path):
- `ring` / `rustls` - Cryptographic operations
- `jsonwebtoken` - JWT parsing and validation
- `tokio` - Async runtime
- `tracing` - Logging infrastructure

**Extra scrutiny required** (directly handles untrusted input):
- Any new JWT/JOSE library
- Any new HTTP client
- Any serialization library (serde is fine, others need review)

**Responding to dependency CVEs:**
1. Assess impact - does the vulnerability affect our usage?
2. Check if patched version exists
3. If no patch: evaluate workaround or temporary fork
4. Update ASAP, don't wait for scheduled dependency updates
5. Document the CVE response in commit message

## Philosophy Reminders

When making decisions, remember:

1. **Would this annoy a user trying to do their job?** - If yes, find a better way
2. **Would this create work for IT admins?** - If yes, automate it
3. **What's the most conservative option that still works?** - Default to that
4. **If this fails, how does the user recover?** - Make it obvious
5. **Would we be comfortable if this code was audited?** - Write for scrutiny

## Contact and Contribution

- **Issues**: GitHub Issues for bugs and features
- **Security**: See SECURITY.md for vulnerability reporting
- **Testing**: See `docs/community-testing-guide.md` for testing on various platforms

---

*This document is part of the unix-oidc project and should evolve with the codebase. When making significant architectural changes, please update this guide.*
