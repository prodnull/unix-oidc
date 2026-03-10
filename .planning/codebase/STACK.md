# Technology Stack

**Analysis Date:** 2026-03-10

## Languages

**Primary:**
- **Rust** 1.88 (MSRV) → Latest stable - Core PAM module, OIDC agent, DPoP implementation
  - Crate types: CDylib for PAM module, Binary for CLI agent
  - Workspace structure: Multi-crate for clean separation of concerns

**Secondary:**
- **Python** 3.9+ - DPoP cross-language reference implementation and testing
  - Build: Hatchling
- **Go** 1.21 - DPoP cross-language library and testing
- **Bash** - Test scripts, CI/CD workflows

## Runtime

**Environment:**
- **Linux** (Primary deployment target)
  - Ubuntu 22.04 LTS (primary CI target)
  - Ubuntu 24.04 LTS (secondary CI target)
  - RHEL 9 / Rocky 9 (community testing)
  - Debian 12 (community testing)
  - Amazon Linux 2023 (community testing)
- **macOS** (Agent only, no PAM support)
  - macOS 14 Apple Silicon (aarch64)

**PAM System:**
- **libpam** (libpam0g-dev on Debian, pam-devel on RHEL)
- **SSSD** integration for user lookup and group management
- **OpenLDAP** for directory integration (in tests)

**Package Manager:**
- **Cargo** (Rust default)
- **Lockfile:** `Cargo.lock` present for reproducible builds

## Frameworks

**Core Async Runtime:**
- **Tokio** 1.0 (full features) - Async task scheduling for I/O-bound operations
  - Used in agent for concurrent token operations
  - Blocking client in PAM module for synchronous context

**Web/HTTP:**
- **Reqwest** 0.11 - HTTP client for OIDC endpoints and webhooks
  - Blocking variant in PAM module (PAM requires synchronous)
  - JSON support enabled
  - TLS via rustls (no OpenSSL dependency)
- **Axum** 0.7 - Web framework for webhook server example (`examples/webhook-server`)

**Cryptography:**
- **P256** 0.13 - NIST P-256 elliptic curve cryptography (DPoP proofs)
  - Features: ECDSA, JWK serialization
- **SHA2** 0.10 - SHA-256 hash for JWK thumbprints
- **Base64** 0.21 - Standard base64 encoding (URL-safe variant)

**JWT/OIDC:**
- **jsonwebtoken** 9.0 - JWT parsing, validation, claim extraction
  - Used for token signature verification against JWKS
  - Algorithm enforcement (ES256 hardcoded for DPoP, validated against issuer for ID tokens)

**CLI:**
- **Clap** 4 (derive) - Command-line argument parsing (agent)

**Storage & Keying:**
- **Keyring** 3 - System keychain integration (agent)
  - Linux: D-Bus integration
  - macOS: Keychain
- **Directories** 5 - XDG Base Directory Specification compliance
- **Dirs** 5 - Cross-platform config/cache directory resolution

**Serialization:**
- **Serde** 1.0 (derive feature) - Serialization framework
- **Serde_json** 1.0 - JSON serialization for OIDC claims and token validation
- **Serde_yaml** 0.9 - YAML for policy configuration files

**System Integration:**
- **Libc** 0.2 - Low-level C bindings for PAM integration
- **Pamsm** 0.5 (libpam feature) - Type-safe PAM module bindings
- **Uzers** 0.12 - Unix user/group enumeration
- **Syslog** 6.1 - Audit logging to system log
- **Gethostname** 0.4 - Hostname resolution for server identification

**Testing:**
- **Tokio-test** 0.4 - Testing utilities for async code
- **Tempfile** 3.0 - Temporary file/directory creation in tests

**Observability:**
- **Tracing** 0.1 - Structured logging and instrumentation
- **Tracing-subscriber** 0.3 (json feature) - Trace output formatting
  - Environment filtering support

**Error Handling:**
- **Thiserror** 1.0 (latest thiserror 2.0 in dpop crate) - Ergonomic error types
- **Anyhow** 1.0 - Flexible error context for applications

**Utilities:**
- **Chrono** 0.4 (serde feature) - DateTime handling for token expiration checks
- **UUID** 1 (v4 feature) - UUID generation for JTI (JWT ID) claims and request IDs
- **Once_cell** 1.19 - Lazy static initialization for JWKS caching and DPoP replay cache
- **Getrandom** 0.3 - Cryptographically secure random generation
- **Subtle** 2.5 - Constant-time comparison for security-sensitive data (DPoP validation)
- **URL** 2.5 - URL parsing and manipulation for OIDC endpoints

## Configuration

**Environment:**
- **OIDC_ISSUER** - Identity provider URL (required)
  - Format: `https://provider.example.com/realm` or `http://localhost:8080/realms/test`
- **OIDC_CLIENT_ID** - OAuth 2.0 client identifier (default: `unix-oidc`)
- **UNIX_OIDC_SOCKET** - Unix domain socket path for agent daemon (optional)
- **UNIX_OIDC_TEST_MODE** - Enable insecure test mode (never in production)
  - Bypasses JWT signature verification
  - Environment variable check: string comparison for `"1"` or `"true"`

**Configuration Files:**
- **`/etc/unix-oidc/policy.yaml`** - PAM policy configuration
  - Host classification (standard, elevated, critical)
  - SSH and sudo requirements
  - Step-up authentication configuration
  - Command-specific rules and ACR enforcement
  - YAML format with serde_yaml parsing
- **`~/.config/unix-oidc/config.yaml`** - Agent configuration (XDG convention)
  - Issuer and client ID
  - Crypto algorithm settings (PQC future support)
  - Socket path override

**Build:**
- **Rust edition:** 2021
- **Features:**
  - `test-mode` - Insecure testing only (PAM module)
  - `client` (default) - Client-side DPoP proof generation
  - `server` (default) - Server-side DPoP validation with replay protection
- **Workspace members:**
  - `pam-unix-oidc` - Core PAM module
  - `unix-oidc-agent` - Client-side token acquisition
  - `examples/webhook-server` - Demo approval server
  - Excluded: `fuzz/` (fuzzing targets, separate build)

## Platform Requirements

**Development:**
- Rust 1.88+ (via rustup)
- Linux with PAM development headers (`libpam0g-dev`, `libpam-dev`, or `pam-devel`)
- OpenSSL development headers (`libssl-dev` or `openssl-devel`)
- `pkg-config` for dependency resolution
- Cargo for building

**Testing:**
- Docker / Docker Compose for containerized test environments
- Keycloak 24.0 for OIDC provider testing
- OpenLDAP 1.5.0 for directory integration testing
- jq for JSON parsing in test scripts
- ldap-utils for LDAP connectivity tests
- cargo-audit for security audits (auto-installed)
- cargo-llvm-cov for code coverage
- cargo-sbom for SBOM generation

**Production:**
- Linux kernel with PAM support
- SSSD daemon for user provisioning and caching
- Network access to OIDC issuer over HTTPS
- TLS/X.509 infrastructure for certificate validation
- NTP synchronization for clock skew tolerance (JWT validation)
- Syslog daemon for audit logging

## Dependency Highlights

**Security-Critical:**
- `jsonwebtoken` 9.0 - JWT signature verification against IdP JWKS
- `p256` 0.13 - Cryptographic operations for DPoP binding
- `subtle` 2.5 - Constant-time comparison for token/proof validation
- `ring` / `rustls` - Transitive: TLS for HTTPS connections

**DPoP Specific:**
- NIST P-256 (secp256r1) exclusively - Hardcoded in DPoP proofs
- ES256 algorithm - Only accepted algorithm for DPoP proofs
- RFC 9449 compliance with replay protection via JTI caching

**OIDC Standard:**
- OpenID Connect Core 1.0 and Discovery
- OAuth 2.0 Device Authorization Grant (RFC 8628)
- JWT/JWS/JWKS handling per RFC 7515/7517/7518

---

*Stack analysis: 2026-03-10*
