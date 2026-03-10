# External Integrations

**Analysis Date:** 2026-03-10

## APIs & External Services

**OpenID Connect (OIDC) Providers:**
- **Keycloak 24.0** - Primary test and integration target
  - Discovery endpoint: `/.well-known/openid-configuration`
  - JWKS endpoint: `/protocol/openid-connect/certs`
  - Device authorization: `/protocol/openid-connect/auth/device`
  - Client: Configuration via `OIDC_ISSUER` environment variable
  - Used in: `docker-compose.test.yaml`, CI provider tests

- **Auth0** - Cloud provider support (requires secrets)
  - Discovery: `https://{domain}/.well-known/openid-configuration`
  - JWKS: Auto-discovered from metadata
  - Client: SDK `jsonwebtoken` with issuer validation
  - Integration test: `.github/workflows/provider-tests.yml`
  - Env: `AUTH0_DOMAIN` (GitHub secret)

- **Google Cloud Identity** - Public endpoint testing
  - Discovery: `https://accounts.google.com/.well-known/openid-configuration`
  - JWKS: `https://www.googleapis.com/oauth2/v3/certs`
  - Client: Standard OIDC via `reqwest`
  - Integration test: `.github/workflows/provider-tests.yml`
  - Algorithm support: RS256

## Authentication & Token Management

**Token Validation:**
- Location: `pam-unix-oidc/src/oidc/validation.rs`
- Implements: JWT signature verification against JWKS
- Claims validated:
  - `iss` (issuer) - Must match configured IdP
  - `aud` (audience) - Must include this service
  - `exp` (expiration) - Must be in future
  - `iat` (issued at) - Within clock skew tolerance
  - `sub` (subject) - User identifier
  - `preferred_username` - Unix username mapping
  - `email` - Secondary identifier
  - `cnf` (confirmation) - DPoP thumbprint binding (optional)
  - `auth_time` - Authentication event age (policy-configurable)
  - `acr` (Authentication Context Class Reference) - MFA level (optional, policy-enforced)

**DPoP (Demonstrating Proof of Possession):**
- Location: `pam-unix-oidc/src/oidc/dpop.rs`
- RFC: RFC 9449 compliance
- Implementation: `p256` ECDSA with SHA-256 thumbprints
- Proof validation:
  - JWK thumbprint computation (canonical JSON format)
  - JTI (JWT ID) replay detection via cache
  - Proof timing (`iat`, `exp` within bounds)
  - HTTP method/URI binding (`htm`, `htu`)
  - Algorithm enforcement: ES256 only
- Cross-language libraries:
  - Rust: `rust-oauth-dpop/` - Published as `oauth-dpop` crate
  - Python: `python-oauth-dpop/` - Hatchling build, cryptography 41.0.0+
  - Go: `go-oauth-dpop/` - Go 1.21+, google/uuid dependency
  - Java: `java-oauth-dpop/` - Gradle build (noted in Dependabot)
  - Cross-language test suite: `dpop-cross-language-tests/`

## User Directory Integration

**SSSD (System Security Services Daemon):**
- Location: `pam-unix-oidc/src/sssd/`
- Purpose: User provisioning, group lookup, caching
- Files: `src/sssd/mod.rs`, `src/sssd/user.rs`
- Configuration: `test/fixtures/sssd/sssd.conf`
- Functions:
  - User enumeration via SSSD D-Bus
  - Group membership queries
  - Home directory resolution
  - Shell configuration

**OpenLDAP (Testing Only):**
- Version: 1.5.0 (via osixia/openldap container)
- Used in: Integration tests for LDAP user lookup
- Configuration: `test/fixtures/ldap/01-users.ldif`
- Container network: Part of `docker-compose.test.yaml`
- Access: ldap://openldap:389, dc=test,dc=local

**Local Unix Users:**
- Fallback user lookup via `libc` and `uzers` crate
- Files: `/etc/passwd`, `/etc/group`
- Break-glass account support for IdP unavailability

## Device Authorization Flow

**OAuth 2.0 Device Authorization Grant:**
- RFC: RFC 8628
- Purpose: Step-up authentication without interrupting SSH session
- Location: `pam-unix-oidc/src/device_flow/`
- Flow:
  1. PAM module initiates device flow: `POST /auth/device` to IdP
  2. Device code, user code, and verification URI returned
  3. User completes authorization in browser (out-of-band)
  4. PAM polls token endpoint: `POST /token` with device code
  5. Token returned after user approval
- Configuration: `examples/policy.yaml`
  - Allowed methods: device_flow, webauthn (future)
  - Timeout: 300 seconds default
  - Grace period: Skip re-auth for command class (configurable)

## Step-Up Authentication

**Webhook Approval Integration:**
- Location: `pam-unix-oidc/src/approval/webhook.rs`
- Purpose: Custom approval workflows for sensitive operations
- Client: `reqwest::blocking` HTTP client
- Example server: `examples/webhook-server/`
  - Framework: Axum 0.7
  - Routes: `POST /approve`, `GET /status/{id}`
  - Database: In-memory (demo only)
- Webhook protocol:
  - POST with JSON: `{ command: "/usr/bin/apt", user: "alice", timestamp: "..." }`
  - Response: `{ approved: true, expires_at: "..." }`
  - Timeout: Policy-configurable (default 5 minutes)

## Audit Logging

**Syslog Integration:**
- Location: `pam-unix-oidc/src/audit.rs`
- Client: `syslog` crate 6.1
- Log facility: AUTH (PAM default)
- Events logged:
  - Successful authentication with username and issuer
  - Failed authentication attempts
  - Token validation errors
  - DPoP proof validation failures
  - Device flow initiated/completed
  - Approval status (approved/denied)
  - Clock skew and timing issues
- Format: Structured with username, issuer, timestamps

**System Log Locations:**
- Linux: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL)
- Access: `journalctl -u sshd -f` or direct file tail

## Data Storage

**JWKS Caching:**
- Location: `pam-unix-oidc/src/oidc/jwks.rs`
- Purpose: Offline OIDC provider key management
- Implementation: `once_cell::sync::Lazy` static cache
- Cache strategy:
  - TTL: Configurable, survives IdP transient failures
  - Refresh: Triggered on key verification failure (kid not found)
  - Fallback: Uses cached keys if IdP endpoint unavailable
  - Source validation: Only caches from configured issuer URL
- Security: TLS validation mandatory for HTTPS endpoint fetch

**DPoP Replay Cache:**
- Location: `pam-unix-oidc/src/security/jti_cache.rs`
- Purpose: Prevent token/proof reuse attacks
- Implementation: In-memory cache with JTI lookup and TTL cleanup
- Size limit: 100,000 entries maximum (DoS protection)
- Cleanup: Removes expired entries before rejecting new proofs

**Session State:**
- Location: `pam-unix-oidc/src/security/session.rs`
- Purpose: Step-up grace period tracking
- Storage: Memory-based during PAM transaction
- Scope: Command-class based (package_management, service_management, etc.)
- Expiration: Grace period timeout (default 5 minutes)

**Policy Configuration:**
- Format: YAML (`serde_yaml`)
- Location: `/etc/unix-oidc/policy.yaml`
- Content: Host classification, SSH/sudo requirements, command rules
- Parsing: `pam-unix-oidc/src/policy/config.rs`

**Agent Configuration:**
- Format: YAML or environment variables
- Location: `~/.config/unix-oidc/config.yaml` (XDG)
- Fallback: `OIDC_ISSUER` and `OIDC_CLIENT_ID` env vars
- Parsing: `unix-oidc-agent/src/config.rs`

## Secrets & Credentials Management

**System Keychain (Agent):**
- Implementation: `keyring` crate 3
- Linux: D-Bus secret service
- macOS: Keychain
- Storage: Token refresh credentials, device flow state
- Lifetime: Persists across agent sessions

**Environment Variables (Server):**
- `OIDC_ISSUER` - IdP URL (required)
- `OIDC_CLIENT_ID` - OAuth client ID
- Test mode (NEVER production):
  - `UNIX_OIDC_TEST_MODE=1` or `=true` - Disables signature verification
  - Location check: `pam-unix-oidc/src/lib.rs`

**Secrets Handling:**
- Never logged: Full tokens, private keys, signatures
- Minimal logging: Token claims (without signature) for debugging
- Audit events: Username, issuer, timestamps only
- Break-glass credentials: External secure vault (hardware tokens recommended)

## CI/CD Integration

**GitHub Actions Workflows:**
- `.github/workflows/ci.yml` - Main: formatting, clippy, tests, MSRV check
- `.github/workflows/provider-tests.yml` - Provider integration (Keycloak, Auth0, Google)
- `.github/workflows/security.yml` - cargo-audit and dependency review
- `.github/workflows/platform-tests.yml` - Ubuntu 22.04, 24.04 multi-arch builds
- `.github/workflows/integration-multiarch.yml` - ARM64/x86_64 integration tests
- `.github/workflows/coverage.yml` - Code coverage with cargo-llvm-cov (55% baseline)
- `.github/workflows/validate-docs.yml` - Documentation validation
- `.github/workflows/fuzz.yml` - Fuzzing targets

**Artifact Management:**
- SBOM generation: CycloneDX JSON, SPDX JSON formats
- Build artifacts: `libpam_unix_oidc.so` (Linux), `unix-oidc-agent` (binary)
- Coverage upload: Codecov integration with `CODECOV_TOKEN` secret

**Dependency Management:**
- Dependabot configuration: `.github/dependabot.yml`
- Update groups:
  - Rust (Cargo): Weekly, all deps grouped for review
  - Python (pip): `python-oauth-dpop/` directory
  - Go (gomod): `go-oauth-dpop/` directory
  - Java (Gradle): `java-oauth-dpop/` directory
  - GitHub Actions: Separate auto-update group

## Testing Environments

**Keycloak Test Realm:**
- Image: `quay.io/keycloak/keycloak:24.0`
- Admin: `admin`/`admin`
- Realm: `unix-oidc-test`
- Import: `test/fixtures/keycloak/unix-oidc-test-realm.json`
- Clients:
  - `unix-oidc` - PAM module
  - `unix-oidc-agent` - Agent CLI
- Port: 8080 (HTTP, test only)
- URL: `http://keycloak:8080/realms/unix-oidc-test` (internal) or `http://localhost:8080` (external)

**Token Exchange Realm:**
- File: `test/fixtures/keycloak/token-exchange-test-realm.json`
- Purpose: Testing OAuth 2.0 Token Exchange (RFC 8693) for multi-hop delegation
- Integration: `.github/workflows/integration-multiarch.yml`

**Test Host Docker Image:**
- Dockerfile: `test/docker/Dockerfile.test-host`
- Role: SSH server with PAM module installed and configured
- Environment: `UNIX_OIDC_TEST_MODE=true` (test only)
- Network: `unix-oidc-test` (internal Docker network)
- Port: 2222 (SSH)

**Python Test Suite:**
- File: `test/tests/test_token_exchange.py`
- Framework: pytest (via `python-oauth-dpop` dev dependencies)
- Purpose: RFC 8693 token exchange testing

**Bash Test Suite:**
- Location: `test/scripts/` and `test/tests/*.sh`
- Runner: `.github/workflows/ci.yml` via `run-integration-tests.sh`
- Tests: OIDC discovery, token acquisition, validation, device flow
- Scripts: Helper functions in `wait-for-healthy.sh`, `get-test-token.sh`

## External API Endpoints

**OIDC Discovery (Auto-detected):**
```
GET /.well-known/openid-configuration
Response: metadata with token_endpoint, jwks_uri, device_authorization_endpoint, etc.
```

**Token Endpoint:**
```
POST /token
body: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: "...", client_id: "..." }
Response: { access_token: "...", token_type: "Bearer", expires_in: 3600, ... }
```

**JWKS Endpoint:**
```
GET {jwks_uri}
Response: { keys: [ { kid: "...", kty: "EC", crv: "P-256", x: "...", y: "...", alg: "ES256" } ] }
```

**Device Authorization Endpoint:**
```
POST /auth/device
body: { client_id: "..." }
Response: { device_code: "ABC123", user_code: "XYZ789", verification_uri: "...", expires_in: 1800 }
```

**Token Validation (Implicit):**
- Signature verification uses JWKS endpoint
- No explicit validation API call
- Validation happens offline in PAM module

---

*Integration audit: 2026-03-10*
