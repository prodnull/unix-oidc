# Architecture

**Analysis Date:** 2026-03-10

## Pattern Overview

**Overall:** Multi-tier authentication system with separated PAM module and daemon components, implementing OIDC with cryptographic token binding (DPoP per RFC 9449).

**Key Characteristics:**
- PAM module validates tokens locally without network calls
- Agent daemon handles OAuth flows and credential management in user context
- Unix socket IPC between PAM and agent using JSON protocol
- DPoP binding prevents token theft even if tokens are intercepted
- Rate limiting and replay protection (JTI cache) at PAM layer
- Audit logging with structured events

## Layers

**Identity Provider (External):**
- Purpose: Authoritative authentication source (Okta, Azure AD, Keycloak, Google, Auth0)
- Location: External service
- Contains: OIDC discovery endpoint, JWKS endpoint, token endpoint
- Depends on: HTTPS connectivity
- Used by: Agent daemon (token acquisition), PAM module (signature verification)

**User Agent Daemon:**
- Purpose: Long-running process managing OIDC tokens, DPoP keys, and OAuth flows
- Location: `unix-oidc-agent/src/`
- Contains:
  - Device flow client (`device_flow/`)
  - Cryptographic operations (`crypto/`)
  - Token/key storage (`storage/`)
  - Daemon IPC server (`daemon/`)
- Depends on: Identity Provider, secure storage (keyring/filesystem)
- Used by: PAM module (via Unix socket), user commands (CLI)

**PAM Module (Security-Critical):**
- Purpose: Validate OIDC tokens and DPoP proofs, authorize login/sudo
- Location: `pam-unix-oidc/src/`
- Contains:
  - Token validation (`oidc/validation.rs`)
  - DPoP proof verification (`oidc/dpop.rs`)
  - SSSD user resolution (`sssd/`)
  - Security controls (`security/`)
  - Policy enforcement (`policy/`)
  - Audit logging (`audit.rs`)
- Depends on: Cached JWKS, agent daemon (via socket), system NSS/SSSD
- Used by: sshd, sudo, login (PAM framework)

**SSSD/NSS Layer:**
- Purpose: Resolve OIDC usernames to Unix UIDs/GIDs
- Location: External (system NSS)
- Contains: User database (LDAP-backed typically)
- Depends on: LDAP/AD server
- Used by: PAM module (user existence check)

## Data Flow

**SSH Login with OIDC:**

1. User runs: `ssh user@server`
2. sshd calls PAM module `authenticate()`
3. PAM module attempts token retrieval:
   - Environment variable (`OIDC_TOKEN`) - test mode only
   - PAM environment (if `UNIX_OIDC_ACCEPT_PAM_ENV=true`)
   - Cached auth token (from agent via SSH_ASKPASS)
   - Interactive prompt (if enabled, but limited to ~512 bytes)
4. PAM module validates token:
   - Parse JWT and extract `preferred_username` claim
   - Fetch JWKS from IdP (cached, with TTL)
   - Verify signature using IdP public key
   - Check issuer, audience, expiration
   - Check ACR level if configured
   - Check auth_time age if configured
5. If token has DPoP binding (`cnf` claim):
   - Read DPoP proof from PAM environment
   - Verify proof signature and JTI (replay protection)
   - Verify proof is bound to token thumbprint
6. PAM module resolves username to Unix user:
   - Query NSS/SSSD for user existence
   - Extract UID, GID, home directory
7. Rate limiting check:
   - Check if user/IP has exceeded failure threshold
8. Log audit event (structured JSON to syslog + file)
9. Return PAM_SUCCESS or error code

**Sudo Step-Up with Device Flow:**

1. User runs: `sudo sensitive-command`
2. PAM module detects sensitive command via policy
3. Requests fresh authentication via device flow:
   - Call agent daemon to initiate device flow
   - Agent displays device code and URL
   - User scans QR code on phone
   - Agent polls token endpoint until user approves
4. New token acquired, proceed with token validation as above
5. Log step-up event with command and approval

**State Management:**

**Token Cache (Agent-side):**
- Tokens stored in secure storage (system keyring or encrypted file)
- Refresh tokens automatically refreshed before expiration
- Revoked on logout

**DPoP Key Pair (Agent-side):**
- Ephemeral EC P-256 key pair generated per login session
- Private key never leaves agent process
- Proof signed with private key for each request
- Thumbprint derived from public key coordinates

**JWKS Cache (PAM-side):**
- Published keys cached with TTL (default configurable)
- Supports key rollover (old keys remain valid during transition)
- Fetched on-demand from IdP discovery endpoint

**JTI Replay Cache (PAM-side):**
- In-memory HashMap tracking JWT IDs (globally)
- Entries expire after token lifetime
- Size-limited (100k entries) to prevent DoS
- Periodic cleanup removes expired entries

**Rate Limit Tracker (PAM-side):**
- Per-user, per-IP failure tracking
- Configurable threshold and cooldown
- Cleared on successful auth

## Key Abstractions

**TokenValidator:**
- Purpose: Validate JWT tokens against IdP configuration
- Examples: `pam-unix-oidc/src/oidc/validation.rs`
- Pattern: Builder-like config, validate method returns claims or error
- Implements RFC 7519 (JWT), RFC 6234 (JWA), RFC 8949 (CBOR)

**DPoPValidator:**
- Purpose: Verify DPoP proofs and prevent replay attacks
- Examples: `pam-unix-oidc/src/oidc/dpop.rs`
- Pattern: Static functions for validation, global JTI cache with locking
- Implements RFC 9449 (DPoP), constant-time comparison for security

**JwksProvider:**
- Purpose: Fetch and cache JWKS from IdP discovery
- Examples: `pam-unix-oidc/src/oidc/jwks.rs`
- Pattern: Lazy-initialized cache with TTL, blocking HTTP client
- Implements RFC 5785 (well-known), RFC 7517 (JWK)

**DeviceFlowClient:**
- Purpose: Execute OAuth 2.0 Device Authorization Grant
- Examples: `unix-oidc-agent/src/device_flow/client.rs`
- Pattern: Async HTTP client, polling with backoff
- Implements RFC 8628 (Device Flow)

**DPoPSigner:**
- Purpose: Create and sign DPoP proofs
- Examples: `unix-oidc-agent/src/crypto/dpop.rs`
- Pattern: Trait-based (SoftwareSigner implements DPoPSigner), generates proofs with JTI
- Implements RFC 9449 client-side

**SecureStorage:**
- Purpose: Persist tokens and keys with encryption
- Examples: `unix-oidc-agent/src/storage/mod.rs`
- Pattern: Trait-based (FileStorage, KeyringStore), key-value store interface
- Supports: System keyring (Linux Secret Service), encrypted file fallback

**PolicyRules:**
- Purpose: Determine when step-up authentication is required
- Examples: `pam-unix-oidc/src/policy/rules.rs`
- Pattern: Configuration-driven rules matching command patterns
- Supports: regex matching, host classification, action types

**AuditEvent:**
- Purpose: Structured logging compatible with SIEM
- Examples: `pam-unix-oidc/src/audit.rs`
- Pattern: Enum-based events with serde serialization
- Outputs: Syslog (AUTH facility), file, stderr
- Compatible with: CIM (Common Information Model), OCSF

## Entry Points

**PAM Module authenticate():**
- Location: `pam-unix-oidc/src/lib.rs:48`
- Triggers: sshd, sudo, login call PAM framework
- Responsibilities:
  1. Get PAM user (from cached state or prompt)
  2. Check rate limiting
  3. Retrieve token from various sources
  4. Validate token cryptographically
  5. Verify DPoP binding if present
  6. Resolve username to local user
  7. Log audit event
  8. Return PAM status code

**Agent daemon command handlers:**
- Location: `unix-oidc-agent/src/main.rs:78`
- Triggers: User CLI (login, status, refresh, etc.) or PAM socket request
- Responsibilities:
  - Authenticate user with device flow
  - Manage token lifecycle
  - Sign DPoP proofs on demand
  - Provide status/metrics

**Webhook approval endpoint:**
- Location: `examples/webhook-server/src/main.rs`
- Triggers: PAM policy requires custom approval
- Responsibilities:
  - Create approval request
  - Return approval status
  - Integrate with external systems (Slack, PagerDuty, etc.)

## Error Handling

**Strategy:** Layered error handling with different panic policies per component

**Patterns:**

**PAM Module (Never Panic):**
- All errors converted to PAM error codes (AUTH_ERR, USER_UNKNOWN, SERVICE_ERR)
- Detailed reasons logged before returning error
- Example: `pam-unix-oidc/src/lib.rs:95-172` (match on AuthError variants)

**Token Validation (Early Return):**
- Validation errors are `Result<Claims, ValidationError>` (thiserror-based)
- Each validation step returns descriptive error
- Example: `pam-unix-oidc/src/oidc/validation.rs:10-52`

**DPoP Validation (Constant-Time on Crypto):**
- Signature verification uses constant-time comparison (subtle crate)
- Replay detection returns early on cache hit
- Example: `pam-unix-oidc/src/oidc/dpop.rs:150-200`

**Agent Daemon (Graceful Shutdown):**
- Network errors trigger fallback or user retry
- Storage errors log and fail gracefully
- Example: `unix-oidc-agent/src/daemon/mod.rs` (error responses via JSON)

**Configuration Errors (Fail Fast):**
- Missing required config detected at startup
- Cannot be recovered, returns descriptive error
- Example: `pam-unix-oidc/src/oidc/validation.rs:68-85` (OIDC_ISSUER required)

## Cross-Cutting Concerns

**Logging:**
- Framework: `tracing` crate with structured spans
- PAM module: `syslog` for AUTH facility + stderr fallback
- Agent: `tracing-subscriber` with JSON output
- Security: Logs include username, source IP, token JTI; exclude full tokens/keys
- Example: `pam-unix-oidc/src/audit.rs` (structured AuditEvent enum)

**Validation:**
- Configuration validated at startup (environment variables)
- Token validation cached (JWKS with TTL)
- DPoP proofs validated with replay protection
- User existence checked via NSS (blocks on SSSD query)
- Policy rules matched against command patterns
- Example: `pam-unix-oidc/src/oidc/validation.rs` (ValidationConfig::from_env)

**Authentication:**
- OIDC token: signature verified against JWKS
- DPoP proof: signature verified, JTI checked for replay
- User identity: preferred_username claim mapped to Unix user
- PAM user: matched against token username claim
- ACR level: checked if configured
- Auth time: checked if max_auth_age configured
- Example: `pam-unix-oidc/src/auth.rs:75-130`

**Security Hardening:**
- Test mode disabled by default (requires explicit `UNIX_OIDC_TEST_MODE=true` or `=1`)
- DPoP JTI cache size-limited to prevent DoS
- Rate limiting per user/IP to prevent brute force
- Constant-time comparison for cryptographic values
- Algorithm enforcement (only ES256 for DPoP)
- No algorithm selection from untrusted input
- Example: `pam-unix-oidc/src/lib.rs:41-44` (test mode gating)

---

*Architecture analysis: 2026-03-10*
