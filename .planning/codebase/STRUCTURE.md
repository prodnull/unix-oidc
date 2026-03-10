# Codebase Structure

**Analysis Date:** 2026-03-10

## Directory Layout

```
unix-oidc/
├── pam-unix-oidc/           # Core PAM module (Rust library compiled to .so)
├── unix-oidc-agent/         # Client-side agent for token management
├── rust-oauth-dpop/         # Standalone DPoP library (RFC 9449 implementation)
├── go-oauth-dpop/           # Go DPoP implementation
├── python-oauth-dpop/       # Python DPoP implementation
├── java-oauth-dpop/         # Java DPoP implementation
├── docs/                    # Documentation and guides
├── deploy/                  # Deployment tools and IaC
├── test/                    # Test fixtures, scripts, and integration tests
├── examples/                # Example configurations
├── fuzz/                    # Fuzzing targets for security testing
├── demo/                    # Interactive demonstration and recordings
├── dpop-cross-language-tests/ # Cross-language DPoP validation tests
├── .github/                 # GitHub Actions CI/CD workflows
├── Cargo.toml              # Rust workspace definition
└── Makefile                # Build and test automation
```

## Directory Purposes

**pam-unix-oidc/**
- Purpose: Core PAM module - the security-critical library loaded by PAM
- Contains: OIDC token validation, DPoP proof verification, SSSD integration, sudo step-up logic
- Key files: `src/lib.rs` (PAM entry points), `src/oidc/` (JWT/DPoP), `src/security/` (replay protection), `src/policy/` (configuration)
- Compiled to: `target/release/libpam_unix_oidc.so` (shared library loaded by sshd/sudo)

**unix-oidc-agent/**
- Purpose: Client-side agent for token acquisition and caching
- Contains: Device flow authentication, DPoP proof generation, token refresh, agent daemon
- Communicates via: Unix socket (`/run/user/*/unix-oidc-agent.sock`)
- Storage: Keyring (preferred) or filesystem with restricted permissions

**rust-oauth-dpop/**
- Purpose: Reusable RFC 9449 DPoP implementation as standalone crate
- Contains: Proof generation (client), proof validation (server), JWK thumbprint computation
- Independent: Separate workspace, can be used by other projects
- Publishes to: crates.io as `oauth-dpop`

**Cross-language DPoP libraries** (go-oauth-dpop/, python-oauth-dpop/, java-oauth-dpop/)
- Purpose: Enable DPoP support in non-Rust applications
- Mirrors: Same API patterns as rust-oauth-dpop for consistency
- Validation: Cross-language tests ensure interoperability

**docs/**
- Purpose: User guides, security analysis, deployment patterns
- Key docs:
  - `installation.md` - Setup instructions
  - `security-guide.md` - Security considerations
  - `deployment-patterns.md` - Enterprise deployment scenarios
  - `THREAT_MODEL.md` - Complete threat analysis
  - `adr/` - Architecture Decision Records
  - `demo-videos/` - Demo recordings

**deploy/**
- Purpose: Infrastructure-as-code and deployment automation
- Tools: Terraform, Ansible, Puppet, Chef, Vagrant
- IdP templates: `idp-templates/` - Okta, Azure AD, Keycloak, Auth0 configurations
- Quickstart: `quickstart/` - 5-minute demo and 15-minute production guides
- Installer: `installer/` - Packaging (deb, rpm)

**test/**
- Purpose: Integration test infrastructure
- `fixtures/` - Test data:
  - `keycloak/` - Keycloak test realm JSON
  - `ldap/` - LDAP directory fixtures
  - `pam/` - PAM module configuration files
  - `sssd/` - SSSD configuration
  - `policy/` - Policy YAML examples
- `tests/` - Test scripts (bash, Python, shell)
- `docker/` - Docker Compose services
- `e2e/` - End-to-end test workflows
- `scripts/` - Test utilities and helpers

**examples/**
- Purpose: Sample configurations for users
- `policy.yaml` - Full policy configuration example (with all options documented)
- `webhook-server/` - Reference webhook approval server (Rust)

**fuzz/**
- Purpose: Security testing via fuzzing
- `fuzz_targets/`:
  - `dpop_proof.rs` - Fuzzes DPoP validation
  - `token_parser.rs` - Fuzzes JWT parsing
  - `policy_parser.rs` - Fuzzes YAML policy parsing
  - `username_mapper.rs` - Fuzzes username extraction from claims
- Run with: `cargo fuzz` (via libFuzzer)

**demo/**
- Purpose: Interactive demos and recordings
- `run-demo.sh` - Launches interactive demo with Keycloak
- `record-demo.sh` - Records demo video via Playwright
- `tests/` - Playwright test suite for demo scenarios
- `output/` - Generated demo artifacts

**dpop-cross-language-tests/**
- Purpose: Validate DPoP implementation across all languages
- `rust-test/`, `go-test/`, `python-test/` - Test implementations
- Shared test vectors: Ensures all implementations produce same proofs

## Key File Locations

**Entry Points (PAM):**
- `pam-unix-oidc/src/lib.rs` - PAM module initialization (`authenticate`, `acct_mgmt`, `chauthtok`)
- Compiled to: `/lib/security/pam_unix_oidc.so` or `/lib64/security/pam_unix_oidc.so`
- Configuration: `/etc/pam.d/sshd` includes `pam_unix_oidc.so`

**Entry Points (Client Agent):**
- `unix-oidc-agent/src/main.rs` - CLI entry point with subcommands (`login`, `status`, `serve`, `refresh`)
- Binary: `/usr/local/bin/unix-oidc-agent` (after installation)
- Socket: `$XDG_RUNTIME_DIR/unix-oidc-agent.sock` (agent communication)

**Core Logic (Security-Critical):**
- `pam-unix-oidc/src/oidc/dpop.rs` - DPoP validation (JTI cache, constant-time comparison)
- `pam-unix-oidc/src/oidc/validation.rs` - JWT signature verification, issuer/audience checks
- `pam-unix-oidc/src/oidc/token.rs` - Token claim extraction
- `pam-unix-oidc/src/security/jti_cache.rs` - Replay protection cache
- `pam-unix-oidc/src/security/rate_limit.rs` - Rate limiting per user
- `pam-unix-oidc/src/sssd/user.rs` - SSSD integration (user lookup)

**Policy & Configuration:**
- `pam-unix-oidc/src/policy/config.rs` - Policy file parsing
- `pam-unix-oidc/src/policy/rules.rs` - Rule evaluation engine
- `pam-unix-oidc/src/auth.rs` - Main authentication orchestration
- Example policy: `examples/policy.yaml`

**Device Flow (Sudo Step-up):**
- `pam-unix-oidc/src/device_flow/mod.rs` - Device authorization flow client
- `pam-unix-oidc/src/device_flow/client.rs` - Token polling
- `pam-unix-oidc/src/device_flow/types.rs` - Response types
- `pam-unix-oidc/src/approval/provider.rs` - Approval provider abstraction
- `pam-unix-oidc/src/approval/webhook.rs` - Webhook-based approval (configurable)

**Client-Side Crypto:**
- `unix-oidc-agent/src/crypto/dpop.rs` - DPoP proof generation
- `unix-oidc-agent/src/crypto/signer.rs` - P-256 signing
- `unix-oidc-agent/src/crypto/thumbprint.rs` - JWK thumbprint computation
- `rust-oauth-dpop/src/thumbprint.rs` - Reusable thumbprint (canonical JSON)

**Token Storage:**
- `unix-oidc-agent/src/storage/keyring_store.rs` - Secure OS keyring (Linux Secret Service, macOS Keychain)
- `unix-oidc-agent/src/storage/file_store.rs` - Fallback filesystem storage (with mode 0600)
- `unix-oidc-agent/src/daemon/mod.rs` - Daemon for token serving

**Audit & Logging:**
- `pam-unix-oidc/src/audit.rs` - Structured JSON audit events
- Logs to: syslog (Linux auth.log or secure)
- Integration: Forwarded via journalctl or rsyslog

**UI & UX:**
- `pam-unix-oidc/src/ui/terminal.rs` - Terminal prompts for device flow
- `pam-unix-oidc/src/ui/mod.rs` - UI abstraction layer

**Testing & Validation:**
- `pam-unix-oidc/src/lib.rs` - Feature gate `test-mode` for test environments
- `test/fixtures/keycloak/unix-oidc-test-realm.json` - Test realm with demo users
- `test/docker-compose.test.yaml` - Keycloak + LDAP + test-host setup

## Naming Conventions

**Files:**
- `src/lib.rs` - Library entry point (for `cdylib` crates like PAM module)
- `src/main.rs` - Binary entry point (for agents and CLI tools)
- `mod.rs` - Module declaration and re-exports
- `*_test.rs` or `*_spec.rs` - Avoided; use `#[cfg(test)]` in same file
- `*.toml` - Configuration (Cargo.toml, cross.toml, deny.toml)

**Directories:**
- `src/` - Rust source code
- `src/oidc/` - OIDC-related functionality
- `src/security/` - Security-hardening code
- `src/policy/` - Policy parsing and evaluation
- `src/device_flow/` - Device authorization flow
- `src/approval/` - Approval provider implementations
- `src/sssd/` - SSSD integration
- `src/storage/` - Token storage backends
- `src/daemon/` - Daemon logic
- `src/crypto/` - Cryptographic operations
- `test/fixtures/` - Test data and configuration
- `test/scripts/` - Shell and utility scripts
- `deploy/` - Deployment tools

**Modules (Rust):**
- `DpopValidator`, `DpopError` - DPoP validation
- `TokenValidator`, `ValidationError` - JWT validation
- `PolicyConfig`, `PolicyRule` - Policy management
- `AuditEvent` - Audit logging
- `AgentServer`, `AgentClient` - Daemon communication
- `SecureStorage`, `FileStorage` - Token backends
- `DPoPSigner`, `SoftwareSigner` - Signing implementations

**Functions:**
- `validate_dpop_proof()` - DPoP proof validation
- `validate_token()` - Complete token validation
- `extract_username()` - Username from claims
- `check_policy()` - Policy evaluation
- `authenticate()` - Main PAM authenticate handler
- `get_token()` - Retrieve or refresh token
- Test functions: use `#[test]` and `#[tokio::test]` attributes (in same file)

**Tests:**
- Located: Inline in same file as code (under `#[cfg(test)]` modules)
- Example: `pam-unix-oidc/src/oidc/dpop.rs` contains test functions for DPoP validation
- Integration tests: Bash scripts in `test/tests/`
- Unit tests: Run with `cargo test --all` or `cargo test -p pam-unix-oidc`
- Doctests: Examples in documentation comments

## Where to Add New Code

**New OIDC Provider Support:**
- Modify: `pam-unix-oidc/src/oidc/jwks.rs` if JWKS discovery differs
- Add test: `test/fixtures/keycloak/` → new provider realm/config
- Document: `deploy/idp-templates/{provider}/README.md`

**New Policy Feature:**
- Add: Rule type in `pam-unix-oidc/src/policy/rules.rs`
- Update: YAML schema comments in `pam-unix-oidc/src/policy/config.rs`
- Test: `test/fixtures/policy/{new-feature}.yaml`
- Example: `examples/policy.yaml`

**New Approval Method:**
- Implement: `pam-unix-oidc/src/approval/provider.rs` trait
- Create: `pam-unix-oidc/src/approval/{method}.rs` (e.g., `push_notification.rs`)
- Register: In `pam-unix-oidc/src/approval/mod.rs`

**New DPoP Feature:**
- Rust: `rust-oauth-dpop/src/lib.rs` or new module
- Mirror: Implement in `go-oauth-dpop/`, `python-oauth-dpop/`, `java-oauth-dpop/`
- Test: `dpop-cross-language-tests/` with shared test vectors

**Documentation:**
- User guides: `docs/` (markdown)
- Architecture: `docs/adr/` (Architecture Decision Records)
- Security: `docs/security-*.md`
- Deployment: `deploy/README.md` and per-tool folders

**Testing:**
- Unit tests: Inline in source files
- Integration: New bash script in `test/tests/test_*.sh`
- Fixtures: Add data to `test/fixtures/{category}/`
- Fuzzing: New target in `fuzz/fuzz_targets/{feature}.rs`

## Special Directories

**target/**
- Purpose: Build artifacts (Cargo generates)
- Generated: Yes
- Committed: No (.gitignored)
- Contents: `debug/`, `release/` with compiled binaries and libraries

**fuzz/corpus/ and artifacts/**
- Purpose: Fuzzing test cases and crash examples
- Generated: Yes (by cargo-fuzz)
- Committed: No (in .gitignore)

**.planning/codebase/**
- Purpose: GSD codebase analysis documents
- Contents: STACK.md, INTEGRATIONS.md, ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, CONCERNS.md
- Generated: Yes (by /gsd:map-codebase)
- Committed: Yes (tracked in git)

**demo/output/ and playwright-report/**
- Purpose: Demo recording and test artifacts
- Generated: Yes (by Playwright)
- Committed: No

**.venv/**
- Purpose: Python virtual environment for test scripts
- Generated: Yes
- Committed: No

---

*Structure analysis: 2026-03-10*
