# unix-oidc: OIDC-Based Unix Authentication with DPoP Binding

## What This Is

A PAM authentication module and client agent that brings OIDC single sign-on to Linux SSH, with DPoP (RFC 9449) token binding to prevent token theft. The agent daemon manages DPoP keys, OAuth tokens, and hardware signer backends with defense-in-depth credential protection. Supports multiple OIDC issuers (Keycloak, Azure Entra ID) with per-issuer policy configuration.

## Core Value

DPoP private keys must be protected at rest, in memory, and on deletion — because a stolen DPoP key defeats the entire proof-of-possession security model that distinguishes unix-oidc from bearer-token systems.

## Requirements

### Validated

- ✓ OIDC token acquisition via OAuth 2.0 Device Authorization Grant (RFC 8628) — existing
- ✓ DPoP proof generation with ES256/P-256 per RFC 9449 — existing
- ✓ PAM module token validation with signature verification, issuer/audience checks — existing
- ✓ DPoP proof verification with JTI replay protection — existing
- ✓ Trait-based `DPoPSigner` abstraction (Software, YubiKey, TPM) — v1.0
- ✓ Trait-based `SecureStorage` abstraction (Keyring, Keyutils, File) — v1.0
- ✓ Memory-locked key material preventing swap exposure (mlock + ZeroizeOnDrop) — v1.0
- ✓ Secure credential deletion with DoD 5220.22-M overwrite — v1.0
- ✓ Hardware key backends (YubiKey PKCS#11, TPM tss-esapi) via optional cargo features — v1.0
- ✓ Keyring as default storage with headless keyutils fallback and file-to-keyring migration — v1.0
- ✓ OAuth tokens wrapped in SecretString with expose_secret() audit boundaries — v1.0
- ✓ PAM panic elimination with deny(clippy::unwrap_used) lint — v2.0
- ✓ DPoP nonce issuance with single-use nonce cache — v2.0
- ✓ Username mapping, group policy, break-glass bypass — v2.0
- ✓ Token introspection, session lifecycle, auto-refresh — v2.0
- ✓ CIBA step-up authentication with FIDO2 via ACR delegation — v2.0
- ✓ Operational hardening (systemd/launchd, peer-auth IPC, structured tracing) — v2.0
- ✓ ML-DSA-65+ES256 hybrid PQC DPoP — v2.0
- ✓ Multi-IdP configuration with per-issuer policy — v2.1
- ✓ Azure Entra ID bearer-only integration — v2.1
- ✓ Full SSH E2E test chain with real JWKS verification — v2.1
- ✓ keycloak-e2e CI job with Playwright device flow automation — v2.1

- ✓ Security bug fixes (source_ip forensic attribution, break-glass alert wiring, optional preferred_username) — v2.2
- ✓ Algorithm allowlist with per-issuer config, HTTPS enforcement, terminal escape sanitization, D-Bus encryption probe — v2.2
- ✓ Tech debt elimination (dead code removal, per-issuer JWKS config, lint foundation, NIST citation update) — v2.2
- ✓ IdP priority ordering, health monitoring with quarantine/recovery, stat-based config hot-reload — v2.2
- ✓ OCSF 1.3.0 enriched audit events (16 variants), HMAC tamper-evidence chain, audit-verify CLI — v2.2
- ✓ Key lifecycle audit events (DPoP + ML-DSA-65+ES256), no-token/session-close audit events — v2.2
- ✓ Standards compliance matrix, identity rationalization guide, JTI cache architecture doc — v2.2
- ✓ Automated E2E: DPoP nonce, break-glass, session lifecycle, systemd/launchd, CIBA FIDO2 ACR — v2.2
- ✓ Log retention compliance (logrotate), GDPR Article 17 erasure guide — v2.2

### Active

See `.planning/REQUIREMENTS.md` for current milestone requirements (created by `/gsd:new-milestone`).

## Current Milestone: Planning Next

v2.2 shipped. Next milestone TBD — run `/gsd:new-milestone` to start v3.0.

## Future Milestones

### v3.0 Capabilities

New product features: SCIM provisioning, AI Agent Delegation (RFC 8693), hardware key attestation, centralized audit log shipping, pentest automation suite, FIPS crypto prep, PAM binary signing, push notification / FIDO2 step-up, break-glass with offline YubiKey OTP, blocking HTTP offload to agent daemon.

### v3.1 External IdP Integration Testing

Live integration tests for Okta (IDPX-01), Auth0 (IDPX-02), Google Cloud Identity (IDPX-03).

### Out of Scope

- Distributed JTI cache (Redis) — separate scalability milestone
- VDI/agent forwarding — anti-feature: breaks PAM non-interactive model and threat model
- Interactive PIN during PAM auth — anti-feature: PAM is non-interactive by design
- SAML integration — unix-oidc is OIDC-only by design

## Context

- **Codebase**: ~32,000 LOC Rust across pam-unix-oidc + unix-oidc-agent crates
- **Tech stack**: Rust 1.88, p256 0.13, keyring 3.6.3, cryptoki 0.7 (yubikey), tss-esapi 7.6 (tpm), tokio, tracing
- **Storage**: Three-tier fallback — Secret Service/Keychain → keyutils @u → file (0600)
- **Signers**: Three backends via DPoPSigner trait — SoftwareSigner (default), YubiKeySigner (--features yubikey), TpmSigner (--features tpm)
- **Security**: Core dumps disabled, key pages mlock'd, tokens in SecretString, secure delete (NIST SP 800-88), OCSF audit events with HMAC chain
- **Test infrastructure**: Keycloak E2E compose stack, Playwright device flow automation, Entra secrets-gated CI, 5 automated E2E suites, 410+ unit tests
- **Shipped milestones**: v1.0 (key protection), v2.0 (production hardening), v2.1 (integration testing), v2.2 (hardening & conformance)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keyring as default, file as fallback | Headless servers may lack D-Bus/keychain; graceful degradation needed | ✓ Good — probe-based detection works reliably |
| `zeroize` for memory + deletion | Battle-tested crate from RustCrypto; derives work with existing types | ✓ Good — unconditional ZeroizeOnDrop in ecdsa-0.16 |
| Hardware keys as optional cargo features | Avoids requiring YubiKey/TPM libs for all users | ✓ Good — base build has zero hardware deps |
| mlock via libc::mlock (not memsec) | Direct syscall, fewer dependencies, best-effort semantics | ✓ Good — WARN on failure, never fatal |
| cryptoki 0.7 instead of planned 0.12 | 0.12 not available; 0.7 fully supports PKCS#11 P-256 operations | ⚠️ Revisit — upgrade when 0.12+ available |
| Three-pass DoD 5220.22-M overwrite | Stronger than single-pass; documented CoW/SSD limitations | ✓ Good — with clear advisory logging |
| Box-only ProtectedSigningKey constructors | Prevents stack copies of key material | ✓ Good — compile-time enforcement |
| Groups resolved from SSSD/NSS, not token claims | FreeIPA is Unix realm authority; avoids Entra overage/GUID issues | ✓ Good — v2.0 Phase 8 |
| Multi-IdP via issuers[] array, not federation | Each issuer independently configured; no cross-IdP trust assumptions | ✓ Good — v2.1 Phase 21 |
| Algorithm allowlist (not blocklist) with per-issuer config | Positive security model; prevents HS256-with-RSA-key confusion | ✓ Good — v2.2 Phase 25 |
| Stat-based config hot-reload, no SIGHUP | PAM in sshd process space; SIGHUP restarts sshd | ✓ Good — v2.2 Phase 27 |
| HMAC chain over OCSF-enriched JSON | Composition: bare event → OCSF → HMAC; tamper-evidence for compliance | ✓ Good — v2.2 Phase 27 |
| GroupSource::TokenClaim removed as dead code | SSSD-only confirmed; dead code in security path is risk | ✓ Good — v2.2 Phase 26 |

## Constraints

- **Security**: No panics in PAM paths; agent uses standard Rust error handling
- **Compatibility**: Linux (Ubuntu 22.04+, RHEL 9+) and macOS (agent only)
- **MSRV**: Rust 1.88
- **Hardware**: YubiKey requires pcscd; TPM requires tpm2-abrmd; both Linux-only for TPM

---
*Last updated: 2026-03-16 after v2.2 milestone complete*
