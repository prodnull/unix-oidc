# unix-oidc: OIDC-Based Unix Authentication with DPoP Binding

## What This Is

A PAM authentication module and client agent that brings OIDC single sign-on to Linux SSH, with DPoP (RFC 9449) token binding to prevent token theft. The agent daemon manages DPoP keys, OAuth tokens, and hardware signer backends with defense-in-depth credential protection.

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

### Active

(No active milestone — run `/gsd:new-milestone` to plan next work)

### Out of Scope

- Distributed JTI cache (Redis) — server-side concern, different milestone
- RwLock panic hardening in PAM module — important but orthogonal to client-side keys
- Token revocation API — requires IdP-side work, separate milestone
- Configurable security modes (Issue #10) — server-side policy, separate milestone
- Agent forwarding — anti-feature: breaks PAM non-interactive model and threat model
- Interactive PIN during PAM auth — anti-feature: PAM is non-interactive by design

## Context

- **Codebase**: ~7,800 LOC Rust (unix-oidc-agent), PAM module in separate crate
- **Tech stack**: Rust 1.88, p256 0.13, keyring 3.6.3, cryptoki 0.7 (yubikey), tss-esapi 7.6 (tpm), tokio, tracing
- **Storage**: Three-tier fallback — Secret Service/Keychain → keyutils @u → file (0600)
- **Signers**: Three backends via DPoPSigner trait — SoftwareSigner (default), YubiKeySigner (--features yubikey), TpmSigner (--features tpm)
- **Security**: Core dumps disabled, key pages mlock'd, tokens in SecretString, secure delete with CoW/SSD advisories

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

## Constraints

- **Security**: No panics in PAM paths; agent uses standard Rust error handling
- **Compatibility**: Linux (Ubuntu 22.04+, RHEL 9+) and macOS (agent only)
- **MSRV**: Rust 1.88
- **Hardware**: YubiKey requires pcscd; TPM requires tpm2-abrmd; both Linux-only for TPM

---
*Last updated: 2026-03-10 after v1.0 milestone*
