# unix-oidc: Client-Side Key Protection Hardening

## What This Is

Hardening milestone for the unix-oidc agent's client-side credential protection. The agent currently stores DPoP private keys and OAuth tokens in plaintext files (`~/.local/share/unix-oidc-agent/`). This milestone activates the existing keyring backend, adds memory protection for key material, implements secure deletion, and introduces hardware key support via the existing `DPoPSigner` trait.

## Core Value

DPoP private keys must be protected at rest, in memory, and on deletion — because a stolen DPoP key defeats the entire proof-of-possession security model that distinguishes unix-oidc from bearer-token systems.

## Requirements

### Validated

- OIDC token acquisition via OAuth 2.0 Device Authorization Grant (RFC 8628) — existing
- DPoP proof generation with ES256/P-256 per RFC 9449 — existing
- PAM module token validation with signature verification, issuer/audience checks — existing
- DPoP proof verification with JTI replay protection — existing
- Trait-based `DPoPSigner` abstraction (`SoftwareSigner` implemented) — existing
- Trait-based `SecureStorage` abstraction (`FileStorage` + `KeyringStore` implemented) — existing
- Unix socket IPC between agent daemon and PAM module — existing
- Structured audit logging (syslog + file) — existing
- Policy-driven step-up authentication for sudo — existing
- Rate limiting and brute-force protection — existing

### Active

- [ ] Keyring backend activated as default storage for DPoP keys and tokens
- [ ] Memory-locked key material preventing swap exposure
- [ ] Secure credential deletion with filesystem-aware wiping
- [ ] Hardware key backend (YubiKey/TPM) via `DPoPSigner` trait

### Out of Scope

- Distributed JTI cache (Redis) — different milestone, server-side concern
- RwLock panic hardening in PAM module — important but orthogonal to client-side keys
- Token revocation API — requires IdP-side work, separate milestone
- Configurable security modes (Issue #10) — server-side policy, separate milestone
- Agent CLI command completion (login/logout stubs) — prerequisite work assumed done or done in parallel

## Context

- **Storage architecture**: Two-tier system exists — `FileStorage` (active, 0600 permissions) and `KeyringStore` (implemented, not wired up). Both implement `SecureStorage` trait.
- **Key files**: `unix-oidc-agent/src/storage/mod.rs` (trait + constants), `file_store.rs` (active), `keyring_store.rs` (dormant), `crypto/signer.rs` (key generation)
- **Key lifecycle**: Generated via `SigningKey::random(&mut OsRng)`, exported to bytes, stored immediately. Reloaded on agent restart via `load_or_create_signer()`.
- **Stored secrets**: `unix-oidc-dpop-key` (P-256 private key bytes), `unix-oidc-access-token`, `unix-oidc-refresh-token`, `unix-oidc-token-metadata` (JSON with issuer, endpoints, client config)
- **Threat model gap**: File permissions protect against other-user access but not same-UID malware, NFS exposure, or forensic recovery from CoW filesystems.
- **Existing deps**: `keyring` 3 (Linux D-Bus, macOS Keychain), `p256` 0.13, `getrandom` 0.3. Missing: `zeroize`, `memsec`/`mlock` wrapper.

## Constraints

- **Security**: No panics in PAM paths — but this milestone is agent-side, so standard Rust error handling applies
- **Compatibility**: Must support Linux (Ubuntu 22.04+, RHEL 9+) and macOS (agent only). Keyring requires D-Bus on Linux, Keychain on macOS.
- **Backward compat**: Existing `FileStorage` users must be migrated gracefully (detect existing file-stored keys, offer migration to keyring)
- **Hardware keys**: YubiKey requires `yubikey` crate; TPM requires `tss-esapi`. Both are optional features to avoid bloating the base build.
- **MSRV**: Rust 1.88

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Keyring as default, file as fallback | Headless servers may lack D-Bus/keychain; graceful degradation needed | -- Pending |
| `zeroize` for memory + deletion | Battle-tested crate from RustCrypto; derives work with existing types | -- Pending |
| Hardware keys as optional cargo features | Avoids requiring YubiKey/TPM libs for all users | -- Pending |
| mlock via `memsec` or `libc::mlock` | Prevents key material from being paged to swap | -- Pending |

---
*Last updated: 2026-03-10 after initialization*
