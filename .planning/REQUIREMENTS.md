# Requirements: unix-oidc Client-Side Key Protection Hardening

**Defined:** 2026-03-10
**Core Value:** DPoP private keys must be protected at rest, in memory, and on deletion

## v1 Requirements

Requirements for this milestone. Each maps to roadmap phases.

### Memory Protection

- [x] **MEM-01**: All key export paths return `Zeroizing<Vec<u8>>` instead of raw `Vec<u8>`
- [x] **MEM-02**: `p256` crate built with `zeroize` feature enabling `ZeroizeOnDrop` on `SigningKey`
- [x] **MEM-03**: In-memory OAuth tokens wrapped in `secrecy::Secret<String>` (access token, refresh token, client secret)
- [x] **MEM-04**: Key material pages locked via `libc::mlock` with best-effort semantics (warn on `EPERM`/`ENOMEM`, never fatal)
- [x] **MEM-05**: Key material allocated on heap only (`Box`/`Arc`), never passed by value across function boundaries, to prevent unzeroized stack copies
- [x] **MEM-06**: Documentation updated with memory protection design rationale and limitations (CLAUDE.md security invariants, README security section)

### Secure Storage

- [x] **STOR-01**: Runtime keyring backend detection via probe write/read/delete at daemon startup
- [x] **STOR-02**: `KeyringStorage` activated as default backend when keyring is available, `FileStorage` as automatic fallback
- [x] **STOR-03**: File-to-keyring migration for existing file-stored credentials (detect on startup, migrate transparently, log migration event)
- [x] **STOR-04**: Linux headless support via `keyutils` user keyring (`@u`, not session `@s`) when D-Bus Secret Service is unavailable
- [x] **STOR-05**: File deletion uses random-overwrite + unlink, with documented limitation that CoW/SSD filesystems may retain copies
- [x] **STOR-06**: `unix-oidc-agent status` reports active storage backend (keyring vs file) and migration status
- [x] **STOR-07**: Documentation updated with storage architecture, backend selection logic, migration instructions, and headless deployment guide

### Hardware Key Backends

- [x] **HW-01**: `YubiKeySigner` implementing `DPoPSigner` trait via `cryptoki` 0.12 (PKCS#11) with P-256 ECDSA signing
- [x] **HW-02**: `TpmSigner` implementing `DPoPSigner` trait via `tss-esapi` 7.6 with P-256 ECDSA signing
- [x] **HW-03**: Both backends gated behind optional cargo features (`yubikey`, `tpm`) to avoid bloating base build
- [x] **HW-04**: YubiKey uses open-sign-close PCSC pattern (no persistent handle) to avoid blocking other applications
- [x] **HW-05**: TPM probes P-256 capability at provisioning time with clear error if unsupported
- [x] **HW-06**: `unix-oidc-agent login --signer yubikey|tpm|software` CLI flag for backend selection
- [x] **HW-07**: Documentation updated with hardware key setup guides (YubiKey PIV provisioning, TPM enrollment), PCSC daemon requirements, and troubleshooting

## v2 Requirements

Deferred to future milestones. Tracked but not in current roadmap.

### Enhanced Key Lifecycle

- **LIFE-01**: Key TTL with automatic rotation after configurable lifetime
- **LIFE-02**: Per-signing-operation audit events (who signed what, when)
- **LIFE-03**: Key attestation verification (prove key was generated on hardware)

### Advanced Storage

- **ASTOR-01**: Encrypted file backend (for environments without keyring or hardware)
- **ASTOR-02**: `unix-oidc-agent migrate-storage` explicit subcommand for manual migration control
- **ASTOR-03**: FIDO2/WebAuthn signer integration (requires protocol work for DPoP compatibility)

### Post-Quantum

- **PQ-01**: ML-DSA / hybrid signing support when OIDC ecosystem adopts PQ algorithms

## Out of Scope

| Feature | Reason |
|---------|--------|
| `p256` upgrade to 0.14.x | Removes JWK feature the agent depends on; separate migration |
| Distributed JTI cache (Redis) | Server-side concern, different milestone |
| RwLock panic hardening in PAM | Orthogonal to client-side key protection |
| Token revocation API | Requires IdP-side work, separate milestone |
| Agent forwarding support | Anti-feature: breaks PAM non-interactive model and threat model |
| Interactive PIN during PAM auth | Anti-feature: PAM is non-interactive by design |
| OpenSSH-style shielded memory | Nice-to-have but `mlock` + `zeroize` covers the primary threat |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| MEM-01 | Phase 1, Phase 5 | Complete |
| MEM-02 | Phase 1, Phase 5 | Complete |
| MEM-03 | Phase 1 | Complete |
| MEM-04 | Phase 1, Phase 5 | Complete |
| MEM-05 | Phase 1 | Complete |
| MEM-06 | Phase 1 | Complete |
| STOR-01 | Phase 2 | Complete |
| STOR-02 | Phase 2 | Complete |
| STOR-03 | Phase 2 | Complete |
| STOR-04 | Phase 2 | Complete |
| STOR-05 | Phase 2 | Complete |
| STOR-06 | Phase 2 | Complete |
| STOR-07 | Phase 2 | Complete |
| HW-01 | Phase 3, Phase 4 | Complete |
| HW-02 | Phase 3, Phase 4 | Complete |
| HW-03 | Phase 3 | Complete |
| HW-04 | Phase 3 | Complete |
| HW-05 | Phase 3 | Complete |
| HW-06 | Phase 3, Phase 4 | Complete |
| HW-07 | Phase 3 | Complete |

**Coverage:**
- v1 requirements: 20 total
- Complete: 20
- Pending: 0
- Mapped to phases: 20
- Unmapped: 0

---
*Requirements defined: 2026-03-10*
*Last updated: 2026-03-10 after Phase 5 audit documentation cleanup*
