# Phase 3: Hardware Signer Backends - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Add YubiKey (via PKCS#11/cryptoki) and TPM 2.0 (via tss-esapi) as optional DPoP signer implementations behind Cargo feature flags (`--features yubikey`, `--features tpm`). Users select a signer at login via `--signer` CLI flag. Users without hardware tokens are unaffected — the default software signer remains.

Requirements: HW-01, HW-02, HW-03, HW-04, HW-05, HW-06, HW-07

</domain>

<decisions>
## Implementation Decisions

### PIN Handling
- PIN cached in memory (SecretString) with configurable timeout per signer backend
- Timeout configured in signer YAML config: `pin_cache_timeout: <seconds>`
- Different defaults per backend type: YubiKey PIN typing defaults to long timeout (e.g., 8h), touch-based confirmation defaults to 0 (always require — it's fast)
- YubiKey touch policy delegated to device's PIV touch policy setting (`ykman piv` config) — agent does not add its own touch layer. PKCS#11 call blocks until touch completes
- TPM PIN follows same cache-with-timeout pattern
- PIN re-prompt on cache expiry at next sign operation

### Key Provisioning
- Separate `provision` command for key generation on hardware: `unix-oidc-agent provision --signer yubikey:9a` or `provision --signer tpm`
- `login --signer <backend>` only uses existing keys — never generates. Clean separation of destructive (provision) vs non-destructive (login) operations
- If PIV slot already has a compatible P-256 key, adopt it (read public key, compute thumbprint, start signing). If not P-256 or incompatible, error with guidance
- YubiKey slot must be specified explicitly: `--signer yubikey:9a`. No default slot — if user omits slot, suggest 9a (PIV Authentication) in the error message
- TPM keys stored in persistent handle (e.g., 0x81000001). Survives reboots. Agent records handle in metadata
- Software signer (`--signer software`, the default) doesn't need provisioning — auto-generates at login as today
- `provision` errors clearly when hardware not found: "No YubiKey detected (is pcscd running?)" or "TPM not available"

### Signer Persistence
- Signer type stored in existing `unix-oidc-token-metadata` JSON: `signer_type: "yubikey:9a"` or `signer_type: "tpm"` or `signer_type: "software"`
- On daemon restart, read metadata and re-initialize the correct signer backend
- If metadata says hardware signer but device not found: ERROR, require re-login. No silent fallback to software signer — that would change the DPoP key and break token binding
- `unix-oidc-agent status` shows signer line: `Signer: software`, `Signer: yubikey (slot 9a)`, `Signer: tpm (handle 0x81000001)`. Consistent with existing storage/mlock status lines

### Hardware Failure UX
- Mid-session hardware failure (YubiKey unplugged, TPM error): fail the DPoP proof immediately, return error via DPoPSigner trait. No silent fallback, no retry. SSH connection fails with actionable message
- Error messages are actionable one-liners: "DPoP signing failed: YubiKey not detected. Plug in your YubiKey and retry." or "DPoP signing failed: TPM error (device busy). Check if another process holds the TPM."
- Detect YubiKey PIN lockout specifically (CKR_PIN_LOCKED): display "YubiKey PIN is locked after too many failed attempts. Use `ykman piv access unblock-pin` to unblock with your PUK."
- Special-case common PKCS#11 and TPM error codes for user-friendly messages (Claude's discretion on which codes to handle)
- PCSC session pattern: strict open-sign-close per operation. No held sessions. Prevents gpg/other PCSC tool conflicts (HW-04)

### Claude's Discretion
- PIN input method at login (TTY prompt, env var, or hybrid — optimize for security across terminal/IDE/cross-OS)
- Which PKCS#11/TPM error codes to special-case beyond PIN lockout
- `HardwareSignerFactory` internal design and signer registration pattern
- `SignerConfig` YAML schema details (field names, validation)
- TPM persistent handle selection strategy (fixed vs. auto-discovered)
- Test fixture design for `#[ignore]` hardware integration tests
- DPoP proof generation refactoring to support hardware signers (current `generate_dpop_proof()` takes `&SigningKey` directly — needs abstraction)

</decisions>

<specifics>
## Specific Ideas

- `provision` vs `login` separation is deliberate: provisioning is destructive (writes to hardware), login is non-destructive. Users who pre-provision via enterprise PKI tooling (`ykman`, `tpm2_tools`) can skip `provision` entirely and go straight to `login --signer yubikey:9a`
- No default YubiKey slot — require explicit specification to avoid accidentally using/overwriting the wrong slot in multi-purpose YubiKey setups
- TPM keys are inherently non-portable between devices. On laptop change: re-provision + re-login. This is by design (non-exportable key storage)
- PIN lockout detection is user-facing quality-of-life: 3 wrong PINs locks the YubiKey, and without specific guidance users will be confused by opaque PKCS#11 errors

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `DPoPSigner` trait (`unix-oidc-agent/src/crypto/signer.rs:20-34`): Stable trait with `thumbprint()`, `sign_proof()`, `public_key_jwk()` — hardware signers implement this directly
- `SoftwareSigner` (`unix-oidc-agent/src/crypto/signer.rs:43-98`): Reference implementation showing the trait contract
- `StorageRouter` (`unix-oidc-agent/src/storage/router.rs`): Stores token metadata including new `signer_type` field
- `AgentState` (`unix-oidc-agent/src/daemon/socket.rs:28-38`): Holds `Arc<dyn DPoPSigner>` — hardware signers slot in via the same Arc pattern
- `generate_dpop_proof()` (`unix-oidc-agent/src/crypto/dpop.rs:40-85`): Currently takes `&SigningKey` — needs refactoring for hardware signers that can't expose raw key reference

### Established Patterns
- `thiserror` for error types — extend `DPoPError` or create `HardwareSignerError`
- `tracing` structured logging — hardware events at INFO/WARN
- `#[cfg(feature = "...")]` for optional compilation — use for `yubikey` and `tpm` features
- `SecretString` for sensitive values — use for cached PINs
- Box-only constructors for security-sensitive types (ProtectedSigningKey pattern)

### Integration Points
- `main.rs` login path: add `--signer` flag parsing, construct appropriate signer via factory
- `main.rs` provision path: new subcommand for hardware key generation
- Token metadata JSON: add `signer_type` field
- Status command: add signer type line
- `Cargo.toml`: add optional `cryptoki` and `tss-esapi` dependencies behind feature flags
- `crypto/mod.rs`: add `yubikey_signer` and `tpm_signer` modules behind `#[cfg(feature)]`

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 03-hardware-signer-backends*
*Context gathered: 2026-03-10*
