# Phase 3: Hardware Signer Backends - Research

**Researched:** 2026-03-10
**Domain:** PKCS#11/YubiKey PIV (cryptoki), TPM 2.0 (tss-esapi), Rust trait abstraction for hardware signing
**Confidence:** MEDIUM (cryptoki 0.12 confirmed; tss-esapi ECC signing path documented but not end-to-end prototyped)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**PIN Handling**
- PIN cached in memory (SecretString) with configurable timeout per signer backend
- Timeout configured in signer YAML config: `pin_cache_timeout: <seconds>`
- Different defaults per backend type: YubiKey PIN typing defaults to long timeout (e.g., 8h), touch-based confirmation defaults to 0 (always require)
- YubiKey touch policy delegated to device's PIV touch policy setting (`ykman piv`) — agent does not add its own touch layer
- TPM PIN follows same cache-with-timeout pattern
- PIN re-prompt on cache expiry at next sign operation

**Key Provisioning**
- Separate `provision` command: `unix-oidc-agent provision --signer yubikey:9a` or `provision --signer tpm`
- `login --signer <backend>` only uses existing keys — never generates
- If PIV slot has compatible P-256 key, adopt it; if incompatible, error with guidance
- YubiKey slot must be specified explicitly (`--signer yubikey:9a`). No default slot
- TPM keys stored in persistent handle (e.g., 0x81000001). Survives reboots. Agent records handle in metadata
- Software signer auto-generates at login as today
- `provision` errors clearly when hardware not found

**Signer Persistence**
- Signer type stored in `unix-oidc-token-metadata` JSON: `signer_type: "yubikey:9a"` / `"tpm"` / `"software"`
- On daemon restart, read metadata and re-initialize the correct signer backend
- If metadata says hardware but device not found: ERROR, require re-login. No silent fallback to software
- `unix-oidc-agent status` shows: `Signer: yubikey (slot 9a)`, `Signer: tpm (handle 0x81000001)`, `Signer: software`

**Hardware Failure UX**
- Mid-session hardware failure: fail DPoP proof immediately, return error via DPoPSigner trait. No retry
- Error messages are actionable one-liners
- Detect YubiKey PIN lockout (CKR_PIN_LOCKED): display unlock instructions with PUK guidance
- PCSC session pattern: strict open-sign-close per operation. No persistent held sessions

### Claude's Discretion
- PIN input method at login (TTY prompt, env var, or hybrid)
- Which PKCS#11/TPM error codes to special-case beyond PIN lockout
- `HardwareSignerFactory` internal design and signer registration pattern
- `SignerConfig` YAML schema details (field names, validation)
- TPM persistent handle selection strategy (fixed vs. auto-discovered)
- Test fixture design for `#[ignore]` hardware integration tests
- DPoP proof generation refactoring (current `generate_dpop_proof()` takes `&SigningKey` directly)

### Deferred Ideas (OUT OF SCOPE)
None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| HW-01 | `YubiKeySigner` implementing `DPoPSigner` via `cryptoki` 0.12 (PKCS#11) with P-256 ECDSA | cryptoki 0.12 API documented: `Session::sign()` with `Mechanism::EcdsaSha256`; open/sign/close pattern verified |
| HW-02 | `TpmSigner` implementing `DPoPSigner` via `tss-esapi` 7.6 with P-256 ECDSA | `Context::sign()` with `EccSignature` extraction; `TctiNameConf::Tabrmd` for abrmd; EccCurve::NistP256 confirmed |
| HW-03 | Both backends gated behind optional cargo features (`yubikey`, `tpm`) | `#[cfg(feature)]` pattern established in project; optional deps in Cargo.toml |
| HW-04 | YubiKey open-sign-close PCSC pattern per operation | `Pkcs11::open_rw_session()` / session drop closes; do not hold session across operations |
| HW-05 | TPM probes P-256 capability at provisioning time with clear error | `Context::get_capability(CapabilityType::ECCCurves, ...)` then check for `EccCurve::NistP256` |
| HW-06 | `--signer yubikey\|tpm\|software` CLI flag + `SignerConfig` YAML | `clap` derive pattern already in use; `serde_yaml` already in Cargo.toml |
| HW-07 | Hardware key setup docs (YubiKey PIV provisioning, TPM enrollment, PCSC daemon) | Failure modes and setup steps documented below |
</phase_requirements>

---

## Summary

Phase 3 adds two hardware DPoP signing backends to unix-oidc-agent behind optional Cargo feature flags. The YubiKey backend uses the `cryptoki` 0.12 PKCS#11 wrapper (parallaxsecond/rust-cryptoki). The TPM backend uses `tss-esapi` 7.6 (parallaxsecond/rust-tss-esapi). Both implement the existing `DPoPSigner` trait. The current `generate_dpop_proof()` function takes a raw `&SigningKey` and must be refactored — hardware signers produce signatures externally and cannot expose the private key reference.

The most critical spike risk is the `CKM_ECDSA_SHA256` vs `CKM_ECDSA` (raw prehash) choice for YKCS11. ES256 (DPoP) requires SHA-256 hashing of header+payload before ECDSA signature. `CKM_ECDSA_SHA256` handles hashing internally and is the correct mechanism to use. Using `CKM_ECDSA` (raw) would require the agent to SHA-256-hash the data before passing it to the YubiKey — this works but adds SHA-256 in the agent. The PKCS#11 standard produces raw `r||s` concatenated bytes (not DER). For JWS ES256, this is exactly the format required (RFC 7518 §3.4). No conversion needed.

For TPM: `tss-esapi` 7.6 `Context::sign()` returns a `Signature::EcDsa(EccSignature)`. Extract r and s via `.signature_r()` and `.signature_s()` on the `EccSignature`, then concatenate as `[r_padded_32 || s_padded_32]` for JWS. TPM signatures are always big-endian but may be shorter than 32 bytes; left-pad with zeros.

**Primary recommendation:** Use `CKM_ECDSA_SHA256` for YKCS11 (simpler, hardware handles hash). Use `TctiNameConf::Tabrmd` for tss-esapi in production. Refactor `generate_dpop_proof()` to accept raw `r||s` bytes + pre-built JWK JSON instead of `&SigningKey`.

---

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `cryptoki` | 0.12.0 | Idiomatic Rust PKCS#11 wrapper | Maintained by parallaxsecond; same org as tss-esapi; 0.12.0 is current latest (2025-06). Previous research in STATE.md rejected `yubikey` 0.8.0 as unaudited |
| `tss-esapi` | 7.6.0 | TPM 2.0 ESAPI wrapper | Official Rust binding for TCG TSS 2.0 ESAPI; maintained by parallaxsecond; current stable |
| `rpassword` | 7.4.0 | Secure PIN/password prompt from TTY | Cross-platform; reads directly from `/dev/tty` not stdin; `prompt_password()` is the primary API |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `sha2` | 0.10 (already in deps) | SHA-256 for prehash path | If using `CKM_ECDSA` raw mechanism (prehash in agent) — optional if using `CKM_ECDSA_SHA256` |
| `tss-esapi-sys` | pulled transitively | FFI bindings for tss-esapi | Pulled automatically; requires `tpm2-tss` native library at build time |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `cryptoki` 0.12 | `pkcs11` 0.5 | `pkcs11` crate is older, less maintained, lower-level; cryptoki is preferred |
| `cryptoki` 0.12 | `yubikey` 0.8 | Already rejected in research: unaudited, experimental warning, 18 months stale |
| `tss-esapi` 7.6 | `tpm2-pkcs11` via cryptoki | Both work; direct ESAPI gives more control over key lifecycle and capability probing |
| `rpassword` 7.4 | `dialoguer` | dialoguer heavier weight; rpassword purpose-built for password input |

### Installation

```toml
# In unix-oidc-agent/Cargo.toml

[features]
yubikey = ["dep:cryptoki"]
tpm = ["dep:tss-esapi"]

[dependencies]
# Existing deps unchanged ...

# Hardware signer backends (optional features)
cryptoki = { version = "0.12", optional = true }
tss-esapi = { version = "7.6", optional = true }

# PIN input (always available — used by hardware signers when feature enabled)
rpassword = { version = "7", optional = true }
```

Note: `rpassword` can be made optional and pulled in with either hardware feature, or unconditional if kept small. Given its tiny size, unconditional is simpler.

---

## Architecture Patterns

### Recommended Project Structure

```
unix-oidc-agent/src/
├── crypto/
│   ├── mod.rs               # Add yubikey_signer and tpm_signer modules
│   ├── dpop.rs              # Refactor: add sign_dpop_proof_raw() accepting bytes
│   ├── signer.rs            # DPoPSigner trait + SoftwareSigner (unchanged)
│   ├── protected_key.rs     # Unchanged
│   ├── thumbprint.rs        # Will be called from hardware signers
│   ├── yubikey_signer.rs    # New: #[cfg(feature = "yubikey")]
│   └── tpm_signer.rs        # New: #[cfg(feature = "tpm")]
├── hardware/
│   ├── mod.rs               # HardwareSignerFactory + SignerConfig
│   └── pin_cache.rs         # PIN cache with timeout (SecretString, Instant)
└── main.rs                  # Add provision subcommand, --signer flag
```

### Pattern 1: DPoP Proof Generation Refactoring

**What:** `generate_dpop_proof()` currently takes `&SigningKey` and signs `header.payload` inline. Hardware signers cannot expose the private key. Refactor to separate JWT construction from signing.

**When to use:** This is the mandatory pre-requisite for both hardware backends.

**Approach:** Split into two functions:

```rust
// Source: existing dpop.rs logic, refactored

/// Build the unsigned DPoP message (header.payload base64url)
pub fn build_dpop_message(
    public_key_jwk: &serde_json::Value,
    method: &str,
    target: &str,
    nonce: Option<&str>,
) -> Result<(String, String), DPoPError> {
    // Returns (message, jti) — message = "header_b64.claims_b64"
}

/// Assemble a DPoP proof from pre-computed r||s signature bytes
/// Signature bytes MUST be 64 bytes: r (32, big-endian) || s (32, big-endian)
pub fn assemble_dpop_proof(message: &str, sig_rs_bytes: &[u8]) -> Result<String, DPoPError> {
    // base64url-encode sig_rs_bytes and append: "message.sig_b64"
}
```

`SoftwareSigner::sign_proof()` continues to use the existing `generate_dpop_proof()` which wraps these two steps internally.

### Pattern 2: YubiKeySigner — PKCS#11 via cryptoki

**What:** Implements `DPoPSigner` by opening a PKCS#11 session per sign operation. Uses `CKM_ECDSA_SHA256` (hardware hashes + signs) to match ES256 requirements.

**When to use:** When `--features yubikey` is enabled.

```rust
// Source: cryptoki 0.12 docs.rs + YKCS11 mechanism support documentation

#[cfg(feature = "yubikey")]
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType, ObjectClass},
    session::UserType,
    types::AuthPin,
};

pub struct YubiKeySigner {
    pkcs11_path: String,       // e.g., "/usr/lib/libykcs11.so"
    slot_id: u8,               // PIV slot: 0x9a, 0x9c, etc.
    pin_cache: PinCache,       // SecretString + Instant + timeout
    thumbprint: String,        // Precomputed at construction
    public_key_jwk: serde_json::Value,  // Precomputed at construction
}

impl DPoPSigner for YubiKeySigner {
    fn sign_proof(&self, method: &str, target: &str, nonce: Option<&str>)
        -> Result<String, DPoPError>
    {
        // 1. Build DPoP message (header.payload)
        let (message, _jti) = build_dpop_message(&self.public_key_jwk, method, target, nonce)?;

        // 2. Open session — never held across calls (HW-04)
        let pkcs11 = Pkcs11::new(&self.pkcs11_path)?;
        pkcs11.initialize(CInitializeArgs::OsThreads)?;
        let slots = pkcs11.get_slots_with_token()?;
        let slot = slots.get(self.slot_id as usize)
            .ok_or(HardwareSignerError::DeviceNotFound)?;
        let session = pkcs11.open_rw_session(*slot)?;

        // 3. Login with cached PIN (or prompt if expired)
        let pin = self.pin_cache.get_or_prompt()?;
        session.login(UserType::User, Some(&AuthPin::new(pin.expose_secret().into())))?;

        // 4. Find private key in slot
        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            // slot-specific attribute omitted here for brevity
        ];
        let handles = session.find_objects(&template)?;
        let key_handle = handles.first()
            .ok_or(HardwareSignerError::KeyNotFound)?;

        // 5. Sign: CKM_ECDSA_SHA256 — hardware hashes + signs, returns raw r||s bytes
        let sig_bytes = session.sign(
            &Mechanism::EcdsaSha256,
            *key_handle,
            message.as_bytes(),
        )?;

        // 6. Session drops here — PKCS#11 session closed automatically

        // 7. Assemble DPoP proof from r||s bytes
        assemble_dpop_proof(&message, &sig_bytes).map_err(DPoPError::from)
    }
}
```

**CKM_ECDSA vs CKM_ECDSA_SHA256 decision:** Use `CKM_ECDSA_SHA256`. It handles the SHA-256 hash internally. If `CKM_ECDSA_SHA256` is not available on a given PKCS#11 module, fall back to: SHA-256 hash the message in agent, then call `session.sign(&Mechanism::Ecdsa, ...)` with the 32-byte digest. The YKCS11 module supports both.

**Signature output format:** PKCS#11 `CKM_ECDSA` and `CKM_ECDSA_SHA256` both return raw `r||s` concatenated bytes (per PKCS#11 spec, section 11.3.1). For P-256, this is exactly 64 bytes (32+32). This is the correct format for JWS ES256 (RFC 7518 §3.4). No DER conversion needed.

### Pattern 3: TpmSigner — TPM 2.0 via tss-esapi

**What:** Implements `DPoPSigner` using a persistent TPM key. Context opened per operation via `TctiNameConf::Tabrmd`.

**When to use:** When `--features tpm` is enabled.

```rust
// Source: tss-esapi 7.6 docs.rs + Context method signatures

#[cfg(feature = "tpm")]
use tss_esapi::{
    Context,
    abstraction::pcr::PcrData,
    handles::{KeyHandle, PersistentTpmHandle},
    interface_types::{
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::Hierarchy,
    },
    structures::{
        EccScheme, HashScheme, Public, Signature, SignatureScheme,
        HashcheckTicket,
    },
    tcti_ldr::{TabrmdConfig, TctiNameConf},
};

pub struct TpmSigner {
    persistent_handle: u32,       // e.g., 0x81000001
    thumbprint: String,
    public_key_jwk: serde_json::Value,
}

impl DPoPSigner for TpmSigner {
    fn sign_proof(&self, method: &str, target: &str, nonce: Option<&str>)
        -> Result<String, DPoPError>
    {
        let (message, _jti) = build_dpop_message(&self.public_key_jwk, method, target, nonce)?;

        // Open context per operation — no persistent context held
        let tcti = TctiNameConf::Tabrmd(TabrmdConfig::default());
        let mut ctx = Context::new(tcti)
            .map_err(|e| HardwareSignerError::TpmError(e.to_string()))?;

        // Load key from persistent handle
        let handle: KeyHandle = ctx.tr_from_tpm_public(
            tss_esapi::handles::TpmHandle::Persistent(
                PersistentTpmHandle::new(self.persistent_handle)
                    .map_err(|e| HardwareSignerError::TpmError(e.to_string()))?
            )
        ).map_err(|e| HardwareSignerError::TpmError(e.to_string()))?.into();

        // SHA-256 hash message in agent (TPM sign takes a digest, not raw data)
        let digest_bytes = sha2::Sha256::digest(message.as_bytes());
        let digest = tss_esapi::structures::Digest::try_from(digest_bytes.as_slice())
            .map_err(|e| HardwareSignerError::TpmError(e.to_string()))?;

        // Signing scheme: ECDSA with SHA-256
        let scheme = SignatureScheme::EcDsa {
            hash_scheme: HashScheme::new(tss_esapi::interface_types::algorithm::HashingAlgorithm::Sha256),
        };

        // ECDSA sign — requires a null/trial validation ticket for unrestricted signing keys
        let validation = HashcheckTicket::try_from(
            tss_esapi::structures::Ticket::try_from(
                tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                    tag: tss_esapi::tss2_esys::TPM2_ST_HASHCHECK,
                    hierarchy: tss_esapi::tss2_esys::TPM2_RH_NULL,
                    digest: Default::default(),
                }
            ).map_err(|e| HardwareSignerError::TpmError(e.to_string()))?
        ).map_err(|e| HardwareSignerError::TpmError(e.to_string()))?;

        let signature = ctx.sign(handle, digest, scheme, validation)
            .map_err(|e| HardwareSignerError::TpmError(e.to_string()))?;

        // Extract r||s bytes from TPM signature
        let sig_bytes = match signature {
            Signature::EcDsa(ecc_sig) => {
                let r = ecc_sig.signature_r().value();
                let s = ecc_sig.signature_s().value();
                // Left-pad to 32 bytes each (big-endian, P-256)
                let mut out = [0u8; 64];
                let r_start = 32 - r.len().min(32);
                let s_start = 32 + (32 - s.len().min(32));
                out[r_start..32].copy_from_slice(&r[r.len().saturating_sub(32)..]);
                out[s_start..64].copy_from_slice(&s[s.len().saturating_sub(32)..]);
                out
            }
            _ => return Err(DPoPError::InvalidKey), // unreachable for ECC key
        };

        assemble_dpop_proof(&message, &sig_bytes).map_err(DPoPError::from)
    }
}
```

### Pattern 4: HardwareSignerFactory

**What:** Parses `--signer` string and constructs the appropriate `Arc<dyn DPoPSigner>`.

**Design (Claude's discretion):** A simple `match` on the signer string is cleaner than a registration map for this number of backends:

```rust
pub fn build_signer(signer_spec: &str, config: &SignerConfig)
    -> anyhow::Result<Arc<dyn DPoPSigner>>
{
    if signer_spec == "software" || signer_spec.is_empty() {
        return Ok(Arc::new(SoftwareSigner::generate()));
    }

    #[cfg(feature = "yubikey")]
    if let Some(slot) = signer_spec.strip_prefix("yubikey:") {
        return Ok(Arc::new(YubiKeySigner::open(slot, config)?));
    }

    #[cfg(feature = "tpm")]
    if signer_spec == "tpm" {
        return Ok(Arc::new(TpmSigner::load(config)?));
    }

    anyhow::bail!("Unknown signer: '{}'. Valid options: software, yubikey:<slot>, tpm", signer_spec)
}
```

### Pattern 5: SignerConfig YAML Schema

**Design (Claude's discretion):**

```yaml
# ~/.config/unix-oidc/signer.yaml (or /etc/unix-oidc/signer.yaml)
yubikey:
  pkcs11_library: /usr/lib/libykcs11.so   # or /usr/local/lib on macOS
  pin_cache_timeout: 28800                 # 8 hours (seconds), 0 = always prompt
  slot: "9a"                              # default slot (overridden by --signer yubikey:9c)

tpm:
  tcti: tabrmd                            # tabrmd | device | mssim
  persistent_handle: 0x81000001           # NV handle for DPoP key
  pin_cache_timeout: 28800
```

### Pattern 6: PinCache

**Design (Claude's discretion):**

```rust
pub struct PinCache {
    cached: Mutex<Option<(SecretString, Instant)>>,
    timeout_secs: u64,
}

impl PinCache {
    pub fn get_or_prompt(&self, prompt: &str) -> anyhow::Result<SecretString> {
        let mut guard = self.cached.lock().unwrap();
        if let Some((ref pin, ref ts)) = *guard {
            if ts.elapsed().as_secs() < self.timeout_secs {
                return Ok(pin.clone());
            }
        }
        // Cache miss or expired: prompt
        let pin = rpassword::prompt_password(prompt)
            .map(SecretString::from)
            .map_err(|e| anyhow::anyhow!("Failed to read PIN: {}", e))?;
        *guard = Some((pin.clone(), Instant::now()));
        Ok(pin)
    }
}
```

For `pin_cache_timeout: 0`, always prompt (skip cache check).

### Anti-Patterns to Avoid

- **Holding PKCS#11 sessions across operations:** Violates HW-04. Always open/sign/close atomically per `sign_proof()` call. A held session acquires a PCSC exclusive lock, blocking `gpg --card-status` and other tools.
- **Using `CKM_ECDSA` with unhashed data:** Results in nonsense signatures. Either use `CKM_ECDSA_SHA256` or pre-hash with SHA-256 when using raw `CKM_ECDSA`.
- **Falling back to software signer on hardware error:** Explicitly prohibited. If metadata says hardware signer, fail loudly (HW-04 decision).
- **Storing PKCS#11 session or TPM Context in `Arc`:** Both are not `Send + Sync` in the general case. Re-create per operation.
- **Not left-padding r/s to 32 bytes:** TPM EccParameter can be shorter than 32 bytes when high bits are zero. JWS requires exactly 64 bytes for P-256.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| PKCS#11 session management | Custom PCSC bindings | `cryptoki` 0.12 | PKCS#11 state machine has many edge cases; cryptoki already wraps them |
| TPM context and command serialization | Direct tpm2-tss FFI | `tss-esapi` 7.6 | ESAPI handles session management, authorization tickets, HMAC sessions |
| Secure PIN prompt (no echo) | Custom termios manipulation | `rpassword` 7.4 | Cross-platform; handles TTY vs pipe correctly; battle-tested |
| DER-to-raw signature conversion | Manual ASN.1 parse | Not needed | PKCS#11 already returns raw r||s; TPM EccSignature has `.signature_r()` / `.signature_s()` accessors |

**Key insight:** The entire complexity of PKCS#11 and TPM session management exists to handle edge cases (slot enumeration, session state, authorization sessions, HMAC sessions). The wrappers handle all of this correctly.

---

## Common Pitfalls

### Pitfall 1: PKCS#11 CKM_ECDSA signature format confusion

**What goes wrong:** Developer assumes PKCS#11 ECDSA output is DER-encoded (like OpenSSL default). Code fails to verify because it base64-encodes a DER blob instead of raw r||s.

**Why it happens:** OpenSSL by default outputs DER ECDSA signatures. PKCS#11 standard (and YKCS11) outputs raw r||s. The formats differ.

**How to avoid:** PKCS#11 spec (section 11.3.1, OASIS PKCS#11 Current v2.40) specifies: "The signature octets correspond to the concatenation of the ECDSA values r and s, both represented as an octet string of equal length of at most nLen." For P-256, output is exactly 64 bytes. Use directly in JWS.

**Warning signs:** Signature decode error in JWS verification; signature length is not 64 bytes for P-256.

### Pitfall 2: CKM_ECDSA_SHA256 not available on all PKCS#11 modules

**What goes wrong:** libykcs11 supports `CKM_ECDSA_SHA256`, but some third-party PKCS#11 modules only expose `CKM_ECDSA` (raw). Hard-coding `CKM_ECDSA_SHA256` causes `CKR_MECHANISM_INVALID`.

**Why it happens:** PKCS#11 mechanism support is module-specific.

**How to avoid:** Probe available mechanisms at provisioning time via `pkcs11.get_mechanism_list(slot)?`. If `CKM_ECDSA_SHA256` is present, use it. If only `CKM_ECDSA` is present, SHA-256 hash the message in the agent before passing to sign.

**Warning signs:** `CKR_MECHANISM_INVALID` (0x00000070) error on first sign attempt.

### Pitfall 3: YubiKey PIN lockout after 3 wrong PINs

**What goes wrong:** Cached PIN becomes stale (user changed PIN via ykman), next sign operation retries and triggers lockout.

**Why it happens:** PINs are cached; external PIN changes are not detected.

**How to avoid:** On `CKR_PIN_INCORRECT`, immediately clear the PIN cache and prompt for new PIN with a clear message. Detect `CKR_PIN_LOCKED` (0x000000A4) and display: "YubiKey PIN is locked. Use `ykman piv access unblock-pin` with your PUK to unblock."

**Warning signs:** `CKR_PIN_INCORRECT` (0x000000A0) — clear cache, re-prompt once. `CKR_PIN_LOCKED` (0x000000A4) — do not retry, display recovery instructions.

### Pitfall 4: TPM HashcheckTicket requirement for unrestricted signing keys

**What goes wrong:** Calling `Context::sign()` without a proper `HashcheckTicket` fails with `TPM2_RC_TICKET` or similar authorization error.

**Why it happens:** TPM restricts signing keys require a proof that the digest was computed by the TPM itself (via TPM2_Hash command). Unrestricted signing keys do NOT have this restriction and accept a null ticket (`TPM2_RH_NULL` hierarchy with empty digest).

**How to avoid:** Create keys as unrestricted signing keys (`objectAttributes` with `SIGN_ENCRYPT` but NOT `RESTRICTED`). Use a null HashcheckTicket (shown in code example above) for unrestricted keys.

**Warning signs:** `TPM2_RC_TICKET` or `TPM2_RC_SCHEME` errors from TPM.

### Pitfall 5: TPM EccParameter shorter than 32 bytes

**What goes wrong:** r or s values with leading zero bytes are returned shorter than 32 bytes by the TPM. Concatenating without padding produces a 63-byte or shorter signature that fails JWS verification.

**Why it happens:** TPM returns minimal length EccParameter values (no unnecessary leading zeros).

**How to avoid:** Always left-pad both r and s to exactly 32 bytes before concatenation (shown in code example above).

**Warning signs:** JWS signature verification failure with "invalid signature length."

### Pitfall 6: Feature-gated modules not compiled into docs/IDE

**What goes wrong:** Code compiles with `cargo build --no-default-features` but `cargo test` or IDE analysis misses hardware signer modules.

**Why it happens:** `#[cfg(feature = "yubikey")]` excludes the module from default builds.

**How to avoid:** Use `cfg_attr` for doc and add `[features] default = []` (no hardware features by default). Use `cargo test --features yubikey` for hardware tests. `cargo check` without features must succeed for the base binary.

---

## Code Examples

### YubiKey: Find EC key in slot 9a

```rust
// Source: cryptoki 0.12 Session::find_objects API + YKCS11 key type documentation
let template = [
    Attribute::Class(ObjectClass::PRIVATE_KEY),
    Attribute::KeyType(KeyType::EC),
    Attribute::Id(vec![0x01]),  // YKCS11: slot 9a = key id 0x01
];
let handles = session.find_objects(&template)?;
```

YKCS11 key ID mapping: slot 9a = 0x01, 9c = 0x02, 9d = 0x03, 9e = 0x04.

### YubiKey: Read public key point for thumbprint computation

```rust
// Source: cryptoki 0.12 Attribute::EcPoint retrieval
let pub_key_attrs = session.get_attributes(
    pub_key_handle,
    &[AttributeType::EcPoint, AttributeType::EcParams],
)?;
// EcPoint is a DER-encoded ECPoint (0x04 || uncompressed point bytes wrapped in OCTET STRING)
// Strip the DER OCTET STRING wrapper: first 2 bytes (04 41 for P-256 uncompressed 65-byte point)
```

### TPM: P-256 capability probe at provisioning

```rust
// Source: tss-esapi 7.6 Context::get_capability + capability_commands.rs source
let (capability_data, _more) = ctx.get_capability(
    tss_esapi::constants::CapabilityType::EccCurves,
    0,
    32,
)?;

let supports_p256 = match capability_data {
    tss_esapi::structures::CapabilityData::EccCurves(curves) => {
        curves.contains(&tss_esapi::interface_types::ecc::EccCurve::NistP256)
    }
    _ => false,
};

if !supports_p256 {
    return Err(anyhow::anyhow!(
        "This TPM does not support P-256 (NistP256 ECC curve). \
         DPoP requires ES256 (P-256 ECDSA). Cloud vTPMs may not support all curves."
    ));
}
```

### TPM: Create unrestricted P-256 signing key and make persistent

```rust
// Source: tss-esapi 7.6 Context::create + evict_control APIs
use tss_esapi::utils::create_unrestricted_signing_ecc_public;

let ecc_public = create_unrestricted_signing_ecc_public(
    EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
    EccCurve::NistP256,
)?;

// Create under Owner hierarchy (survives reboots in persistent NV)
let result = ctx.execute_with_session(None, |ctx| {
    ctx.create_primary(
        Hierarchy::Owner,
        ecc_public,
        None,  // no auth value (PIN handled via TPM authorization session if needed)
        None, None, None,
    )
})?;

// Make persistent at handle 0x81000001
let persistent = PersistentTpmHandle::new(0x81000001)?;
ctx.evict_control(Provision::Owner, result.key_handle.into(), Persistent::Persistent(persistent))?;
```

### Signer type in token metadata JSON

```json
{
  "expires_at": 1741650000,
  "refresh_token": "...",
  "issuer": "https://sso.example.com",
  "token_endpoint": "https://sso.example.com/token",
  "client_id": "unix-oidc",
  "signer_type": "yubikey:9a"
}
```

Daemon restart reads `signer_type` and re-initializes appropriate backend. On hardware not found, `load_agent_state()` returns `Err` (not `Ok` with no signer).

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `yubikey` 0.8.0 pure-Rust PIV crate | `cryptoki` 0.12 via PKCS#11 | Pre-roadmap decision | More portable; supports any PKCS#11 device, not just YubiKey |
| Direct `/dev/tpm0` access | `tss-esapi` with `tpm2-abrmd` TCTI | Industry standard since ~2019 | Multi-process safe; resource manager handles concurrent TPM access |
| DER-encoded ECDSA signatures (OpenSSL convention) | Raw r||s (PKCS#11 and JWS convention) | Always correct for JWS | No conversion layer needed |

**Deprecated/outdated:**
- `yubikey` 0.8.0 crate: experimental warning, stale 18 months (noted in STATE.md research decisions)
- Direct `/dev/tpm0` access without abrmd: works single-process only; conflicts with other TPM users (systemd-cryptenroll, etc.)
- `CKM_ECDSA` with raw message (not hashed): only valid for prehashed data; use `CKM_ECDSA_SHA256` instead

---

## Open Questions

1. **cryptoki 0.12 EcPoint DER encoding for public key extraction**
   - What we know: `AttributeType::EcPoint` returns a DER-encoded octet string per PKCS#11 spec
   - What's unclear: Exact byte offset to skip DER OCTET STRING wrapper to reach the uncompressed EC point (0x04 prefix)
   - Recommendation: Spike in Plan 03-01. Expected format: `04 41 04 <32-byte-x> <32-byte-y>` (first two bytes are DER OCTET STRING TLV, third byte is the uncompressed point prefix). Strip first 2 bytes.

2. **TPM `create_unrestricted_signing_ecc_public` availability in tss-esapi 7.6**
   - What we know: The function exists in the `utils` module per documentation (~17% coverage)
   - What's unclear: Exact import path and whether it accepts `EccScheme` directly or requires a `PublicEccParametersBuilder`
   - Recommendation: Check `tss_esapi::utils::create_unrestricted_signing_ecc_public` at compile time in Plan 03-02. If absent, use `PublicEccParametersBuilder` directly.

3. **TPM null HashcheckTicket construction**
   - What we know: Unrestricted signing keys take a null ticket; `TPM2_RH_NULL` hierarchy with empty digest
   - What's unclear: Whether `tss-esapi` 7.6 has a convenience constructor for null HashcheckTicket
   - Recommendation: Spike in Plan 03-02. Check for `HashcheckTicket::null()` or similar. If absent, construct via raw TPMT_TK_HASHCHECK as shown in code example.

4. **Cloud vTPM P-256 support (AWS Nitro, GCP, Azure)**
   - What we know: Physical TPMs generally support P-256; cloud vTPMs vary
   - What's unclear: Confirmed list of cloud vTPMs that support P-256 ECDSA
   - Recommendation: The P-256 capability probe (HW-05) handles this at runtime. Document in HW-07 that cloud vTPM users should run `unix-oidc-agent provision --signer tpm` on their instance to verify before deploying.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | `cargo test` (Rust built-in) |
| Config file | `unix-oidc-agent/Cargo.toml` (dev-dependencies: tempfile, tokio-test) |
| Quick run command | `cargo test -p unix-oidc-agent --lib` |
| Full suite command | `cargo test -p unix-oidc-agent` |
| Hardware tests command | `cargo test -p unix-oidc-agent --features yubikey,tpm -- --include-ignored` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| HW-01 | YubiKeySigner implements DPoPSigner trait | unit (mock session) | `cargo test -p unix-oidc-agent --features yubikey crypto::yubikey_signer` | ❌ Wave 0 |
| HW-01 | YubiKey generates valid DPoP proof (r\|\|s format) | integration (#[ignore]) | `cargo test -p unix-oidc-agent --features yubikey -- --ignored yubikey` | ❌ Wave 0 |
| HW-02 | TpmSigner implements DPoPSigner trait | unit (mock context) | `cargo test -p unix-oidc-agent --features tpm crypto::tpm_signer` | ❌ Wave 0 |
| HW-02 | TPM generates valid DPoP proof | integration (#[ignore]) | `cargo test -p unix-oidc-agent --features tpm -- --ignored tpm` | ❌ Wave 0 |
| HW-03 | Base build with no features compiles clean | build test | `cargo build -p unix-oidc-agent` | ✅ (existing CI) |
| HW-04 | PCSC open-sign-close per operation (no held session) | unit (verify session not stored) | `cargo test -p unix-oidc-agent --features yubikey no_held_session` | ❌ Wave 0 |
| HW-05 | P-256 capability probe rejects TPM without NistP256 | unit (mock capability response) | `cargo test -p unix-oidc-agent --features tpm p256_capability_probe` | ❌ Wave 0 |
| HW-06 | `--signer` flag parsed correctly; factory builds right type | unit | `cargo test -p unix-oidc-agent hardware::factory` | ❌ Wave 0 |
| HW-07 | Docs present (manual verification) | manual | n/a | ❌ Wave 0 |

### Sampling Rate

- **Per task commit:** `cargo test -p unix-oidc-agent --lib` (unit tests, no hardware required)
- **Per wave merge:** `cargo test -p unix-oidc-agent` (full suite including integration)
- **Phase gate:** Full suite green + `cargo build -p unix-oidc-agent` (no features) succeeds

### Wave 0 Gaps

- [ ] `unix-oidc-agent/src/crypto/yubikey_signer.rs` — covers HW-01, HW-04
- [ ] `unix-oidc-agent/src/crypto/tpm_signer.rs` — covers HW-02
- [ ] `unix-oidc-agent/src/hardware/mod.rs` — HardwareSignerFactory, covers HW-06
- [ ] `unix-oidc-agent/src/hardware/pin_cache.rs` — PIN cache implementation
- [ ] `unix-oidc-agent/tests/hardware_integration.rs` — `#[ignore]` tests for HW-01, HW-02

---

## Sources

### Primary (HIGH confidence)

- `cryptoki` 0.12 — docs.rs/cryptoki/latest — Session::sign, Mechanism enum, find_objects API
- YKCS11 Yubico documentation — developers.yubico.com/yubico-piv-tool/YKCS11/Functions_and_values.html — CKM_ECDSA_SHA256 supported, P-256 confirmed, raw r||s output format
- `tss-esapi` 7.6.0 — docs.rs/tss-esapi/7.6.0 — Context::sign, EccSignature, EccParameter::value(), TctiNameConf::Tabrmd, evict_control, EccCurve::NistP256
- PKCS#11 spec — docs.oasis-open.org/pkcs11/pkcs11-curr/v2.40/cs01/ — §11.3.1 EC signature format (raw r||s)
- RFC 7518 §3.4 — tools.ietf.org/html/rfc7518 — JWS ES256 signature format (raw r||s, 64 bytes P-256)

### Secondary (MEDIUM confidence)

- docs.rs/rpassword/7.4.0 — prompt_password(), TTY vs pipe behavior
- STATE.md project decisions — yubikey 0.8.0 rejection rationale, cryptoki selection

### Tertiary (LOW confidence)

- tss-esapi `create_unrestricted_signing_ecc_public` exact signature — not confirmed in docs (17% doc coverage); inferred from utils module listing and function name
- null HashcheckTicket construction exact API — inferred from TPMT_TK_HASHCHECK structure; needs spike confirmation

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — cryptoki 0.12.0 confirmed latest; tss-esapi 7.6.0 confirmed; rpassword 7.4.0 confirmed
- Architecture: MEDIUM — YubiKey PKCS#11 flow well-documented; TPM ECC path documented but not end-to-end prototyped (Plan 03-01 is explicitly a spike)
- Pitfalls: HIGH — PKCS#11 r||s format confirmed from spec; PIN lockout codes from PKCS#11 spec; TPM padding requirement from EccParameter docs

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (stable libraries; 30-day window)
