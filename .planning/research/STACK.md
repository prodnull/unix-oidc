# Technology Stack: Client-Side Key Protection

**Project:** unix-oidc — Key Storage Hardening Milestone
**Researched:** 2026-03-10
**Scope:** OS keyring, memory locking, secure zeroing, YubiKey PIV, TPM 2.0

---

## Recommended Stack

### Domain 1 — OS Keyring / Keychain Integration

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `keyring` | **3.6.3** (stable) | OS keychain integration — macOS Keychain, Linux Secret Service, Linux kernel keyutils | HIGH |

**Recommendation:** Upgrade from `keyring = "3"` (which resolves to 3.6.3) and enable the `linux-native-sync-persistent` feature set for Linux headless-server compatibility.

**Rationale:**

The project already depends on `keyring` 3. Version 3.6.3 is the latest stable (released 2025-07-27). Version 4.0.0-rc.3 exists but is pre-release (multiple betas yanked, not yet stable as of 2026-02-01). **Do not upgrade to 4.x until it stabilises.**

The critical decision for this project is the Linux backend selection. The crate exposes three distinct Linux backends:

1. **`linux-native` (kernel keyutils, `linux-keyutils` 0.2.4)** — Uses the Linux kernel's in-kernel keyring via raw syscalls. No D-Bus, no daemon dependency. Survives headless/containerised/systemd service environments. **Does not persist across reboots** (in-memory only at the kernel level). This is the right backend for DPoP key caching within a session.

2. **`sync-secret-service` (D-Bus libsecret)** — Uses the FreeDesktop Secret Service API (GNOME Keyring, KWallet). Persists across reboots. **Requires a running D-Bus session bus and a Secret Service provider** — absent on headless servers, minimal cloud VMs, and containers. Known tokio deadlock risk if called on the main async thread (must spawn blocking thread).

3. **`linux-native-sync-persistent`** — Combines both: stores in kernel keyutils for fast access, falls back to Secret Service for persistence. Best of both worlds but introduces D-Bus dependency.

**For unix-oidc specifically:** The agent stores DPoP private keys that must survive reboots (otherwise the user must re-authenticate on every boot). The right feature set is `linux-native-sync-persistent` on Linux and `apple-native` on macOS. The existing `KeyringStorage` must add graceful degradation: if Secret Service is unavailable (headless server), fall back to `linux-native` (session-scoped) with a logged warning that keys will not survive reboot, then fall further back to `FileStorage`.

**Feature flags to specify:**

```toml
[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "3.6.3", features = ["linux-native-sync-persistent", "crypto-rust"] }

[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "3.6.3", features = ["apple-native"] }
```

Use `crypto-rust` (not `crypto-openssl`) to avoid introducing an OpenSSL dependency — the project already uses `rustls` exclusively.

**Known issues:**
- KDE Wallet (KWallet) is limited to UTF-8 strings. The existing base64-encoding in `KeyringStorage` already handles this correctly.
- Tokio deadlock: the existing `KeyringStorage` is synchronous; do not call it from an async context without `tokio::task::spawn_blocking`.
- `delete_credential()` (3.x API) differs from `delete_password()` (2.x) — already handled in the existing code.

---

### Domain 2 — Secure Memory Zeroing on Drop

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `zeroize` | **1.8.2** | Zero key material bytes on drop; `#[derive(ZeroizeOnDrop)]`; integrates with RustCrypto types | HIGH |
| `secrecy` | **0.10.3** | `Secret<T>` wrapper that zeroes T on drop; enforces that secrets are not accidentally logged or compared | HIGH |

**Rationale:**

`zeroize` 1.8.2 (released 2025-09-29, 372M downloads) is the RustCrypto-ecosystem standard for secure zeroing. It uses volatile writes and compiler fences to prevent the optimizer from eliding the zeroing. It is already the transitive dependency of `p256` 0.13, `secrecy`, and dozens of other crates in this ecosystem — adding it explicitly does not widen the dependency tree.

The `p256` crate's `SigningKey` type already implements `ZeroizeOnDrop` (via `elliptic-curve`'s integration with zeroize). **However**, `SoftwareSigner::export_key()` currently returns `Vec<u8>` — a raw allocation that will not be zeroed on drop. This is the primary gap to fix.

**Fix pattern:**

```rust
use zeroize::Zeroizing;

// BEFORE (unsafe — key bytes linger in heap until allocator reclaims them)
pub fn export_key(&self) -> Vec<u8> {
    self.signing_key.to_bytes().to_vec()
}

// AFTER (bytes zeroed when the Zeroizing wrapper is dropped)
pub fn export_key(&self) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(self.signing_key.to_bytes().to_vec())
}
```

`secrecy` 0.10.3 wraps a `Secret<T: Zeroize>` that:
- Calls `T::zeroize()` on drop
- Redacts the value in `Debug` output (prevents accidental log leakage)
- Prevents `PartialEq` comparisons that might leak via timing

Use `Secret<Zeroizing<Vec<u8>>>` for in-memory token and key storage within the agent daemon. `secrecy` depends on `zeroize ^1.6`, which is compatible with `zeroize` 1.8.2.

**What NOT to use:**
- `memsec` 0.7.0 — implements libsodium-style `mlock`/`memzero`. Last released 2024-06-06. Provides `mlock` wrapper but requires `unsafe` throughout. For zeroing alone, `zeroize` is cleaner, better maintained, and already in the dependency tree.
- `secrets` 1.2.0 — stale since 2022, low adoption.

---

### Domain 3 — Memory Locking (mlock / prevent swap)

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `memsec` | **0.7.0** | `mlock`/`munlock` wrappers for pinning key pages to RAM | MEDIUM |
| `libc` (direct) | **0.2.x** (workspace) | `libc::mlock` / `libc::munlock` raw syscall — already a workspace dep | HIGH |

**Recommendation: Use `libc::mlock` directly, not `memsec`.**

**Rationale:**

`mlock(2)` prevents kernel pages containing key material from being written to swap. This is a `POSIX.1-2001` syscall, available on all Linux targets (Ubuntu 22.04+, RHEL 9+) and macOS. `libc` 0.2 is already a workspace dependency (required by `pamsm`). Adding a `mlock` call costs zero additional dependencies.

The pattern for a memory-locked buffer wrapping a P-256 key:

```rust
use std::ptr;
use libc::{mlock, munlock};

pub struct LockedBuffer {
    data: Vec<u8>,
}

impl LockedBuffer {
    pub fn new(data: Vec<u8>) -> Self {
        // SAFETY: Valid pointer, size is len() of a Vec<u8>
        unsafe {
            mlock(data.as_ptr() as *const _, data.len());
        }
        Self { data }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        // Zeroize first, then unlock
        use zeroize::Zeroize;
        self.data.zeroize();
        unsafe {
            munlock(self.data.as_ptr() as *const _, self.data.len());
        }
    }
}
```

**Important constraints:**

- `mlock` requires `CAP_IPC_LOCK` capability or the locked bytes must fit within the process's `RLIMIT_MEMLOCK` limit. On Linux, the default limit for non-root users is 64 KiB — sufficient for a P-256 key (32 bytes) plus a few tokens, but insufficient for large allocations. The agent binary should document this requirement and handle `EPERM` gracefully (log warning, continue without locking).
- `mlock` locks the page containing the address, not just the bytes. On a 4 KiB page, a 32-byte key locks the full 4 KiB. Multiple small keys on the same page are locked by a single call.
- `memsec` 0.7.0 wraps the same syscall but introduces a crate boundary for a three-line wrapper. Only prefer `memsec` if the team wants its `malloc`-based guarded allocation (`malloc_mprotect`) which places guard pages around the allocation — this provides stronger protection but is heavier and not needed for this use case.
- `secmem-proc` 0.3.8 (2025-12-31) addresses a different threat: it uses `prctl(PR_SET_DUMPABLE, 0)` to prevent core dumps and `/proc/self/mem` reads. Worth adding as a defence-in-depth measure in the agent daemon's startup code. It does not perform `mlock`.

**macOS note:** `mlock` on macOS requires `sudo` or an entitlement for non-privileged processes. The agent should attempt `mlock` and log (not fail) if `EPERM` is returned.

---

### Domain 4 — YubiKey PKCS#11 / PIV Integration

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `cryptoki` | **0.12.0** | PKCS#11 high-level Rust wrapper (via YKCS11 shared library) | HIGH |
| `yubikey` | **0.8.0** | Pure Rust PIV driver (direct PC/SC, no PKCS#11 layer) | LOW — experimental |

**Recommendation: Use `cryptoki` 0.12.0 (PKCS#11 path), not `yubikey` 0.8.0 (direct PIV path).**

**Rationale:**

Two integration paths exist. They are architecturally different.

**Path A: `cryptoki` + YKCS11 (PKCS#11)**

`cryptoki` 0.12.0 (released 2026-01-22, maintained by the Parsec community) is a Rust wrapper around the standard PKCS#11 C API. On YubiKey, Yubico ships `libykcs11.so` — their official PKCS#11 module. The Rust code loads the module at runtime, opens a session, and calls `C_Sign` with `CKM_ECDSA` for P-256 signing. This is the path used by production deployments of ssh-agent, GPG, and TLS clients against YubiKeys.

Advantages:
- Hardware-vendor-supported path. `libykcs11.so` is the official interface.
- Generic — the same `YubikeyPkcs11Signer` implementation will work against other PKCS#11-capable tokens (Nitrokey, smart cards, HSMs) with zero code changes.
- `cryptoki` is actively maintained (six releases in 2025, latest 2026-01-22) and used by multiple production projects.
- No dependency on PC/SC (though PKCS#11 modules themselves often use it internally).

Disadvantages:
- Requires `libykcs11.so` installed on the host (available in `yubikey-manager` or `ykcs11` packages on Debian/Ubuntu; `ykpers` on RHEL).
- Runtime dynamic loading means errors surface at runtime, not compile time.

**Path B: `yubikey` 0.8.0 (pure Rust direct PIV)**

The `yubikey` crate (iqlusioninc/yubikey.rs, last release 2023-08-16) communicates directly with the YubiKey PIV applet over PC/SC (`pcsc` crate). Supports P-256 and P-384 ECDSA.

**Not recommended for this project:**
- Explicitly labelled "experimental" with "No security audits of this crate have ever been performed" in the README.
- Last released August 2023 — no maintenance for 18 months.
- Multiple forks exist (sandbox-quantum, cowriepayments, str4d) indicating upstream stagnation.
- The `untested` feature is the only defined Cargo feature — the crate's own maturity signal is a warning.
- For a security-critical PAM-adjacent agent, an unaudited experimental crate for the hardware key path is a high risk.

**Implementation sketch (cryptoki path):**

```toml
[features]
yubikey = ["dep:cryptoki"]

[dependencies]
cryptoki = { version = "0.12.0", optional = true }
```

```rust
// YubikeyPkcs11Signer implements DPoPSigner
// At init: cryptoki::Pkcs11::new(libykcs11_path)?
// Sign:    session.sign(&mechanism, key_handle, &digest)?
// Mechanism: Mechanism::Ecdsa (CKM_ECDSA, signs raw digest)
```

For DPoP proofs: sign the SHA-256 digest of the JWS signing input with `CKM_ECDSA` (raw ECDSA, not `CKM_ECDSA_SHA256` which hashes internally) to maintain full control over the digest computation, consistent with how `p256::ecdsa::SigningKey::sign_digest` operates.

---

### Domain 5 — TPM 2.0 Integration

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `tss-esapi` | **7.6.0** (stable) | TPM 2.0 ESAPI Rust bindings for key generation and signing | MEDIUM |

**Do NOT use `tss-esapi` 8.0.0-alpha.2 in this milestone.**

**Rationale:**

`tss-esapi` 7.6.0 (released 2024-12-14) is the current stable release from the Parsec / parallaxsecond project. It wraps the C `libtss2-esys` library and exposes ESAPI functions including `sign()` and key creation commands. The `rustcrypto` feature (available in 8.x alpha, not 7.x stable) adds type conversions between TPM key types and RustCrypto traits — useful but not blocking.

`tss-esapi` 8.0.0-alpha.2 (released 2026-02-26) adds the `bundled` feature (vendors `tpm2-tss` C source via cmake, eliminating the system library dependency) and the `rustcrypto`/`rustcrypto-full` features. However, it is alpha — the API is unstable and multiple alpha versions exist without a release candidate. **Pin to 7.6.0 for this milestone; plan upgrade to 8.x stable in a follow-on milestone.**

**System library requirement:**

`tss-esapi` 7.6.0 requires `libtss2-esys` ≥ 3.x installed on the system:
- Ubuntu 22.04 Jammy: `libtss2-esys-3.0.2-0` (version 3.2.0) — available in the default repos
- RHEL 9: `tpm2-tss` package available via BaseOS/AppStream — version 3.x
- The `generate-bindings` feature is optional; use pregenerated bindings (default) to avoid needing `bindgen` and `clang` at build time

**Integration as optional Cargo feature:**

```toml
[features]
tpm = ["dep:tss-esapi"]

[dependencies]
tss-esapi = { version = "7.6.0", optional = true }
```

The `TpmSigner` implements `DPoPSigner` by:
1. Loading an EC P-256 key from a persistent TPM handle (by handle index) or creating one
2. Calling `context.sign(key_handle, &digest, scheme, validation)` where `scheme` is `SigScheme::EcDsa(HashScheme::new::<Sha256>())`
3. Marshalling the ECDSA signature into DER or raw (r,s) format for the JWT

**Key creation and persistence:** TPM persistent handles (0x81000000 range) survive reboots. The agent should create a P-256 key under a primary key (EK or SRK hierarchy) and persist it at a deterministic handle. The handle index can be stored in the agent config file (plaintext, non-secret).

**Deployment constraint:** The host must have a TPM 2.0 chip and `tpm2-abrmd` (TPM access broker) running, or the agent must be run as a user with direct `/dev/tpm0` access. This is a significant deployment prerequisite and is why the TPM feature must remain strictly optional.

---

## Alternatives Considered and Rejected

| Category | Recommended | Alternative | Why Rejected |
|----------|-------------|-------------|--------------|
| OS keyring | `keyring` 3.6.3 | `keyring` 4.0.0-rc.3 | Pre-release; multiple yanked betas; breaking API changes not yet stable |
| Secure zeroing | `zeroize` 1.8.2 | `memsec` 0.7.0 for zeroing | `memsec` adds unsafe patterns; `zeroize` already transitive dep; purpose-built for this |
| Memory locking | `libc::mlock` (direct) | `memsec::mlock` | `libc` already a workspace dep; avoids unnecessary crate boundary for 3-line syscall wrapper |
| YubiKey | `cryptoki` 0.12.0 | `yubikey` 0.8.0 | `yubikey` is explicitly experimental, unaudited, 18-month stale; security-critical code path requires audited library |
| PKCS#11 | `cryptoki` 0.12.0 | `pkcs11` 0.5.0 | `pkcs11` 0.5.0 last released April 2020 — 6 years stale; `cryptoki` is its maintained successor |
| TPM alpha | `tss-esapi` 7.6.0 | `tss-esapi` 8.0.0-alpha.2 | Alpha with unstable API; `bundled` feature useful but deferrable; 7.6.0 is stable and sufficient |
| Secret wrapping | `secrecy` 0.10.3 | Raw `Zeroizing<Vec<u8>>` | `secrecy` adds Debug redaction and prevents accidental equality comparisons, both relevant for tokens in logs |

---

## Dependency Addition Plan

**Add to workspace (all platforms):**

```toml
# Cargo.toml workspace.dependencies
zeroize = { version = "1.8.2", features = ["derive"] }
secrecy = "0.10.3"
```

**Add to unix-oidc-agent only:**

```toml
# unix-oidc-agent/Cargo.toml
[dependencies]
zeroize = { workspace = true }
secrecy = { workspace = true }
secmem-proc = "0.3.8"   # prctl(PR_SET_DUMPABLE) at daemon startup

# Platform-specific keyring features
[target.'cfg(target_os = "linux")'.dependencies]
keyring = { version = "3.6.3", features = ["linux-native-sync-persistent", "crypto-rust"] }

[target.'cfg(target_os = "macos")'.dependencies]
keyring = { version = "3.6.3", features = ["apple-native"] }

# Optional hardware features
[features]
default = []
yubikey = ["dep:cryptoki"]
tpm = ["dep:tss-esapi"]

[dependencies]
cryptoki = { version = "0.12.0", optional = true }
tss-esapi = { version = "7.6.0", optional = true }
```

---

## Breaking Change Flag: p256 Upgrade

**Do not upgrade `p256` to 0.14.x in this milestone.**

`p256` 0.14.0-rc.7 (pre-release, 2026-02-03) **removes the `jwk` feature**. The agent's `SoftwareSigner::public_key_jwk()` and `KeyringStorage` depend on JWK serialization from `p256`. Upgrading to 0.14.x would require replacing `p256`'s JWK serialization with a custom implementation (which already exists in `thumbprint.rs` and `dpop.rs` as manual base64 encoding). This is a separate refactor — not part of the key protection milestone.

**Stay on `p256 = "0.13"` (resolves to 0.13.2) for this milestone.**

---

## Security Notes

1. **`zeroize` and compiler optimisations:** `zeroize` uses `ptr::write_volatile` and `atomic::compiler_fence(SeqCst)` to prevent the compiler from eliding zeroing. This is correct on stable Rust. It does NOT prevent the hardware CPU from caching values in registers — but Rust's ownership model makes register retention across function boundaries impossible in normal code.

2. **`mlock` and `RLIMIT_MEMLOCK`:** The default `RLIMIT_MEMLOCK` for unprivileged users on Linux is 64 KiB. A P-256 private key is 32 bytes; a page is 4 KiB. In practice, locking a single key consumes one page (4 KiB) against the limit. Handle `EPERM` (permission denied) and `ENOMEM` (would exceed limit) gracefully — lock if possible, log if not, never abort.

3. **`secmem-proc` in daemon startup:** `prctl(PR_SET_DUMPABLE, 0)` prevents `/proc/self/mem` reads and core dumps containing key material. Call this once at agent daemon startup, before key material is loaded. On macOS the equivalent is not available via this crate (platform-specific entitlements required).

4. **PKCS#11 session thread safety:** `cryptoki` sessions are not `Send`. Each thread that performs signing operations must own its own session. For the agent daemon's async context, use `tokio::task::spawn_blocking` for all `cryptoki` calls.

5. **TPM key non-exportability:** A TPM-resident key created with `sensitiveDataOrigin = true` and no `userWithAuth` duplication policy cannot be extracted from the TPM in usable form. This is the desired property — the private key never exists in process memory.

---

## Sources

- crates.io API, keyring 3.6.3: https://crates.io/crates/keyring (fetched 2026-03-10)
- crates.io API, zeroize 1.8.2: https://crates.io/crates/zeroize (fetched 2026-03-10)
- crates.io API, yubikey 0.8.0: https://crates.io/crates/yubikey (fetched 2026-03-10)
- crates.io API, tss-esapi 7.6.0: https://crates.io/crates/tss-esapi (fetched 2026-03-10)
- crates.io API, cryptoki 0.12.0: https://crates.io/crates/cryptoki (fetched 2026-03-10)
- crates.io API, memsec 0.7.0: https://crates.io/crates/memsec (fetched 2026-03-10)
- crates.io API, secrecy 0.10.3: https://crates.io/crates/secrecy (fetched 2026-03-10)
- crates.io API, secmem-proc 0.3.8: https://crates.io/crates/secmem-proc (fetched 2026-03-10)
- crates.io API, linux-keyutils 0.2.4: https://crates.io/crates/linux-keyutils (fetched 2026-03-10)
- keyring docs — Linux backends: https://docs.rs/keyring/latest/keyring/secret_service/index.html
- keyring docs — keyutils module: https://docs.rs/keyring/latest/keyring/keyutils/index.html
- yubikey.rs experimental/unaudited warning: https://github.com/iqlusioninc/yubikey.rs (README)
- cryptoki Parsec community crate: https://github.com/parallaxsecond/rust-cryptoki
- tss-esapi parallaxsecond: https://github.com/parallaxsecond/rust-tss-esapi
- Ubuntu 22.04 tpm2-tss package (libtss2-esys 3.2.0): https://launchpad.net/ubuntu/jammy/+package/libtss2-esys-3.0.2-0
- zeroize pitfall with move semantics: https://benma.github.io/2020/10/16/rust-zeroize-move.html
- mlock(2) Linux manual page: https://man7.org/linux/man-pages/man2/mlock.2.html
- RFC 9449 — DPoP: https://www.rfc-editor.org/rfc/rfc9449
