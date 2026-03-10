# Architecture Patterns: Client-Side Key Protection

**Domain:** Secure key storage integration for a Rust OAuth agent with trait-based abstractions
**Researched:** 2026-03-10
**Overall confidence:** HIGH (primary source: codebase + authoritative crate docs)

---

## Existing Architecture (Ground Truth)

The agent already has the correct trait boundaries defined. The work is plumbing — not new
abstraction. The three load-bearing traits are:

```
DPoPSigner          (unix-oidc-agent/src/crypto/signer.rs)
  └─ SoftwareSigner (implemented — keys in heap memory)
  └─ YubiKeySigner  (stub, optional feature)
  └─ TpmSigner      (stub, optional feature)

SecureStorage       (unix-oidc-agent/src/storage/mod.rs)
  └─ FileStorage    (implemented — active default, 0600 files)
  └─ KeyringStorage (implemented — dormant, not wired up)
```

`main.rs` currently hardcodes `FileStorage` in all five command paths (`login`, `logout`,
`refresh`, `reset`, `serve`). `KeyringStorage` exists but is never constructed outside of
tests. `SoftwareSigner` holds a raw `SigningKey` (p256 0.13) without zeroize or mlock.

---

## Component Boundaries

### Component 1: StorageRouter

**Responsibility:** Select the right `SecureStorage` backend at runtime; own the single
construction point for storage so all command paths get consistent backend selection.

**Communicates with:**
- `KeyringStorage` — primary on graphical/session-dbus environments
- `FileStorage` — fallback on headless servers or when keyring probe fails
- `main.rs` command handlers — returns `Arc<dyn SecureStorage>`

**Detection logic:** The `keyring` crate v3 returns `Error::PlatformFailure` or
`Error::NoStorageAccess` when D-Bus Secret Service is absent. A probe write/read/delete
of a sentinel key on startup distinguishes "backend available and writable" from "backend
present but locked" from "backend absent." This probe must happen once at daemon start,
not per-operation. Confidence: HIGH (keyring v3 error taxonomy confirmed via crates.io
source, issue #879 from block/goose shows the exact error text in the wild).

**Why not compile-time selection:** Headless CI builders, SSH-only servers, and desktop
machines are often the same binary. Runtime detection is the only sound approach.

```
StorageRouter::detect() -> Arc<dyn SecureStorage>
  1. Attempt KeyringStorage probe (write sentinel, read back, delete)
  2. On success -> return KeyringStorage
  3. On Error::PlatformFailure | Error::NoStorageAccess -> log warning, fall through
  4. Return FileStorage
```

**Migration concern:** Existing `FileStorage` users have live keys in
`~/.local/share/unix-oidc-agent/`. `StorageRouter` must check for file-stored keys and
offer (or silently perform) migration into the keyring on first successful keyring probe.
This is a one-way operation: read from file, store to keyring, then securely delete file.

---

### Component 2: ProtectedKeyMaterial

**Responsibility:** Wrap raw key bytes in memory with zeroize-on-drop guarantees and
optional mlock to prevent swap exposure.

**Communicates with:**
- `SoftwareSigner` — holds `ProtectedKeyMaterial` instead of raw `SigningKey`
- OS kernel via `libc::mlock` / `libc::munlock` — optional, Linux/macOS only

**Design:** Two layers, independent of each other:

**Layer A — Zeroize on drop (mandatory, no unsafe required):**

The `elliptic-curve` crate's `SecretKey` type (which backs `p256::SigningKey` under the
hood via `p256::NonZeroScalar`) implements `ZeroizeOnDrop` when the `zeroize` feature of
the `elliptic-curve` crate is enabled. The `p256` crate exposes a `zeroize` feature flag
that propagates this. Adding `p256 = { version = "0.13", features = ["ecdsa", "jwk",
"zeroize"] }` to `Cargo.toml` is sufficient for the signing key to zero itself on drop.
Confidence: HIGH (confirmed from RustCrypto/traits source and elliptic-curve docs showing
`ZeroizeOnDrop` implementation on `SecretKey`).

The `export_key()` method on `SoftwareSigner` returns a plain `Vec<u8>`. That buffer
must be wrapped in `zeroize::Zeroizing<Vec<u8>>` so the exported bytes are wiped after
use in storage write paths.

**Layer B — mlock (optional, platform-conditional):**

`libc::mlock(ptr, len)` prevents the page containing the key from being swapped. The
`memsec` crate wraps this behind a safe interface and handles cross-platform concerns.
`mlock` fails silently on most systems if `RLIMIT_MEMLOCK` is exceeded (common in
container environments). The correct behavior is: attempt mlock, log if it fails, never
abort. mlock region covers the `SigningKey` internal scalar, not the exported bytes
(which are always short-lived in a `Zeroizing` wrapper).

Alternative: `shush-rs` provides `mlock + mprotect` together in one crate (discovered
via secrecy issue #480 discussion). It is less widely adopted than `memsec`. Prefer
`libc::mlock` directly for minimal dependency surface on a security-critical path.

**Concrete struct:**

```rust
pub struct ProtectedSigningKey {
    inner: p256::ecdsa::SigningKey,  // ZeroizeOnDrop when zeroize feature enabled
    _mlock_guard: Option<MlockGuard>, // munlock on drop
}

struct MlockGuard { ptr: *const u8, len: usize }
impl Drop for MlockGuard {
    fn drop(&mut self) { unsafe { libc::munlock(self.ptr as *mut _, self.len) }; }
}
```

This wraps `SoftwareSigner.signing_key` — no change to the `DPoPSigner` trait interface.

---

### Component 3: SecureFileDelete

**Responsibility:** Replace the naive overwrite-then-remove in `FileStorage::delete()` with
a filesystem-aware secure deletion strategy.

**Communicates with:**
- `FileStorage` — replaces its `delete()` implementation
- OS (via `std::fs`, `libc` for `fsync`/`fdatasync`)

**Current gap:** The existing `delete()` writes zeros then calls `fs::remove_file`. On
CoW filesystems (Btrfs, APFS, ZFS) and SSDs with wear-leveling, this does not overwrite
the original data blocks. The zeros go to a new block; the old block is released to the
FTL. True secure deletion on modern storage is not reliably achievable in userspace.

**Recommended approach:** Three-pass strategy with explicit acknowledgment of limitations:

1. Overwrite with random bytes (not zeros — patterns are easier to detect forensically)
2. `fsync()` to flush to the storage device
3. `unlink()` (via `fs::remove_file`)

Additionally, log a structured warning when `FileStorage` is used as primary backend that
the underlying filesystem may not honor overwrites. This is honest and actionable.

Do not attempt the 35-pass Gutmann method — it is irrelevant on SSDs and flash storage
(NIST SP 800-88 Rev. 1 is the authoritative source: a single overwrite pass followed by
verification is sufficient for magnetic media; for flash, purge commands are required at
the device level, beyond userspace reach).

**Source:** NIST SP 800-88 Rev. 1, "Guidelines for Media Sanitization," December 2014.

---

### Component 4: HardwareSignerFactory (optional features)

**Responsibility:** Construct a `DPoPSigner` backed by hardware (YubiKey PIV or TPM) and
surface a unified error type when hardware is unavailable.

**Communicates with:**
- `DPoPSigner` trait — hardware backends implement this
- `yubikey` crate (optional feature `yubikey-support`)
- `tss-esapi` crate (optional feature `tpm-support`)
- Agent CLI — `--signer yubikey:9a` or `--signer tpm` flag

**YubiKey via PIV:**

The `yubikey` crate (iqlusioninc/yubikey.rs) supports ECDSA P-256 signing against PIV
key slots. The private key never leaves the hardware. The signing operation invokes the
YubiKey's ECDSA signing command via PCSC, returning a DER-encoded signature. This maps
cleanly onto `DPoPSigner::sign_proof()` — the signer calls `p256::ecdsa::Signature::from_der()`
on the YubiKey output and re-encodes to JWS compact form.

The public key must be exported from the YubiKey once (at key generation or import time)
to compute the JWK thumbprint. `DPoPSigner::public_key_jwk()` can read the certificate
from the slot rather than the raw key.

**Important caveat:** The `yubikey` crate carries no security audit as of latest releases.
It is in active use by the broader community but carries an explicit "experimental" warning
in its own documentation. Budget time to review the relevant portions of the codebase
before depending on it in a security-critical path. Confidence: MEDIUM (crate exists and
supports P-256 ECDSA; audit status unconfirmed).

**TPM via tss-esapi:**

`tss-esapi` wraps the TCG TSS 2.0 ESAPI. It supports EC key generation and signing inside
the TPM. The `TransientKeyContext` abstraction provides the highest-level interface for
sign/verify without managing key handles directly.

TPM support requires `libtss2-esys` installed on the host (`libtss2-dev` on Debian/Ubuntu,
`tpm2-tss-devel` on RHEL). This is a significant system dependency and is the main reason
it must remain an optional cargo feature. Without the library, the build must still succeed.

**FIDO2 / authenticator-rs:**

FIDO2 (`authenticator-rs`, `ctap-types`) is out of scope for this milestone. FIDO2 does
not support arbitrary ECDSA — it uses `ES256` but over CTAP2 assertion flows that bind
the signature to a relying-party challenge. Adapting this for DPoP proof generation would
require significant protocol work. Defer to a future milestone.

**Component boundary:**

```
HardwareSignerFactory::build(config: &SignerConfig) -> Result<Arc<dyn DPoPSigner>, SignerError>
  match config.backend:
    Backend::Software   -> SoftwareSigner (loads from SecureStorage)
    Backend::Yubikey(slot) -> YubiKeySigner::new(slot)  [feature = "yubikey-support"]
    Backend::Tpm        -> TpmSigner::new()              [feature = "tpm-support"]
```

`SignerConfig` is read from the agent's YAML config at startup. Default: `Software`.

---

## Data Flow

### Key Lifecycle (Software Path, Current → Target)

```
CURRENT (all paths hardcode FileStorage):

  agent startup
    └─ load_or_create_signer(&FileStorage)
         └─ FileStorage::retrieve("unix-oidc-dpop-key")
              -> raw Vec<u8> -> SigningKey::from_slice()
              -> SoftwareSigner { signing_key: SigningKey, ... }
                 (no zeroize, no mlock, raw bytes in heap)

TARGET:

  agent startup
    └─ StorageRouter::detect()
         └─ probe KeyringStorage -> success -> Arc<KeyringStorage>
              OR failure -> warn + Arc<FileStorage>
    └─ MigrationCheck::maybe_migrate(old: &FileStorage, new: &dyn SecureStorage)
         (if file exists and keyring selected: migrate, secure-delete file)
    └─ HardwareSignerFactory::build(&config)
         └─ SoftwareSigner path:
              storage.retrieve("unix-oidc-dpop-key")
                -> Zeroizing<Vec<u8>>
                -> ProtectedSigningKey::from_bytes()
                     -> SigningKey::from_slice() [ZeroizeOnDrop via p256 zeroize feature]
                     -> libc::mlock(addr, size) [best-effort, log if fails]
                -> SoftwareSigner { key: ProtectedSigningKey }
```

### Token Storage Data Flow (all secrets)

```
  write path:
    secret: &[u8]
      -> SecureStorage::store(key, secret)
           -> KeyringStorage: base64-encode -> keyring Entry::set_password()
              (keyring v3 encrypts via Secret Service / Keychain — no additional
               application-level encryption needed)
           -> FileStorage: write to 0600 file -> fsync

  delete path:
    SecureStorage::delete(key)
      -> KeyringStorage: Entry::delete_credential()
      -> FileStorage: overwrite-random -> fsync -> unlink
```

### DPoP Proof Generation (unchanged interface, improved internals)

```
  PAM socket request -> AgentServer -> AgentState.signer.sign_proof(method, target, nonce)
    -> DPoPSigner::sign_proof()
         -> SoftwareSigner: ProtectedSigningKey.inner.sign(digest)
            (private key never exported; Zeroizing<Vec<u8>> used only for storage I/O)
         -> YubiKeySigner: pcsc::Transaction -> YubiKey sign command -> DER signature
            -> p256::ecdsa::Signature::from_der() -> compact JWS
```

---

## Suggested Build Order

Dependencies run in one direction. Build lower layers first; each layer is testable
before the next is started.

### Phase 1: Memory protection (no behavior change, pure hardening)

**What:** Add `zeroize` feature to `p256` dep. Wrap `export_key()` return type in
`Zeroizing<Vec<u8>>`. Add `MlockGuard` to `SoftwareSigner`. Replace `FileStorage::delete()`
random-overwrite implementation.

**Why first:** Zero external dependencies, no interface changes, no migration risk.
Purely additive safety. All existing tests continue to pass without modification.

**Dependencies:** None on other phases.

**Deliverables:**
- `p256` dep gains `zeroize` feature
- `Zeroizing<Vec<u8>>` wraps every `export_key()` call site
- `ProtectedSigningKey` struct (or inline mlock in `SoftwareSigner`)
- `FileStorage::delete()` uses random overwrite via `OsRng`
- New dep: `zeroize = "1"`, `libc` (already transitively present, make explicit)

---

### Phase 2: Storage backend wiring (activate KeyringStorage as default)

**What:** Implement `StorageRouter::detect()`. Wire all five command paths in `main.rs`
through `StorageRouter` instead of hardcoded `FileStorage::new()`. Implement migration
from file to keyring.

**Why second:** Requires Phase 1 to be in place so that when the keyring backend is
active, key material exported for storage write is already wrapped in `Zeroizing`.

**Dependencies:** Phase 1 complete.

**Deliverables:**
- `StorageRouter` struct with `detect()` and `build()` methods
- Migration logic: `FileStorage` -> `KeyringStorage` for existing keys
- All `main.rs` command handlers use `StorageRouter` output
- Integration test: `#[ignore]` tagged, requires D-Bus, exercises full round-trip
- Unit test: mock that simulates keyring unavailability, verifies fallback to file

---

### Phase 3: Hardware signer backends (optional features, additive)

**What:** Implement `YubiKeySigner` behind `yubikey-support` feature. Implement
`TpmSigner` behind `tpm-support` feature. Add `SignerConfig` to agent YAML config.
Add `HardwareSignerFactory`.

**Why third:** Independent of Phase 2 (both use `DPoPSigner` trait), but should come
after Phase 2 so the full storage path is stable before introducing hardware complexity.
Hardware paths do not store private keys at all — keys live on the device — so storage
migration is not a concern for hardware paths.

**Dependencies:** Phase 1 for `Zeroizing` usage patterns. Phase 2 for stable storage
of any per-device metadata (e.g., slot configuration).

**Deliverables:**
- `YubiKeySigner: DPoPSigner` (optional feature, PCSC-based)
- `TpmSigner: DPoPSigner` (optional feature, requires tss-esapi)
- `HardwareSignerFactory::build()`
- `SignerConfig` in YAML with `backend` field (default: software)
- `#[ignore]` integration tests requiring physical hardware

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: Compile-time backend selection via cfg

**What:** `#[cfg(target_os = "linux")] use KeyringStorage` at the top of `main.rs`.

**Why bad:** The same binary runs on headless SSH-only servers (where D-Bus is absent)
and developer desktops (where it is present). Compile-time selection either breaks
headless or ignores the keyring on desktops. The probe-and-fallback in `StorageRouter`
is the right answer.

**Instead:** `StorageRouter::detect()` at runtime.

---

### Anti-Pattern 2: Encrypting secrets before keyring storage

**What:** Applying an application-level encryption layer before calling
`KeyringStorage::store()`.

**Why bad:** The OS keyring (Secret Service on Linux, Keychain on macOS) already provides
encryption at rest. Double-encrypting adds key management complexity (where does the
application key live?) without additional security. The keyring backend's encryption is
handled by the OS security daemon with hardware-backed key storage where available.

**Exception:** `FileStorage` is plaintext at rest (0600 permissions only). If the
organization requires encryption at rest for the file fallback, a DEK wrapped by a
user-supplied passphrase is appropriate, but this is a separate policy decision and out
of scope for this milestone.

---

### Anti-Pattern 3: Storing hardware signer private key bytes in SecureStorage

**What:** Exporting the key from YubiKey into `SecureStorage` for "backup."

**Why bad:** The entire security value proposition of hardware keys is that private key
bytes never leave the hardware. Any export path defeats this. `DPoPSigner` on hardware
backends should never implement `export_key()`. The method should return `Err(SignerError::ExportNotSupported)`.

---

### Anti-Pattern 4: Blocking on mlock failure

**What:** Treating `libc::mlock()` failure as a fatal error.

**Why bad:** `RLIMIT_MEMLOCK` defaults to 64KB on most Linux distros. Container
environments, systemd sandboxing, and unprivileged users regularly hit this limit.
mlock is a best-effort hardening measure, not a prerequisite for correct operation.
Log at `warn!` level and continue.

---

### Anti-Pattern 5: Using p256::ecdsa::SigningKey::to_bytes() for storage without Zeroizing

**What:** `let bytes = signer.signing_key.to_bytes().to_vec()` passed directly to
`storage.store()`.

**Why bad:** `to_bytes()` returns a `FieldBytes` (a fixed-size array). Calling `.to_vec()`
allocates a heap buffer that lives until the garbage collector (here, when the binding
goes out of scope). Without `Zeroizing`, the heap buffer is not cleared. Rust's drop
does not zero memory. The bytes remain readable in the process's address space until
overwritten by a future allocation.

**Instead:** `let bytes = Zeroizing::new(signer.signing_key.to_bytes().to_vec())`.

---

## Scalability and Platform Considerations

| Concern | Linux headless server | Linux desktop | macOS |
|---------|-----------------------|---------------|-------|
| Keyring availability | D-Bus absent in most cases | D-Bus + gnome-keyring/kwallet present | Keychain always present |
| mlock limit | Default 64KB RLIMIT_MEMLOCK; may need `ulimit -l unlimited` in agent systemd unit | Same | Default 4MB |
| Hardware key (YubiKey) | PCSC requires pcscd daemon | Same | Same |
| Hardware key (TPM) | tpm2-tss required; vTPM in cloud VMs | Rare | Not applicable |
| Zeroize behavior | Consistent across platforms | Consistent | Consistent |

**For systemd service units:** Add `LimitMEMLOCK=65536` (or `infinity` for strict
environments) to the agent's unit file to allow mlock to succeed in practice.

---

## Sources

- `unix-oidc-agent/src/storage/mod.rs`, `keyring_store.rs`, `file_store.rs`, `crypto/signer.rs` — codebase ground truth
- RustCrypto `elliptic-curve` source: `ZeroizeOnDrop` on `SecretKey` confirmed at `RustCrypto/traits/elliptic-curve/src/secret_key.rs`
- `keyring` crate v3 error taxonomy: [keyring error.rs source](https://docs.rs/keyring/latest/src/keyring/error.rs.html), [real-world D-Bus error](https://github.com/block/goose/issues/879)
- `memsec` crate for mlock: [docs.rs/memsec](https://docs.rs/memsec/latest/memsec/fn.mlock.html)
- `secrecy` mlock discussion: [iqlusioninc/crates issue #480](https://github.com/iqlusioninc/crates/issues/480)
- `yubikey` crate PIV ECDSA: [docs.rs/yubikey](https://docs.rs/yubikey), [iqlusioninc/yubikey.rs](https://github.com/iqlusioninc/yubikey.rs)
- `tss-esapi` signing: [docs.rs/tss-esapi](https://docs.rs/tss-esapi/6.1.1/tss_esapi/), [parallaxsecond/rust-tss-esapi](https://github.com/parallaxsecond/rust-tss-esapi)
- NIST SP 800-88 Rev. 1, "Guidelines for Media Sanitization" (December 2014) — authoritative source for secure deletion recommendations
