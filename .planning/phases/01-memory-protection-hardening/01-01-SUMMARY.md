---
phase: 01-memory-protection-hardening
plan: "01"
subsystem: unix-oidc-agent/crypto
tags: [memory-protection, zeroize, mlock, dpop, signing-key]
dependency_graph:
  requires: []
  provides: [ProtectedSigningKey, MlockStatus, mlock_probe, Zeroizing-export_key]
  affects: [unix-oidc-agent/src/crypto/signer.rs, unix-oidc-agent/src/main.rs]
tech_stack:
  added:
    - "zeroize 1.x (Zeroizing<T> wrapper)"
    - "secrecy 0.10 (staged for Plan 02)"
    - "libc 0.2 (mlock/munlock syscalls)"
  patterns:
    - "Box-only constructors to prevent stack copies of key material"
    - "RAII MlockGuard for automatic munlock on drop"
    - "ZeroizeOnDrop via ecdsa-0.16 (unconditional, no feature flag needed)"
key_files:
  created:
    - unix-oidc-agent/src/crypto/protected_key.rs
  modified:
    - unix-oidc-agent/Cargo.toml
    - unix-oidc-agent/src/crypto/mod.rs
    - unix-oidc-agent/src/crypto/signer.rs
decisions:
  - "p256 0.13 has no 'zeroize' feature flag; ZeroizeOnDrop is unconditional in ecdsa-0.16 — feature entry removed from Cargo.toml"
  - "mlock covers entire Box<ProtectedSigningKey> rather than trying to address opaque SigningKey internals"
  - "from_key(SigningKey) round-trips through Zeroizing bytes to avoid stack key copies"
metrics:
  duration: "7m"
  completed_date: "2026-03-10"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 4
  files_created: 1
---

# Phase 1 Plan 1: ProtectedSigningKey Foundation Summary

ProtectedSigningKey wrapper with ZeroizeOnDrop (ecdsa-0.16 unconditional), mlock of Box allocation, and Zeroizing<Vec<u8>> export; SoftwareSigner refactored to hold Box<ProtectedSigningKey> throughout.

## What Was Built

Two tasks implemented following TDD (RED tests written first, then GREEN implementation):

### Task 1: ProtectedSigningKey module

New file `unix-oidc-agent/src/crypto/protected_key.rs` providing:

- `MlockStatus` enum (`Active` | `Unavailable(String)`) for observability
- `MlockGuard` RAII struct: holds raw pointer + len, calls `munlock(2)` on drop
- `mlock_probe()`: allocates test buffer, probes mlock availability, logs at INFO/WARN, never fatal
- `ProtectedSigningKey` struct with:
  - `Box`-only constructors: `generate() -> Box<Self>`, `from_bytes(&[u8]) -> Result<Box<Self>, SignerError>`
  - No public stack constructor (MEM-05)
  - mlock of the entire Box allocation via `try_mlock()` (MEM-04, best-effort)
  - `export_key() -> Zeroizing<Vec<u8>>` (MEM-01)
  - `thumbprint()`, `signing_key()`, `verifying_key()` accessors

Dependencies added to `unix-oidc-agent/Cargo.toml`:
- `zeroize = { version = "1", features = ["derive"] }`
- `secrecy = "0.10"` (staged for Plan 02)
- `libc = "0.2"`

### Task 2: SoftwareSigner refactored

`unix-oidc-agent/src/crypto/signer.rs` updated to:
- Replace `signing_key: SigningKey` + `thumbprint: String` fields with `key: Box<ProtectedSigningKey>`
- `export_key()` returns `Zeroizing<Vec<u8>>` (was `Vec<u8>`)
- `import_key()` uses `ProtectedSigningKey::from_bytes()` internally
- `from_key(SigningKey)` round-trips through `Zeroizing` bytes (no stack key lingering)
- All `DPoPSigner` impl methods delegate to `self.key.*`

The callers in `main.rs` (lines ~758-763) are unaffected because `Zeroizing<Vec<u8>>` implements `Deref<Target=[u8]>`, so `&exported` coerces to `&[u8]` transparently.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] p256 0.13 has no `zeroize` feature flag**

- **Found during:** Task 1, initial dependency update
- **Issue:** The plan specified `p256 = { version = "0.13", features = ["ecdsa", "jwk", "zeroize"] }`. p256 0.13's actual feature set (verified from Cargo.toml.orig) has no `zeroize` feature. Cargo rejected the dependency with "package does not have that feature."
- **Investigation:** Checked the actual source: `ZeroizeOnDrop` is implemented unconditionally for `SigningKey<C>` in `ecdsa-0.16/src/signing.rs`. No feature gate required.
- **Fix:** Removed the `zeroize` feature from the p256 dependency; added a comment explaining the situation. The memory-protection goal (MEM-02) is still fully achieved.
- **Files modified:** `unix-oidc-agent/Cargo.toml`
- **Commits:** 6a83b58

**2. [Rule 1 - Bug] mlock pointer derived from to_bytes() was a copy, not the in-struct address**

- **Found during:** Task 1, new_inner() implementation
- **Issue:** Initial implementation called `signing_key.to_bytes().as_ptr()` to get the mlock address. `to_bytes()` on `SigningKey` calls `to_repr()` which returns a new `FieldBytes` (stack allocation), not a pointer into the struct's internal storage. mlocking that pointer would lock the wrong (temporary) memory.
- **Fix:** Changed to mlock the entire `Box<Self>` allocation via `std::slice::from_raw_parts_mut(&mut *boxed as *mut Self as *mut u8, size_of::<Self>())`. This is correct, simpler, and covers all sensitive fields including any verifying key bytes cached internally by ecdsa-0.16.
- **Files modified:** `unix-oidc-agent/src/crypto/protected_key.rs`
- **Commits:** 6a83b58

**3. [Rule 3 - Clippy] `vec![0u8; 64]` in mlock_probe flagged by -D warnings**

- **Found during:** Task 2, clippy verification
- **Issue:** `vec![]` in `mlock_probe()` triggered `clippy::useless-vec` (can use array directly).
- **Fix:** Changed to `let mut buf = [0u8; 64]` (stack array; semantically equivalent for probe purposes).
- **Files modified:** `unix-oidc-agent/src/crypto/protected_key.rs`
- **Commits:** 8ad9477

## Verification Results

```
cargo build -p unix-oidc-agent    ✓ no warnings
cargo test -p unix-oidc-agent     ✓ 51 passed, 2 ignored (keychain), 0 failed
cargo clippy -p unix-oidc-agent -- -D warnings  ✓ clean
```

grep checks (plan verification criteria):
- No raw `Vec<u8>` return from `export_key`: confirmed (both implementations return `Zeroizing<Vec<u8>>`)
- No stack-constructible `ProtectedSigningKey`: confirmed (no `pub fn new() -> Self`)
- `ProtectedSigningKey` used in `SoftwareSigner`: confirmed (`key: Box<ProtectedSigningKey>`)

## Self-Check: PASSED

Files verified to exist:
- unix-oidc-agent/src/crypto/protected_key.rs ✓
- unix-oidc-agent/src/crypto/signer.rs ✓ (modified)
- unix-oidc-agent/Cargo.toml ✓ (modified)
- unix-oidc-agent/src/crypto/mod.rs ✓ (modified)

Commits verified:
- 6a83b58 feat(01-01): add ProtectedSigningKey with ZeroizeOnDrop, mlock, Zeroizing export ✓
- 8ad9477 feat(01-01): wire ProtectedSigningKey into SoftwareSigner ✓
