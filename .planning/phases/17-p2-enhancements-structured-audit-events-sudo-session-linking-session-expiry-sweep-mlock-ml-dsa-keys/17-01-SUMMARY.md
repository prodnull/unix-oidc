---
phase: 17-p2-enhancements
plan: 01
subsystem: crypto
tags: [mlock, zeroize, pqc, ml-dsa, dpop, memory-protection, rust]

requires:
  - phase: pqc-implementation
    provides: HybridPqcSigner struct with EC + ML-DSA-65 composite DPoP signing

provides:
  - Box-only HybridPqcSigner with mlock over full allocation (MEM-04, MEM-05)
  - ML-DSA-65 key bytes verified to zero on drop via ZeroizeOnDrop (MEM-02)
  - try_mlock and MlockGuard promoted to pub(crate) for reuse across crypto module

affects:
  - unix-oidc-agent/src/crypto/pqc_signer.rs
  - unix-oidc-agent/src/crypto/protected_key.rs
  - unix-oidc-agent/src/main.rs

tech-stack:
  added: []
  patterns:
    - "Box-only constructor pattern: new_inner() -> Box<Self> with mlock, all public ctors delegate"
    - "pub(crate) mlock helpers: MlockGuard and try_mlock shared between ProtectedSigningKey and HybridPqcSigner"
    - "ZeroizeOnDrop verification test: drop_in_place + raw pointer read from live allocation"

key-files:
  created: []
  modified:
    - unix-oidc-agent/src/crypto/pqc_signer.rs
    - unix-oidc-agent/src/crypto/protected_key.rs
    - unix-oidc-agent/src/main.rs

key-decisions:
  - "HybridPqcSigner::generate() and from_key_bytes() return Box<Self>, not Self — matches ProtectedSigningKey MEM-05 invariant"
  - "MlockGuard and try_mlock made pub(crate) in protected_key.rs; not duplicated in pqc_signer.rs"
  - "mlock covers entire HybridPqcSigner Box allocation (not just pq_key field) — simpler and covers all sensitive fields including pq_vk and pq_seed"
  - "Call sites in main.rs use *pqc to dereference Box before Arc::new() — no blanket DPoPSigner impl for Box<T>"

patterns-established:
  - "Pattern: Box-only crypto structs with mlock — new_inner() allocates Box, computes size_of::<Self>(), mlocks, stores guard — both ProtectedSigningKey and HybridPqcSigner follow this pattern"

requirements-completed: [MEM-07]

duration: 5min
completed: 2026-03-13
---

# Phase 17 Plan 01: mlock ML-DSA Key Material in HybridPqcSigner Summary

**Box-only HybridPqcSigner with mlock'd Box allocation and verified ML-DSA-65 ZeroizeOnDrop, matching ProtectedSigningKey memory-safety guarantees for PQC key material**

## Performance

- **Duration:** 5 min
- **Started:** 2026-03-13T04:32:43Z
- **Completed:** 2026-03-13T04:38:00Z
- **Tasks:** 1
- **Files modified:** 3

## Accomplishments
- Changed `HybridPqcSigner::generate()` and `from_key_bytes()` to return `Box<Self>` (MEM-05)
- Added `new_inner()` private constructor that Boxes the struct and mlocks the full allocation (MEM-04, best-effort)
- Made `MlockGuard` and `try_mlock` `pub(crate)` to share without duplication
- Verified `ml_dsa::SigningKey<MlDsa65>` zeroes key bytes on drop via `test_ml_dsa_zeroize_on_drop` test
- Added 4 new tests (Box return type checks, ZeroizeOnDrop, DPoPSigner usability through Box)
- Updated `main.rs` call sites to dereference `Box<HybridPqcSigner>` before `Arc::new()`

## Task Commits

1. **Task 1: Box HybridPqcSigner with mlock and verify ZeroizeOnDrop** - `0d28603` (feat)

**Plan metadata:** (docs commit — see below)

## Files Created/Modified
- `unix-oidc-agent/src/crypto/pqc_signer.rs` - Added _mlock_guard field, new_inner(), Box return types, 4 new tests
- `unix-oidc-agent/src/crypto/protected_key.rs` - Made MlockGuard and try_mlock pub(crate)
- `unix-oidc-agent/src/main.rs` - Updated load_or_create_pqc_signer return type, dereferenced Box at Arc::new() sites

## Decisions Made

- `MlockGuard` and `try_mlock` made `pub(crate)` rather than duplicated — single implementation in protected_key.rs; both structs benefit.
- mlock covers entire `HybridPqcSigner` allocation (not just `pq_key`) — simpler, and covers all sensitive fields (`pq_vk`, `pq_seed`, `ec_key` pointer).
- `Arc::new(*pqc)` (unbox before Arc) at call sites: `Box<HybridPqcSigner>` does not auto-impl `DPoPSigner`; dereferencing moves the value out of the Box onto the Arc heap allocation. This is semantically correct.
- ZeroizeOnDrop for `ml_dsa::SigningKey<MlDsa65>` confirmed working via drop_in_place test pattern.

## Deviations from Plan

None — plan executed exactly as written. The `try_mlock`/`MlockGuard` visibility promotion was explicitly called out in the plan's action step 1.

## Issues Encountered

None. Build succeeded on first attempt after implementation. All 13 unit tests and all 5 integration tests green.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness
- MEM-07 requirement satisfied. ML-DSA key material now has same memory protection as EC keys.
- Phase 17-02 (structured audit events) can proceed independently.
- PQC promotion from experimental to production no longer blocked by memory protection gap.

---
*Phase: 17-p2-enhancements*
*Completed: 2026-03-13*
