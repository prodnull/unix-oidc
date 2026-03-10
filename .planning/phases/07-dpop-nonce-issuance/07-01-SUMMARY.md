---
phase: 07-dpop-nonce-issuance
plan: 01
subsystem: auth
tags: [dpop, nonce, rfc9449, moka, enforcement-mode, cache, rust]

# Dependency graph
requires:
  - phase: 06-pam-panic-elimination
    provides: EnforcementMode, SecurityModes, CacheConfig, PolicyConfig.effective_security_modes()

provides:
  - DPoPNonceCache: moka-backed single-use nonce cache with issue()/consume()
  - generate_dpop_nonce(): 32-byte CSPRNG, 43-char base64url
  - global_nonce_cache(): process-global singleton (100k cap, 60s TTL)
  - DPoPProofResult: validate_dpop_proof() return type with thumbprint + nonce
  - CacheConfig.nonce_max_entries and nonce_ttl_secs with RFC 9449 defaults
  - authenticate_with_dpop() threads dpop_required from policy with cache enforcement

affects:
  - 07-02 (nonce issuance in lib.rs / pam_sm_authenticate)
  - any phase touching DPoP validation or auth flow

# Tech tracking
tech-stack:
  added:
    - moka 0.12 (sync feature) — TTL+capacity-bounded concurrent cache
  patterns:
    - moka::sync::Cache remove() as atomic single-use consume primitive
    - EnforcementMode::Strict/Warn/Disabled for configurable nonce enforcement
    - DPoPProofResult struct decouples thumbprint-for-binding from nonce-for-cache
    - global once_cell::sync::Lazy singleton for nonce cache (mirrors jti_cache pattern)

key-files:
  created:
    - pam-unix-oidc/src/security/nonce_cache.rs
  modified:
    - pam-unix-oidc/Cargo.toml
    - pam-unix-oidc/src/security/mod.rs
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/oidc/dpop.rs
    - pam-unix-oidc/src/oidc/mod.rs
    - pam-unix-oidc/src/auth.rs

key-decisions:
  - "moka Cache.remove() is the atomic single-use primitive — no separate contains_key() to avoid TOCTOU"
  - "Nonce replay (ConsumedOrExpired on second consume) is always hard-fail regardless of dpop_required enforcement mode"
  - "Missing nonce enforcement respects dpop_required: strict=reject, warn=log+allow, disabled=skip"
  - "validate_dpop_proof() returns DPoPProofResult{thumbprint, nonce} not bare String — decouples binding check from nonce cache consumption"
  - "Cache-backed path (expected_nonce=None, require_nonce=true) lives in auth.rs; direct single-value path (expected_nonce=Some) stays in dpop.rs for backward compat"
  - "nonce_max_entries: u64 (moka uses u64 for max_capacity); jti_max_entries stays usize for HashMap compat"

patterns-established:
  - "Global cache singletons via once_cell::sync::Lazy<T> in security/* modules"
  - "TDD: write failing test skeleton first, then implementation, then verify green"
  - "Enforcement mode tests replicate inner logic in helper closure for unit testability without SSSD"

requirements-completed: [SEC-05, SEC-06]

# Metrics
duration: 45min
completed: 2026-03-10
---

# Phase 7 Plan 01: DPoP Nonce Cache Infrastructure Summary

**moka-backed single-use DPoP nonce cache (RFC 9449 §8) with dpop_required enforcement mode threading from policy.yaml into authenticate_with_dpop()**

## Performance

- **Duration:** ~45 min
- **Started:** 2026-03-10T22:50:00Z
- **Completed:** 2026-03-10T23:16:07Z
- **Tasks:** 2 of 2
- **Files modified:** 7

## Accomplishments

- Created `security/nonce_cache.rs`: `DPoPNonceCache` backed by moka sync cache with atomic `issue()`/`consume()` API. `Cache::remove()` provides the TOCTOU-free single-use primitive. 11 tests including concurrent TOCTOU adversarial test.
- Extended `CacheConfig` with `nonce_max_entries` (100k) and `nonce_ttl_secs` (60) with correct defaults and YAML override support. Hand-rolled Deserialize updated.
- Changed `validate_dpop_proof()` return from `String` to `DPoPProofResult { thumbprint, nonce }`, enabling auth.rs to do cache-based nonce validation without re-parsing the proof.
- Resolved the TODO at `auth.rs:211-212`: `authenticate_with_dpop()` now threads `dpop_required` from `PolicyConfig.effective_security_modes()` and applies cache-backed nonce enforcement (replay=hard-fail always; missing nonce respects strict/warn/disabled).

## Task Commits

1. **Task 1: Create DPoP nonce cache module** - `469483d` (feat)
2. **Task 2: Extend CacheConfig, thread enforcement, wire nonce cache** - `87ba0aa` (feat)

## Files Created/Modified

- `pam-unix-oidc/src/security/nonce_cache.rs` — DPoPNonceCache, NonceConsumeError, NonceIssueError, generate_dpop_nonce(), global_nonce_cache()
- `pam-unix-oidc/Cargo.toml` — added moka 0.12 sync dependency
- `pam-unix-oidc/src/security/mod.rs` — pub mod nonce_cache; re-exports
- `pam-unix-oidc/src/policy/config.rs` — CacheConfig extended with nonce_max_entries, nonce_ttl_secs
- `pam-unix-oidc/src/oidc/dpop.rs` — DPoPProofResult type, validate_dpop_proof() return type change, 3 new tests
- `pam-unix-oidc/src/oidc/mod.rs` — DPoPProofResult re-export
- `pam-unix-oidc/src/auth.rs` — dpop_required threading, nonce enforcement closure, 7 new tests

## Decisions Made

- **moka vs parking_lot::RwLock**: moka chosen for its built-in TTL and LRU eviction — removes the need for a separate cleanup thread or cleanup_interval logic (which jti_cache.rs must do manually). Tradeoff: adds moka transitive deps (crossbeam, portable-atomic). Decision justified by DECISIONS table in STATE.md: "moka 0.12.14 chosen for all TTL caches."
- **u64 for nonce_max_entries**: moka's `max_capacity` takes `u64`; jti_max_entries stays `usize` for the HashMap-based jti_cache. Kept types consistent with their respective backend APIs.
- **DPoPProofResult placement**: Defined in dpop.rs (where validation happens), exported through oidc::mod. auth.rs imports it from crate::oidc. Keeps validation logic and result type co-located.
- **Backward compat for single-value nonce path**: Callers that set `expected_nonce = Some(...)` continue to go through dpop.rs constant-time comparison. The new cache path is activated only when `require_nonce=true` and `expected_nonce=None`.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- dpop.rs tests referenced the old `String` return type of `validate_dpop_proof()`. Updated 2 tests to destructure `DPoPProofResult` and added 1 new test verifying both fields. (Rule 1 auto-fix, minimal impact.)

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `global_nonce_cache()` ready for Plan 02: `pam_sm_authenticate` can call `generate_dpop_nonce()`, issue into cache, send nonce to client, then `authenticate_with_dpop()` will consume it on the next call with `require_nonce=true, expected_nonce=None`.
- `DPoPAuthConfig.require_nonce=true, expected_nonce=None` is the trigger for the cache path — Plan 02 must set this when constructing `DPoPAuthConfig` from `pam_sm_authenticate`.
- All 129 pam-unix-oidc unit tests pass; workspace clean.

## Self-Check: PASSED

- nonce_cache.rs: FOUND
- dpop.rs: FOUND
- 07-01-SUMMARY.md: FOUND
- Commit 469483d (Task 1): FOUND in git log
- Commit 87ba0aa (Task 2): FOUND in git log

---
*Phase: 07-dpop-nonce-issuance*
*Completed: 2026-03-10*
