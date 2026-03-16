---
phase: 27-multi-idp-advanced-observability
plan: 02
subsystem: crypto
tags: [tracing, audit, dpop, pqc, ml-dsa, key-lifecycle, siem]

# Dependency graph
requires:
  - phase: 17-p2-enhancements
    provides: unix_oidc_audit target pattern and structured audit event convention
provides:
  - KEY_GENERATED structured audit event on ProtectedSigningKey::generate()
  - KEY_LOADED structured audit event on ProtectedSigningKey::from_bytes()
  - KEY_DESTROYED structured audit event on ProtectedSigningKey drop
  - KEY_GENERATED structured audit event on HybridPqcSigner::generate()
  - KEY_DESTROYED structured audit event on HybridPqcSigner drop
  - tracing-test no-env-filter enabled for cross-target audit event assertions
affects:
  - phase-28-e2e-tests
  - any SIEM/log-pipeline consuming unix_oidc_audit events

# Tech tracking
tech-stack:
  added:
    - tracing-test no-env-filter feature (dev-dep only)
  patterns:
    - Drop impl emits KEY_DESTROYED before ZeroizeOnDrop zeroes key bytes
    - key_id = first 8 chars of JWK thumbprint (SHA-256 base64url prefix)
    - No-panic drop pattern: thumbprint.len().min(8) guards against impossible truncation

key-files:
  created: []
  modified:
    - unix-oidc-agent/src/crypto/protected_key.rs
    - unix-oidc-agent/src/crypto/pqc_signer.rs
    - unix-oidc-agent/Cargo.toml

key-decisions:
  - "Drop impl added to ProtectedSigningKey and HybridPqcSigner to emit KEY_DESTROYED before automatic ZeroizeOnDrop runs"
  - "key_id uses 8-char thumbprint prefix (not full 43-char SHA-256 base64url) for correlation without fingerprint leakage"
  - "tracing-test no-env-filter feature enabled so unit tests can assert on unix_oidc_audit target events"
  - "HybridPqcSigner drop emits ML-DSA-65+ES256 event; ec_key drop independently emits DPoP event — both provide full lifecycle audit trail"
  - "from_bytes() emits KEY_LOADED (not generate()) since from_bytes is the only path for loading from storage"

patterns-established:
  - "Key lifecycle pattern: emit audit event in constructor/destructor using key_id = thumbprint[..8]"
  - "Cross-target audit events require tracing-test no-env-filter to be testable in unit tests"

requirements-completed: [OBS-04]

# Metrics
duration: 25min
completed: 2026-03-16
---

# Phase 27 Plan 02: Key Lifecycle Audit Events Summary

**KEY_GENERATED/KEY_LOADED/KEY_DESTROYED structured audit events on ProtectedSigningKey and HybridPqcSigner with 8-char thumbprint key_id for SIEM lifecycle tracing**

## Performance

- **Duration:** ~25 min
- **Started:** 2026-03-16T13:48:00Z
- **Completed:** 2026-03-16T13:59:04Z
- **Tasks:** 2 (both TDD)
- **Files modified:** 3

## Accomplishments

- `ProtectedSigningKey::generate()` emits `KEY_GENERATED` with `key_type="DPoP"` and `key_id` (8-char thumbprint prefix)
- `ProtectedSigningKey::from_bytes()` emits `KEY_LOADED` to distinguish storage-loaded keys from freshly-generated ones
- `ProtectedSigningKey::drop()` emits `KEY_DESTROYED` before `ZeroizeOnDrop` zeroes key bytes — thumbprint still accessible
- `HybridPqcSigner::generate()` emits `KEY_GENERATED` with `key_type="ML-DSA-65+ES256"`
- `HybridPqcSigner::drop()` emits `KEY_DESTROYED` with `key_type="ML-DSA-65+ES256"`
- All events use `target: "unix_oidc_audit"` for SIEM filtering consistency with Phase 17 pattern
- tracing-test `no-env-filter` feature enabled so unit tests can capture `unix_oidc_audit` events

## Task Commits

TDD approach — each task had RED (failing tests) then GREEN (implementation) commits:

1. **Task 1 RED: DPoP key lifecycle tests** - `c5889b2` (test)
2. **Task 1 GREEN: DPoP key lifecycle implementation** - `14028ae` (feat)
3. **Task 2 RED: PQC key lifecycle tests** - `88c1bce` (test)
4. **Task 2 GREEN: PQC key lifecycle implementation** - `9d72341` (feat)

## Files Created/Modified

- `unix-oidc-agent/src/crypto/protected_key.rs` - Added `generate()` KEY_GENERATED, `from_bytes()` KEY_LOADED, `Drop` impl KEY_DESTROYED; 7 new tests
- `unix-oidc-agent/src/crypto/pqc_signer.rs` - Added `generate()` KEY_GENERATED, `Drop` impl KEY_DESTROYED; 3 new tests
- `unix-oidc-agent/Cargo.toml` - Enabled `no-env-filter` feature on tracing-test dev-dep

## Decisions Made

- **Drop impl approach**: Added explicit `Drop for ProtectedSigningKey` and `Drop for HybridPqcSigner` rather than adding audit calls elsewhere. Rust drop order ensures the body runs before fields are dropped, so `self.thumbprint` is still live when we read it.
- **key_id = 8-char prefix**: Full 43-char SHA-256 base64url thumbprint would be a useful fingerprint for attackers. First 8 chars provide enough correlation for lifecycle tracking without being a useful fingerprint.
- **from_bytes() emits KEY_LOADED**: This is the only path where a key is loaded from storage. `generate()` emits KEY_GENERATED. This distinction matters for SIEM — auditors can distinguish fresh key generation from storage recovery.
- **no-env-filter on tracing-test**: `tracing-test 0.2` default filter is `<crate_name>=trace`, which filters out events with `target: "unix_oidc_audit"`. Enabling `no-env-filter` captures all targets. This is dev-dep only (no production impact).
- **HybridPqcSigner emits two KEY_DESTROYED events at drop**: The `ec_key: Box<ProtectedSigningKey>` field independently emits its DPoP KEY_DESTROYED event when the field is dropped after the HybridPqcSigner Drop body completes. This is intentional — it provides full traceability of both the PQC layer and the EC component.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] tracing-test default filter suppresses unix_oidc_audit events**

- **Found during:** Task 1 GREEN (test verification)
- **Issue:** `tracing-test 0.2` uses `EnvFilter` with `<crate_name>=trace` by default. Events with `target: "unix_oidc_audit"` (not matching `unix_oidc_agent`) were silently filtered, making `logs_contain("KEY_GENERATED")` always false even when the event fired.
- **Fix:** Enabled `no-env-filter` feature on the `tracing-test` dev-dep in Cargo.toml, which captures events from all targets.
- **Files modified:** `unix-oidc-agent/Cargo.toml`
- **Verification:** `logs_contain("KEY_GENERATED")` now correctly returns true after generate() emits the event; all 7 lifecycle tests pass.
- **Committed in:** `14028ae` (part of Task 1 GREEN commit)

---

**Total deviations:** 1 auto-fixed (Rule 3 — blocking issue during test verification)
**Impact on plan:** Required change was minimal (one line in dev-deps). No production code affected.

## Issues Encountered

None beyond the tracing-test filter deviation documented above.

## Next Phase Readiness

- Key lifecycle audit events are complete for 27-02 (OBS-04)
- All 190 lib tests pass (206 with --features pqc); zero clippy warnings
- Phase 27 wave 1 plans 01-02 both complete; wave 2 plans (03-05) can proceed
- SIEM pipelines can now filter for `target: "unix_oidc_audit"` events with `event_type IN (KEY_GENERATED, KEY_LOADED, KEY_DESTROYED)` to trace DPoP and PQC key lifecycle

---
*Phase: 27-multi-idp-advanced-observability*
*Completed: 2026-03-16*
