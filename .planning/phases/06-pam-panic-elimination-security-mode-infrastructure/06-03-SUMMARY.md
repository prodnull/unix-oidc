---
phase: 06-pam-panic-elimination-security-mode-infrastructure
plan: "03"
subsystem: validation-pipeline
tags: [enforcement-mode, jti, clippy-deny, parking_lot, security-modes, issue-10]
dependency_graph:
  requires: [06-01-parking_lot-migration, 06-02-SecurityModes-figment]
  provides: [jti-enforcement-pipeline, deny-unwrap-lint]
  affects:
    - pam-unix-oidc/src/oidc/validation.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/sudo.rs
tech_stack:
  added: []
  patterns:
    - EnforcementMode match-gated JTI check with Disabled outer guard
    - if let Ok(policy) = PolicyConfig::from_env() with silent fallback
    - crate-level deny(clippy::unwrap_used, clippy::expect_used) with test-module allow
    - parking_lot::Mutex in static context (no .unwrap() on lock())
key_files:
  created: []
  modified:
    - pam-unix-oidc/src/oidc/validation.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/sudo.rs
decisions:
  - "ValidationConfig.enforce_jti: bool replaced by jti_enforcement: EnforcementMode — removes UNIX_OIDC_DISABLE_JTI_CHECK env var in favour of policy.yaml enforcement"
  - "Replay detection remains hard-fail in all modes (Strict/Warn/Disabled) — missing JTI is configurable but replayed JTI is never configurable (CLAUDE.md invariant)"
  - "Disabled mode short-circuits before the cache lookup — avoids unnecessary state for deployments that opt out of JTI tracking"
  - "PolicyConfig::from_env() threaded into authenticate_with_token/dpop with if let Ok(policy) fallback — missing policy file non-fatal, Warn default preserved"
  - "DPoP enforcement mode threading deferred to Phase 7 (nonce issuance); TODO comment added in auth.rs"
  - "ENV_MUTEX migrated to parking_lot::Mutex in lib.rs tests — no .unwrap() on .lock() required"
metrics:
  duration_secs: 803
  completed_date: "2026-03-10"
  tasks_completed: 2
  files_changed: 4
---

# Phase 6 Plan 03: Enforcement Mode Pipeline + Deny Lint Summary

JTI enforcement mode wired end-to-end (strict/warn/disabled) from policy.yaml through auth functions into the validation pipeline; deny(clippy::unwrap_used, clippy::expect_used) activated crate-wide with zero violations.

## Objective

Wire SecurityModes enforcement modes into the token validation pipeline and activate the crate-wide deny lint, making unwrap/expect a compile error in production code.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Wire EnforcementMode into JTI validation pipeline | a1d063a | validation.rs, auth.rs, sudo.rs |
| 2 | Activate deny(clippy::unwrap_used, clippy::expect_used) crate-wide | b8dfb35 | lib.rs, auth.rs |

## Implementation Details

### Task 1: JTI Enforcement Mode Pipeline

**ValidationConfig change:**

```rust
// Before (v1.0):
pub enforce_jti: bool,

// After (v2.0):
pub jti_enforcement: EnforcementMode,
```

The `UNIX_OIDC_DISABLE_JTI_CHECK` environment variable is retired. Enforcement is now controlled by `policy.yaml`'s `security_modes.jti_enforcement` field.

**Validation logic:**

```rust
if self.config.jti_enforcement != EnforcementMode::Disabled {
    let jti_result = global_jti_cache().check_and_record(...);
    match jti_result {
        JtiCheckResult::Valid => {}
        JtiCheckResult::Replay => {
            // Always hard-fail — replay is never configurable
            return Err(ValidationError::TokenReplay { ... });
        }
        JtiCheckResult::Missing => {
            match self.config.jti_enforcement {
                Strict   => return Err(ValidationError::MissingJti),
                Warn     => tracing::warn!(...),
                Disabled => { /* unreachable, outer guard prevents this */ }
            }
        }
    }
}
```

**auth.rs threading:**

```rust
let mut config = ValidationConfig::from_env()?;
if let Ok(policy) = PolicyConfig::from_env() {
    config.jti_enforcement = policy.effective_security_modes().jti_enforcement;
}
```

Applied to both `authenticate_with_token()` and `authenticate_with_dpop()`.

**sudo.rs:** Updated `ValidationConfig` literal from `enforce_jti: true` to `jti_enforcement: EnforcementMode::Warn`.

### Task 2: Deny Lint Activation

Added to `lib.rs` immediately after the existing unsafe deny:

```rust
#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used)]
```

All test modules annotated with `#[allow(clippy::unwrap_used, clippy::expect_used)]`:
- `pam-unix-oidc/src/lib.rs` — `mod tests`
- `pam-unix-oidc/src/auth.rs` — `mod tests`
- `pam-unix-oidc/src/oidc/validation.rs` — `mod tests` (added during Task 1)

`ENV_MUTEX` in `lib.rs` migrated from `std::sync::Mutex` to `parking_lot::Mutex`, removing 10 `.unwrap()` call sites on `.lock()`.

## Test Coverage

122 tests pass with `--features test-mode`. New tests added:

| Test | Mode | Expected |
|------|------|----------|
| `test_jti_strict_rejects_missing` | Strict | `Err(MissingJti)` |
| `test_jti_warn_allows_missing` | Warn | `Ok(claims)` |
| `test_jti_disabled_skips_check` | Disabled | `Ok(claims)` |
| `test_v1_default_behavior` | Warn (default) | missing JTI passes; replay rejected |

## Deviations from Plan

### Auto-fixed: sudo.rs ValidationConfig literal

**Rule 3 — Blocking issue**

- **Found during:** Task 1 compilation
- **Issue:** `sudo.rs` still used `enforce_jti: true` which caused a compile error after the field was renamed.
- **Fix:** Updated to `jti_enforcement: EnforcementMode::Warn` with a comment explaining why Warn (not Strict) is the appropriate default for step-up flows.
- **Files modified:** `pam-unix-oidc/src/sudo.rs`
- **Commit:** a1d063a

## Verification Results

```
cargo clippy -p pam-unix-oidc -- -D clippy::unwrap_used -D clippy::expect_used:
  zero errors, zero warnings

cargo test -p pam-unix-oidc:
  110 passed

cargo test -p pam-unix-oidc --features test-mode:
  122 passed

cargo test -p pam-unix-oidc --features test-mode test_jti:
  6 passed (jti_cache + enforcement mode tests)

grep 'deny(clippy::unwrap_used' pam-unix-oidc/src/lib.rs:
  #![deny(clippy::unwrap_used, clippy::expect_used)]

cargo build --workspace:
  Finished (clean)
```

## Self-Check: PASSED

- pam-unix-oidc/src/oidc/validation.rs: FOUND
- pam-unix-oidc/src/auth.rs: FOUND
- pam-unix-oidc/src/lib.rs: FOUND
- pam-unix-oidc/src/sudo.rs: FOUND
- Commit a1d063a: FOUND
- Commit b8dfb35: FOUND
- 122 tests passing: VERIFIED
- deny lint active with zero violations: VERIFIED
