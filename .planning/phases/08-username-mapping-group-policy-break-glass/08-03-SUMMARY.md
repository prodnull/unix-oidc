---
phase: 08-username-mapping-group-policy-break-glass
plan: "03"
subsystem: identity-collision-safety
tags:
  - security-invariant
  - identity
  - collision-detection
  - hard-fail
  - IDN-03
dependency_graph:
  requires:
    - 08-01 (UsernameMapper, IdentityConfig, TransformConfig)
    - 08-02 (auth.rs mapper construction site)
  provides:
    - check_collision_safety() hard-fail gatekeeper in collision.rs
    - AuthError::Config propagation path for non-injective pipelines
  affects:
    - authenticate_with_token
    - authenticate_with_dpop
tech_stack:
  added:
    - thiserror::Error on CollisionError (already a crate dep)
  patterns:
    - Option<Result<T, E>>.transpose()? for early-return from Option::map closure
    - Inline closure return type annotation to resolve ambiguous Result<T, E>
key_files:
  modified:
    - pam-unix-oidc/src/identity/collision.rs
    - pam-unix-oidc/src/identity/mod.rs
    - pam-unix-oidc/src/auth.rs
decisions:
  - "check_collision_safety() delegates to validate_collision_safety() and wraps non-empty warnings as Err — single source of truth for heuristics"
  - "validate_collision_safety() preserved unchanged — backward compat for any tooling callers; doc-commented as advisory-only"
  - "Closure return type annotation (|policy| -> Result<UsernameMapper, AuthError>) required to resolve ambiguous error type when both CollisionError and IdentityError are mapped to AuthError"
  - "Tests in auth.rs mirror production .map(...).transpose()? pattern via helper — no SSSD dependency required"
metrics:
  duration: "~4 minutes"
  completed: "2026-03-10"
  tasks: 2
  files_modified: 3
---

# Phase 08 Plan 03: IDN-03 Collision Detection Hard-Fail Summary

**One-liner:** `check_collision_safety()` hard-fail gatekeeper closes IDN-03 gap — strip_domain and regex pipelines now propagate `AuthError::Config`, not a logged warning.

## What Was Built

### Task 1: `CollisionError` and `check_collision_safety()` in `collision.rs`

Added two public items:

**`CollisionError`** — a `thiserror::Error` struct with a `reason: String` field that names each offending transform. The Display output includes "Non-injective username transform pipeline detected" so the error is self-describing in logs.

**`check_collision_safety(config: &IdentityConfig) -> Result<(), CollisionError>`** — calls the existing `validate_collision_safety()` and, if any warnings are present, wraps them as `Err(CollisionError { reason: warnings.join("; ") })`. Returns `Ok(())` when the pipeline is safe.

`validate_collision_safety()` is preserved unchanged for backward compatibility.

`mod.rs` updated to re-export `check_collision_safety` and `CollisionError`.

### Task 2: Hard-fail in `auth.rs`

Replaced the advisory `validate_collision_safety()` warn block (two occurrences — `authenticate_with_token` and `authenticate_with_dpop`) with the hard-fail pattern:

```rust
let mapper = policy_opt
    .as_ref()
    .map(|policy| -> Result<UsernameMapper, AuthError> {
        crate::identity::collision::check_collision_safety(&policy.identity)
            .map_err(|e| AuthError::Config(e.to_string()))?;
        UsernameMapper::from_config(&policy.identity)
            .map_err(|e| AuthError::IdentityMapping(e.to_string()))
    })
    .transpose()?;
```

Key design points:
- `-> Result<UsernameMapper, AuthError>` annotation required to resolve type inference when both `CollisionError` and `IdentityError` are mapped to `AuthError`
- `.transpose()?` makes `mapper` type `Option<UsernameMapper>` — downstream match arms updated from `Some(Ok(ref m))` / `Some(Err(e))` to `Some(ref m)` / `None`
- When `policy_opt` is `None`, the closure is never called — collision check is skipped (correct: no policy = no identity config = no collision risk)

The `tracing::warn!` for `collision_warning` is completely removed from `auth.rs`.

## Test Coverage

### collision.rs (12 tests total, 6 new)
- `check_strip_domain_returns_err_with_transform_name` — Err contains "strip_domain"
- `check_regex_returns_err_with_transform_name` — Err contains "regex"
- `check_both_strip_domain_and_regex_lists_both` — Err contains both names
- `check_lowercase_only_is_ok` — Ok(()) for safe pipeline
- `check_no_transforms_is_ok` — Ok(()) for empty pipeline
- `check_collision_error_display_contains_detail` — Display includes "Non-injective" and transform name

### auth.rs (5 new tests in collision section)
- `collision_check_strip_domain_propagates_auth_config_error` — AuthError::Config with "Non-injective" and "strip_domain"
- `collision_check_regex_propagates_auth_config_error` — AuthError::Config with "regex"
- `collision_check_lowercase_does_not_trigger_hard_fail` — Ok(Some(mapper))
- `collision_check_no_policy_skips_check` — Ok(None) when policy_opt is None
- `collision_check_both_transforms_config_error_lists_both` — both names in error

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Closure error type annotation required for type inference**
- **Found during:** Task 2 implementation
- **Issue:** The closure `|policy| { ... }` contained two different error mappings (`CollisionError → AuthError::Config` and `IdentityError → AuthError::IdentityMapping`). Rust's type inference could not unify these without an explicit return type annotation.
- **Fix:** Added `-> Result<UsernameMapper, AuthError>` return type to both production closures and to the test helper `construct_mapper_like_auth`.
- **Files modified:** `pam-unix-oidc/src/auth.rs`
- **Commit:** f510910

None of these deviations are architectural — they are type system mechanics of Rust closures with multiple error type mappings in the same body.

## Verification

```
cargo test -p pam-unix-oidc    → 217 passed; 0 failed
cargo clippy -p pam-unix-oidc -- -D warnings  → clean
cargo fmt --check -p pam-unix-oidc            → clean
grep "check_collision_safety" auth.rs         → 2 production call sites confirmed
grep "collision_warning" auth.rs              → 0 results (warn path confirmed removed)
```

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1 | 94ada10 | feat(08-03): add CollisionError and check_collision_safety() hard-fail gatekeeper |
| 2 | f510910 | feat(08-03): hard-fail in auth.rs on non-injective transform pipeline (IDN-03) |

## Self-Check: PASSED

- `pam-unix-oidc/src/identity/collision.rs` — FOUND
- `pam-unix-oidc/src/identity/mod.rs` — FOUND
- `pam-unix-oidc/src/auth.rs` — FOUND
- Commit 94ada10 — FOUND
- Commit f510910 — FOUND
- 217 tests pass
