---
phase: 08-username-mapping-group-policy-break-glass
plan: "02"
subsystem: auth-flow-integration
tags:
  - break-glass
  - username-mapping
  - group-policy
  - auth-flow
  - audit
dependency_graph:
  requires:
    - 08-01 (UsernameMapper, check_group_policy, AuditEvent::break_glass_auth)
  provides:
    - pam-unix-oidc/src/auth.rs (mapper integration, group policy, mapped_from audit)
    - pam-unix-oidc/src/lib.rs (break-glass bypass guard, new error dispatch)
    - pam-unix-oidc/src/sudo.rs (sudo_groups check before step-up)
  affects:
    - All PAM SSH authentication paths (authenticate_with_token, authenticate_with_dpop)
    - Sudo step-up path (authenticate_sudo)
tech_stack:
  added: []
  patterns:
    - Break-glass-first PAM guard (before rate limiting)
    - mapper.map() replaces hardcoded preferred_username in production paths
    - Optional mapper in test path (None = backward compat)
    - NSS group check after user_exists() (gid needed for getgrouplist)
    - log-and-deny pattern for GroupDenied and IdentityMapping errors
key_files:
  created: []
  modified:
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/sudo.rs
decisions:
  - "Break-glass check is unconditionally FIRST in authenticate() — before rate limiting, nonce issuance, and OIDC; ensures no side effects on break-glass accounts"
  - "authenticate_with_config gains optional mapper parameter defaulting to None — backward compat with all 134 pre-Phase-8 tests preserved"
  - "mapped_from field set to Some(raw) only when mapping changes the value — no noise in audit log for identity-preserving configs"
  - "sudo group check occurs BEFORE device flow initiation — avoids issuing browser challenge to user who will be denied regardless"
  - "Empty sudo_groups skips NSS lookup entirely — backward compat invariant from MEMORY.md"
metrics:
  duration_seconds: 310
  completed_date: "2026-03-10"
  tasks_completed: 2
  tasks_total: 2
  test_count_before: 197
  test_count_after: 206
  new_tests: 9
  files_created: 0
  files_modified: 3
---

# Phase 08 Plan 02: Auth Flow Integration — Summary

**One-liner:** Break-glass bypass (PAM_IGNORE before rate limiting), configurable username claim+transform pipeline, and NSS group policy enforcement wired into all three authentication paths.

## What Was Built

Two tasks completing the Phase 8 integration — connecting the Plan 01 building blocks into the live PAM authentication and sudo step-up flows.

### Task 1 — auth.rs + lib.rs integration

**lib.rs:**
- `is_break_glass_user()` helper checks both `break_glass.accounts` (v2.0) and `break_glass.local_account` (v1.0 compat).
- Break-glass guard at the FIRST statement of `PamServiceModule::authenticate()`, before rate limiting, nonce issuance, and token validation. When matched and `enabled=true`: emits `AuditEvent::BreakGlassAuth` (CRITICAL severity) and returns `PamError::IGNORE`.
- Two new error dispatch arms: `AuthError::GroupDenied` → `ssh_login_failed` + `AUTH_ERR`; `AuthError::IdentityMapping` → `ssh_login_failed` + `AUTH_ERR`.

**auth.rs:**
- `AuthError::GroupDenied(String)` and `AuthError::IdentityMapping(String)` variants added.
- `AuthResult::mapped_from: Option<String>` added for audit trail; set to `Some(raw_claim)` only when the mapper changed the value (no noise for identity-preserving configs).
- `authenticate_with_token()`: constructs `UsernameMapper` from `PolicyConfig.identity`, logs collision safety warnings, calls `mapper.map()` → `username_str`, logs `groups_for_audit()` at INFO for audit enrichment, then calls `check_group_policy()` after `user_exists()` with `login_groups` + `groups_enforcement`.
- `authenticate_with_dpop()`: same mapper + group policy pattern as `authenticate_with_token()`.
- `authenticate_with_config()`: gains `mapper: Option<&UsernameMapper>` parameter; `None` = backward compat (all pre-Phase-8 tests unchanged); group policy NOT enforced (test path only).

### Task 2 — sudo.rs integration

- `SudoError::GroupDenied(String)` variant added with "Sudo group policy denied step-up" prefix.
- `SudoError::UserResolution(#[from] UserError)` variant added for NSS lookup failures.
- `authenticate_sudo()`: before `log_step_up_initiated()`, if `sudo_groups` is non-empty, calls `get_user_info()` for the user's GID, then `check_group_policy()` with `sudo_groups` + `groups_enforcement`. `GroupDenied` → logs `step_up_failed` ("user not in sudo_groups") and returns `SudoError::GroupDenied`. Empty `sudo_groups` → check skipped entirely (backward compat invariant).

## Deviations from Plan

None — plan executed exactly as written.

## Test Coverage

| Scope | Tests Added | Notes |
|-------|-------------|-------|
| lib.rs — break-glass helper | 5 | accounts list, local_account v1 compat, disabled guard, empty default, both fields |
| auth.rs — new error variants | 1 | GroupDenied and IdentityMapping display |
| auth.rs — mapped_from field | 2 | Some and None cases via AuthResult construction |
| sudo.rs — GroupDenied variant | 3 | display, descriptive detail, empty list backward compat |

**Total new tests:** 9 (197 → 206)

## Self-Check: PASSED

- FOUND: pam-unix-oidc/src/auth.rs (modified, contains `UsernameMapper`, `GroupDenied`, `IdentityMapping`, `mapped_from`)
- FOUND: pam-unix-oidc/src/lib.rs (modified, contains `break_glass`, `is_break_glass_user`)
- FOUND: pam-unix-oidc/src/sudo.rs (modified, contains `sudo_groups`, `GroupDenied`)
- FOUND commit: 6c9e83b (Task 1)
- FOUND commit: fdcdfe1 (Task 2)
- test result: ok. 206 passed; 0 failed; 0 ignored
- clippy: clean (no warnings)
- fmt: clean
- break-glass is at line 97, rate_limit at line 108 (break-glass is first confirmed)
- no hardcoded `claims.preferred_username` in production auth functions (only in None/fallback arms when policy absent)
