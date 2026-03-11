---
phase: 08-username-mapping-group-policy-break-glass
plan: "01"
subsystem: identity-mapping-and-group-policy
tags:
  - identity
  - username-mapping
  - group-policy
  - nss
  - audit
  - break-glass
  - config
dependency_graph:
  requires: []
  provides:
    - identity/mapper.rs (UsernameMapper, UsernameTransform, IdentityError)
    - identity/collision.rs (validate_collision_safety)
    - sssd/groups.rs (resolve_nss_group_names, is_group_member, check_group_policy)
    - policy/config.rs (IdentityConfig, TransformConfig, groups_enforcement, login_groups, sudo_groups, accounts)
    - oidc/token.rs (get_claim_str, groups_for_audit, extra flatten)
    - audit.rs (AuditEvent::BreakGlassAuth)
  affects:
    - Plan 02 (wires these building blocks into auth flow)
tech_stack:
  added:
    - regex = "1.10" (safe finite-automata engine; no backtracking; catastrophic ReDoS impossible)
  patterns:
    - TDD (RED then GREEN per task)
    - thiserror for all error enums
    - Hand-rolled Deserialize for SecurityModes (pattern continued from Phase 06)
    - NSS-first group resolution (SSSD/FreeIPA as Unix authority; token groups audit-only)
    - Testable seam pattern for platform-specific NSS behaviour
key_files:
  created:
    - pam-unix-oidc/src/identity/mod.rs
    - pam-unix-oidc/src/identity/mapper.rs
    - pam-unix-oidc/src/identity/collision.rs
    - pam-unix-oidc/src/sssd/groups.rs
  modified:
    - pam-unix-oidc/Cargo.toml (regex dep)
    - pam-unix-oidc/src/policy/config.rs (IdentityConfig, TransformConfig, new fields)
    - pam-unix-oidc/src/oidc/token.rs (extra flatten, get_claim_str, groups_for_audit)
    - pam-unix-oidc/src/audit.rs (BreakGlassAuth variant)
    - pam-unix-oidc/src/sssd/mod.rs (re-export groups module)
    - pam-unix-oidc/src/lib.rs (pub mod identity)
decisions:
  - "Groups resolved from NSS (SSSD/FreeIPA), never from token claims — FreeIPA is Unix authority (see MEMORY.md)"
  - "Empty allowed_groups always permits (backward compat invariant)"
  - "groups_enforcement defaults to Warn (not Strict) to preserve v1.0 behaviour for operators adding new config"
  - "Regex (?P<username>...) validated before Regex::new() to surface operator error at config load not auth time"
  - "macOS getgrouplist returns Some for nonexistent users; enforcement-mode tests use simulation helper not real NSS"
  - "GroupDenied pre-formats display strings in constructor (thiserror cannot format Vec<String> directly)"
  - "BreakGlassConfig.accounts is Vec<String> with empty default; local_account kept for v1.0 backward compat"
metrics:
  duration_seconds: 560
  completed_date: "2026-03-10"
  tasks_completed: 3
  tasks_total: 3
  test_count_before: 134
  test_count_after: 197
  new_tests: 63
  files_created: 4
  files_modified: 6
---

# Phase 08 Plan 01: Config Extensions, Identity Mapper, NSS Group Resolution — Summary

**One-liner:** Pluggable username claim extraction with regex/strip/lowercase transform pipeline, NSS-backed group membership enforcement, and CRITICAL-severity BreakGlassAuth audit event.

## What Was Built

Three self-contained building blocks for Phase 8, not yet wired into the authentication flow (Plan 02 does that):

### Task 1 — Config extensions + TokenClaims + AuditEvent

- `IdentityConfig` with `username_claim` (default `preferred_username`) and `transforms: Vec<TransformConfig>`.
- `TransformConfig` with `#[serde(untagged)]`: Simple string (`"strip_domain"`, `"lowercase"`) or Object (`{ type: regex, pattern: "..." }`).
- `SshConfig.login_groups: Vec<String>` — NSS group allow-list for SSH login.
- `SudoConfig.sudo_groups: Vec<String>` — NSS group allow-list for sudo.
- `BreakGlassConfig.accounts: Vec<String>` — multi-account break-glass (v1.0 `local_account` retained).
- `SecurityModes.groups_enforcement: EnforcementMode` — default `Warn`; hand-rolled Deserialize updated.
- `PolicyConfig.identity: IdentityConfig` — new top-level field with figment support.
- `TokenClaims.extra: HashMap<String, serde_json::Value>` with `#[serde(flatten)]` for arbitrary claim access.
- `TokenClaims::get_claim_str()` — typed fields first, then extra map fallback.
- `TokenClaims::groups_for_audit()` — extracts `groups` claim array for audit enrichment only.
- `AuditEvent::BreakGlassAuth` — CRITICAL severity, all fields, `break_glass_auth()` constructor, `event_type()` arm.

### Task 2 — Identity mapper

- `UsernameMapper::from_config()` builds from `IdentityConfig`; pre-compiles regex at config load.
- Regex patterns validated for `(?P<username>...)` named capture group before `Regex::new()`.
- `UsernameTransform::apply()`: StripDomain (split `@`, take first), Lowercase, Regex (named group).
- Pipeline: each transform receives previous output; `None` → `TransformFailed`.
- Username sanitization: rejects empty, null bytes, slashes, values > 256 bytes.
- `validate_collision_safety()`: warns for `strip_domain` (non-injective across domains) and `regex` (advisory).
- Adversarial tests: null-byte injection, catastrophic-input regex (regex crate handles via DFA), overlong values.

### Task 3 — NSS group resolution

- `resolve_nss_group_names(username, gid)` via `uzers::get_user_groups`; non-UTF-8 names skipped with warn.
- `is_group_member(user_groups, allowed)` — empty `allowed` returns `true` (no restriction).
- `check_group_policy(username, gid, allowed_groups, enforcement)` — returns `Ok(groups)` or `GroupPolicyError`.
- Enforcement table: Disabled=skip, Warn=allow on NSS failure, Strict=deny on NSS failure.
- `GroupPolicyError::GroupDenied` captures `user_groups` + `allowed_groups` for audit enrichment.
- Integration test: `root` user resolves from real NSS with at least one group.
- Platform deviation: macOS `getgrouplist` returns `Some` for non-existent users; enforcement-mode logic tested via simulation helper (not brittle real-NSS test).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `splitn(2, '@')` → clippy `needless_splitn`**
- Found during: Task 3 clippy run
- Issue: `clippy::needless_splitn` lint fired; `splitn(2, …).next()` is equivalent to `split(…).next()`
- Fix: Changed to `input.split('@').next()?` in `mapper.rs`
- Files modified: `pam-unix-oidc/src/identity/mapper.rs`
- Commit: 6236d9c

**2. [Rule 1 - Bug] `thiserror` cannot format `Vec<String>` in derive macro error messages**
- Found during: Task 3 compile
- Issue: `#[error("... [{user_groups}]")]` on a `Vec<String>` field fails — Vec does not implement Display
- Fix: Added `GroupPolicyError::group_denied()` constructor that pre-formats display strings; error message references the pre-formatted `String` fields
- Files modified: `pam-unix-oidc/src/sssd/groups.rs`
- Commit: 6236d9c

**3. [Rule 1 - Bug] macOS `getgrouplist` returns `Some` for nonexistent users**
- Found during: Task 3 test run
- Issue: Tests for warn/strict enforcement on NSS lookup failure used `"nonexistent_user_99999"` expecting `None` return — macOS returns `Some([gid])` for any gid even with unknown username
- Fix: Replaced brittle NSS integration tests with `simulate_enforcement_on_lookup_failure()` helper that directly tests the enforcement logic branch without depending on real NSS behaviour
- Files modified: `pam-unix-oidc/src/sssd/groups.rs`
- Commit: 6236d9c

**4. [Rule 2 - Missing Debug] `UsernameMapper` and `UsernameTransform` need Debug for test assertions**
- Found during: Task 2 compile
- Fix: Added `#[derive(Debug)]` to `UsernameTransform`; manual `Debug` impl for `UsernameMapper` (since `regex::Regex` implements Debug via its own derive)
- Commit: 71a1078

## Test Coverage

| Scope | Tests Added | Notes |
|-------|-------------|-------|
| policy/config — new fields | 15 | IdentityConfig, TransformConfig, login_groups, sudo_groups, accounts, groups_enforcement |
| oidc/token — extra + methods | 6 | get_claim_str, groups_for_audit, flatten transparency |
| audit — BreakGlassAuth | 4 | serialization, event_type, constructor, no-IP case |
| identity/mapper | 21 | all transforms, pipeline, sanitization, adversarial |
| identity/collision | 5 | lowercase safe, strip warns, regex warns, combined |
| sssd/groups | 13 | is_group_member, check_group_policy, root integration, enforcement logic |

## Self-Check: PASSED

- FOUND: pam-unix-oidc/src/identity/mod.rs
- FOUND: pam-unix-oidc/src/identity/mapper.rs
- FOUND: pam-unix-oidc/src/identity/collision.rs
- FOUND: pam-unix-oidc/src/sssd/groups.rs
- FOUND commit: 9c76189 (Task 1)
- FOUND commit: 71a1078 (Task 2)
- FOUND commit: 6236d9c (Task 3)
- test result: ok. 197 passed; 0 failed; 0 ignored
