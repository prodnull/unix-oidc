---
phase: 08-username-mapping-group-policy-break-glass
verified: 2026-03-10T00:00:00Z
status: passed
score: 15/15 must-haves verified
re_verification:
  previous_status: gaps_found
  previous_score: 14/15
  gaps_closed:
    - "Two IdP identities that would map to the same Unix username cause the daemon to refuse to start with a clear config error"
  gaps_remaining: []
  regressions: []
---

# Phase 08: Username Mapping + Group Policy + Break-Glass — Verification Report

**Phase Goal:** Enterprise deployments can map IdP claim values to local Unix usernames, restrict login to specific OIDC groups, and rely on break-glass accounts being enforced with an audit trail
**Verified:** 2026-03-10
**Status:** passed
**Re-verification:** Yes — after gap closure (Plan 08-03 closed IDN-03 hard-fail gap)

## Goal Achievement

### Observable Truths

Combined must_haves from Plan 01, Plan 02, and Plan 03 (gap-closure) frontmatter.

| #  | Truth | Status | Evidence |
|----|-------|--------|----------|
| 1  | A UsernameMapper can extract any claim (sub, email, preferred_username, custom) from token claims and apply an ordered transform pipeline | VERIFIED | `mapper.rs:173` — `map()` calls `get_claim_str` then applies `self.transforms` in order |
| 2  | Regex transforms without `(?P<username>...)` named capture group are rejected at config load time with a clear error | VERIFIED | `mapper.rs:148-149` — pattern checked for `(?P<username>` before `Regex::new()`, returns `MissingCaptureGroup` |
| 3  | Collision detection warns at config load when strip_domain is configured | VERIFIED | `collision.rs:99-107` — `strip_domain` always emits a warning; also hard-fails via `check_collision_safety` |
| 4  | NSS group resolution returns the mapped user's group list via `uzers::get_user_groups` | VERIFIED | `groups.rs:93-114` — `get_user_groups(username, gid)` called; filter_map with `to_str` (strict UTF-8) |
| 5  | Group membership check tests set intersection between user groups and allow-list | VERIFIED | `groups.rs:122-127` — `is_group_member` returns `true` when any element of `user_groups` is in `allowed` |
| 6  | BreakGlassConfig supports multiple accounts via Vec<String> with empty default | VERIFIED | `config.rs` — `BreakGlassConfig.accounts: Vec<String>` with `#[serde(default)]`; `local_account` retained for compat |
| 7  | AuditEvent::BreakGlassAuth emits with CRITICAL severity and correct fields | VERIFIED | `audit.rs:122-131` — variant has `severity: &'static str`; constructor sets `"CRITICAL"`, `reason: "break-glass bypass"` |
| 8  | `groups_enforcement` field in SecurityModes controls NSS lookup failure behavior | VERIFIED | `config.rs:220` — field present; `groups.rs:174-188` — enforces Strict/Warn/Disabled on `None` from NSS |
| 9  | Break-glass accounts bypass OIDC entirely and return PAM_IGNORE before any rate-limiting, nonce issuance, or token validation | VERIFIED | `lib.rs:90-105` — break-glass guard at line 99, rate-limit check at line 108; guard fires first |
| 10 | Break-glass authentication emits AuditEvent::BreakGlassAuth with CRITICAL severity before returning PAM_IGNORE | VERIFIED | `lib.rs:102-103` — `.log()` called before `return PamError::IGNORE` |
| 11 | Username mapping via configurable claim + transform pipeline replaces hardcoded preferred_username in all three auth functions | VERIFIED | `auth.rs:130-144` (`authenticate_with_token`), `auth.rs:412-425` (`authenticate_with_dpop`); `authenticate_with_config` has optional mapper param |
| 12 | NSS group policy check after user_exists denies login when user not in login_groups | VERIFIED | `auth.rs:163-179` — `check_group_policy` called with `policy.ssh_login.login_groups` after `user_exists` |
| 13 | Sudo group policy check denies step-up when user not in sudo_groups | VERIFIED | `sudo.rs:136-155` — guard checks `sudo_groups.is_empty()` first, then `check_group_policy` before step-up |
| 14 | Token groups claim logged for audit enrichment but never used for access decisions | VERIFIED | `auth.rs:147-153,428-434` — `groups_for_audit()` result logged at `tracing::info!` with explicit comment; no conditional on result |
| 15 | A transform pipeline with strip_domain or regex causes authentication to fail with AuthError::Config, not a warning | VERIFIED | `collision.rs:60-68` — `check_collision_safety()` returns `Err(CollisionError)`; `auth.rs:105-113,290-298` — both production auth functions call it via `.transpose()?`; 5 dedicated unit tests in `auth::tests` confirm hard-fail propagation |

**Score:** 15/15 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/identity/mod.rs` | Re-exports UsernameMapper, IdentityConfig, transforms, collision | VERIFIED | Exports `UsernameMapper`, `UsernameTransform`, `IdentityError`, `validate_collision_safety`, `check_collision_safety`, `CollisionError` (line 14) |
| `pam-unix-oidc/src/identity/mapper.rs` | UsernameMapper, UsernameTransform enum, pipeline execution (min 80 lines) | VERIFIED | 502 lines; full pipeline with StripDomain, Lowercase, Regex |
| `pam-unix-oidc/src/identity/collision.rs` | `check_collision_safety()` returning Result; `validate_collision_safety()` preserved; `CollisionError` type | VERIFIED | 328 lines; `CollisionError` at line 38; `check_collision_safety` at line 60; 12 tests all pass |
| `pam-unix-oidc/src/sssd/groups.rs` | resolve_nss_group_names, is_group_member, check_group_policy functions (min 40 lines) | VERIFIED | 387 lines; all three public functions present |
| `pam-unix-oidc/src/policy/config.rs` | IdentityConfig, TransformConfig, extended SshConfig/SudoConfig/BreakGlassConfig/SecurityModes | VERIFIED | All new fields present with correct defaults and serde attrs |
| `pam-unix-oidc/src/oidc/token.rs` | TokenClaims with extra HashMap + get_claim_str + groups_for_audit | VERIFIED | `extra: HashMap<String, Value>` with `#[serde(flatten)]`; both methods implemented |
| `pam-unix-oidc/src/audit.rs` | AuditEvent::BreakGlassAuth variant + break_glass_auth() constructor + event_type() arm | VERIFIED | Variant at line 122; constructor at 247; `event_type()` arm at 284 |
| `pam-unix-oidc/src/lib.rs` | Break-glass guard in authenticate(), mapper construction from policy config | VERIFIED | `is_break_glass_user` helper; guard at line 99 before rate-limit at 108 |
| `pam-unix-oidc/src/auth.rs` | Username mapper integration, group policy checks, collision hard-fail in authenticate_with_token/authenticate_with_dpop | VERIFIED | `check_collision_safety` called at lines 108 and 293; `.transpose()?` propagates `AuthError::Config`; 5 collision unit tests added |
| `pam-unix-oidc/src/sudo.rs` | sudo_groups check before step-up authentication | VERIFIED | `sudo_groups` guard at lines 136-155; fires before `log_step_up_initiated` |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `identity/mapper.rs` | `oidc/token.rs` | `TokenClaims::get_claim_str` used by `UsernameMapper::map` | WIRED | `mapper.rs:176` — `claims.get_claim_str(&self.claim)` |
| `identity/mapper.rs` | `policy/config.rs` | `TransformConfig` deserialized into `UsernameTransform` | WIRED | `mapper.rs:125-156` — `match tc { TransformConfig::Simple(..) \| TransformConfig::Object { .. } }` |
| `sssd/groups.rs` | `uzers::get_user_groups` | NSS group resolution | WIRED | `groups.rs:30` — `use uzers::get_user_groups`; `groups.rs:94` — `get_user_groups(username, gid)?` |
| `lib.rs` | `audit.rs` | `AuditEvent::break_glass_auth()` emitted before PAM_IGNORE | WIRED | `lib.rs:102` — `AuditEvent::break_glass_auth(&pam_user, source_ip).log()` |
| `auth.rs` | `identity/mapper.rs` | `UsernameMapper::map()` replaces `claims.preferred_username` | WIRED | `auth.rs:3,134,138,418,422` — imported and called in both production auth functions |
| `auth.rs` | `identity/collision.rs` | `check_collision_safety()` called before mapper construction; Err propagated as AuthError::Config | WIRED | `auth.rs:108-113` (authenticate_with_token); `auth.rs:293-298` (authenticate_with_dpop); `.transpose()?` on both |
| `auth.rs` | `sssd/groups.rs` | `check_group_policy()` called after `user_exists` | WIRED | `auth.rs:165` in `authenticate_with_token`; `auth.rs:445` in `authenticate_with_dpop` |
| `sudo.rs` | `sssd/groups.rs` | `check_group_policy()` called with `sudo_groups` | WIRED | `sudo.rs:140-154` — `check_group_policy(&ctx.user, user_info.gid, &policy.sudo.sudo_groups, ...)` |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|---------|
| IDN-01 | 08-01, 08-02 | Username claim mapping with configurable claim source | SATISFIED | `IdentityConfig.username_claim` + `UsernameMapper::from_config` + wired in both production auth paths |
| IDN-02 | 08-01, 08-02 | Username transform functions (strip domain, regex with capture group, lowercase) | SATISFIED | All three `UsernameTransform` variants implemented, tested, and wired |
| IDN-03 | 08-01, 08-03 | Username uniqueness validation — non-injective pipelines prevent authentication | SATISFIED | `check_collision_safety()` returns `Err(CollisionError)` for strip_domain or regex; auth.rs propagates as `AuthError::Config` via `.transpose()?`; hard-fail path covered by 5 unit tests in `auth::tests` |
| IDN-04 | 08-01, 08-02 | Group-based login access policy from NSS groups with configurable allow-list | SATISFIED | `login_groups` field in `SshConfig`; `check_group_policy` called in both auth paths |
| IDN-05 | 08-01, 08-02 | Group-based sudo access policy (sudo_groups) gating step-up authorization | SATISFIED | `sudo_groups` field in `SudoConfig`; guard in `authenticate_sudo` before device flow |
| IDN-06 | 08-01, 08-02 | Break-glass account enforcement — skip OIDC for configured accounts, pass to next PAM module | SATISFIED | `is_break_glass_user` + `PamError::IGNORE` before rate-limit in `lib.rs` |
| IDN-07 | 08-01, 08-02 | Break-glass audit event emitted on every break-glass authentication | SATISFIED | `AuditEvent::break_glass_auth(..).log()` called before returning `PAM_IGNORE` |

### Anti-Patterns Found

No blocker or warning-level anti-patterns found. No TODO/FIXME/placeholder comments. No empty implementations. No `tracing::warn!` for collision detection remaining in the auth path (`collision_warning` grep returns zero results in `auth.rs`). 217 tests pass. Clippy clean (`-D warnings`). Format clean (`cargo fmt --check`).

### Human Verification Required

The following items cannot be verified programmatically:

#### 1. Break-glass end-to-end PAM flow

**Test:** Configure a local account as `break_glass.accounts: [breakglass]` and `enabled: true`. SSH as that user. Observe that authentication proceeds to `pam_unix.so` (or equivalent local auth) rather than terminating with OIDC failure.
**Expected:** Login succeeds with local password; audit log shows `BREAK_GLASS_AUTH` event with `severity: CRITICAL`.
**Why human:** Requires a live PAM stack with SSHD; cannot simulate PAM module chain in unit tests.

#### 2. Username strip-domain + lowercase transform on real OIDC token

**Test:** Configure `identity: { username_claim: email, transforms: [strip_domain, lowercase] }`. Observe that authentication is immediately rejected with a config error naming `strip_domain` as non-injective, before any OIDC token exchange occurs.
**Expected:** `AuthError::Config` containing "Non-injective username transform pipeline detected — ... strip_domain" returned before token validation. No token exchange initiated.
**Why human:** Requires a live PAM session to observe the error surface to the SSH client; unit tests confirm the error but not the PAM presentation.

#### 3. Group policy denial with real NSS

**Test:** Configure `login_groups: [unix-users]`. Authenticate with a valid OIDC token for a user who exists in NSS but is NOT in the `unix-users` group.
**Expected:** Authentication fails with `AUTH_ERR`; denial logged with user's actual NSS groups and the allowed-groups list.
**Why human:** Requires a live SSSD-enrolled user with known group membership.

#### 4. Sudo group policy denial before device flow

**Test:** Configure `sudo_groups: [wheel]`. Initiate `sudo` as a user not in `wheel`. Observe that the device-flow browser challenge is NOT issued (no `StepUpInitiated` audit event).
**Expected:** Step-up denied immediately with `GroupDenied`; no browser prompt shown.
**Why human:** Requires live sudo PAM integration and device flow infrastructure.

### Re-verification Summary

**Gap closed:** IDN-03 collision hard-fail is now fully implemented and tested.

Plan 08-03 added `check_collision_safety()` returning `Result<(), CollisionError>` to `collision.rs`, and replaced the previous `tracing::warn!`-only advisory path in `auth.rs` with a `.transpose()?` propagation of `AuthError::Config`. Both `authenticate_with_token` (line 105-113) and `authenticate_with_dpop` (lines 290-298) now hard-fail on non-injective pipelines. The existing `validate_collision_safety()` advisory function is preserved for tooling use. Five dedicated unit tests in `auth::tests` confirm: strip_domain propagates `AuthError::Config`; regex propagates `AuthError::Config`; both together list both transforms in the error; lowercase-only does not trigger the check; absent policy skips the check entirely.

All 217 tests pass. Clippy and fmt are clean. All 7 IDN requirements are satisfied with substantive, wired implementations.

---

_Verified: 2026-03-10_
_Verifier: Claude (gsd-verifier)_
_Re-verification after gap closure by Plan 08-03_
