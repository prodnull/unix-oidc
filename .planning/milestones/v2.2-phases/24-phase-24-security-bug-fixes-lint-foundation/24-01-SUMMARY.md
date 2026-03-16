---
phase: 24-phase-24-security-bug-fixes-lint-foundation
plan: 01
subsystem: auth
tags: [oidc, pam, audit, dpop, preferred_username, break-glass, syslog, forensics]

# Dependency graph
requires: []
provides:
  - "Correct oidc_issuer attribution in TOKEN_VALIDATION_FAILED audit events (SBUG-01)"
  - "break_glass.alert_on_use flag wired to syslog severity (SBUG-02)"
  - "Graceful preferred_username=None handling in auth.rs and sudo.rs (SBUG-03)"
affects:
  - "phase-25 (SIEM alerting on break-glass events now conditional on alert_on_use)"
  - "phase-28 E2E tests (audit event field correctness)"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "extract_iss_for_routing() called before auth dispatch in lib.rs to capture issuer for audit without requiring auth success"
    - "alert_on_use bool field on BreakGlassAuth variant drives conditional syslog severity at Critical vs Info"
    - "preferred_username absent: auth.rs uses get_claim_str(username_claim), sudo.rs falls back to claims.sub"

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/audit.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/sudo.rs

key-decisions:
  - "BreakGlassAuth.severity changed from &'static str to String to allow runtime CRITICAL/INFO selection based on alert_on_use; alert_on_use field is #[serde(skip)] to avoid serialization duplication"
  - "SBUG-01 uses best-effort pre-auth issuer extraction via extract_iss_for_routing() — if token is malformed, oidc_issuer is honestly None in the audit event"
  - "SBUG-03 sudo fallback uses sub claim (always present, OIDC Core §2) rather than raising a separate error, producing legible UserMismatch messages when preferred_username is absent"

patterns-established:
  - "Capture forensic context (issuer, user) before the auth call, not inside error handlers — the error handler may not have access to the data that caused the error"
  - "alert_on_use configurable severity: CRITICAL for production alerting, INFO for routine/automation break-glass accounts"

requirements-completed: [SBUG-01, SBUG-02, SBUG-03]

# Metrics
duration: 35min
completed: 2026-03-14
---

# Phase 24 Plan 01: Security Bug Fixes (SBUG-01/02/03) Summary

**Three forensic-correctness security fixes: correct issuer attribution in audit events, conditional break-glass alert severity, and sub-claim fallback when preferred_username is absent.**

## Performance

- **Duration:** ~35 min
- **Started:** 2026-03-14T00:00:00Z
- **Completed:** 2026-03-14T00:35:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- SBUG-01: All `token_validation_failed()` audit calls in lib.rs now pass the token's issuer URL extracted via best-effort pre-auth parse; UnknownIssuer arm uses the issuer from the variant directly
- SBUG-02: `BreakGlassAuth` variant gains `alert_on_use: bool` field; `break_glass_auth()` constructor accepts the flag from `policy.break_glass.alert_on_use`; `syslog_severity()` returns Critical when true, Info when false; serialized `severity` field is `"CRITICAL"` or `"INFO"`
- SBUG-03: `auth.rs` Step 7 uses `get_claim_str(username_claim)` instead of `preferred_username.clone().unwrap_or_default()` for the `raw_claim` audit trail field; `sudo.rs` falls back to `claims.sub` when `preferred_username` is None

## Task Commits

Each task was committed atomically:

1. **Task 1: SBUG-01 + SBUG-02** - `fd0a16d` (fix)
2. **Task 2: SBUG-03** - `0def7df` (fix)

## Files Created/Modified

- `pam-unix-oidc/src/audit.rs` — BreakGlassAuth variant: severity String (was &'static str), alert_on_use bool field, conditional syslog_severity(); break_glass_auth() signature updated; 9 new tests
- `pam-unix-oidc/src/lib.rs` — token_issuer_for_audit extracted pre-auth; all token_validation_failed() calls updated; break-glass path passes alert_on_use; 6 new SBUG-01 tests
- `pam-unix-oidc/src/auth.rs` — authenticate_multi_issuer Step 7: raw_claim via get_claim_str(username_claim); 5 new SBUG-03 tests
- `pam-unix-oidc/src/sudo.rs` — perform_device_flow_step_up: token_user_str falls back to claims.sub

## Decisions Made

- Changed `BreakGlassAuth.severity` from `&'static str` to `String` to allow runtime selection. Marked `alert_on_use` field with `#[serde(skip)]` — it's a policy-mirroring flag for internal logic, not an additional JSON field consumers need.
- SBUG-01 uses `extract_iss_for_routing()` (already existed for multi-issuer routing) — safe because the function reads only the unauthenticated payload `iss` claim without signature verification, and that value is used only for audit attribution, not for any security decision.
- SBUG-03 sudo fallback: chose `sub` over an error ("no identity claim") because the caller already has a valid authenticated token — the appropriate behavior is graceful mismatch detection, not a separate error class.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## Next Phase Readiness

- Phase 24-02 (lint/clippy fixes) can proceed; these files are now clean
- Phase 25 hardening work has correct audit foundation (issuer attribution, severity)
- All 354 lib tests pass; `cargo clippy -D warnings` clean

---
*Phase: 24-phase-24-security-bug-fixes-lint-foundation*
*Completed: 2026-03-14*
