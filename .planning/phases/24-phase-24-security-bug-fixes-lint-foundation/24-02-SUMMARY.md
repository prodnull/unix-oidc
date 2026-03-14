---
phase: 24-phase-24-security-bug-fixes-lint-foundation
plan: "02"
subsystem: testing
tags: [clippy, lint, pam-unix-oidc, ci, debt]

requires:
  - phase: 24-phase-24-security-bug-fixes-lint-foundation/24-01
    provides: SBUG-01/02/03 security bug fixes in auth.rs, lib.rs, sudo.rs

provides:
  - Clippy-clean pam-unix-oidc crate — cargo clippy --all-targets --all-features -D warnings exits 0
  - CI check job unblocked — token-exchange job can now run
  - DEBT-01 verified closed — zero production unwrap/expect in all six named files

affects:
  - 24-phase-24-security-bug-fixes-lint-foundation/24-03
  - 25-phase-25 (inherits clean lint baseline)
  - 26-phase-26 (multi-IdP dead code removal requires clean lint baseline)

tech-stack:
  added: []
  patterns:
    - "Use struct literal + ..Default::default() instead of mut + field reassignment (field_reassign_with_default)"
    - "Use HashMap::contains_key() instead of .get().is_some()/.is_none() (unnecessary_get_then_check)"
    - "#[allow(dead_code)] on test-mode-only helper functions defined but not yet called in tests"

key-files:
  created: []
  modified:
    - pam-unix-oidc/tests/multi_idp_integration.rs
    - pam-unix-oidc/tests/entra_integration.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs

key-decisions:
  - "Dead test-mode helper functions (make_test_jwt_no_preferred_username, make_test_jwt_with_email_no_preferred_username) annotated with #[allow(dead_code)] rather than deleted — they are scaffolding for SBUG-03 tests not yet written"
  - "DEBT-01 verified via --lib target (excludes #[cfg(test)]) — crate-level deny at lib.rs:19 already enforces unwrap_used/expect_used for all future production code"

patterns-established:
  - "Struct literal pattern: PolicyConfig { issuers: vec![...], ..PolicyConfig::default() } replaces mut + reassignment throughout test helpers"

requirements-completed: [DEBT-01, DEBT-07]

duration: 15min
completed: "2026-03-14"
---

# Phase 24 Plan 02: Clippy Lint Fixes and DEBT-01 Verification Summary

**All clippy lint violations in pam-unix-oidc eliminated — cargo clippy --all-targets --all-features -D warnings now exits 0, unblocking the token-exchange CI job**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-03-14T03:05:00Z
- **Completed:** 2026-03-14T03:20:00Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments

- Fixed 10 `field_reassign_with_default` violations across 4 files by converting `mut default + field reassignment` to `struct literal + ..Default::default()`
- Fixed 1 `unnecessary_get_then_check` violation: `.get("...").is_none()` replaced with `!contains_key("...")`
- Suppressed 2 dead-code warnings on test-mode-only scaffold functions with `#[allow(dead_code)]`
- Confirmed DEBT-01 closed: `cargo clippy --lib -W clippy::unwrap_used -W clippy::expect_used` exits 0; crate-level deny at `lib.rs:19` enforces this for all future changes
- All 33 existing tests pass without regression

## Task Commits

1. **Task 1: Fix all field_reassign_with_default and unnecessary_get_then_check lint violations** - `00297e9` (fix)
2. **Task 2: Verify and document DEBT-01 production code cleanliness** - `7b20fba` (chore)

## Files Created/Modified

- `pam-unix-oidc/tests/multi_idp_integration.rs` - Fixed 6 field_reassign_with_default + 1 unnecessary_get_then_check
- `pam-unix-oidc/tests/entra_integration.rs` - Fixed 1 field_reassign_with_default
- `pam-unix-oidc/src/auth.rs` - Fixed 1 field_reassign_with_default in test module; added #[allow(dead_code)] to 2 scaffold functions
- `pam-unix-oidc/src/lib.rs` - Fixed 1 field_reassign_with_default in test module

## Decisions Made

- Dead test-mode helper functions (`make_test_jwt_no_preferred_username`, `make_test_jwt_with_email_no_preferred_username`) suppressed with `#[allow(dead_code)]` rather than deleted. They are SBUG-03 test scaffolding placed by Plan 24-01 for tests not yet written in this plan; deleting them would require re-adding in a future plan.
- No per-file `#![deny]` annotations added to the six DEBT-01 files — the crate-level deny at `pam-unix-oidc/src/lib.rs:19` (`#![deny(clippy::unwrap_used, clippy::expect_used)]`) already covers all production code. The test module at line 929 carries a matching `#[allow(clippy::unwrap_used, clippy::expect_used)]` for legitimate test use.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Dead code warnings on test-mode scaffold functions**
- **Found during:** Task 1 (running clippy to verify field_reassign fixes)
- **Issue:** Plan documented 10 field_reassign + 1 unnecessary_get_then_check errors. Clippy also emitted 2 dead-code errors for `make_test_jwt_no_preferred_username` and `make_test_jwt_with_email_no_preferred_username` in auth.rs (not listed in plan interfaces, likely added by Plan 24-01)
- **Fix:** Added `#[allow(dead_code)]` to both functions
- **Files modified:** `pam-unix-oidc/src/auth.rs`
- **Verification:** Clippy exits 0 after fix
- **Committed in:** `00297e9` (part of Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — clippy error discovered at execution time)
**Impact on plan:** Fix necessary to achieve exit-0 clippy goal. No scope creep.

## Issues Encountered

None — plan executed cleanly once actual line numbers from live clippy output were confirmed (slightly different from plan's predicted lines, but same patterns).

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- CI check job will now pass, unblocking `token-exchange` job
- Phase 24-03 (if exists) or Phase 25 can proceed with a clean lint baseline
- All six DEBT-01 files verified production-clean; crate-level deny prevents regression

---
*Phase: 24-phase-24-security-bug-fixes-lint-foundation*
*Completed: 2026-03-14*
