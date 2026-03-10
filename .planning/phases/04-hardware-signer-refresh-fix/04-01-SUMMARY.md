---
phase: 04-hardware-signer-refresh-fix
plan: 01
subsystem: auth
tags: [dpop, hardware-signer, yubikey, tpm, token-refresh, bug-fix]

requires:
  - phase: 03-hardware-signer-backends
    provides: signer_type metadata field and load_agent_state() hardware signer reconstruction
provides:
  - signer_type preserved across token refresh in both run_refresh() and perform_token_refresh()
  - regression test proving signer_type survives refresh for all signer variants
affects: [hardware-signer-backends, dpop]

tech-stack:
  added: []
  patterns:
    - "Forward all metadata fields through refresh paths to prevent silent data loss"

key-files:
  created: []
  modified:
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/daemon/socket.rs

key-decisions:
  - "Test helper mirrors production metadata construction pattern rather than testing production function directly -- correct granularity for a JSON field-forwarding bug"

patterns-established:
  - "Refresh metadata must forward all fields from original metadata, not just the ones known at initial implementation time"

requirements-completed: [HW-01, HW-02, HW-06]

duration: 2min
completed: 2026-03-10
---

# Phase 04 Plan 01: Hardware Signer Refresh Fix Summary

**Fix signer_type field dropped during token refresh, preventing hardware signer fallback to software after refresh + restart**

## Performance

- **Duration:** 2 min
- **Started:** 2026-03-10T18:03:09Z
- **Completed:** 2026-03-10T18:04:43Z
- **Tasks:** 1
- **Files modified:** 2

## Accomplishments
- Fixed signer_type being dropped from stored metadata during token refresh in both `run_refresh()` (main.rs) and `perform_token_refresh()` (socket.rs)
- Added regression test covering YubiKey, TPM, software, and legacy (missing) signer_type cases
- All 98 tests pass (97 existing + 1 new), clippy clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Forward signer_type in both refresh paths and add regression test**
   - `c3c7fc3` (test: add regression test for signer_type preservation)
   - `fc8f0b2` (fix: preserve signer_type across token refresh in both paths)

## Files Created/Modified
- `unix-oidc-agent/src/main.rs` - Added `"signer_type": metadata["signer_type"]` to `run_refresh()` updated_metadata; added regression test module
- `unix-oidc-agent/src/daemon/socket.rs` - Added `"signer_type": metadata["signer_type"]` to `perform_token_refresh()` updated_metadata

## Decisions Made
- Test helper mirrors production metadata construction pattern rather than testing the production function directly -- correct granularity for a JSON field-forwarding bug, avoids needing network mocks

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
None

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Hardware signer users will now retain their DPoP hardware binding across token refreshes
- No blockers or concerns

---
*Phase: 04-hardware-signer-refresh-fix*
*Completed: 2026-03-10*
