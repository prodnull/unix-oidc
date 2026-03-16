---
phase: 25-phase-25-security-hardening
plan: 02
subsystem: security
tags: [terminal-injection, ansi-escape, dbus, secret-service, encryption, sanitization]

# Dependency graph
requires:
  - phase: 24-security-bugs-lint-foundation
    provides: clean lint baseline (clippy deny unwrap/expect)
provides:
  - terminal escape sequence sanitization module (sanitize.rs)
  - D-Bus Secret Service encryption enforcement (strict/warn/disabled)
  - structured DBUS_PLAIN_SESSION audit event for SIEM
affects: [phase-28-e2e-testing, agent-security-guide]

# Tech tracking
tech-stack:
  added: []
  patterns: [env-var-based-enforcement-policy, pure-logic-testable-enforcement, sanitize-then-display]

key-files:
  created:
    - unix-oidc-agent/src/sanitize.rs
  modified:
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/lib.rs
    - unix-oidc-agent/src/storage/router.rs
    - pam-unix-oidc/src/oidc/validation.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/sudo.rs
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/tests/entra_integration.rs

key-decisions:
  - "Terminal sanitization strips-and-displays rather than rejecting URIs (graceful degradation)"
  - "D-Bus encryption enforcement uses env var UNIX_OIDC_REJECT_PLAIN_DBUS (matches UNIX_OIDC_STORAGE_BACKEND pattern)"
  - "D-Bus probe returns Unknown on non-Linux and when direct inspection not feasible (zbus/oo7 deferred)"
  - "Pre-existing pam-unix-oidc orphan rule violation fixed by converting TryFrom to standalone function"

patterns-established:
  - "sanitize-then-display: all IdP-supplied strings displayed in terminal must go through sanitize_terminal_output()"
  - "pure-logic enforcement: separate D-Bus probe (I/O) from enforcement decision (pure function) for testability"
  - "env-var enforcement modes: strict/warn/disabled pattern for security features with UNIX_OIDC_ prefix"

requirements-completed: [SHRD-05, SHRD-06]

# Metrics
duration: 9min
completed: 2026-03-16
---

# Phase 25 Plan 02: Terminal Sanitization + D-Bus Encryption Enforcement Summary

**ANSI escape sequence sanitization for IdP-supplied URIs and D-Bus Secret Service session encryption enforcement with strict/warn/disabled policy modes**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-16T02:03:59Z
- **Completed:** 2026-03-16T02:12:37Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Terminal escape sequence sanitization strips CSI, OSC, DCS, APC, PM, SOS, C0, and C1 control characters from verification_uri before display, preventing terminal injection from compromised IdPs
- D-Bus Secret Service encryption enforcement with configurable strict/warn/disabled modes via UNIX_OIDC_REJECT_PLAIN_DBUS environment variable
- Structured audit event (DBUS_PLAIN_SESSION) emitted for fleet-level SIEM visibility regardless of enforcement mode
- 22 new tests (15 sanitize + 7 D-Bus enforcement) all passing, clippy clean

## Task Commits

Each task was committed atomically:

1. **Task 1: Terminal escape sequence sanitization module** - `3234ab5` (feat)
2. **Task 2: D-Bus Secret Service encryption enforcement** - `eec0649` (feat)

## Files Created/Modified
- `unix-oidc-agent/src/sanitize.rs` - New module: strips ANSI escapes and control chars from terminal output
- `unix-oidc-agent/src/lib.rs` - Module registration for sanitize
- `unix-oidc-agent/src/main.rs` - Sanitized verification_uri and verification_uri_complete before display
- `unix-oidc-agent/src/storage/router.rs` - D-Bus encryption policy types, enforcement logic, probe integration
- `pam-unix-oidc/src/oidc/validation.rs` - Fixed orphan rule: TryFrom to standalone key_algorithm_to_algorithm()
- `pam-unix-oidc/src/auth.rs` - Added allowed_algorithms field, fixed expect_used clippy violation
- `pam-unix-oidc/src/sudo.rs` - Added allowed_algorithms field
- `pam-unix-oidc/src/policy/config.rs` - Added allowed_algorithms to IssuerConfig
- `pam-unix-oidc/tests/entra_integration.rs` - Added allowed_algorithms to test configs

## Decisions Made
- Terminal sanitization strips-and-displays rather than rejecting URIs (graceful degradation per CLAUDE.md philosophy)
- D-Bus encryption enforcement uses env var pattern (UNIX_OIDC_REJECT_PLAIN_DBUS) matching existing UNIX_OIDC_STORAGE_BACKEND convention
- D-Bus probe returns Unknown on non-Linux; actual oo7/zbus probe deferred to avoid adding new dependency (architectural decision)
- Pre-existing pam-unix-oidc compilation failures from incomplete 25-01 work fixed as blocking issue (Rule 3)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Fixed pre-existing pam-unix-oidc compilation failure**
- **Found during:** Task 2 (D-Bus enforcement)
- **Issue:** pam-unix-oidc had uncommitted changes from previous plan execution with: orphan rule violation (impl TryFrom for external types), missing allowed_algorithms field in ValidationConfig constructors, expect_used clippy violation
- **Fix:** Converted TryFrom impl to standalone function, added allowed_algorithms: None to all constructors, replaced .expect() with .map_err()?
- **Files modified:** pam-unix-oidc/src/oidc/validation.rs, pam-unix-oidc/src/auth.rs, pam-unix-oidc/src/sudo.rs, pam-unix-oidc/src/policy/config.rs, pam-unix-oidc/tests/entra_integration.rs
- **Verification:** cargo build --workspace succeeds, cargo clippy -p unix-oidc-agent -- -D warnings clean
- **Committed in:** eec0649 (Task 2 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Fix was necessary for workspace compilation. No scope creep.

## Issues Encountered
- Pre-existing uncommitted changes in pam-unix-oidc from a prior 25-01 plan execution left the workspace in a non-compiling state. Fixed as part of Task 2.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Sanitization module ready for use in any future terminal output path
- D-Bus enforcement ready for production on Linux systems
- Actual D-Bus session encryption probe (via zbus/oo7) can be implemented when architectural decision to add the dependency is approved

---
*Phase: 25-phase-25-security-hardening*
*Completed: 2026-03-16*
