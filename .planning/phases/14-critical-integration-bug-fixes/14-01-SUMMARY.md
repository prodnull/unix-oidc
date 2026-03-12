---
phase: 14-critical-integration-bug-fixes
plan: 01
subsystem: auth
tags: [dpop, pam, ipc, clock-skew, policy-config, socket, tokio]

# Dependency graph
requires:
  - phase: 13-operational-hardening
    provides: TimeoutsConfig, figment config wiring, session IPC scaffolding

provides:
  - SessionClosed IPC with trailing newline (BufReader::read_line compatible)
  - PamTimeoutsConfig struct with clock_skew_future_secs and clock_skew_staleness_secs
  - DPoPAuthConfig::from_policy() constructor reading clock skew from PolicyConfig.timeouts
  - ValidationConfig.clock_skew_tolerance_secs wired from PolicyConfig.timeouts in authenticate_with_dpop()
  - Safe HashMap::get in handle_step_up_result (let-else replaces unwrap)

affects:
  - 14-02-ssh-askpass
  - any phase that reads clock skew or issues SessionClosed IPC

# Tech tracking
tech-stack:
  added: []
  patterns:
    - DPoPAuthConfig::from_policy() is the canonical constructor for PAM auth paths; never use from_env()
    - PolicyConfig.timeouts is the single source of truth for clock skew values
    - IPC newline framing: always append \n after JSON payload to keep BufReader::read_line compatible
    - TOCTOU HashMap access: use let-else not unwrap when second lock may race with entry removal

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/oidc/validation.rs
    - unix-oidc-agent/src/daemon/socket.rs

key-decisions:
  - "DPoPAuthConfig::from_env() dead code removed; from_policy(&PolicyConfig) is the replacement — callers in lib.rs use struct update syntax (..DPoPAuthConfig::from_policy(&policy))"
  - "PamTimeoutsConfig.clock_skew_staleness_secs (default 60) maps to both DPoPAuthConfig.max_proof_age and ValidationConfig.clock_skew_tolerance_secs"
  - "TOCTOU guard in handle_step_up_result returns STEP_UP_CONSUMED (not NOT_FOUND) to distinguish the race case from an unknown ID"
  - "CLOCK_SKEW_TOLERANCE constant removed from validation.rs — all active paths use config.clock_skew_tolerance_secs"

patterns-established:
  - "Pattern: operator clock-skew is read from PolicyConfig.timeouts — never hardcoded in lib.rs or auth.rs"
  - "Pattern: let-else on HashMap::get at second lock in async functions — prevents TOCTOU panic"

requirements-completed:
  - SES-04
  - SES-07
  - SES-08
  - OPS-09

# Metrics
duration: 10min
completed: 2026-03-12
---

# Phase 14 Plan 01: Critical Integration Bug Fixes Summary

**SessionClosed IPC newline fix + PamTimeoutsConfig + clock skew wiring + socket.rs TOCTOU unwrap removal**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-12T00:00:58Z
- **Completed:** 2026-03-12T00:10:49Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Fixed SessionClosed IPC blocking: `notify_agent_session_closed()` now appends `\n` after JSON so the agent's `BufReader::read_line()` returns immediately instead of waiting for the 2s write timeout. Token revocation and DPoP key cleanup now trigger on every session close.
- Wired operator-configurable clock skew: `PamTimeoutsConfig` struct added to `PolicyConfig` with `clock_skew_future_secs=5` and `clock_skew_staleness_secs=60` defaults; values flow into both `DPoPAuthConfig` and `ValidationConfig` in the PAM auth path.
- Removed `DPoPAuthConfig::from_env()` dead code and replaced with `from_policy(&PolicyConfig)`, and removed the `#[allow(dead_code)] CLOCK_SKEW_TOLERANCE` constant from `validation.rs`.
- Fixed TOCTOU `unwrap()` panic in `handle_step_up_result()`: second `HashMap::get()` now uses `let-else` returning `STEP_UP_CONSUMED` error response.

## Task Commits

1. **Task 1: Fix SessionClosed IPC + PamTimeoutsConfig + clock skew wiring** - `cba886b` (fix/feat/chore)
2. **Task 2: Fix socket.rs unwrap() TOCTOU** - `9d9023c` (fix)

## Files Created/Modified

- `pam-unix-oidc/src/policy/config.rs` - Added `PamTimeoutsConfig` struct, `PolicyConfig.timeouts` field, `"timeouts"` in figment env filter
- `pam-unix-oidc/src/auth.rs` - Added `DPoPAuthConfig::from_policy()`, removed `from_env()`, wired `clock_skew_tolerance_secs` from policy in `authenticate_with_dpop()`
- `pam-unix-oidc/src/lib.rs` - `pam_sm_authenticate()` reads clock skew from `PolicyConfig.timeouts` via `from_policy()`; `notify_agent_session_closed()` appends `\n`
- `pam-unix-oidc/src/oidc/validation.rs` - Removed dead `CLOCK_SKEW_TOLERANCE` constant
- `unix-oidc-agent/src/daemon/socket.rs` - `handle_step_up_result()` second `HashMap::get()` uses `let-else`; added two TDD tests

## Decisions Made

- `DPoPAuthConfig::from_env()` dead code removed; `from_policy(&PolicyConfig)` is the replacement. Callers use struct update syntax: `..DPoPAuthConfig::from_policy(&policy)` to set target_host after.
- `PamTimeoutsConfig.clock_skew_staleness_secs` serves dual purpose: `DPoPAuthConfig.max_proof_age` (proof freshness window) and `ValidationConfig.clock_skew_tolerance_secs` (ID token clock tolerance). Same semantic: how stale a timestamp may be.
- TOCTOU guard returns `STEP_UP_CONSUMED` (not `NOT_FOUND`) at second `get()` to distinguish concurrent consumption from unknown correlation ID.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- `figment::providers::Yaml::string()` requires `use figment::providers::Format as _` trait import in test modules outside policy/config.rs. Fixed inline (Rule 3 — blocking compile error).
- `test_key_material_zeroed_after_drop` test in unix-oidc-agent has a pre-existing UB check failure (unsafe `ptr::copy_nonoverlapping` precondition). Confirmed pre-existing by stash/verify. Out of scope — deferred to `deferred-items.md`.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- IPC framing, clock skew config, and socket safety fixes complete.
- PAM module now reads all timing parameters from `policy.yaml` — operator can tune without rebuild.
- Phase 14-02 (ssh-askpass) was already completed; these fixes close the remaining Phase 14 items.

---
*Phase: 14-critical-integration-bug-fixes*
*Completed: 2026-03-12*
