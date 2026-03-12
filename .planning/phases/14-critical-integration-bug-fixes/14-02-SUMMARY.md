---
phase: 14-critical-integration-bug-fixes
plan: "02"
subsystem: auth
tags: [ssh-askpass, dpop, oidc, pam, keyboard-interactive, tmpfile, ipc]

# Dependency graph
requires:
  - phase: 07-dpop-nonce-issuance
    provides: PAM conversation flow with DPOP_NONCE/DPOP_PROOF/OIDC Token prompts

provides:
  - unix-oidc-agent ssh-askpass subcommand handling all three PAM prompt types
  - PPID-keyed tmpfile state persistence across SSH_ASKPASS invocations
  - DPoP nonce round-trip: stores nonce from DPOP_NONCE prompt, passes it to GetProof IPC on DPOP_PROOF prompt
  - Token caching between DPOP_PROOF and OIDC Token rounds via tmpfile

affects:
  - phase 14 integration tests
  - end-to-end SSH login with dpop_required=Strict

# Tech tracking
tech-stack:
  added: []
  patterns:
    - SSH_ASKPASS stateless invocation model bridged via PPID-keyed tmpfiles
    - async entry point (run_ssh_askpass) with pure-logic helpers testable without IPC

key-files:
  created:
    - unix-oidc-agent/src/askpass.rs
  modified:
    - unix-oidc-agent/src/main.rs

key-decisions:
  - "PPID keying for tmpfiles: uses parent_id() (the ssh client process PID) so two concurrent SSH sessions from the same user do not collide"
  - "Token cached between DPOP_PROOF and OIDC Token rounds in a per-session tmpfile to avoid a second GetProof IPC call"
  - "0600 tmpfile permissions as defense-in-depth: nonce is not a secret but token is; both get restricted perms"
  - "Unrecognized prompts return empty line (safe default) rather than failing authentication"
  - "Missing nonce tmpfile on DPOP_PROOF: gracefully passes None to GetProof (fallback to nonce-less flow)"
  - "askpass.rs is a binary module (mod askpass in main.rs) not a library module; uses unix_oidc_agent:: path prefix for daemon types"

patterns-established:
  - "SSH_ASKPASS bridge pattern: stateless per-prompt process, state via PPID-keyed tmpfiles"
  - "Two-file state machine: nonce_path for round 1->2, token_path for round 2->3"

requirements-completed:
  - SEC-05

# Metrics
duration: 12min
completed: 2026-03-12
---

# Phase 14 Plan 02: ssh-askpass Subcommand Summary

**SSH_ASKPASS handler for PAM DPoP keyboard-interactive: PPID-keyed tmpfile bridge between DPOP_NONCE/DPOP_PROOF/OIDC Token prompts and GetProof IPC**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-12T00:21:20Z
- **Completed:** 2026-03-12T00:33:00Z
- **Tasks:** 1 (TDD: RED pass — compile errors, GREEN pass — 13/13 tests pass)
- **Files modified:** 2

## Accomplishments

- Implemented `unix-oidc-agent ssh-askpass <PROMPT>` subcommand that handles all three PAM keyboard-interactive prompt types
- DPOP_NONCE: stores server nonce to a PPID-keyed tmpfile with 0600 permissions; prints empty line to stdout
- DPOP_PROOF: reads and deletes nonce tmpfile, calls `AgentClient::get_proof()` IPC with nonce, caches returned token, prints dpop_proof
- OIDC Token: reads cached token tmpfile (from round 2) or falls back to GetProof IPC; prints token
- 13 unit tests covering permissions, PPID collision prevention, prompt parsing, tmpfile lifecycle

## Task Commits

1. **Task 1: Implement ssh-askpass subcommand with nonce handler** - `4464d2a` (feat)

## Files Created/Modified

- `unix-oidc-agent/src/askpass.rs` - SSH_ASKPASS handler module: prompt dispatch, tmpfile helpers, 13 unit tests
- `unix-oidc-agent/src/main.rs` - Added `mod askpass;`, `SshAskpass` variant in `Commands` enum, match arm in `main()`

## Decisions Made

- `askpass.rs` is a binary module (`mod askpass;` in `main.rs`) not a library module — it uses `AgentClient` which is already public in `unix_oidc_agent::daemon`, so no library changes needed
- Used `std::os::unix::process::parent_id()` for PPID (stable across all three SSH_ASKPASS invocations from the same ssh client process)
- Missing nonce tmpfile on DPOP_PROOF gracefully passes `None` to `get_proof()`, allowing the agent to generate a nonce-less proof rather than hard-failing
- Token tmpfile write failure is non-fatal (warn to stderr); round 3 falls back to another GetProof call

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed import path for daemon types in binary module**

- **Found during:** Task 1 (compilation — RED phase)
- **Issue:** `crate::daemon` does not resolve in `askpass.rs` because `crate` refers to the binary crate (`unix-oidc-agent`), not the library. `mod askpass` is wired into `main.rs`.
- **Fix:** Changed `use crate::daemon` to `use unix_oidc_agent::daemon` — the correct library crate path.
- **Files modified:** `unix-oidc-agent/src/askpass.rs`
- **Verification:** Compiled cleanly; 13 tests pass
- **Committed in:** `4464d2a` (Task 1 commit)

**2. [Rule 1 - Bug] Fixed type inference for get_proof() return**

- **Found during:** Task 1 (compilation — RED phase)
- **Issue:** Rust could not infer the return type for `.get_proof(...).await` in two call sites without an explicit type annotation.
- **Fix:** Added `let response: AgentResponse = ...` type annotation at both call sites.
- **Files modified:** `unix-oidc-agent/src/askpass.rs`
- **Verification:** Compiled cleanly; clippy clean
- **Committed in:** `4464d2a` (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 — compile errors discovered in RED phase, fixed in GREEN)
**Impact on plan:** Both fixes are necessary for compilation correctness. No scope creep. The plan's intended behavior was not changed.

## Issues Encountered

None beyond the two auto-fixed compile errors above.

## User Setup Required

To use the `ssh-askpass` subcommand for passwordless SSH with DPoP nonce binding:

```bash
export SSH_ASKPASS=unix-oidc-agent  # or full path to binary
export SSH_ASKPASS_REQUIRE=force
ssh user@host
```

No additional installation steps — the subcommand is part of the existing agent binary.

## Next Phase Readiness

- `unix-oidc-agent ssh-askpass` is fully implemented and tested
- End-to-end SSH login with `dpop_required=Strict` now has a complete client-side handler for the DPoP nonce round-trip
- Integration test coverage for the full SSH flow (PAM + agent + SSH_ASKPASS) is the recommended next gap

---
*Phase: 14-critical-integration-bug-fixes*
*Completed: 2026-03-12*
