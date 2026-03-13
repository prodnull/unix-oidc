---
phase: 17-p2-enhancements
plan: 03
subsystem: unix-oidc-agent/daemon, pam-unix-oidc/sudo
tags: [audit-events, observability, session-linking, siem, tracing]
requirements: [OBS-1, OBS-3]

dependency_graph:
  requires: [17-02]
  provides:
    - structured audit events with target "unix_oidc_audit" at 5 agent event points
    - parent_session_id field on AgentRequest::StepUp and AgentResponseData::StepUpComplete
    - parent_session_id read from UNIX_OIDC_SESSION_ID in PAM sudo.rs
    - PendingStepUp.parent_session_id field for session threading
    - StepUpOutcome::Complete.parent_session_id field for result propagation
  affects:
    - unix-oidc-agent/src/daemon/protocol.rs (StepUp, StepUpComplete, PendingStepUp, StepUpOutcome)
    - unix-oidc-agent/src/daemon/socket.rs (9 audit event emission points)
    - pam-unix-oidc/src/sudo.rs (parent_session_id read from env)

tech_stack:
  added: []
  patterns:
    - tracing::info!(target: "unix_oidc_audit", ...) for SIEM-parseable structured events
    - serde skip_serializing_if = Option::is_none + default for backward-compat optional fields
    - std::env::var("UNIX_OIDC_SESSION_ID") for best-effort parent session correlation

key_files:
  created: []
  modified:
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - pam-unix-oidc/src/sudo.rs

decisions:
  - "session_id='n/a' for GetProof and background refresh: pam_sm_open_session runs after auth; no session_id exists in agent at proof-issue time"
  - "username='n/a' for AGENT_SESSION_CLOSED: username is cleared before audit event emitted; session_id provides sufficient SIEM correlation"
  - "parent_session_id threaded through poll_ciba() as a new parameter; avoids PendingStepUp lookup in the inner async task"
  - "UNIX_OIDC_SESSION_ID read via std::env::var (best-effort, never fails auth): consistent with Phase 09 session correlation decision"
  - "9 audit event emission points cover all failure paths in GetProof plus 4 event types; redundancy is intentional for complete audit coverage"

metrics:
  duration_minutes: 8
  completed_date: "2026-03-13"
  tasks_completed: 2
  files_modified: 3
---

# Phase 17 Plan 03: Structured Audit Events + Sudo Session Linking Summary

**One-liner:** Nine structured `tracing::info!(target: "unix_oidc_audit")` events cover authentication, token refresh, session close, and step-up lifecycle; parent SSH session ID threads from PAM sudo through CIBA poll to `StepUpComplete` response for end-to-end SIEM correlation.

## What Was Built

This plan implements OBS-1 (structured audit events) and OBS-3 (sudo-to-SSH session linking).

### Audit Events (OBS-1)

Five logical event types across nine emission points in `socket.rs`:

| Event | Where Emitted | session_id | Notes |
|-------|---------------|------------|-------|
| `AGENT_AUTH` (failure: not logged in) | GetProof handler | `n/a` | Before session exists |
| `AGENT_AUTH` (failure: no token) | GetProof handler | `n/a` | Before session exists |
| `AGENT_AUTH` (failure: sign error) | GetProof handler | `n/a` | Before session exists |
| `AGENT_AUTH` (success) | GetProof handler | `n/a` | target field provides correlation |
| `AGENT_REFRESH` | spawn_refresh_task success | `n/a` | Background task |
| `AGENT_SESSION_CLOSED` | cleanup_session completion | PAM session_id | Full lifecycle coverage |
| `AGENT_STEP_UP` | handle_step_up after CIBA spawn | parent_session_id or `n/a` | Includes method |
| `AGENT_STEP_UP_COMPLETE` | handle_step_up_result | sudo_session_id | Both IDs included |
| `AGENT_STEP_UP_TIMED_OUT` | handle_step_up_result | parent_session_id or `n/a` | Reason included |

Every event includes: `event_type`, `session_id`, `username`, `outcome`. The `timestamp` field is provided automatically by the tracing-subscriber JSON layer configured in `main.rs`.

### Session Linking (OBS-3)

`parent_session_id` field added to three types in the IPC protocol:

1. `AgentRequest::StepUp` — PAM sends the SSH session ID when initiating step-up
2. `PendingStepUp` struct — stored in `AgentState.pending_step_ups` for duration of CIBA poll
3. `StepUpOutcome::Complete` — carried through `poll_ciba()` back to `handle_step_up_result`
4. `AgentResponseData::StepUpComplete` — echoed back in the IPC response for PAM-side audit

In `pam-unix-oidc/src/sudo.rs`, `perform_step_up_via_ipc()` reads `UNIX_OIDC_SESSION_ID` from the environment (set by `pam_sm_open_session` via PAM putenv) and includes it in the `StepUp` JSON. Absence is best-effort: a `debug!` log is emitted and `parent_session_id` is omitted from the JSON (backward compatible).

### Backward Compatibility

Both new fields use `#[serde(skip_serializing_if = "Option::is_none", default)]`:
- Old PAM clients that do not send `parent_session_id` deserialize correctly (field is `None`)
- Old agent versions that do not include `parent_session_id` in `StepUpComplete` deserialize correctly

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Add parent_session_id to StepUp IPC protocol | ffdff1e | protocol.rs, socket.rs, sudo.rs |
| 2 | Add structured audit events at five agent event points | ab4e3d1 | socket.rs |

## Test Coverage

Task 1 added 5 new serde round-trip tests in `protocol.rs`:
1. `test_step_up_without_parent_session_id_backward_compat` — backward compat (None)
2. `test_step_up_with_parent_session_id` — Some("abc-123")
3. `test_step_up_complete_with_parent_session_id_round_trip` — full round-trip
4. `test_step_up_complete_without_parent_session_id_backward_compat` — backward compat
5. `test_step_up_complete_still_discriminates_with_parent_session_id` — serde discriminant

All existing tests updated for new struct fields. Full workspace: **518 tests, 0 failures**.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing functionality] Nine emission points instead of five**
- **Found during:** Task 2
- **Issue:** GetProof has three distinct failure modes that should each emit an audit event (not logged in, no access token, sign error). Emitting only one would create audit gaps.
- **Fix:** Added 3 failure-path audit events in GetProof in addition to the success event.
- **Files modified:** unix-oidc-agent/src/daemon/socket.rs
- **Commit:** ab4e3d1

**2. [Rule 1 - Bug] username preservation in spawn_refresh_task**
- **Found during:** Task 2 (adding AGENT_REFRESH audit event)
- **Issue:** The existing code used `if let Some(u) = username` which moves `username` before it could be used for the audit event. Re-structured to use `if let Some(ref u) = username` and clone, preserving the value for the audit log.
- **Fix:** Changed to `ref u` pattern with `.clone()` to avoid move.
- **Files modified:** unix-oidc-agent/src/daemon/socket.rs
- **Commit:** ab4e3d1

## Self-Check: PASSED

- protocol.rs modified: FOUND
- socket.rs modified: FOUND
- sudo.rs modified: FOUND
- grep "unix_oidc_audit" socket.rs: 9 matches FOUND
- grep "parent_session_id" protocol.rs: 32 matches FOUND
- grep "parent_session_id" sudo.rs: 7 matches FOUND
- commit ffdff1e: FOUND
- commit ab4e3d1: FOUND
