---
phase: 09-token-introspection-session-lifecycle-token-refresh
plan: "03"
subsystem: unix-oidc-agent
tags: [session-lifecycle, token-refresh, rfc7009, revocation, dpop, ipc, background-task]
dependency_graph:
  requires:
    - phase: 09-01
      provides: session-record-infrastructure, PAM close_session that sends SessionClosed IPC
  provides:
    - session-closed-ipc-handler
    - background-auto-refresh-task
    - rfc7009-revocation-best-effort
    - credential-cleanup-on-session-close
  affects:
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/daemon/mod.rs
    - unix-oidc-agent/src/main.rs
tech_stack:
  added: []
  patterns:
    - ACK-before-cleanup: SessionClosed IPC ACKs immediately, spawns tokio::spawn for cleanup
    - exponential-backoff: 5s/10s/20s delays for token refresh retries (4 total attempts)
    - refresh-threshold: sleep = token_lifetime * threshold_percent / 100 before refresh attempt
    - fire-and-forget revocation: RFC 7009 POST with 5s timeout, logged at WARN on failure
    - AbortHandle stored in AgentState for cancellation at session close
key_files:
  created: []
  modified:
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/daemon/mod.rs
    - unix-oidc-agent/src/main.rs
key_decisions:
  - "SessionAcknowledged placed before Ok{} in untagged AgentResponseData enum — acknowledged:bool discriminant prevents serde from matching Ok{} first during deserialization"
  - "cleanup_session() reads a fresh StorageRouter per invocation — cleanup is not performance critical and avoids holding a handle across the async cleanup lifetime"
  - "spawn_refresh_task() exported as pub from daemon module; cleanup_session() remains private — cleanup is only invoked from handle_connection in the same file"
  - "revocation_endpoint extracted from OIDC discovery at login and preserved across token refresh in metadata JSON — cleanup_session() reads it without requiring a re-discovery call"
  - "refresh_failed flag in AgentState surfaced in Status IPC response only when true — backward compat: existing callers that don't handle the field are unaffected"

requirements-completed: [SES-04, SES-07, SES-08]

duration: 10min
completed: "2026-03-11"
---

# Phase 9 Plan 03: Agent Session Lifecycle Summary

**Background token auto-refresh (80% threshold, 5/10/20s backoff), SessionClosed IPC with immediate ACK + background RFC 7009 revocation, and full credential cleanup (abort refresh task, zeroize DPoP key, delete stored credentials).**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-11T02:23:06Z
- **Completed:** 2026-03-11T02:26:26Z
- **Tasks:** 2 (combined into single commit, TDD pattern)
- **Files modified:** 4

## Accomplishments

- `spawn_refresh_task()`: calculates sleep as `(token_lifetime * 80 / 100)` seconds, retries on failure with 5s/10s/20s exponential backoff (4 total attempts), sets `refresh_failed=true` after exhausting retries, re-arms on success with new token expiry. Wired into `run_serve()` so daemon restart picks up existing sessions.
- `cleanup_session()`: cancels refresh task via AbortHandle, sends RFC 7009 revocation (best-effort, 5s timeout), clears in-memory state (SecretString zeroizes on drop, Arc drop triggers ProtectedSigningKey ZeroizeOnDrop), deletes all stored credentials via StorageRouter.
- `revoke_token_best_effort()`: reads `revocation_endpoint` from `KEY_TOKEN_METADATA`, sends Basic Auth form POST, logs WARN on any failure, never panics.
- `SessionClosed` IPC: ACKs with `SessionAcknowledged` before spawning background cleanup — PAM `pam_sm_close_session` returns within the IPC roundtrip time (not blocked by revocation/storage).
- `revocation_endpoint` stored in token metadata at login (from OIDC discovery) and preserved across token refresh.
- `refresh_failed: Option<bool>` added to Status IPC response (backward compat, omitted when None).

## Task Commits

1. **Tasks 1 + 2: IPC protocol + auto-refresh + SessionClosed handler** — `278eed3` (feat)

## Files Created/Modified

- `unix-oidc-agent/src/daemon/protocol.rs` — Added `AgentRequest::SessionClosed`, `AgentResponseData::SessionAcknowledged`, `refresh_failed` in Status, `session_acknowledged()` and `status_with_refresh_failed()` constructors
- `unix-oidc-agent/src/daemon/socket.rs` — Added `refresh_task`/`refresh_failed` to AgentState, `spawn_refresh_task()`, `revoke_token_best_effort()`, `cleanup_session()`, SessionClosed dispatch in `handle_connection`, Status arm updated to include `refresh_failed`
- `unix-oidc-agent/src/daemon/mod.rs` — Export `spawn_refresh_task`
- `unix-oidc-agent/src/main.rs` — Wire `spawn_refresh_task` in `run_serve()`, store `revocation_endpoint` in token metadata at login, handle `refresh_failed` in status display

## Decisions Made

- `SessionAcknowledged { acknowledged: bool }` placed before `Ok {}` in the untagged enum: `bool` field acts as discriminant so serde's untagged deserializer doesn't collapse it into `Ok {}`.
- `cleanup_session` is module-private (only called from `handle_connection`); `spawn_refresh_task` is `pub` so `main.rs` can call it at daemon startup.
- `revocation_endpoint` round-trips through token metadata (login → metadata JSON → refresh preserves it → cleanup reads it) without needing a re-discovery call at session close.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] SessionAcknowledged/Ok{} serde collision in untagged enum**
- **Found during:** Task 1 TDD GREEN (test_session_acknowledged_response_serialization failing)
- **Issue:** Both `Ok {}` and `SessionAcknowledged {}` serialize to `{}` in serde untagged. Deserialization always matched `Ok {}` first.
- **Fix:** Added `acknowledged: bool` discriminant field to `SessionAcknowledged`; reordered variant before `Ok {}` so serde matches on the required field.
- **Files modified:** unix-oidc-agent/src/daemon/protocol.rs
- **Verification:** Round-trip test passes; Ok{} still deserializes correctly from `{}`
- **Committed in:** 278eed3

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug)
**Impact on plan:** Required for correct IPC round-trip. No scope creep.

## Issues Encountered

- Pre-existing test `test_key_material_zeroed_after_drop` aborts with UB precondition error when run alongside the full test suite (SIGABRT). Runs fine in isolation — out of scope for this plan.

## Next Phase Readiness

- SES-04, SES-07, SES-08 satisfied: auto-refresh, revocation, full cleanup on SessionClosed
- Phase 09-04 (token introspection) can proceed — session infrastructure is complete
- `revocation_endpoint` now available in token metadata for any future introspection integration

---
*Phase: 09-token-introspection-session-lifecycle-token-refresh*
*Completed: 2026-03-11*
