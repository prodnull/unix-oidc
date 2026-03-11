---
phase: 13-operational-hardening
plan: 05
subsystem: infra
tags: [tracing, structured-logging, observability, dpop, ipc, systemd, journald, json]

# Dependency graph
requires:
  - phase: 13-03
    provides: handle_connection with idle_timeout, peer_pid extraction in serve loop
  - phase: 13-04
    provides: AgentServer with idle_timeout builder, metrics collector in AgentState

provides:
  - init_tracing() with JSON auto-detection via UNIX_OIDC_LOG_FORMAT and JOURNAL_STREAM
  - tracing-journald layer (Linux, best-effort) for structured sd-journal output
  - request-scoped ipc_request span with request_id UUID, command, peer_pid fields
  - #[instrument] on generate_dpop_proof, build_dpop_message, assemble_dpop_proof
  - GetProof INFO log with username, target, signer_type fields (OPS-13)
  - AgentRequest::command_name() for stable span field population
  - tracing-test verified test for GetProof INFO emission

affects: [future-ops-dashboards, log-aggregation, audit-trail, debugging]

# Tech tracking
tech-stack:
  added:
    - "tracing-subscriber json feature (0.3)"
    - "tracing-journald 0.3 (Linux-only cfg gate)"
    - "tracing-test 0.2 (dev-dep, test log capture)"
  patterns:
    - "JSON log auto-detect via UNIX_OIDC_LOG_FORMAT=json or JOURNAL_STREAM env vars"
    - "#[instrument(skip(key_material))] to prevent credential leakage in spans"
    - "tracing::field::Empty + Span::current().record() for deferred span field population"
    - "tracing-journald added best-effort; Err from layer() falls back to JSON-only"
    - "try_init() instead of init() to support multi-call in test harnesses"

key-files:
  created: []
  modified:
    - unix-oidc-agent/Cargo.toml
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/crypto/dpop.rs

key-decisions:
  - "init_tracing() uses try_init() — prevents double-registration panics in tests; consistent with RESEARCH.md Pitfall 6"
  - "tracing-journald gated to cfg(target_os = 'linux') — macOS builds do not link the journald socket library"
  - "peer_pid forwarded from serve loop to handle_connection via new parameter — avoids second get_peer_credentials() syscall"
  - "extract_jwk_from_proof() NOT instrumented — operates on untrusted input; adding spans could leak proof content"
  - "AgentRequest::command_name() returns &'static str — zero-allocation span field recording, stable across refactors"
  - "GetProof INFO log emitted before signer check so username/target are always visible even on not-logged-in errors"

patterns-established:
  - "IPC request tracing: every handle_connection invocation gets a UUID request_id for grep-based trace reconstruction"
  - "DPoP key material exclusion: signing_key and nonce always skipped in #[instrument] attributes"
  - "Structured operational log: GetProof INFO with username+target+signer_type enables per-request audit trail"

requirements-completed: [OPS-11, OPS-13]

# Metrics
duration: 8min
completed: 2026-03-11
---

# Phase 13 Plan 05: Structured Tracing Instrumentation Summary

**Structured tracing added across agent IPC and DPoP proof paths: request_id UUID spans, #[instrument] on all DPoP functions (skipping key material), GetProof INFO audit log, and JSON/journald output auto-detection via JOURNAL_STREAM.**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-11T12:30:19Z
- **Completed:** 2026-03-11T12:37:56Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Implemented `init_tracing()` with JSON auto-detection: `UNIX_OIDC_LOG_FORMAT=json` or `JOURNAL_STREAM` set activates JSON output; human-readable is the default for interactive sessions
- Added `tracing-journald` (Linux-only) as a best-effort layer composable alongside JSON formatter when `JOURNAL_STREAM` is set — maps tracing levels to syslog PRIORITY codes for `journalctl -p err` filtering
- Added request-scoped `ipc_request` span to `handle_connection` with `request_id` UUID, `command` (recorded after JSON parse), and `peer_pid` (forwarded from serve loop, no second syscall)
- Added `#[instrument]` to `generate_dpop_proof`, `build_dpop_message`, and `assemble_dpop_proof` — key material and nonces explicitly skipped in all three; spans inherit request context automatically
- Added `GetProof` INFO log with `username`, `target`, and `signer_type` fields for per-request operator audit trail (OPS-13)
- All 148 + 3 + 1 = 152 tests pass; clippy clean

## Task Commits

1. **Task 1: Add init_tracing() with JSON auto-detection and journald layer** - `2756766` (feat)
2. **Task 2: Add request-scoped spans, DPoP instrumentation, and GetProof INFO logging** - `02002a6` (feat)

## Files Created/Modified

- `unix-oidc-agent/Cargo.toml` - Added tracing-subscriber json feature, tracing-journald (Linux cfg), tracing-test dev-dep
- `unix-oidc-agent/src/main.rs` - Added `init_tracing()` with JSON auto-detect and journald compose; replaced manual init call; added no-panic test
- `unix-oidc-agent/src/daemon/socket.rs` - Added `#[instrument]` to `handle_connection` with request_id/command/peer_pid span fields; added GetProof INFO log; forwarded peer_pid from serve loop; added tracing-test verified test
- `unix-oidc-agent/src/daemon/protocol.rs` - Added `AgentRequest::command_name()` for stable span field population
- `unix-oidc-agent/src/crypto/dpop.rs` - Added `#[instrument]` to `generate_dpop_proof`, `build_dpop_message`, `assemble_dpop_proof` with appropriate key-material skip directives

## Decisions Made

- `try_init()` used throughout rather than `init()` — prevents double-registration panics when tests call `init_tracing()` multiple times in the same process
- `tracing-journald` gated to `cfg(target_os = "linux")` — the journald socket (`/run/systemd/journal/socket`) does not exist on macOS and the crate would fail to compile there
- `peer_pid` forwarded as a new parameter to `handle_connection` rather than calling `get_peer_credentials()` a second time — the serve loop already extracted it for the UID check
- `extract_jwk_from_proof()` deliberately NOT instrumented — it processes untrusted input and adding tracing spans could propagate attacker-controlled data into log fields
- `GetProof` INFO log is emitted unconditionally before the `signer.is_none()` check — this means the log appears even on NOT_LOGGED_IN errors, which is useful for diagnosing misconfigured clients

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

One minor clippy warning (`unneeded late initialization` for `accepted_peer_pid`) was fixed inline by collapsing the declaration into the `match` expression. No functional impact.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

Phase 13 operational hardening is now complete (plans 01-05). The agent has:
- Configurable timeouts (Plan 01)
- sd-notify readiness protocol (Plan 02)
- Hardware signer instrumentation (Plan 03)
- Idle timeout per IPC connection (Plan 04)
- Structured tracing with request correlation (Plan 05)

The agent is ready for production deployment with full observability via structured logs, systemd integration, and per-request trace correlation.

## Self-Check: PASSED

All expected files present. Both task commits verified in git history.

---
*Phase: 13-operational-hardening*
*Completed: 2026-03-11*
