---
phase: 17-p2-enhancements
plan: 02
subsystem: unix-oidc-agent/daemon
tags: [session-management, background-tasks, configuration, sweep]
requirements: [SES-09]

dependency_graph:
  requires: []
  provides:
    - sweep_interval_secs in TimeoutsConfig (UNIX_OIDC_TIMEOUTS__SWEEP_INTERVAL_SECS)
    - daemon/sweep.rs session_expiry_sweep_loop + sweep_expired_sessions
    - AgentServer.with_sweep_interval() + with_session_dir() builder chain
  affects:
    - unix-oidc-agent/src/config.rs (TimeoutsConfig)
    - unix-oidc-agent/src/daemon/mod.rs (module registration)
    - unix-oidc-agent/src/daemon/socket.rs (AgentServer builder fields + serve_with_listener spawn)
    - unix-oidc-agent/src/main.rs (Gate 2 config capture + AgentServer builder chain)

tech_stack:
  added: []
  patterns:
    - tokio::time::interval with skip-first-tick pattern for background loop
    - serde_json::Value for schema-independent field extraction (avoids cross-crate type dep)
    - Builder pattern with Option<T> fields for opt-in sweep configuration
    - ENOENT-as-success pattern for concurrent-delete race handling

key_files:
  created:
    - unix-oidc-agent/src/daemon/sweep.rs
  modified:
    - unix-oidc-agent/src/config.rs
    - unix-oidc-agent/src/daemon/mod.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/main.rs

decisions:
  - "sweep_expired_sessions parses session files as serde_json::Value (not SessionRecord) — avoids importing pam-unix-oidc types in the sweep function; resilient to schema evolution"
  - "sweep_interval minimum 60s validation in TimeoutsConfig::validate() — prevents I/O thrashing on active servers"
  - "AgentServer sweep fields default to None (opt-in) — existing tests are unaffected; sweep only activates when both sweep_interval and session_dir are Some"
  - "Skip first tick in session_expiry_sweep_loop — daemon startup I/O (credential loading + JWKS prefetch) is already heavy; first sweep deferred by one full interval"
  - "ENOENT from remove_file treated as success — concurrent PAM pam_sm_close_session delete is idempotent"

metrics:
  duration_minutes: 4
  completed_date: "2026-03-13"
  tasks_completed: 2
  files_modified: 5
---

# Phase 17 Plan 02: Session Expiry Sweep Summary

**One-liner:** Tokio background sweep task removes expired and corrupt session files from `/run/unix-oidc/sessions/` on a configurable 300s interval, preventing unbounded accumulation from crashed sshd workers.

## What Was Built

This plan implements SES-09: a safety-net sweep for orphaned session records.

Session records are created by `pam_sm_open_session` and removed by `pam_sm_close_session` via IPC. When an sshd worker crashes between open and close, the session file is orphaned. Without a sweep, `/run/unix-oidc/sessions/` grows without bound.

### sweep.rs

Two public entry points:

1. `session_expiry_sweep_loop(session_dir, interval)` — async Tokio task. Runs indefinitely, skipping the first tick (defers startup sweep), then calling `sweep_expired_sessions` on every subsequent tick.

2. `sweep_expired_sessions(session_dir)` — synchronous sweep. Iterates `.json` files; removes expired ones (`token_exp <= now`) and corrupt ones (invalid JSON or missing `token_exp`). Skips non-`.json` files and handles missing directory gracefully. ENOENT from `remove_file` is treated as success.

Session files are parsed as `serde_json::Value` rather than the full `SessionRecord` type — this avoids a hard dependency on pam-unix-oidc types in the sweep path and is resilient to schema changes.

### TimeoutsConfig extension

New field `sweep_interval_secs` (default 300, minimum 60). Configurable via:
- YAML: `timeouts: { sweep_interval_secs: 120 }`
- Env: `UNIX_OIDC_TIMEOUTS__SWEEP_INTERVAL_SECS=120`

Validation rejects values below 60 to prevent I/O thrashing.

### AgentServer wiring

Two new builder fields (`sweep_interval: Option<Duration>`, `session_dir: Option<PathBuf>`) and corresponding `with_sweep_interval()` / `with_session_dir()` methods. `serve_with_listener()` spawns the sweep loop when both are `Some`.

In `main.rs`, Gate 2 now captures the full `TimeoutsConfig` (not just `ipc_idle_timeout_secs`) and wires `sweep_interval_secs` + `/run/unix-oidc/sessions/` into the builder chain.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Add sweep_interval_secs + sweep.rs | 3c46f93 | config.rs, sweep.rs, daemon/mod.rs |
| 2 | Wire sweep into AgentServer + main.rs | 05de55a | socket.rs, main.rs |

## Test Coverage

9 unit tests (TDD) in `daemon/sweep::tests`:

1. `test_sweep_interval_default_300` — TimeoutsConfig default is 300
2. `test_removes_expired_session` — removes token_exp in the past
3. `test_skips_valid_session` — leaves token_exp in the future
4. `test_removes_corrupt_json` — invalid JSON removed with warning
5. `test_removes_json_missing_token_exp` — valid JSON but no token_exp field removed
6. `test_enoent_handled_gracefully` — remove_session_file on non-existent path: no panic
7. `test_ignores_non_json_files` — .lock and .tmp files untouched
8. `test_missing_directory_no_panic` — read_dir failure: warn and return, no panic
9. `test_env_override_sweep_interval` — UNIX_OIDC_TIMEOUTS__SWEEP_INTERVAL_SECS env override works

All 159 existing agent lib tests continue to pass.

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- sweep.rs: FOUND
- config.rs: FOUND
- socket.rs: FOUND
- main.rs: FOUND
- commit 3c46f93: FOUND
- commit 05de55a: FOUND
