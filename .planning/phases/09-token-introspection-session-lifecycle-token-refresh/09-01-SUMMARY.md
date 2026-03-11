---
phase: 09-token-introspection-session-lifecycle-token-refresh
plan: "01"
subsystem: pam-unix-oidc
tags: [session-lifecycle, audit, config, pam, session-records]
dependency_graph:
  requires: []
  provides: [session-record-infrastructure, introspection-config, session-config, session-audit-events]
  affects: [pam-unix-oidc/src/session/mod.rs, pam-unix-oidc/src/policy/config.rs, pam-unix-oidc/src/audit.rs, pam-unix-oidc/src/lib.rs, pam-unix-oidc/src/auth.rs]
tech_stack:
  added: []
  patterns:
    - atomic-write-then-rename for session records (O_WRONLY + rename(2))
    - PAM putenv/getenv for cross-fork session ID correlation
    - best-effort IPC via blocking std UnixStream (no tokio in PAM)
    - figment Serialized::defaults + .only() filter for backward-compat config sections
key_files:
  created:
    - pam-unix-oidc/src/session/mod.rs
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/audit.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/auth.rs
decisions:
  - "Session correlation via PAM putenv/getenv is best-effort: failure to set/read env vars logs WARN but never fails auth or session open/close"
  - "Session records are 0600 owner root; session directory is 0700 owner root — relies on sshd running as root during pam_sm_open_session"
  - "notify_agent_session_closed() uses blocking std::os::unix::net::UnixStream with 2s timeout — acceptable in PAM (no async runtime)"
  - "AuthResult gains token_exp: i64 and token_issuer: String to avoid re-parsing the token in open_session"
  - "IntrospectionConfig.enforcement defaults to Warn (not Strict) — Phase 02 will harden to Strict for new deployments with a policy migration note"
metrics:
  duration_secs: 428
  completed_date: "2026-03-11"
  tasks_completed: 2
  files_modified: 5
---

# Phase 9 Plan 01: Session Record Lifecycle Infrastructure Summary

Session record lifecycle infrastructure for the PAM module: atomic JSON session records (0600), IntrospectionConfig/SessionConfig with figment backward compat, four new audit event variants, and pam_sm_open_session/pam_sm_close_session implementations with cross-fork session ID correlation via PAM putenv/getenv.

## What Was Built

### Task 1: Config types + session record module + audit events

**pam-unix-oidc/src/session/mod.rs** (new, 300+ lines)
- `SessionRecord` struct: session_id, username, token_jti, token_exp, session_start, client_ip, sshd_pid, issuer — Serialize/Deserialize
- `ensure_session_dir(dir)` — create_dir_all + set_permissions 0o700, idempotent
- `write_session_record(dir, id, record)` — validate session_id (no `/`, `\0`, `..'`), write to `.json.tmp` with 0o600, rename atomically
- `delete_session_record(dir, id)` — read file, remove, return `Ok(Some(record))` or `Ok(None)` on NotFound
- `session_duration_secs(start)` — helper for close_session duration calculation
- Path traversal prevention: session IDs validated against `[a-zA-Z0-9_.-]` charset

**pam-unix-oidc/src/policy/config.rs** (modified)
- `IntrospectionConfig`: enabled (bool, default false), endpoint (Option<String>), enforcement (EnforcementMode, default Warn), cache_ttl_secs (u64, default 60). Hand-rolled Deserialize for strict rejection of invalid enforcement strings.
- `SessionConfig`: session_dir (String, default `/run/unix-oidc/sessions`), token_refresh_threshold_percent (u8, default 80). Derive Deserialize with `#[serde(default)]`.
- Both fields added to `PolicyConfig` with `#[serde(default)]`
- Added `"introspection"` and `"session"` to `.only()` filter in `load_from()` and `from_env()` Figment chains

**pam-unix-oidc/src/audit.rs** (modified)
- Added `SessionOpened { timestamp, session_id, username, client_ip, host, token_exp }`
- Added `SessionClosed { timestamp, session_id, username, host, duration_secs }`
- Added `TokenRevoked { timestamp, session_id, username, host, outcome, reason }`
- Added `IntrospectionFailed { timestamp, session_id, username, host, reason, enforcement }`
- Constructor methods: `session_opened()`, `session_closed()`, `token_revoked()`, `introspection_failed()`
- Extended `event_type()` match arms with all four new variants

### Task 2: Wire open_session and close_session

**pam-unix-oidc/src/lib.rs** (modified)
- `authenticate()`: after successful auth, set `UNIX_OIDC_SESSION_ID`, `UNIX_OIDC_TOKEN_JTI`, `UNIX_OIDC_TOKEN_EXP`, `UNIX_OIDC_ISSUER` via `pam_putenv`. Best-effort WARN on failure — never fails auth.
- `open_session()`: reads session ID from PAM env, reads username/token metadata/client_ip, calls `ensure_session_dir` + `write_session_record`, emits `SessionOpened` audit event. All errors WARN, returns SUCCESS.
- `close_session()`: reads session ID from PAM env, calls `delete_session_record` to get duration, emits `SessionClosed` audit event, calls `notify_agent_session_closed()`. Always returns SUCCESS.
- `notify_agent_session_closed()`: blocking `std::os::unix::net::UnixStream` connect to `UNIX_OIDC_AGENT_SOCKET` (or XDG_RUNTIME_DIR fallback), 2s read/write timeout, sends `{"action":"session_closed","session_id":"..."}`, reads ACK. All errors WARN.

**pam-unix-oidc/src/auth.rs** (modified)
- `AuthResult` gains two new fields: `token_exp: i64` and `token_issuer: String`
- Both `authenticate_with_token()`, `authenticate_with_dpop()`, and `authenticate_with_config()` populate these from `claims.exp` and `claims.iss`

## Verification Results

```
cargo test -p pam-unix-oidc --features test-mode  → 258 passed, 0 failed
cargo clippy -p pam-unix-oidc -- -D warnings      → Finished (no warnings)
cargo build -p pam-unix-oidc                       → Finished (no test-mode)
```

## Commits

| Task | Commit | Description |
|------|--------|-------------|
| 1    | dc13d17 | feat(09-01): session record module, introspection/session config, audit events |
| 2    | 22177df | feat(09-01): wire open_session/close_session with putenv/getenv correlation |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] AuthResult missing token_exp and token_issuer fields**
- **Found during:** Task 2
- **Issue:** The plan required storing token_exp and token_issuer in PAM env vars in `authenticate()`, but `AuthResult` (returned by the auth functions) did not expose `token_exp` or `token_issuer` — these live in `TokenClaims` which is local to `authenticate_with_token/dpop`. Storing them via `result.token_exp` in `lib.rs` required adding the fields to `AuthResult`.
- **Fix:** Added `token_exp: i64` and `token_issuer: String` to `AuthResult`; updated all three construction sites in `auth.rs` (authenticate_with_token, authenticate_with_dpop, authenticate_with_config) plus two test construction sites.
- **Files modified:** pam-unix-oidc/src/auth.rs
- **Commit:** 22177df

## Self-Check: PASSED

- session/mod.rs: FOUND
- policy/config.rs: FOUND
- audit.rs: FOUND
- commit dc13d17: FOUND
- commit 22177df: FOUND
