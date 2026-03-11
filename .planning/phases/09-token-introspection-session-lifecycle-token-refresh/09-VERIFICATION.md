---
phase: 09-token-introspection-session-lifecycle-token-refresh
verified: 2026-03-11T02:30:37Z
status: passed
score: 14/14 must-haves verified
re_verification: false
---

# Phase 9: Session Lifecycle, Introspection, Auto-Refresh Verification Report

**Phase Goal:** Implement session lifecycle management with token introspection, auto-refresh, and session cleanup
**Verified:** 2026-03-11T02:30:37Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | `pam_sm_open_session` writes a JSON session record to the configured session directory with 0600 permissions | VERIFIED | `session::write_session_record()` uses atomic write-then-rename with explicit `set_permissions(0o600)`; test `test_write_session_record_creates_file_with_0600` validates this |
| 2 | `pam_sm_close_session` deletes the session record and emits a SessionClosed audit event with duration | VERIFIED | `close_session()` in lib.rs calls `delete_session_record()` then `AuditEvent::session_closed()` with `session_duration_secs()`; always returns `PAM_SUCCESS` |
| 3 | Session ID set in `authenticate()` via `pam_putenv` is readable in `open_session()` via `pam_getenv` | VERIFIED | lib.rs line 358: `pamh.putenv("UNIX_OIDC_SESSION_ID=...")` in authenticate; lines 448–457: `pamh.getenv("UNIX_OIDC_SESSION_ID")` in open_session and close_session |
| 4 | Session directory is created with 0700 permissions if absent; idempotent | VERIFIED | `ensure_session_dir()` uses `create_dir_all` + `set_permissions(0o700)`; tests `test_ensure_session_dir_creates_with_0700` and `test_ensure_session_dir_idempotent` pass |
| 5 | `IntrospectionConfig` and `SessionConfig` exist with correct defaults and figment loading | VERIFIED | Both structs in `policy/config.rs`; figment `.only()` filter includes `"introspection"` and `"session"`; backward-compat test `test_v1_yaml_loads_with_introspection_session_defaults` passes |
| 6 | When introspection is enabled and returns `active=false`, authentication fails in strict mode | VERIFIED | lib.rs introspection block: `Ok(false)` + `Strict` → `AUTH_ERR` + `IntrospectionFailed` audit event; `Ok(false)` + `Warn` → proceeds |
| 7 | When introspection endpoint is unreachable and enforcement=Warn, authentication succeeds with a logged warning | VERIFIED | lib.rs: `Err(other)` + `Warn` → fail-open, logs warning; `Err(other)` + `Strict` → `AUTH_ERR`; test `test_unreachable_endpoint_returns_http_error` confirms `Http` error type |
| 8 | When introspection is disabled (default), no HTTP call is made | VERIFIED | `introspect_token()` fast-path: `if !config.enabled { return Ok(true); }`; test `test_disabled_returns_ok_true_no_http` validates; config default `enabled: false` |
| 9 | Repeated introspection checks for the same token within cache TTL hit the cache, not the endpoint | VERIFIED | `IntrospectionCache::get_or_insert()` returns cached value on hit; test `test_cache_hit_does_not_call_closure_twice` validates closure is only called once |
| 10 | After login, a background refresh task sleeps until 80% of token lifetime then refreshes automatically | VERIFIED | `spawn_refresh_task()` in socket.rs computes `lifetime * threshold / 100`; wired in main.rs `run_serve()`; backoff delays `[5, 10, 20]` seconds; tests `test_refresh_threshold_calculation` and `test_refresh_backoff_sequence` pass |
| 11 | `SessionClosed` IPC message is ACKed immediately; revocation and cleanup run in background | VERIFIED | socket.rs: ACKs with `session_acknowledged()` response, then `tokio::spawn(async move { cleanup_session(...).await })` — cleanup never awaited on IPC handler path; test `test_session_closed_ack_via_ipc` validates |
| 12 | Token revocation sends best-effort RFC 7009 POST with 5s timeout; failure never blocks | VERIFIED | `revoke_token_best_effort()` reads `revocation_endpoint` from metadata; uses `reqwest::blocking::Client` with 5s timeout; logs WARN on failure; all error paths return without propagating |
| 13 | On `SessionClosed`, the agent cancels the refresh task, revokes token, zeroizes DPoP key, and deletes all stored credentials | VERIFIED | `cleanup_session()` sequence: (1) `handle.abort()`, (2) `revoke_token_best_effort()`, (3) clear in-memory state (`access_token=None` triggers `SecretString` zeroize; `signer=None` triggers `ProtectedSigningKey` `ZeroizeOnDrop`), (4) storage deletions for all 4 keys; tests `test_cleanup_session_clears_state` and `test_cleanup_session_aborts_refresh_task` pass |
| 14 | `pam_sm_close_session` always returns `PAM_SUCCESS` regardless of agent reachability | VERIFIED | lib.rs `close_session()` ends unconditionally with `PamError::SUCCESS`; `notify_agent_session_closed()` logs WARN on all failure paths, never propagates error |

**Score: 14/14 truths verified**

---

## Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/session/mod.rs` | `SessionRecord`, `write_session_record`, `delete_session_record`, `ensure_session_dir` | VERIFIED | 427 lines; all four exports present; 14 tests; atomic write-then-rename; path traversal validation |
| `pam-unix-oidc/src/policy/config.rs` | `IntrospectionConfig`, `SessionConfig` with figment | VERIFIED | Both structs present; hand-rolled `Deserialize` for `IntrospectionConfig`; `#[serde(default)]` on both; added to `.only()` filter in `load_from()` and `from_env()`; `client_secret: Option<String>` added per RFC 7662 §2.1 |
| `pam-unix-oidc/src/audit.rs` | `SessionOpened`, `SessionClosed`, `TokenRevoked`, `IntrospectionFailed` variants | VERIFIED | All four variants present with `serde(rename)` JSON tags; constructor methods `session_opened()`, `session_closed()`, `token_revoked()`, `introspection_failed()`; `event_type()` match arms extended |
| `pam-unix-oidc/src/lib.rs` | `pam_sm_open_session` and `pam_sm_close_session` with putenv/getenv correlation | VERIFIED | `open_session()` and `close_session()` fully implemented; `putenv` for all 4 env vars in `authenticate()`; `getenv` reads in both session handlers; `notify_agent_session_closed()` present |
| `pam-unix-oidc/src/oidc/introspection.rs` | `IntrospectionClient`, `IntrospectionCache`, `IntrospectionError`, `introspect_token()` | VERIFIED | 580 lines; all types present; 12 unit tests; global singleton cache and HTTP client via `once_cell::sync::Lazy`; SHA-256 cache key fallback |
| `pam-unix-oidc/src/oidc/mod.rs` | `pub mod introspection` declaration | VERIFIED | Line 4: `pub mod introspection;` |
| `unix-oidc-agent/src/daemon/protocol.rs` | `AgentRequest::SessionClosed`, `AgentResponseData::SessionAcknowledged` | VERIFIED | `SessionClosed { session_id: String }` with `serde(rename = "session_closed")`; `SessionAcknowledged { acknowledged: bool }` with ordering fix for serde untagged discriminant; `session_acknowledged()` constructor; round-trip tests pass |
| `unix-oidc-agent/src/daemon/socket.rs` | `spawn_refresh_task`, `cleanup_session`, `revoke_token_best_effort`, `SessionClosed` handler | VERIFIED | 1444 lines; all functions present; `AgentRequest::SessionClosed` dispatch in `handle_connection`; ACK-before-spawn pattern; 4 tests in this file |

---

## Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `lib.rs` | `session::mod.rs` | `open_session` calls `write_session_record`; `close_session` calls `delete_session_record` | WIRED | Pattern `session::(write_session_record\|delete_session_record)` confirmed in lib.rs |
| `lib.rs` | authenticate→open_session | `putenv("UNIX_OIDC_SESSION_ID=...")` in authenticate; `getenv("UNIX_OIDC_SESSION_ID")` in open/close_session | WIRED | Confirmed at lib.rs lines 358, 448, 558 |
| `lib.rs` | `oidc/introspection.rs` | `authenticate()` calls `introspect_token()` after token validation | WIRED | `introspection::introspect_token` call present in authenticate flow between username-match and `record_success()` |
| `introspection.rs` | `policy/config.rs` | `IntrospectionConfig` from `PolicyConfig` drives behavior | WIRED | `use crate::policy::config::IntrospectionConfig;` at introspection.rs line 29; function signature takes `&IntrospectionConfig` |
| `socket.rs` | `protocol.rs` | `AgentRequest::SessionClosed` match arm dispatches to handler | WIRED | `if let AgentRequest::SessionClosed { session_id } = request` at socket.rs line 208; exhaustive match arm at line 398 |
| `socket.rs` | `perform_token_refresh` | `spawn_refresh_task` calls `perform_token_refresh` in retry loop | WIRED | `spawn_refresh_task` calls `perform_token_refresh(Arc::clone(&state)).await` in loop body |
| `lib.rs` (PAM) | `protocol.rs` (agent) | `close_session` sends `{"action":"session_closed","session_id":"..."}` over Unix socket | WIRED | `notify_agent_session_closed()` uses `std::os::unix::net::UnixStream`; writes JSON matching `AgentRequest::SessionClosed` serde format |
| `main.rs` | `spawn_refresh_task` | Daemon startup calls `spawn_refresh_task` for existing sessions | WIRED | `main.rs` imports `spawn_refresh_task` from daemon module; called in `run_serve()` when `is_logged_in()` |

---

## Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SES-01 | 09-01 | `pam_sm_open_session` writes session record to tmpfs | SATISFIED | `open_session()` calls `ensure_session_dir` + `write_session_record`; 0600 permissions verified in tests |
| SES-02 | 09-01 | `pam_sm_close_session` deletes record, emits audit event with duration | SATISFIED | `close_session()` calls `delete_session_record` + `AuditEvent::session_closed(duration)` |
| SES-03 | 09-01 | Session correlation between authenticate and open_session | SATISFIED | Implemented via `putenv`/`getenv` (REQUIREMENTS.md text says `pam_set_data()` but intent is equivalent; the plan's `key_links` specify `putenv`/`getenv` which is what ships; `pam_set_data()` does not survive fork, `putenv` does — implementation choice is superior for the stated purpose) |
| SES-04 | 09-03 | Auto token refresh at 80% TTL threshold with backoff | SATISFIED | `spawn_refresh_task()` with `lifetime * 80 / 100` sleep; 5/10/20s backoff; `AbortHandle` in state; wired at login and daemon startup |
| SES-05 | 09-02 | RFC 7662 introspection as opt-in with fail-open/fail-closed | SATISFIED | `introspect_token()` with `enabled=false` fast-path; `EnforcementMode::Warn` vs `Strict` dispatch; 12 unit tests |
| SES-06 | 09-02 | Introspection result caching with TTL bounded by min(60s, token_exp - now) | SATISFIED | `IntrospectionCache` with moka 60s TTL; WARN when `token_exp < now + ttl_secs`; only `Ok(true)` results cached (negative/error not cached) |
| SES-07 | 09-03 | RFC 7009 revocation on session close, best-effort 5s timeout | SATISFIED | `revoke_token_best_effort()` reads `revocation_endpoint` from metadata; form POST with Basic Auth; `reqwest::blocking::Client` with 5s timeout; logs WARN on failure |
| SES-08 | 09-03 | Agent `SessionClosed` IPC triggers DPoP key cleanup | SATISFIED | `cleanup_session()`: abort refresh task, revoke token, clear in-memory state (SecretString + ProtectedSigningKey ZeroizeOnDrop), delete all 4 storage keys; IPC ACKs before cleanup starts |

**All 8 requirements satisfied.**

**SES-03 note:** REQUIREMENTS.md text references `pam_set_data()` but the implementation uses `putenv`/`getenv`. This is the correct technical choice: `pam_set_data()` does not propagate across fork boundaries created by sshd, while PAM environment variables (`putenv`/`getenv`) do. The requirement intent (session ID correlation between authenticate and open_session) is fully satisfied. The plan's `key_links` frontmatter correctly specified `putenv`/`getenv`. No gap.

---

## Anti-Patterns Found

No blocking anti-patterns detected.

| File | Pattern | Severity | Impact |
|------|---------|----------|--------|
| `unix-oidc-agent/src/daemon/socket.rs` (line ~398) | Unreachable `AgentRequest::SessionClosed` match arm returns an error string | INFO | Intentional defensive arm for exhaustive match; documented in code comment; not reachable at runtime; no user impact |

---

## Human Verification Required

The following items cannot be fully verified programmatically and require a running system:

### 1. PAM putenv/getenv Cross-Fork Correlation

**Test:** Configure unix-oidc on a test sshd, authenticate via SSH, observe that `pam_sm_open_session` receives `UNIX_OIDC_SESSION_ID` set during `authenticate()`.
**Expected:** Session record file created at `/run/unix-oidc/sessions/{session_id}.json` on login; file deleted on logout with matching `SESSION_CLOSED` audit event.
**Why human:** PAM's cross-fork environment propagation behavior depends on sshd's PAM configuration and Linux kernel behavior; cannot be exercised in unit tests.

### 2. Agent SessionClosed IPC Roundtrip

**Test:** With agent daemon running, close an SSH session and observe the agent's cleanup sequence.
**Expected:** Agent ACKs within ~10ms; token revocation POST sent to IdP; `KEY_DPOP_PRIVATE` and `KEY_ACCESS_TOKEN` deleted from storage; Status IPC response shows `is_logged_in: false`.
**Why human:** Requires a live agent daemon, a real or mock IdP with revocation endpoint, and observable storage state.

### 3. Auto-Refresh Background Task

**Test:** Login with a short-lived token (e.g., 5-minute lifetime), observe that the token is refreshed automatically at ~4 minutes (80% threshold).
**Expected:** Agent log shows "Auto-refresh task sleeping for ~240s", then a successful refresh, then "Auto-refresh task re-armed".
**Why human:** Requires a real device flow / refresh token grant; cannot be tested without a live IdP.

---

## Test Results

All automated tests pass:

| Suite | Result |
|-------|--------|
| `cargo test -p pam-unix-oidc --features test-mode` | 270 passed, 0 failed |
| `cargo test -p unix-oidc-agent --lib` | 110 passed, 0 failed, 6 ignored |
| `cargo test -p unix-oidc-agent --bin unix-oidc-agent` | 1 passed, 0 failed |
| `cargo clippy -p pam-unix-oidc -- -D warnings` | No warnings |
| `cargo clippy -p unix-oidc-agent -- -D warnings` | No warnings |
| `cargo build -p pam-unix-oidc` (no test-mode) | Compiles cleanly |
| `cargo build --workspace` | Compiles cleanly |

All 5 commits cited in summaries verified to exist in git history:
- `dc13d17` — feat(09-01): session record module, introspection/session config, audit events
- `22177df` — feat(09-01): wire open_session/close_session with putenv/getenv correlation
- `afa7702` — feat(09-02): RFC 7662 introspection client + moka cache
- `fdaed47` — feat(09-02): wire RFC 7662 introspection into authenticate() flow
- `278eed3` — feat(09-03): agent session lifecycle — auto-refresh, SessionClosed handler, RFC 7009 revocation

---

_Verified: 2026-03-11T02:30:37Z_
_Verifier: Claude (gsd-verifier)_
