---
phase: 01-memory-protection-hardening
plan: "02"
subsystem: unix-oidc-agent/daemon
tags: [memory-protection, secrecy, secret-string, process-hardening, prctl, mlock]
dependency_graph:
  requires: [ProtectedSigningKey, MlockStatus, mlock_probe]
  provides: [SecretString-access_token, disable_core_dumps, mlock_status-reporting]
  affects: [unix-oidc-agent/src/daemon/socket.rs, unix-oidc-agent/src/main.rs, unix-oidc-agent/src/daemon/protocol.rs]
tech_stack:
  added:
    - "secrecy 0.10 (SecretString alias for Secret<String>; [REDACTED] Debug formatting)"
  patterns:
    - "SecretString wrapping at acquisition time (parse response -> wrap -> never unwrap except at audit boundary)"
    - "expose_secret() called only at two explicit audit boundaries: storage write, SSH client response"
    - "Process hardening at daemon startup before key material loaded"
    - "mlock_status propagated from probe result to AgentState to status response"
key_files:
  created:
    - unix-oidc-agent/src/security.rs
  modified:
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/storage/secure_delete.rs
decisions:
  - "SecretString (type alias for Secret<String>) used over Secret<String> directly — linter preference, semantically identical"
  - "Manual Debug impl for AgentState rather than derive — Arc<dyn DPoPSigner> is not Debug, manual impl allows signer thumbprint in debug output"
  - "mlock_status stored as Option<String> (human-readable) in AgentState — avoids coupling protocol to MlockStatus enum; agent formats it once at startup"
  - "disable_core_dumps placed in security.rs module — clean separation from crypto concerns, grep-able location"
metrics:
  duration: "9m"
  completed_date: "2026-03-10"
  tasks_completed: 1
  tasks_total: 1
  files_modified: 4
  files_created: 2
requirements_completed: [MEM-01]
---

# Phase 1 Plan 2: Secret<String> Token Wrapping and Process Hardening Summary

SecretString wrapping for access_token (MEM-03) with [REDACTED] Debug output, disable_core_dumps() at daemon startup (prctl/PT_DENY_ATTACH), and mlock probe status surfaced in `unix-oidc-agent status`.

## What Was Built

Single TDD task (RED-GREEN cycle):

### security.rs (new module)

`unix-oidc-agent/src/security.rs` providing `disable_core_dumps()`:

- `#[cfg(target_os = "linux")]`: `libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0)` — marks process non-dumpable, prevents `/proc/PID/mem` access. Logs result at INFO (success) or WARN (failure).
- `#[cfg(target_os = "macos")]`: `libc::ptrace(libc::PT_DENY_ATTACH, 0, null, 0)` — prevents debugger attach and core dump generation. Logs result at INFO (success) or WARN (failure).
- `#[cfg(not(any(...))]`: logs WARN that platform is unsupported.
- Best-effort: never panics or returns error. Daemon continues regardless.

### AgentState: SecretString access_token field

`unix-oidc-agent/src/daemon/socket.rs`:

- `access_token` field type changed: `Option<String>` → `Option<SecretString>`
- Added `mlock_status: Option<String>` field for daemon startup probe result
- Manual `Debug` impl: signer shown as thumbprint (String), access_token shows `[REDACTED]` via `SecretString`'s `Debug`
- `GetProof` handler: `t.expose_secret().to_string()` — the ONLY place raw token leaves `AgentState`, going to SSH client
- `perform_token_refresh()` return type changed: `(String, ...)` → `(SecretString, ...)` — token wrapped immediately after parse
- Status handler: passes `mlock_status.clone()` to `AgentResponse::status()`

### Protocol: mlock_status in Status response

`unix-oidc-agent/src/daemon/protocol.rs`:

- `AgentResponseData::Status` gains `mlock_status: Option<String>` with `#[serde(skip_serializing_if = "Option::is_none")]`
- `AgentResponse::status()` constructor gains `mlock_status` parameter

### main.rs: startup hardening + SecretString wrapping

`unix-oidc-agent/src/main.rs`:

- `run_serve()`: calls `disable_core_dumps()` then `mlock_probe()` before `load_agent_state()`. Probe result formatted into `mlock_status_str` and stored in `AgentState.mlock_status`.
- `run_login()`: `access_token` wrapped in `SecretString::from(...)` immediately after IdP response parse; `expose_secret()` for storage write
- `run_refresh()`: same pattern — `SecretString::from(...)` at acquisition; `expose_secret()` for storage write
- `load_agent_state()`: `access_token_raw` (plain String) used for username extraction, then `access_token_raw.map(SecretString::from)` wraps it before storing in `AgentState`
- `run_status()`: pattern-match on `AgentResponseData::Status` now includes `mlock_status`; printed as `Memory protection: {mem}`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Clippy] Pre-existing `clippy::ptr_arg` in secure_delete.rs**

- **Found during:** Clippy verification pass
- **Issue:** `fn overwrite_pass(buf: &mut Vec<u8>, ...)` — Clippy -D warnings fails on this because `&mut Vec<u8>` should be `&mut [u8]`. This was introduced in Plan 01 in `secure_delete.rs`.
- **Fix:** Changed parameter type to `&mut [u8]` — semantically identical for all callers (Vec coerces to slice).
- **Files modified:** `unix-oidc-agent/src/storage/secure_delete.rs`
- **Commit:** 9517c0a

**2. [Rule 1 - Adaptation] Linter preferred `SecretString` over `Secret<String>`**

- **Found during:** Implementation
- **Issue:** The rust-analyzer linter replaced `Secret` with `SecretString` (the type alias). `SecretString = Secret<String>` — semantically identical.
- **Fix:** Adopted `SecretString` consistently throughout. Plan spec said `Secret<String>`, but `SecretString` is the idiomatic alias in secrecy 0.10.
- **Files modified:** socket.rs, main.rs

**3. [Rule 2 - Design] `#[derive(Debug)]` not possible on AgentState**

- **Found during:** Adding Debug test for redaction verification
- **Issue:** `AgentState` has `Arc<dyn DPoPSigner>` where `DPoPSigner` trait doesn't bound `Debug`. `#[derive(Debug)]` would fail to compile.
- **Fix:** Implemented manual `Debug` for `AgentState`. The manual impl shows signer as `thumbprint()` string, `access_token` delegates to `SecretString`'s `Debug` (emits `[REDACTED]`), and all other fields use standard `Debug`. This is strictly better than derive — shows more useful signer info.
- **Files modified:** `unix-oidc-agent/src/daemon/socket.rs`
- **Commit:** 9517c0a

## Verification Results

```
cargo build -p unix-oidc-agent              clean (0 warnings)
cargo test -p unix-oidc-agent               62 passed, 2 ignored (keychain), 0 failed
cargo clippy -p unix-oidc-agent -D warnings clean
```

grep checks (plan verification criteria):
- No unwrapped String for access_token in AgentState: confirmed (`grep -n "access_token.*String" socket.rs | grep -v SecretString` returns empty)
- prctl/PT_DENY_ATTACH in security.rs: confirmed
- disable_core_dumps called in run_serve: confirmed (line 158, main.rs)
- mlock_probe called in run_serve: confirmed (line 162, main.rs)
- expose_secret() at storage write boundaries only (grep shows 2 in main.rs, 2 in socket.rs — all at storage write or SSH client send)

## Self-Check: PASSED

Files verified:
- unix-oidc-agent/src/security.rs FOUND
- unix-oidc-agent/src/daemon/socket.rs FOUND
- unix-oidc-agent/src/daemon/protocol.rs FOUND
- unix-oidc-agent/src/main.rs FOUND

Commits verified:
- 1968219 test(01-02): add RED tests for Secret<String> wrapping, core dump disabling, mlock status FOUND
- 9517c0a feat(01-02): wrap tokens in SecretString, add process hardening, mlock status reporting FOUND
