---
phase: 13-operational-hardening
plan: "03"
subsystem: unix-oidc-agent/daemon
tags: [ipc-hardening, peer-auth, idle-timeout, defense-in-depth]
dependency_graph:
  requires: ["13-02"]
  provides: [peer-credential-check, ipc-idle-timeout]
  affects: [unix-oidc-agent/src/daemon/socket.rs, unix-oidc-agent/src/daemon/peer_cred.rs]
tech_stack:
  added: []
  patterns:
    - SO_PEERCRED (Linux) / getpeereid(3) (macOS) for IPC peer authentication
    - tokio::time::timeout per-read idle timeout pattern
    - AgentServer builder method for configurable idle timeout
key_files:
  created:
    - unix-oidc-agent/src/daemon/peer_cred.rs
  modified:
    - unix-oidc-agent/src/daemon/mod.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - unix-oidc-agent/src/main.rs
decisions:
  - "idle_timeout stored in AgentServer as Duration field with with_idle_timeout() builder; default matches TimeoutsConfig default (60s); tests construct server with short timeout via builder"
  - "Per-read timeout (not per-connection total): tokio::time::timeout wraps each read_line call; resets after every successful request so active connections are never disconnected"
  - "main.rs captures ipc_idle_timeout_secs from AgentConfig::load() at Gate 2 and passes to AgentServer::with_idle_timeout(); fallback to 60s if config load fails"
metrics:
  duration_secs: 331
  completed_date: "2026-03-11"
  tasks_completed: 2
  files_changed: 4
---

# Phase 13 Plan 03: IPC Peer Authentication and Idle Timeout Summary

IPC peer authentication (SO_PEERCRED/getpeereid) and configurable per-read idle timeout added to the agent daemon's connection handling as defense-in-depth layers on top of existing 0600 socket file permissions.

## Tasks Completed

| Task | Name | Commit | Key Files |
|------|------|--------|-----------|
| 1 | Create peer_cred.rs with get_peer_credentials() | 9d4b369 | unix-oidc-agent/src/daemon/peer_cred.rs, daemon/mod.rs |
| 2 | Wire peer check into serve loop and add idle timeout | 20b0c91 | unix-oidc-agent/src/daemon/socket.rs, main.rs |

## What Was Built

### peer_cred.rs module

`get_peer_credentials(stream: &tokio::net::UnixStream) -> std::io::Result<(u32, Option<u32>)>` returns the peer's (uid, Option<pid>):

- **Linux**: `getsockopt(fd, SOL_SOCKET, SO_PEERCRED)` returns `ucred { pid, uid, gid }`; pid is `Some(ucred.pid as u32)`.
- **macOS**: `getpeereid(fd, &mut uid, &mut gid)` returns uid only; pid is `None` (getpeereid does not expose PID).
- **Other platforms**: `Err(ErrorKind::Unsupported)` — fail-closed per CLAUDE.md security invariant.

Three tests covering UID equality, same-process daemon UID matching, and platform PID behavior.

### Peer UID check in serve_with_listener

After `listener.accept()` succeeds, before spawning the handler task:

1. `get_peer_credentials(&stream)` called.
2. `Err` → WARN log "Peer credential retrieval failed — rejecting (fail-closed)", drop stream, continue.
3. `peer_uid != daemon_uid` → WARN log with both UIDs, drop stream, continue.
4. Match → DEBUG log with peer_pid if available (Linux only), proceed to spawn.

### Idle timeout in handle_connection

The `while reader.read_line` loop replaced with an explicit loop wrapping each `read_line` in `tokio::time::timeout(idle_timeout, ...)`:

- `Ok(Ok(0))` — EOF, clean break.
- `Ok(Ok(n))` — data received, continue.
- `Ok(Err(e))` — error, log + break.
- `Err(_elapsed)` — DEBUG "IPC connection closed: idle timeout", break.

The timeout is per-read, not per-connection total, so active clients are never disconnected.

### AgentServer builder and main.rs wiring

`AgentServer` gains:
- `idle_timeout: Duration` field (default 60s via `DEFAULT_IPC_IDLE_TIMEOUT_SECS`).
- `with_idle_timeout(self, Duration) -> Self` builder method.

`main.rs` captures `ipc_idle_timeout_secs` from `AgentConfig::load()` at Gate 2 and applies it via `.with_idle_timeout()`. Falls back to 60s if config load fails (non-fatal).

## Verification

- `cargo test -p unix-oidc-agent peer_cred::` — 3 tests pass (UID, daemon UID match, PID platform behavior)
- `cargo test -p unix-oidc-agent` — 147+2+1 tests pass; includes `test_idle_timeout_closes_silent_connection`
- `cargo clippy -p unix-oidc-agent` — clean (no warnings)

## Deviations from Plan

None — plan executed exactly as written.

## Self-Check: PASSED

- unix-oidc-agent/src/daemon/peer_cred.rs — FOUND
- unix-oidc-agent/src/daemon/socket.rs — FOUND
- Commit 9d4b369 (Task 1) — FOUND
- Commit 20b0c91 (Task 2) — FOUND
