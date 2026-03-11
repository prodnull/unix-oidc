---
phase: 13-operational-hardening
plan: "02"
subsystem: daemon-lifecycle
tags: [systemd, socket-activation, sd-notify, graceful-shutdown, listenfd, signal-handling]

requires:
  - phase: 13-operational-hardening
    plan: "01"
    provides: TimeoutsConfig, figment-based AgentConfig::load(), JwksProvider::with_timeouts()

provides:
  - acquire_listener() with systemd LISTEN_FDS activation and standalone fallback
  - AgentServer::serve_with_listener() accepting pre-bound UnixListener
  - SIGTERM/SIGINT graceful shutdown with 5s drain + credential cleanup
  - sd-notify READY=1 after socket + config + JWKS prefetch gates
  - run_credential_cleanup() for daemon-shutdown zeroization + best-effort revocation
  - systemd user service + socket unit files in contrib/systemd/

affects:
  - 13-03 (IPC peer credential check and idle timeout build on serve_with_listener pattern)
  - 13-04 (launchd placeholder in acquire_listener() at cfg(target_os = "macos") step 2)

tech-stack:
  added:
    - listenfd 1.0 (LISTEN_FDS/LISTEN_PID socket activation with fd-hijacking protection)
    - sd-notify 0.5 (READY=1/STOPPING=1 pure-Rust no libsystemd FFI)
  patterns:
    - Signal handlers registered BEFORE accept loop (prevents missed signals during startup)
    - tokio::select! races accept() against sigterm.recv()/sigint.recv()
    - sd-notify no-ops gracefully when NOTIFY_SOCKET absent (standalone mode safe)
    - acquire_listener priority: systemd → launchd (placeholder) → standalone bind

key-files:
  created:
    - contrib/systemd/unix-oidc-agent.service — Type=notify user service with all hardening directives
    - contrib/systemd/unix-oidc-agent.socket — ListenStream=%t/unix-oidc-agent.sock SocketMode=0600
  modified:
    - unix-oidc-agent/Cargo.toml — listenfd 1.0, sd-notify 0.5 added
    - unix-oidc-agent/src/daemon/socket.rs — acquire_listener(), serve_with_listener(), graceful shutdown, run_credential_cleanup(), 2 new tests
    - unix-oidc-agent/src/daemon/mod.rs — acquire_listener re-exported
    - unix-oidc-agent/src/main.rs — sd-notify readiness gates, println! replaced, JWKS prefetch, serve_with_listener call

key-decisions:
  - "sd-notify 0.5 API takes &[NotifyState] only (no bool arg) — research docs referenced older API; fixed during build"
  - "acquire_listener() exported from daemon mod.rs so main.rs can call it directly for the sd-notify gate ordering"
  - "run_credential_cleanup() is shutdown-specific (no stored credential deletion) — avoids wiping keyring on each restart; SessionClosed IPC and logout CLI handle full deletion"
  - "libc::kill(SIGTERM to self) in Shutdown IPC handler routes through graceful shutdown path instead of abrupt process::exit(0)"
  - "JWKS prefetch is best-effort: issuer must be non-empty and JwksProvider::refresh_jwks() success/failure both allow READY=1"

requirements-completed: [OPS-01, OPS-02, OPS-04]

duration: 8min
completed: "2026-03-11"
---

# Phase 13 Plan 02: systemd User Service Integration Summary

**systemd socket activation (listenfd LISTEN_FDS), sd-notify READY=1 with three readiness gates, SIGTERM/SIGINT graceful 5s-drain shutdown, and hardened contrib/systemd unit files**

## Performance

- **Duration:** ~8 min
- **Started:** 2026-03-11T12:12:58Z
- **Completed:** 2026-03-11T12:20:35Z
- **Tasks:** 2
- **Files modified:** 6 (2 created, 4 modified)

## Accomplishments

- Created `contrib/systemd/unix-oidc-agent.socket` with `ListenStream=%t/unix-oidc-agent.sock` and `SocketMode=0600`
- Created `contrib/systemd/unix-oidc-agent.service` with `Type=notify`, full hardening directives (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome=read-only`, `MemoryDenyWriteExecute`, `RestrictNamespaces`, `RestrictRealtime`, `RestrictSUIDSGID`, `PrivateTmp`, `SystemCallFilter=@system-service @network-io`), `ReadWritePaths` for file storage backend, and PKCS#11 advisory comment
- Added `listenfd 1.0` + `sd-notify 0.5` to `unix-oidc-agent/Cargo.toml`
- Implemented `acquire_listener()`: systemd `LISTEN_FDS` activation via `ListenFd::from_env()` (validates `LISTEN_PID` match) → macOS launchd placeholder → standalone bind with stale socket removal and `chmod 0600`
- Refactored `AgentServer::serve()` to call `acquire_listener()` then `serve_with_listener()` — no breaking change to existing callers
- Added SIGTERM/SIGINT handlers registered before the accept loop; `tokio::select!` races `listener.accept()` against signal receives
- On signal: `sd_notify STOPPING=1` → 5s drain → `run_credential_cleanup()` (abort refresh task, abort CIBA tasks, best-effort RFC 7009 revocation, in-memory key zeroization)
- Replaced `AgentRequest::Shutdown` `process::exit(0)` with `libc::kill(SIGTERM)` to route through graceful shutdown
- Added sd-notify readiness sequence in `run_serve()`: Gate 1 (socket acquired) → Gate 2 (config validated) → Gate 3 (JWKS prefetch best-effort) → `READY=1`; `println!("Press Ctrl+C to stop")` removed
- 452 workspace tests pass; 2 new tests for `acquire_listener` (standalone bind, stale socket removal)

## Task Commits

1. **Task 1: Create systemd unit files** — `9587b04` (feat)
2. **Task 2: Socket acquisition, sd-notify, signal handling, graceful shutdown** — `77865e2` (feat)

## Files Created/Modified

- `contrib/systemd/unix-oidc-agent.service` — Type=notify user service, all hardening directives
- `contrib/systemd/unix-oidc-agent.socket` — socket unit with %t expansion and 0600 mode
- `unix-oidc-agent/Cargo.toml` — listenfd 1.0, sd-notify 0.5 added with documentation comments
- `unix-oidc-agent/src/daemon/socket.rs` — acquire_listener(), serve_with_listener(), graceful shutdown loop, run_credential_cleanup(), 2 new tests
- `unix-oidc-agent/src/daemon/mod.rs` — acquire_listener re-exported
- `unix-oidc-agent/src/main.rs` — sd-notify readiness gates (3-gate sequence), JWKS prefetch, serve_with_listener call, println! replaced

## Decisions Made

- `sd-notify 0.5` API signature is `notify(&[NotifyState])` — no leading `bool` parameter (research docs referenced older API); corrected during build
- `acquire_listener()` exported from `daemon::mod.rs` so `run_serve()` in `main.rs` can call it before creating `AgentServer` to satisfy Gate 1 ordering
- `run_credential_cleanup()` at daemon shutdown skips keyring/file deletion — daemon restart should find existing credentials; `SessionClosed` IPC and `logout` CLI handle full secure deletion
- `libc::kill(getpid(), SIGTERM)` in `Shutdown` IPC handler: routes cleanup through the Tokio signal handler rather than bypassing it with `process::exit(0)`

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] sd-notify 0.5 API mismatch (research doc referenced older API)**
- **Found during:** Task 2 first build attempt
- **Issue:** Research.md showed `sd_notify::notify(false, &[...])` (2 args); actual `sd-notify 0.5` API is `notify(&[NotifyState])` (1 arg — no leading `bool`)
- **Fix:** Removed the `bool` argument from all `sd_notify::notify` calls in socket.rs
- **Files modified:** `unix-oidc-agent/src/daemon/socket.rs`
- **Committed in:** `77865e2`

---

**Total deviations:** 1 auto-fixed (Rule 1 - API mismatch)
**Impact on plan:** One-line fix; zero scope creep.

## Issues Encountered

None beyond the sd-notify API mismatch above.

## User Setup Required

To enable systemd user service management:

```bash
# Install unit files
mkdir -p ~/.config/systemd/user/
cp contrib/systemd/unix-oidc-agent.{service,socket} ~/.config/systemd/user/

# Enable and start
systemctl --user daemon-reload
systemctl --user enable --now unix-oidc-agent.socket

# Verify
systemctl --user status unix-oidc-agent.service
journalctl --user -u unix-oidc-agent.service -f
```

The daemon continues to work without systemd via `unix-oidc-agent serve` (standalone mode). `sd-notify` and `listenfd` are no-ops when `NOTIFY_SOCKET` / `LISTEN_FDS` are absent.

## Next Phase Readiness

- `serve_with_listener()` pattern ready for Plan 03 (IPC peer credential check wraps the accept result before spawning handler)
- `acquire_listener()` launchd placeholder at `cfg(target_os = "macos")` step 2 ready for Plan 04
- `ipc_idle_timeout_secs` from `TimeoutsConfig` ready to be wired into `handle_connection()` in Plan 03

---
*Phase: 13-operational-hardening*
*Completed: 2026-03-11*
