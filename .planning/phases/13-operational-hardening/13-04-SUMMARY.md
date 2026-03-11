---
phase: 13-operational-hardening
plan: "04"
subsystem: infra
tags: [launchd, macos, socket-activation, ffi, plist, cli, install]

requires:
  - phase: 13-02
    provides: acquire_listener() with systemd + standalone paths; placeholder for launchd step 2

provides:
  - contrib/launchd/com.unix-oidc.agent.plist.template — launchd plist with KeepAlive, RunAtLoad, Sockets dict (0600 mode), per-user log paths
  - Install/Uninstall CLI subcommands with placeholder substitution and launchctl integration
  - launchd_socket::take() FFI module on macOS that inherits pre-bound socket from launchd
  - acquire_listener() step 2 filled in — checks launchd socket after systemd, before standalone bind

affects: [13-operational-hardening, deploy, macos-packaging]

tech-stack:
  added: []
  patterns:
    - "launchd socket activation via launch_activate_socket(3) FFI — parallel to systemd sd_listen_fds"
    - "include_str!() embeds plist template at compile time so install works without contrib/ present at runtime"
    - "cfg(target_os=macos) / cfg(not(target_os=macos)) pair for platform-specific CLI paths without unreachable-code warnings"

key-files:
  created:
    - contrib/launchd/com.unix-oidc.agent.plist.template
  modified:
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/daemon/socket.rs

key-decisions:
  - "install subcommand derives socket path from $TMPDIR (macOS per-user temp dir) so multiple users on the same host get independent sockets"
  - "launchd_socket::take() returns None on ESRCH (not running under launchd) — normal for foreground invocations; fallthrough to standalone is correct behavior"
  - "plist template embedded via include_str!() at compile time — no runtime dependency on contrib/ directory location"
  - "SockPathMode 384 (octal 0600 decimal) in plist matches standalone bind permissions — owner-only access"

patterns-established:
  - "Pattern: platform-conditional CLI impls use cfg(target_os=X) / cfg(not(target_os=X)) blocks rather than early return + unreachable, eliminating unreachable_code warnings"
  - "Pattern: FFI socket activation follows same contract as listenfd — return None on non-activation, Some(listener) on success"

requirements-completed: [OPS-03]

duration: 9min
completed: 2026-03-11
---

# Phase 13 Plan 04: macOS launchd Integration Summary

**launchd plist template with KeepAlive/RunAtLoad/Sockets, install/uninstall CLI subcommands with launchctl integration, and launch_activate_socket(3) FFI for socket activation in acquire_listener()**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-11T12:22:56Z
- **Completed:** 2026-03-11T12:31:42Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- Created launchd plist template with all required keys: Label, ProgramArguments, KeepAlive, RunAtLoad, Sockets dict (Unix socket, 0600 mode, per-user $TMPDIR path), StandardOutPath/StandardErrorPath with {{HOME}} placeholder
- Added `install` and `uninstall` subcommands: macOS writes plist to ~/Library/LaunchAgents/, runs launchctl load/unload; Linux prints systemd redirect instructions
- Implemented `launchd_socket` module (macOS-only) with `launch_activate_socket(3)` FFI — `take("Listeners")` inherits pre-bound socket or returns None gracefully when not under launchd
- Filled in the Plan 02 placeholder in `acquire_listener()` step 2 — launchd check runs after systemd, before standalone bind

## Task Commits

1. **Task 1: launchd plist template and install/uninstall subcommands** - `fce12cf` (feat)
2. **Task 2: macOS launchd socket activation in acquire_listener** - `74aeac8` (feat)

**Plan metadata:** (docs commit follows)

## Files Created/Modified

- `contrib/launchd/com.unix-oidc.agent.plist.template` — XML plist template with KeepAlive, RunAtLoad, Sockets dict (SockPathMode 384), log paths; {{BINARY_PATH}}, {{SOCKET_PATH}}, {{HOME}} substituted at install time
- `unix-oidc-agent/src/main.rs` — Install/Uninstall variants in Commands enum; run_install() and run_uninstall() implementations; template substitution test
- `unix-oidc-agent/src/daemon/socket.rs` — launchd_socket pub(crate) mod with FFI extern, take() implementation, None-under-launchd compile test; acquire_listener() step 2 filled in

## Decisions Made

- Socket path derived from `$TMPDIR` (not `$XDG_RUNTIME_DIR`) because macOS sets `$TMPDIR` to a per-user directory under `/var/folders/` — avoids socket collision between users on shared machines
- Template embedded via `include_str!()` so the install subcommand works on a target machine that does not have the source tree present
- `SockPathMode` integer `384` in the plist (decimal representation of octal 0600) — matches standalone bind permissions for consistency
- `cfg(target_os="macos")` / `cfg(not(target_os="macos"))` block pairs used instead of early-return + unreachable fallthrough, eliminating Rust unreachable-code warnings

## Deviations from Plan

**1. [Rule 1 - Bug] Fixed format string error in println! with shell brace expansion**
- **Found during:** Task 1 (run_uninstall Linux path)
- **Issue:** `println!("rm ...{service,socket}")` — Rust format parser treats `{` as opening a format placeholder; compile error
- **Fix:** Escaped to `{{service,socket}}` — produces literal `{service,socket}` in output
- **Files modified:** unix-oidc-agent/src/main.rs
- **Verification:** Build passes; `cargo build -p unix-oidc-agent` clean
- **Committed in:** fce12cf (Task 1 commit)

**2. [Rule 1 - Bug] Removed unused import and restructured to eliminate unreachable-code warnings**
- **Found during:** Task 1 (first build attempt)
- **Issue:** `use std::path::Path` unused; `return Ok(())` inside `#[cfg(target_os="macos")]` block made non-macOS println!() calls unreachable on macOS builds
- **Fix:** Removed unused import; split Linux paths into `#[cfg(not(target_os="macos"))]` blocks
- **Files modified:** unix-oidc-agent/src/main.rs
- **Verification:** `cargo build -p unix-oidc-agent` — zero warnings
- **Committed in:** fce12cf (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 - Bug, compile-time issues)
**Impact on plan:** Minor — both were compile-time corrections caught on first build. No scope change.

## Issues Encountered

None beyond the compile-time fixes documented above.

## Next Phase Readiness

- macOS launchd integration complete; `unix-oidc-agent install` and `unix-oidc-agent uninstall` are functional on macOS
- The launchd socket activation path (`acquire_listener` step 2) is compiled and tested to return None outside launchd; full integration test requires `launchctl load` + connect
- Phase 13 Plan 04 is the final plan in the phase; all three OPS requirements addressed across Plans 01-04

---
*Phase: 13-operational-hardening*
*Completed: 2026-03-11*
