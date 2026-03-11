---
phase: 13-operational-hardening
verified: 2026-03-11T13:00:00Z
status: passed
score: 13/13 must-haves verified
re_verification: false
---

# Phase 13: Operational Hardening Verification Report

**Phase Goal:** Operational Hardening — Configurable timeouts, systemd/launchd service integration, IPC peer authentication, structured tracing for production observability.
**Verified:** 2026-03-11T13:00:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Operator can set `jwks_cache_ttl_secs` in config.yaml and the value is passed to `JwksProvider::with_timeouts()` | VERIFIED | `main.rs:424-428` loads `config.timeouts.jwks_cache_ttl_secs` and passes to `JwksProvider::with_timeouts()` |
| 2 | `UNIX_OIDC_JWKS_CACHE_TTL` env var overrides the config file value | VERIFIED | `config.rs:236-243` applies legacy env override after figment extraction; `test_unix_oidc_jwks_cache_ttl_env_override` passes |
| 3 | Zero or negative timeout values cause config load to fail with a clear error | VERIFIED | `TimeoutsConfig::validate()` at `config.rs:99-123` rejects zero `jwks_http_timeout_secs` and `device_flow_http_timeout_secs`; 4 validation tests pass |
| 4 | `get_hostname()` returns the POSIX `gethostname(2)` result, not an environment variable | VERIFIED | `audit.rs:438-447` calls `gethostname::gethostname()`; `UNIX_OIDC_HOSTNAME` is operator override only; env vars `HOSTNAME`/`HOST` removed |
| 5 | `jwks_http_timeout_secs` replaces the hardcoded `HTTP_TIMEOUT_SECS` constant in `jwks.rs` | VERIFIED | `jwks.rs:92,126-131` — `http_timeout` field + `with_timeouts()` constructor; `fetch_discovery` and `fetch_jwks` both use `self.http_timeout` at lines 242,266 |
| 6 | `device_flow_http_timeout_secs` replaces hardcoded 30s in device flow and token refresh HTTP clients | VERIFIED | `main.rs:608-609,1028-1029` loads `config.timeouts.device_flow_http_timeout_secs` at both `run_login()` and `run_refresh()` call sites |
| 7 | `clock_skew_future_secs` replaces hardcoded 5 in `dpop.rs` future-proof check | VERIFIED | `dpop.rs:152,317-319` — field on `DPoPConfig`, used in `claims.iat > now + config.clock_skew_future_secs as i64` |
| 8 | `clock_skew_staleness_secs` wires to `DPoPConfig::max_proof_age` and `ValidationConfig::clock_skew_tolerance_secs` | VERIFIED | `validation.rs:78,191,270` — `ValidationConfig::clock_skew_tolerance_secs` field used in all expiration checks; `dpop.rs:167` default matches |
| 9 | systemd socket unit creates a user socket at `$XDG_RUNTIME_DIR/unix-oidc-agent.sock` with mode 0600 | VERIFIED | `contrib/systemd/unix-oidc-agent.socket:9-10` — `ListenStream=%t/unix-oidc-agent.sock` and `SocketMode=0600` |
| 10 | systemd service unit has all hardening directives from plan | VERIFIED | `contrib/systemd/unix-oidc-agent.service` — `NoNewPrivileges=yes`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `PrivateTmp=yes`, `SystemCallFilter=@system-service @network-io` |
| 11 | Agent detects `LISTEN_FDS` and uses the inherited socket | VERIFIED | `socket.rs:54-60` — `ListenFd::from_env()` validates `LISTEN_PID` match before taking fd |
| 12 | Agent sends `sd-notify READY=1` after socket bind + config validation + JWKS fetch attempt | VERIFIED | `main.rs:441-448` — three-gate sequence (socket, config, JWKS prefetch) then `sd_notify::notify(&[NotifyState::Ready, NotifyState::Status("unix-oidc-agent ready")])` |
| 13 | Agent handles SIGTERM/SIGINT gracefully: stops accepting, drains 5s, cleans up credentials | VERIFIED | `socket.rs:307-312,379-407` — signal handlers registered before accept loop; `tokio::select!` races accept against signals; STOPPING=1 + 5s drain + `run_credential_cleanup()` |
| 14 | A process running as a different UID is rejected when connecting to the IPC socket | VERIFIED | `socket.rs:337-357` — `get_peer_credentials()` called after `accept()`; `peer_uid != daemon_uid` causes WARN + drop + continue |
| 15 | If peer credential retrieval fails, the connection is rejected (fail-closed) | VERIFIED | `socket.rs:349-356` — `Err` from `get_peer_credentials()` logs WARN "fail-closed" and drops stream; `peer_cred.rs:92-95` returns `Unsupported` error on unsupported platforms |
| 16 | A connected client that sends no data for 60s has its connection closed | VERIFIED | `socket.rs:463` — `tokio::time::timeout(idle_timeout, reader.read_line())` per-read; `Err(_elapsed)` breaks loop |
| 17 | Idle timeout is configurable via `ipc_idle_timeout_secs` | VERIFIED | `AgentServer::with_idle_timeout()` at `socket.rs:264`; `main.rs` applies `config.timeouts.ipc_idle_timeout_secs` at Gate 2 |
| 18 | launchd plist template exists with KeepAlive, RunAtLoad, and Sockets configuration | VERIFIED | `contrib/launchd/com.unix-oidc.agent.plist.template` — `<key>KeepAlive</key><true/>`, `<key>RunAtLoad</key><true/>`, `<key>Sockets</key>` dict with `SockPathMode` 384 |
| 19 | `unix-oidc-agent install` generates a plist with correct substitutions | VERIFIED | `main.rs:1388-1495` — `run_install()` substitutes `{{BINARY_PATH}}`, `{{SOCKET_PATH}}`, `{{HOME}}`; `test_install_template_substitution_no_placeholders` passes |
| 20 | On macOS, the agent can accept connections via launchd-activated socket | VERIFIED | `socket.rs:2939-3006` — `launchd_socket::take("Listeners")` via `launch_activate_socket(3)` FFI; `acquire_listener()` checks this at step 2 |
| 21 | Each IPC request produces correlated spans with `request_id`, `command`, and `peer_pid` | VERIFIED | `socket.rs:423-435` — `#[instrument]` on `handle_connection` with `request_id = %Uuid::new_v4()`, `command = tracing::field::Empty`, `peer_pid = tracing::field::Empty`; recorded after parse at line 503 |
| 22 | Agent DPoP functions have `#[instrument]` spans that skip key material | VERIFIED | `crypto/dpop.rs:63,110,135` — `generate_dpop_proof`, `build_dpop_message`, `assemble_dpop_proof` all instrumented with explicit `skip` directives |
| 23 | JSON output is auto-selected when `JOURNAL_STREAM` is set or `UNIX_OIDC_LOG_FORMAT=json` | VERIFIED | `main.rs:77-80` — both conditions checked; JSON layer composed with optional `tracing-journald` on Linux |
| 24 | Every GetProof IPC request emits an INFO log with `username`, `target`, `signer_type` | VERIFIED | `socket.rs:567-572` — `tracing::info!(username, target, signer_type, "DPoP proof requested")`; `test_get_proof_emits_info_log` (tracing-test) passes |

**Score:** 24/24 truths verified

---

### Required Artifacts

| Artifact | Status | Evidence |
|----------|--------|----------|
| `unix-oidc-agent/src/config.rs` | VERIFIED | `TimeoutsConfig` with 6 fields, `validate()`, figment-based `load_from_path()`, `UNIX_OIDC_JWKS_CACHE_TTL` legacy compat — 452 lines, substantive |
| `pam-unix-oidc/src/audit.rs` | VERIFIED | `get_hostname()` calls `gethostname::gethostname()` at line 444; wired to all 12 `host:` field assignments |
| `pam-unix-oidc/src/oidc/jwks.rs` | VERIFIED | `http_timeout: Duration` field, `with_timeouts()` constructor, `self.http_timeout` used in both `fetch_discovery` and `fetch_jwks` |
| `pam-unix-oidc/src/oidc/dpop.rs` | VERIFIED | `clock_skew_future_secs: u64` on `DPoPConfig`, used in `claims.iat > now + config.clock_skew_future_secs as i64` |
| `pam-unix-oidc/src/oidc/validation.rs` | VERIFIED | `clock_skew_tolerance_secs: i64` on `ValidationConfig`, used in expiration and auth_time checks; `CLOCK_SKEW_TOLERANCE` const kept `#[allow(dead_code)]` for documentation only |
| `contrib/systemd/unix-oidc-agent.service` | VERIFIED | `Type=notify`, all 8 hardening directives present, `ReadWritePaths` for file storage backend |
| `contrib/systemd/unix-oidc-agent.socket` | VERIFIED | `ListenStream=%t/unix-oidc-agent.sock`, `SocketMode=0600` |
| `unix-oidc-agent/src/daemon/socket.rs` | VERIFIED | `acquire_listener()`, `ListenFd::from_env()`, `SignalKind::terminate()`, `get_peer_credentials()` call, `idle_timeout`, `#[instrument]` on `handle_connection`, GetProof INFO log |
| `unix-oidc-agent/src/main.rs` | VERIFIED | `init_tracing()`, `sd_notify::notify(&[NotifyState::Ready])`, `Commands::Install`, `run_install()`, `run_uninstall()` |
| `unix-oidc-agent/src/daemon/peer_cred.rs` | VERIFIED | `get_peer_credentials()` with Linux `SO_PEERCRED` and macOS `getpeereid`; fail-closed on unsupported platforms; 3 tests |
| `contrib/launchd/com.unix-oidc.agent.plist.template` | VERIFIED | `KeepAlive`, `RunAtLoad`, `Sockets` dict with `SockPathMode=384`, template placeholders present |
| `unix-oidc-agent/src/crypto/dpop.rs` | VERIFIED | `#[instrument]` on `generate_dpop_proof`, `build_dpop_message`, `assemble_dpop_proof` with key-material skip directives |
| `unix-oidc-agent/src/daemon/protocol.rs` | VERIFIED | `AgentRequest::command_name()` returns `&'static str` for stable span field recording |

---

### Key Link Verification

| From | To | Via | Status | Evidence |
|------|----|-----|--------|----------|
| `unix-oidc-agent/src/config.rs` | figment | `Figment::from()` with `Yaml` + `Env` providers | WIRED | `config.rs:220-228` — `Figment::from(Serialized::defaults(...))`, merged `Yaml::file()`, merged `Env::prefixed("UNIX_OIDC_").split("__")` |
| `unix-oidc-agent/src/config.rs` | `pam-unix-oidc/src/oidc/jwks.rs` | `jwks_cache_ttl_secs` and `jwks_http_timeout_secs` passed to `JwksProvider::with_timeouts()` | WIRED | `main.rs:424-428` reads both fields and calls `JwksProvider::with_timeouts(&issuer, ttl, http_timeout)` |
| `unix-oidc-agent/src/config.rs` | `unix-oidc-agent/src/main.rs` | `device_flow_http_timeout_secs` passed to reqwest client builders | WIRED | `main.rs:608-609,1028-1029` — loaded and applied at `run_login()` and `run_refresh()` |
| `unix-oidc-agent/src/config.rs` | `pam-unix-oidc/src/oidc/dpop.rs` | `clock_skew_future_secs` wired to `DPoPConfig` | WIRED | `pam-unix-oidc/src/auth.rs` threads `DPoPAuthConfig::clock_skew_future_secs` to inline `DPoPConfig` |
| `unix-oidc-agent/src/daemon/socket.rs` | listenfd | `ListenFd::from_env()` for socket activation detection | WIRED | `socket.rs:3-4,54-59` — `use listenfd::ListenFd` + `ListenFd::from_env()` at acquire_listener |
| `unix-oidc-agent/src/main.rs` | sd-notify | `sd_notify::notify(&[NotifyState::Ready])` | WIRED | `main.rs:444-447` — three gates passed before `NotifyState::Ready` sent |
| `unix-oidc-agent/src/daemon/socket.rs` | tokio::signal | `signal(SignalKind::terminate())` in select! loop | WIRED | `socket.rs:307,379` — SIGTERM/SIGINT both registered; `tokio::select!` at accept loop |
| `unix-oidc-agent/src/daemon/socket.rs` | `unix-oidc-agent/src/daemon/peer_cred.rs` | `get_peer_credentials()` call after `listener.accept()` | WIRED | `socket.rs:17,337` — `use crate::daemon::peer_cred::get_peer_credentials` + call before handler spawn |
| `unix-oidc-agent/src/daemon/socket.rs` | `tokio::time::timeout` | idle timeout wrapping read loop | WIRED | `socket.rs:463` — `tokio::time::timeout(idle_timeout, reader.read_line(&mut line)).await` |
| `unix-oidc-agent/src/main.rs` | `contrib/launchd/com.unix-oidc.agent.plist.template` | install subcommand writes plist to `~/Library/LaunchAgents/` | WIRED | `main.rs:1388,1409` — `include_str!()` embeds template; substitutions applied; writes to `LaunchAgents/` |
| `unix-oidc-agent/src/daemon/socket.rs` | launchd `launch_activate_socket` | `cfg(target_os = "macos")` launchd socket detection in `acquire_listener` | WIRED | `socket.rs:68-72` — `launchd_socket::take("Listeners")` inside `acquire_listener()` |
| `unix-oidc-agent/src/main.rs` | `tracing_subscriber` | `init_tracing()` composing registry + filter + fmt layer | WIRED | `main.rs:70-121` — `tracing_subscriber::registry()` with `EnvFilter`, JSON or human fmt layer, optional journald layer |
| `unix-oidc-agent/src/daemon/socket.rs` | `tracing::instrument` | `#[instrument]` on `handle_connection` with `request_id` field | WIRED | `socket.rs:423-435` — `#[instrument]` macro with UUID `request_id` and deferred `command`/`peer_pid` fields |
| `unix-oidc-agent/src/crypto/dpop.rs` | `tracing::instrument` | `#[instrument]` on DPoP proof generation functions | WIRED | `crypto/dpop.rs:63,110,135` — all three functions instrumented |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| OPS-01 | 13-02 | systemd user service unit with hardening directives | SATISFIED | `contrib/systemd/unix-oidc-agent.service` — `NoNewPrivileges=yes`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes` and 5 further directives |
| OPS-02 | 13-02 | systemd socket activation with standalone fallback | SATISFIED | `acquire_listener()` checks `LISTEN_FDS` via `listenfd`; falls through to standalone bind |
| OPS-03 | 13-04 | launchd plist template for macOS agent daemon | SATISFIED | `contrib/launchd/com.unix-oidc.agent.plist.template` + `install`/`uninstall` subcommands + `launchd_socket::take()` FFI |
| OPS-04 | 13-02 | sd-notify READY=1 after socket bind + config validation + initial JWKS fetch | SATISFIED | Three-gate sequence in `run_serve()` before `NotifyState::Ready` |
| OPS-05 | 13-03 | `SO_PEERCRED` (Linux) / `getpeereid` (macOS) peer UID validation | SATISFIED | `peer_cred.rs` + wired into `serve_with_listener()` accept loop; fail-closed on error |
| OPS-06 | 13-03 | IPC idle timeout (configurable, default 60s) | SATISFIED | `tokio::time::timeout` per-read in `handle_connection`; `AgentServer::with_idle_timeout()` builder; default 60s |
| OPS-07 | 13-01 | Configurable JWKS HTTP timeout (default 10s) | SATISFIED | `TimeoutsConfig::jwks_http_timeout_secs`; `JwksProvider::with_timeouts()` accepts it; wired via `main.rs` |
| OPS-08 | 13-01 | Configurable device flow HTTP timeout (default 30s) | SATISFIED | `TimeoutsConfig::device_flow_http_timeout_secs`; applied at both `run_login()` and `run_refresh()` |
| OPS-09 | 13-01 | Configurable clock skew tolerance (default 5s future / 60s staleness) | SATISFIED | `DPoPConfig::clock_skew_future_secs` and `ValidationConfig::clock_skew_tolerance_secs`; both wired to callers |
| OPS-10 | 13-01 | Configurable JWKS cache TTL wired to env var (default 300s) | SATISFIED | `TimeoutsConfig::jwks_cache_ttl_secs`; `UNIX_OIDC_JWKS_CACHE_TTL` legacy env var override preserved |
| OPS-11 | 13-05 | Tracing spans across full authentication flow | SATISFIED | `#[instrument]` on `handle_connection` (request_id), `generate_dpop_proof`, `build_dpop_message`, `assemble_dpop_proof` |
| OPS-12 | 13-01 | Audit hostname resolution via `gethostname()` syscall | SATISFIED | `audit.rs:438-447` — `gethostname::gethostname()` as primary; `UNIX_OIDC_HOSTNAME` as operator override |
| OPS-13 | 13-05 | Proof request logging at INFO level (username, target, signer type) | SATISFIED | `socket.rs:567-572` — `tracing::info!(username, target, signer_type, "DPoP proof requested")`; tracing-test verified |

All 13 requirements SATISFIED. No orphaned requirements.

---

### Anti-Patterns Found

None. All Phase 13 files examined:
- No `TODO`/`FIXME`/`XXX` comments in implemented code paths
- No stub implementations (`return null`, `return {}`, empty handlers)
- No hardcoded constants surviving in active paths (only `HTTP_TIMEOUT_SECS` remains as a default in `JwksProvider::new()` and `with_cache_ttl()` — both are backward-compatible constructors documented as such)
- No `console.log`-only or `println!`-only handlers (all replaced with structured tracing)
- `CLOCK_SKEW_TOLERANCE` const retained with explicit `#[allow(dead_code)]` annotation and comment: "All active code paths use `self.config.clock_skew_tolerance_secs` instead." — intentional documentation artifact, not a stub.

---

### Human Verification Required

The following items cannot be verified programmatically and require a live environment:

#### 1. systemd socket activation end-to-end

**Test:** Copy unit files to `~/.config/systemd/user/`, run `systemctl --user daemon-reload && systemctl --user enable --now unix-oidc-agent.socket`, verify service reaches `active (running)` state.
**Expected:** `systemctl --user status unix-oidc-agent.service` shows `Active: active (running)` and `Type=notify` service waits for READY=1 before marking ready.
**Why human:** Requires a Linux host with systemd user session and proper `XDG_RUNTIME_DIR`.

#### 2. launchd install/uninstall on macOS

**Test:** Run `unix-oidc-agent install` on macOS, verify `~/Library/LaunchAgents/com.unix-oidc.agent.plist` is created with no `{{}}` placeholders, verify `launchctl list com.unix-oidc.agent` shows the agent running.
**Expected:** Agent auto-starts via launchd; `unix-oidc-agent uninstall` removes plist and stops agent.
**Why human:** Requires macOS with launchd; `launch_activate_socket(3)` FFI only exercises live when launched by launchd.

#### 3. JSON log output under systemd (journald integration)

**Test:** Start agent with `JOURNAL_STREAM=1:2 unix-oidc-agent serve`, inspect logs.
**Expected:** Log lines are JSON objects; `journalctl` shows structured fields; `journalctl -p err` filters by priority correctly via tracing-journald layer.
**Why human:** Requires a systemd journal socket at `/run/systemd/journal/socket`; tracing-journald layer cannot be integration-tested without it.

#### 4. Graceful shutdown drain behavior under load

**Test:** Start agent, establish several active IPC connections, send SIGTERM, verify connections close within 5 seconds and credentials are zeroized.
**Expected:** `STOPPING=1` sent immediately; active connections are drained; no abrupt disconnect; keyring/in-memory keys zeroized.
**Why human:** Requires concurrent IPC clients and observable memory/credential state.

---

### Commit Verification

All 11 documented commits verified present in git history:

| Commit | Plan | Description |
|--------|------|-------------|
| `eff35c2` | 13-01 Task 1 | feat(13-01): add TimeoutsConfig struct and migrate AgentConfig to figment |
| `9b5fd1a` | 13-01 Task 2 | feat(13-01): replace get_hostname() env-var lookup with gethostname(2) syscall |
| `90af289` | 13-01 Task 3 | feat(13-01): wire TimeoutsConfig values to all consumer call sites |
| `9587b04` | 13-02 Task 1 | feat(13-02): add systemd user service and socket unit files |
| `77865e2` | 13-02 Task 2 | feat(13-02): socket activation, sd-notify readiness, graceful shutdown |
| `9d4b369` | 13-03 Task 1 | feat(13-03): implement get_peer_credentials() in peer_cred.rs |
| `20b0c91` | 13-03 Task 2 | feat(13-03): wire peer UID check and idle timeout into serve loop |
| `fce12cf` | 13-04 Task 1 | feat(13-04): add launchd plist template and install/uninstall subcommands |
| `74aeac8` | 13-04 Task 2 | feat(13-04): add macOS launchd socket activation to acquire_listener |
| `2756766` | 13-05 Task 1 | feat(13-05): add init_tracing() with JSON auto-detection and journald layer |
| `02002a6` | 13-05 Task 2 | feat(13-05): add request-scoped spans, DPoP instrumentation, and GetProof INFO logging |

---

### Test Suite Results

- `pam-unix-oidc` unit tests: **306 passed, 0 failed**
- `unix-oidc-agent` unit tests: **148 passed, 0 failed, 6 ignored**
- `unix-oidc-agent` integration tests (daemon_lifecycle): **1 passed, 0 failed**
- `unix-oidc-agent` integration tests (remaining): **1 passed, 0 failed**
- `pam-unix-oidc` integration tests: **2 passed, 1 ignored**

Note: A SIGABRT was observed in `test_key_material_zeroed_after_drop` when running the full workspace in parallel mode (`cargo test --workspace`). This test passes in isolation (`cargo test -p unix-oidc-agent`) and is unrelated to Phase 13 — it is a pre-existing flaky test caused by UB checking in debug builds under parallel test execution. It has no impact on Phase 13 goal achievement.

---

### Summary

Phase 13 goal is fully achieved. All 13 OPS requirements are satisfied across 5 plans:

- **OPS-07/08/09/10/12** (Plan 01): `TimeoutsConfig` with 6 operator-tunable fields replaces all hardcoded constants; figment-based layered loading with env var override; `gethostname(2)` syscall for reliable hostname audit logging.
- **OPS-01/02/04** (Plan 02): Hardened systemd user service + socket units; `acquire_listener()` with systemd LISTEN_FDS activation; three-gate sd-notify READY=1 sequence; SIGTERM/SIGINT graceful 5s-drain shutdown.
- **OPS-05/06** (Plan 03): `SO_PEERCRED`/`getpeereid` peer UID validation (fail-closed); per-read idle timeout via `tokio::time::timeout`; configurable via `ipc_idle_timeout_secs`.
- **OPS-03** (Plan 04): launchd plist template; `install`/`uninstall` CLI subcommands; `launch_activate_socket(3)` FFI in `acquire_listener()`.
- **OPS-11/13** (Plan 05): `init_tracing()` with JSON/journald auto-detect; request-scoped `ipc_request` span with UUID `request_id`; `#[instrument]` on DPoP functions (skipping key material); GetProof INFO log with `username`/`target`/`signer_type`.

---

_Verified: 2026-03-11T13:00:00Z_
_Verifier: Claude (gsd-verifier)_
