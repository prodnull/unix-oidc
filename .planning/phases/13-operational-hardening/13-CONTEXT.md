# Phase 13: Operational Hardening - Context

**Gathered:** 2026-03-11
**Status:** Ready for planning

<domain>
## Phase Boundary

The agent daemon ships with production-ready service integration, peer-authenticated IPC, configurable network and cache parameters, and structured observability. Implements OPS-01 through OPS-13.

This phase does NOT add new authentication features, new storage backends, or new protocol support. It hardens the existing daemon for production deployment.

Requirements: OPS-01, OPS-02, OPS-03, OPS-04, OPS-05, OPS-06, OPS-07, OPS-08, OPS-09, OPS-10, OPS-11, OPS-12, OPS-13

</domain>

<decisions>
## Implementation Decisions

### systemd Service Integration (OPS-01, OPS-02, OPS-04)

- **User service, not system service** — `systemctl --user enable --now unix-oidc-agent`. Each user runs their own agent with their own DPoP keys. This matches the threat model: keys are per-user, not shared.
- **Socket activation via systemd** (OPS-02) — `unix-oidc-agent.socket` unit creates the Unix socket; `unix-oidc-agent.service` starts on first connection. Standalone fallback: if `LISTEN_FDS` is not set, the agent creates and binds its own socket (current behavior). Socket activation is preferred for zero-downtime upgrades and clean lifecycle management.
- **sd-notify readiness** (OPS-04) — Agent sends `READY=1` after: (1) socket bind (or fd inheritance), (2) config validation (config parse + enforcement mode sanity), (3) initial JWKS fetch attempt (best-effort — failure downgrades to WARN, does not block readiness; JWKS will be fetched on first auth). This ensures `systemctl start` blocks until the daemon is actually ready to serve.
- **Hardening directives in service unit** — `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `PrivateTmp=yes`, `SystemCallFilter=@system-service @network-io`. These are standard systemd hardening; each is independently justified by NIST SP 800-123 principle of least privilege.
- **Graceful shutdown** — Handle SIGTERM via `tokio::signal::unix::signal(SignalKind::terminate())`. On SIGTERM: (1) stop accepting new connections, (2) drain in-flight requests (5s grace period), (3) run credential cleanup (zeroize keys, revoke tokens best-effort), (4) exit 0. SIGINT same behavior. This replaces the current IPC-only shutdown.
- **sd_journal_print for logging** — When running under systemd (detect via `JOURNAL_STREAM` env var), log directly to journal with structured fields. Otherwise, use current tracing_subscriber text format. No dependency on libsystemd — use the `sd-notify` crate for readiness and `tracing-journald` for journal integration.

### launchd Integration (OPS-03)

- **launchd plist template** — `com.unix-oidc.agent.plist` in `~/Library/LaunchAgents/`. KeepAlive=true, RunAtLoad=true. Socket activation via launchd `Sockets` dictionary with `SockPathMode=0600`.
- **Same binary, platform detection** — No separate macOS binary. Agent detects platform at startup: if `LISTEN_FDS` is set, use systemd socket activation; if launched by launchd with socket, use `launch_activate_socket()`; otherwise, standalone mode.
- **Install helper** — `unix-oidc-agent install` subcommand writes the plist and runs `launchctl load`. `unix-oidc-agent uninstall` runs `launchctl unload` and removes plist.

### IPC Peer Authentication (OPS-05)

- **SO_PEERCRED on Linux, getpeereid on macOS** — Every incoming IPC connection is checked: peer UID must match the daemon's UID. Reject with error and WARN log if mismatch. This is defense-in-depth on top of socket file permissions (0600).
- **Fail-closed** — If peer credential retrieval fails (unlikely but possible on exotic platforms), reject the connection. Never fall through to unauthenticated handling.
- **Log the peer PID** — On Linux, `SO_PEERCRED` also provides PID. Log at DEBUG level for forensic correlation.

### IPC Idle Timeout (OPS-06)

- **Per-connection read timeout** — If a connected client sends no data for 60s (configurable: `ipc_idle_timeout_secs`), the connection is closed. Prevents Tokio task leaks from abandoned connections.
- **Implementation** — `tokio::time::timeout()` wrapping the read loop. Clean close with DEBUG log. No global connection limit in this phase (deferred to scalability milestone if needed).

### Configurable Timeouts (OPS-07, OPS-08, OPS-09, OPS-10)

- **All timeouts in agent config** under `[timeouts]` section:
  - `jwks_http_timeout_secs` — Default 10s (matches existing `HTTP_TIMEOUT_SECS` constant in jwks.rs). Operator-tunable for high-latency IdP environments.
  - `device_flow_http_timeout_secs` — Default 30s (matches existing hardcoded value). Longer because device flow involves user interaction at IdP.
  - `clock_skew_future_secs` — Default 5s. Maximum clock-ahead tolerance for token `iat` claims.
  - `clock_skew_staleness_secs` — Default 60s. Maximum clock-behind tolerance for DPoP proof freshness.
  - `jwks_cache_ttl_secs` — Default 300s (matches existing `DEFAULT_CACHE_TTL_SECS`). Wired to env var `UNIX_OIDC_JWKS_CACHE_TTL` for quick operational override without config file change.
  - `ipc_idle_timeout_secs` — Default 60s. Per-connection idle timeout.
- **figment loading** — Consistent with Phase 6 pattern: YAML config with `UNIX_OIDC_TIMEOUTS__` env var prefix for overrides.
- **Validation at config load** — Reject nonsensical values: negative/zero timeouts, clock_skew_future > clock_skew_staleness, JWKS TTL < JWKS timeout. Config load fails with clear error (same refuse-to-load pattern as Phase 6).

### Tracing Spans (OPS-11)

- **Request-scoped spans** — Each IPC request gets a span with `request_id` (UUID), `command` (GetProof/Status/etc), `peer_pid` (if available). All child operations (JWKS fetch, token validation, DPoP verify, user lookup) inherit the span.
- **`#[instrument]` on key functions** — `validate_token()`, `verify_dpop_proof()`, `fetch_jwks()`, `lookup_user()`, `perform_token_refresh()`, `introspect_token()`. Each with `skip(self)` and relevant field captures.
- **Timing in spans** — Each span records wall-clock duration automatically via tracing. No manual Instant::now() timing code needed.
- **JSON structured output** — When `UNIX_OIDC_LOG_FORMAT=json` is set (or auto-detected under systemd), use `tracing_subscriber::fmt::json()`. Default remains human-readable text. This enables log aggregation (ELK, Datadog, Splunk) without custom parsers.
- **Span correlation** — `request_id` propagated through all log lines in a request, enabling grep-based trace reconstruction from plain text logs.

### Audit Hostname (OPS-12)

- **`gethostname(2)` syscall via the `gethostname` crate** — Already in `pam-unix-oidc/Cargo.toml` as a dependency. Replace the current `std::env::var("HOSTNAME").or(env::var("HOST"))` fallback with `gethostname::gethostname()` as primary, env vars as override only.
- **Rationale** — Env vars can be unset, spoofed by users, or absent in minimal containers. `gethostname(2)` is the POSIX-standard way to get the machine identity. If an operator needs to override (e.g., CNAME vs hostname), they set `UNIX_OIDC_HOSTNAME` explicitly.
- **Cache the result** — Call `gethostname()` once at startup, store in config. Hostname doesn't change during daemon lifetime.

### Proof Request Logging (OPS-13)

- **INFO-level log on every GetProof IPC request** — Fields: `username` (from token claims), `target` (SSH target host if available from IPC context), `signer_type` (Software/YubiKey/TPM).
- **Not audit-level** — This is operational logging, not security audit. Audit events (SshLoginSuccess, etc.) already exist in the PAM module. This log helps operators monitor agent activity and debug connectivity.
- **Rate: one log line per SSH connection** — Acceptable for enterprise environments. If operators find it noisy, they can filter via tracing directives (`unix_oidc_agent::daemon=warn`).

### Claude's Discretion

- Exact systemd unit file content (Wants, After, environment setup for Wayland/X11-less sessions)
- sd-notify crate vs raw socket protocol (crate preferred for correctness)
- launchd `launch_activate_socket()` implementation (may need `libc` FFI or `launch-rs` crate evaluation)
- Tracing layer composition (EnvFilter + fmt layer + optional journald layer)
- Whether `tracing-journald` is worth the dependency or if journal logging via stdout is sufficient (systemd captures stdout to journal by default)
- Config struct organization (single `AgentConfig` with nested sections vs separate config types)
- Test strategy: real systemd integration tests vs unit tests with mocked sd-notify

</decisions>

<specifics>
## Specific Ideas

- Standing directive: ultra secure, standards/best practice compliant, enterprise ready, fully audited and tested
- Every timeout and config knob must have a sensible default that works for 95% of deployments — knobs exist for the 5% who need them
- systemd hardening directives are not optional nice-to-haves; they're baseline expectation for any daemon handling credentials (NIST SP 800-123, CIS benchmarks)
- Peer credential checking is defense-in-depth, not the primary security boundary (that's the socket permissions). But defense-in-depth is the entire philosophy of this project
- JSON structured logging should be zero-config under systemd — auto-detect and do the right thing
- Follow patterns established in Phases 6-9: figment config, parking_lot, moka, deny(clippy::unwrap_used), thiserror, tracing structured logging

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `AgentConfig` (`unix-oidc-agent/src/config.rs`): Extend with `[timeouts]` section. Already has `issuer`, `client_id`, `socket_path`, `crypto`.
- `run_serve()` (`unix-oidc-agent/src/main.rs:169-254`): Main daemon loop — add signal handling, sd-notify, socket activation detection.
- `SocketHandler` (`unix-oidc-agent/src/daemon/socket.rs`): Connection handler — add peer credential check, idle timeout wrapper, request-scoped spans.
- `MetricsCollector` (`unix-oidc-agent/src/daemon/socket.rs:42`): Already tracks per-request latency histograms — enhance with span integration.
- `get_hostname()` (`pam-unix-oidc/src/audit.rs:427-431`): Replace env var fallback with `gethostname::gethostname()`.
- `JwksProvider::with_cache_ttl()` (`pam-unix-oidc/src/oidc/jwks.rs`): JWKS TTL already configurable — wire to new config field.
- `HTTP_TIMEOUT_SECS` constant (`pam-unix-oidc/src/oidc/jwks.rs:19`): Replace with configurable value from `[timeouts]`.
- `disable_core_dumps()` / `mlock_probe()` (`unix-oidc-agent/src/security.rs`): Existing startup hardening — sd-notify goes after these.
- `gethostname` crate: Already in pam-unix-oidc Cargo.toml — available immediately.

### Established Patterns
- figment-based config with `UNIX_OIDC_` env var prefix (Phase 6)
- `parking_lot::RwLock` for all shared state (Phase 6)
- `deny(clippy::unwrap_used, clippy::expect_used)` lint (Phase 6)
- `thiserror` for error types, `tracing` for structured logging (all phases)
- `moka::sync::Cache` for TTL-bounded caches (Phase 7, 9)
- `SecretString` for sensitive values (Phase 1)
- Best-effort hardening that logs WARN on failure but never blocks startup (mlock, core dumps)

### Integration Points
- `unix-oidc-agent/src/main.rs`: Socket bind path — add systemd fd inheritance, sd-notify, signal handlers
- `unix-oidc-agent/src/daemon/socket.rs`: Connection accept loop — add peer credential check, idle timeout
- `unix-oidc-agent/src/config.rs`: AgentConfig — add `[timeouts]` section
- `unix-oidc-agent/Cargo.toml`: Add `sd-notify`, `tokio::signal`, optionally `tracing-journald`
- `pam-unix-oidc/src/audit.rs`: Replace `get_hostname()` implementation
- `pam-unix-oidc/src/oidc/jwks.rs`: Wire configurable timeouts to HTTP client and cache TTL
- `examples/policy.yaml`: Add `[timeouts]` section documentation
- New files: `contrib/systemd/unix-oidc-agent.service`, `contrib/systemd/unix-oidc-agent.socket`, `contrib/launchd/com.unix-oidc.agent.plist`

</code_context>

<deferred>
## Deferred Ideas

- Global connection limit / rate limiting on IPC socket — defer to scalability milestone if needed
- Prometheus metrics endpoint — future observability phase (current MetricsCollector is IPC-only)
- Hot config reload (SIGHUP) — deferred; restart is acceptable for config changes in v2.0
- systemd watchdog (WatchdogSec + sd_notify WATCHDOG=1) — nice-to-have, not blocking v2.0
- Centralized audit log shipping (syslog-ng/fluentd integration) — future operational tooling phase

</deferred>

---

*Phase: 13-operational-hardening*
*Context gathered: 2026-03-11*
