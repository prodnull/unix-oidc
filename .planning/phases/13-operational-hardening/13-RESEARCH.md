# Phase 13: Operational Hardening - Research

**Researched:** 2026-03-11
**Domain:** systemd/launchd service integration, IPC peer authentication, configurable timeouts, structured observability (Rust)
**Confidence:** HIGH

## Summary

Phase 13 hardens the existing `unix-oidc-agent` daemon for production deployment across Linux and macOS without adding new authentication features. The work spans five distinct sub-domains: (1) service manager integration (systemd user units + launchd), (2) IPC peer authentication via kernel credentials, (3) a figment-based `[timeouts]` config section wiring all previously hardcoded timeout constants, (4) tracing span instrumentation across the full authentication flow, and (5) two small audit improvements (hostname via `gethostname(2)`, proof request logging). All decisions are locked in CONTEXT.md; research confirms they are technically sound and documents the exact APIs and crate versions needed.

The codebase already has nearly all needed dependencies. The main additions are `sd-notify 0.5`, `listenfd 1.0`, `figment 0.10` (add to `unix-oidc-agent`), and optionally `tracing-journald 0.3`. The `gethostname` crate is already in `pam-unix-oidc/Cargo.toml`. Socket peer credential checking uses raw `libc` syscalls already present in the crate — no new dependency required. The macOS `launch_activate_socket()` path requires either a thin `libc` FFI wrapper or the `launch` crate, which is effectively unmaintained; the `libc` FFI approach is strongly preferred.

**Primary recommendation:** Implement in three waves — (1) service files + signal handling + sd-notify, (2) IPC hardening (peer auth + idle timeout) + config `[timeouts]` section, (3) tracing instrumentation + OPS-12/OPS-13 logging polish. Each wave is independently testable.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- **User service, not system service** — `systemctl --user enable --now unix-oidc-agent`
- **Socket activation via systemd** (OPS-02) — `.socket` unit creates socket; `.service` starts on first connection; standalone fallback if `LISTEN_FDS` not set
- **sd-notify READY=1** (OPS-04) — after socket bind + config validation + initial JWKS fetch attempt (best-effort; failure downgrades to WARN)
- **Hardening directives** — `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=read-only`, `MemoryDenyWriteExecute=yes`, `RestrictNamespaces=yes`, `RestrictRealtime=yes`, `RestrictSUIDSGID=yes`, `PrivateTmp=yes`, `SystemCallFilter=@system-service @network-io`
- **Graceful shutdown** — SIGTERM/SIGINT via `tokio::signal::unix::signal(SignalKind::terminate())`: stop accepting, drain 5s, zeroize keys/revoke tokens best-effort, exit 0
- **sd_journal via crate** — `sd-notify` crate for readiness, `tracing-journald` for journal integration; no libsystemd dependency
- **launchd plist** — `com.unix-oidc.agent.plist` in `~/Library/LaunchAgents/`; KeepAlive=true, RunAtLoad=true; socket via launchd `Sockets` dict at 0600
- **Same binary, platform detection** — detect `LISTEN_FDS` (systemd) vs launchd socket vs standalone
- **Install helper** — `unix-oidc-agent install` / `uninstall` subcommands
- **SO_PEERCRED (Linux) / getpeereid (macOS)** — peer UID must match daemon UID; fail-closed; log peer PID at DEBUG
- **IPC idle timeout** — 60s default (configurable `ipc_idle_timeout_secs`); `tokio::time::timeout()` wrapping read loop
- **All timeouts under `[timeouts]` config section** with listed defaults; figment with `UNIX_OIDC_TIMEOUTS__` env prefix
- **Config validation at load** — reject zero/negative, nonsensical ordering, JWKS TTL less than JWKS timeout
- **Request-scoped tracing spans** — `request_id` UUID, `command`, `peer_pid`; `#[instrument]` on key functions; JSON output when `UNIX_OIDC_LOG_FORMAT=json` or under systemd
- **`gethostname(2)` via `gethostname` crate** as primary hostname source; env var as override only; cached at startup
- **INFO log on every GetProof** — username, target, signer_type fields

### Claude's Discretion
- Exact systemd unit file content (Wants, After, environment setup for Wayland/X11-less sessions)
- sd-notify crate vs raw socket protocol (crate preferred for correctness)
- launchd `launch_activate_socket()` implementation (libc FFI vs `launch-rs` crate evaluation)
- Tracing layer composition (EnvFilter + fmt layer + optional journald layer)
- Whether `tracing-journald` is worth the dependency or if journal logging via stdout is sufficient
- Config struct organization (single `AgentConfig` with nested sections vs separate config types)
- Test strategy: real systemd integration tests vs unit tests with mocked sd-notify

### Deferred Ideas (OUT OF SCOPE)
- Global connection limit / rate limiting on IPC socket
- Prometheus metrics endpoint
- Hot config reload (SIGHUP)
- systemd watchdog (WatchdogSec + sd_notify WATCHDOG=1)
- Centralized audit log shipping
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| OPS-01 | systemd user service unit with hardening directives | systemd unit format, hardening directives, specifier table documented below |
| OPS-02 | systemd socket activation support with standalone fallback | `listenfd 1.0` + `LISTEN_FDS` detection pattern documented below |
| OPS-03 | launchd plist template for macOS agent daemon | launchd plist schema, libc FFI for launch_activate_socket, install helper pattern |
| OPS-04 | sd-notify READY=1 after socket bind + config validation + initial JWKS fetch | `sd-notify 0.5` NotifyState API documented below |
| OPS-05 | SO_PEERCRED (Linux) / getpeereid (macOS) peer UID validation | libc getsockopt pattern on tokio UnixStream::as_raw_fd() documented below |
| OPS-06 | IPC idle timeout (configurable, default 60s) | `tokio::time::timeout()` wrapping read loop pattern documented below |
| OPS-07 | Configurable JWKS HTTP timeout (default 10s) | Wire `HTTP_TIMEOUT_SECS` constant to `[timeouts].jwks_http_timeout_secs` |
| OPS-08 | Configurable device flow HTTP timeout (default 30s) | Wire to `[timeouts].device_flow_http_timeout_secs` |
| OPS-09 | Configurable clock skew tolerance (default 5s future / 60s staleness) | Wire to `[timeouts].clock_skew_future_secs` / `clock_skew_staleness_secs` |
| OPS-10 | Configurable JWKS cache TTL wired to env var (default 300s) | `JwksProvider::with_cache_ttl()` already exists; env var `UNIX_OIDC_JWKS_CACHE_TTL` |
| OPS-11 | Tracing spans across full authentication flow | `#[instrument]` + `tracing::Span::current().record()` + JSON layer composition |
| OPS-12 | Audit hostname via gethostname() syscall | `gethostname` crate already in pam-unix-oidc; replace `audit.rs:427-431` |
| OPS-13 | Proof request logging at INFO level (username, target, signer type) | Structured `tracing::info!` in handle_connection for GetProof command |
</phase_requirements>

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `sd-notify` | 0.5.0 | systemd READY=1 / STOPPING=1 notification | No libsystemd FFI; pure Rust; handles NOTIFY_SOCKET not set gracefully |
| `listenfd` | 1.0.2 | Accept pre-bound fds from systemd socket activation | Validates LISTEN_PID match; prevents fd hijacking; handles edge cases |
| `figment` | 0.10.19 | Layered config (YAML + env var overrides with nested paths) | Already used in pam-unix-oidc; same pattern mandated by CONTEXT.md |
| `tracing-journald` | 0.3.2 | Structured tracing events direct to systemd journal | Adds PRIORITY, SYSLOG_IDENTIFIER, per-field TRACING_* keys; enables journalctl filtering |
| `tokio::signal` | 1.x | SIGTERM / SIGINT handling in async context | Already in tokio = "1" features = ["full"]; no new dep |
| `gethostname` | already in pam-unix-oidc | POSIX gethostname(2) syscall | Already present in project; no new dep |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `libc` | 0.2 (already present) | SO_PEERCRED, getpeereid syscalls + launchd FFI | Peer credential checking; macOS socket activation |
| `uuid` | 1.x (already present) | Request-scoped request_id span fields | One UUID per IPC connection for trace correlation |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `sd-notify` crate | Raw write to $NOTIFY_SOCKET | Raw protocol is 7 bytes but crate handles null-guard and env var absence |
| `listenfd` crate | Manual LISTEN_FDS parsing | listenfd validates LISTEN_PID match to prevent fd hijacking |
| `tracing-journald` | stdout captured by systemd journal | journald layer adds structured metadata (PRIORITY, per-field) for journalctl filtering |
| libc FFI for launch_activate_socket | `launch-rs` crate | launch-rs last released 2019, unmaintained; libc FFI is safer and more maintainable |

**Installation additions to `unix-oidc-agent/Cargo.toml`:**
```
sd-notify = "0.5"
listenfd = "1.0"
figment = { version = "0.10", features = ["yaml", "env"] }
tracing-journald = "0.3"
```

## Architecture Patterns

### Recommended Project Structure
```
unix-oidc-agent/
  src/
    main.rs                  # Add socket activation, signal handler, sd-notify, init_tracing
    config.rs                # Add TimeoutsConfig struct, figment loading, validation
    daemon/
      socket.rs              # Add peer credential check, idle timeout, request spans
      peer_cred.rs           # New: get_peer_credentials() function (Linux + macOS)
contrib/
  systemd/
    unix-oidc-agent.service  # New
    unix-oidc-agent.socket   # New
  launchd/
    com.unix-oidc.agent.plist.template  # New (template; install subcommand substitutes paths)
```

### Pattern 1: Socket Acquisition with Activation Fallback

**What:** Single `acquire_listener()` function covering systemd, launchd, and standalone.
**When to use:** Called once at the start of `run_serve()` replacing the current `UnixListener::bind()` call.

```rust
// Source: listenfd 1.0 — https://docs.rs/listenfd/latest/listenfd/
use listenfd::ListenFd;
use tokio::net::UnixListener;

fn acquire_listener(socket_path: &std::path::Path) -> std::io::Result<UnixListener> {
    // 1. systemd socket activation
    let mut listenfd = ListenFd::from_env();
    if let Some(listener) = listenfd.take_unix_listener(0)? {
        listener.set_nonblocking(true)?;
        return UnixListener::from_std(listener);
    }

    // 2. launchd socket activation (macOS only)
    #[cfg(target_os = "macos")]
    if let Some(listener) = launchd_socket::take("Listeners") {
        return Ok(listener);
    }

    // 3. Standalone: bind ourselves
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }
    let listener = UnixListener::bind(socket_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(listener)
}
```

### Pattern 2: sd-notify Readiness Sequence

**What:** Send READY=1 after the three readiness gates pass.
**When to use:** In `run_serve()` after socket is acquired, config is validated, JWKS fetch is attempted.

```rust
// Source: sd-notify 0.5 — https://docs.rs/sd-notify/0.5.0/sd_notify/
use sd_notify::NotifyState;

// Gate 1: socket acquired (listener returned from acquire_listener)
// Gate 2: config validated (AgentConfig::load() succeeded + timeouts.validate() passed)
// Gate 3: JWKS fetch attempted (best-effort; failure is WARN only)
match jwks_prefetch(&config).await {
    Ok(_) => info!("Initial JWKS prefetch succeeded"),
    Err(e) => warn!(error = %e, "Initial JWKS prefetch failed — will retry on first auth"),
}

// Send readiness regardless of JWKS result
let _ = sd_notify::notify(false, &[
    NotifyState::Ready,
    NotifyState::Status("unix-oidc-agent ready".to_string()),
]);
```

### Pattern 3: IPC Peer Credential Check

**What:** Extract peer UID on every accepted connection; reject mismatches fail-closed.
**When to use:** Immediately after `listener.accept()` in the serve loop, before spawning the handler task.

```rust
// Source: libc 0.2 — SO_PEERCRED (Linux socket(7)), getpeereid (macOS getpeereid(3))
// Called on the tokio::net::UnixStream via AsRawFd.

pub fn get_peer_credentials(
    stream: &tokio::net::UnixStream,
) -> std::io::Result<(u32, Option<u32>)> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let mut ucred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut ucred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok((ucred.uid, Some(ucred.pid as u32)));
    }

    #[cfg(target_os = "macos")]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        return Ok((uid, None));
    }

    // Fail-closed on unsupported platforms
    #[allow(unreachable_code)]
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer credential check not supported on this platform",
    ))
}

// In serve loop after accept:
let daemon_uid = unsafe { libc::getuid() };
match get_peer_credentials(&stream) {
    Ok((peer_uid, peer_pid)) => {
        if peer_uid != daemon_uid {
            warn!(peer_uid, daemon_uid, "IPC rejected: UID mismatch");
            return; // drop stream
        }
        if let Some(pid) = peer_pid {
            tracing::debug!(peer_pid = pid, "IPC connection accepted");
        }
    }
    Err(e) => {
        warn!(error = %e, "Peer credential retrieval failed — rejecting (fail-closed)");
        return;
    }
}
```

### Pattern 4: IPC Idle Timeout

**What:** Each read in the connection handler is wrapped with `tokio::time::timeout()`.
**When to use:** In `handle_connection()` wrapping the read-request loop.

```rust
use tokio::time::{timeout, Duration};

// Per-read timeout (not per-connection total)
let idle = Duration::from_secs(state_read.config.timeouts.ipc_idle_timeout_secs);
loop {
    match timeout(idle, read_next_request(&mut reader)).await {
        Ok(Ok(Some(req))) => handle_request(req, &mut writer, &state).await?,
        Ok(Ok(None)) => break, // client closed cleanly
        Ok(Err(e)) => { error!(error = %e, "IPC read error"); break; }
        Err(_elapsed) => {
            tracing::debug!("IPC connection closed: idle timeout");
            break;
        }
    }
}
```

### Pattern 5: Graceful Shutdown

**What:** tokio::select! races the accept loop against SIGTERM/SIGINT.
**When to use:** Replaces the current `loop { listener.accept() }` in `serve()`.

```rust
// Source: tokio::signal docs — https://docs.rs/tokio/latest/tokio/signal/unix/
use tokio::signal::unix::{signal, SignalKind};
use sd_notify::NotifyState;

// CRITICAL: Register signal handlers BEFORE the select! loop
let mut sigterm = signal(SignalKind::terminate())?;
let mut sigint  = signal(SignalKind::interrupt())?;

loop {
    tokio::select! {
        result = listener.accept() => {
            match result {
                Ok((stream, _)) => {
                    // peer check + spawn handler
                }
                Err(e) => error!(error = %e, "Accept error"),
            }
        }
        _ = sigterm.recv() => { info!("SIGTERM — shutting down"); break; }
        _ = sigint.recv()  => { info!("SIGINT — shutting down"); break; }
    }
}
// Notify systemd we're stopping
let _ = sd_notify::notify(false, &[NotifyState::Stopping]);
// 5s drain for in-flight requests
tokio::time::sleep(Duration::from_secs(5)).await;
run_credential_cleanup(&state).await;
```

### Pattern 6: figment-based AgentConfig with TimeoutsConfig

**What:** Replace `serde_yaml::from_str()` in `config.rs` with figment loading. Add nested `[timeouts]` section.

```rust
// Source: figment 0.10 — consistent with pam-unix-oidc/src/policy/config.rs pattern
use figment::{Figment, providers::{Format, Yaml, Env, Serialized}};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub issuer: String,
    #[serde(default = "default_client_id")]
    pub client_id: String,
    #[serde(default)]
    pub socket_path: Option<std::path::PathBuf>,
    #[serde(default)]
    pub crypto: CryptoConfig,
    #[serde(default)]
    pub timeouts: TimeoutsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutsConfig {
    #[serde(default = "d_jwks_http")]   pub jwks_http_timeout_secs: u64,        // 10
    #[serde(default = "d_device_flow")] pub device_flow_http_timeout_secs: u64, // 30
    #[serde(default = "d_skew_future")] pub clock_skew_future_secs: u64,        // 5
    #[serde(default = "d_skew_stale")]  pub clock_skew_staleness_secs: u64,     // 60
    #[serde(default = "d_jwks_ttl")]    pub jwks_cache_ttl_secs: u64,           // 300
    #[serde(default = "d_ipc_idle")]    pub ipc_idle_timeout_secs: u64,         // 60
}

impl AgentConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let config_path = Self::default_config_path();
        let mut fig = Figment::from(Serialized::defaults(AgentConfig::default()));
        if config_path.exists() {
            fig = fig.merge(Yaml::file(&config_path));
        }
        // UNIX_OIDC_TIMEOUTS__JWKS_CACHE_TTL_SECS etc.
        fig = fig.merge(Env::prefixed("UNIX_OIDC_").split("__").only(&[
            "issuer", "client_id", "socket_path",
            "timeouts__jwks_http_timeout_secs",
            "timeouts__device_flow_http_timeout_secs",
            "timeouts__clock_skew_future_secs",
            "timeouts__clock_skew_staleness_secs",
            "timeouts__jwks_cache_ttl_secs",
            "timeouts__ipc_idle_timeout_secs",
        ]));
        let mut config: Self = fig.extract()
            .map_err(|e| ConfigError::ParseError(e.to_string()))?;
        // Legacy shortcut: UNIX_OIDC_JWKS_CACHE_TTL (no nested path)
        if let Ok(v) = std::env::var("UNIX_OIDC_JWKS_CACHE_TTL") {
            if let Ok(secs) = v.parse::<u64>() {
                config.timeouts.jwks_cache_ttl_secs = secs;
            }
        }
        config.timeouts.validate()?;
        Ok(config)
    }
}

impl TimeoutsConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.jwks_http_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "timeouts.jwks_http_timeout_secs must be > 0".into()
            ));
        }
        if self.device_flow_http_timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "timeouts.device_flow_http_timeout_secs must be > 0".into()
            ));
        }
        if self.jwks_cache_ttl_secs < self.jwks_http_timeout_secs {
            return Err(ConfigError::Validation(
                "timeouts.jwks_cache_ttl_secs must be >= jwks_http_timeout_secs".into()
            ));
        }
        if self.clock_skew_future_secs > self.clock_skew_staleness_secs {
            return Err(ConfigError::Validation(
                "timeouts.clock_skew_future_secs must be <= clock_skew_staleness_secs".into()
            ));
        }
        Ok(())
    }
}
```

### Pattern 7: Tracing Layer Composition

**What:** Auto-detect JSON mode and compose layers in `main()`.
**When to use:** Replace the current `tracing_subscriber::fmt().with_env_filter(...).init()` call.

```rust
// Source: tracing-subscriber 0.3 + tracing-journald 0.3
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

pub fn init_tracing() {
    let filter = EnvFilter::from_default_env()
        .add_directive("unix_oidc_agent=info".parse().unwrap());

    // Auto-detect: explicit env var OR running under systemd (JOURNAL_STREAM is set by systemd)
    let use_json = std::env::var("UNIX_OIDC_LOG_FORMAT").as_deref() == Ok("json")
        || std::env::var("JOURNAL_STREAM").is_ok();

    if use_json {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer().json())
            .init();
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .init();
    }
    // tracing-journald: add as additional layer when JOURNAL_STREAM is set for
    // structured PRIORITY + per-field metadata. JSON-on-stdout is sufficient for
    // most deployments; journald layer is the enterprise upgrade path.
}
```

### Pattern 8: Request-Scoped Spans with #[instrument]

```rust
// Source: tracing 0.1 — https://docs.rs/tracing/latest/tracing/attr.instrument.html
use tracing::instrument;

// In socket.rs — outer span per IPC connection:
#[instrument(
    skip(stream, state),
    fields(
        request_id = %uuid::Uuid::new_v4(),
        command = tracing::field::Empty,
        peer_pid = tracing::field::Empty,
    )
)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    state: Arc<RwLock<AgentState>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // After parsing command variant:
    tracing::Span::current().record("command", &tracing::field::display("GetProof"));
    // After peer credential check:
    if let Some(pid) = peer_pid {
        tracing::Span::current().record("peer_pid", pid);
    }
    ...
}

// On key functions — child spans inherit request_id from parent:
#[instrument(skip(self, token_str), fields(issuer = %self.config.issuer))]
pub async fn validate_token(&self, token_str: &str) -> Result<Claims, ValidationError> { ... }

#[instrument(skip(self, proof), fields(htm, htu))]
pub fn verify_dpop_proof(&self, proof: &str, htm: &str, htu: &str) -> Result<DpopResult, DpopError> { ... }

#[instrument(skip(self))]
pub async fn fetch_jwks(&self) -> Result<JwkSet, JwksError> { ... }
```

### Pattern 9: OPS-13 GetProof Logging

```rust
// In handle_connection, when command is GetProof:
tracing::info!(
    username = %token_claims.username,
    target = %target_host,
    signer_type = %state_read.signer_type.as_deref().unwrap_or("unknown"),
    "DPoP proof requested"
);
```

### Pattern 10: macOS launchd Socket Activation

```rust
// Source: Apple man page launch_activate_socket(3) — available macOS 10.9+
// No crate needed — thin libc FFI wrapper is sufficient.

#[cfg(target_os = "macos")]
mod launchd_socket {
    use std::os::unix::io::FromRawFd;

    extern "C" {
        fn launch_activate_socket(
            name: *const libc::c_char,
            fds: *mut *mut libc::c_int,
            cnt: *mut libc::size_t,
        ) -> libc::c_int;
    }

    pub fn take(name: &str) -> Option<tokio::net::UnixListener> {
        let cname = std::ffi::CString::new(name).ok()?;
        let mut fds: *mut libc::c_int = std::ptr::null_mut();
        let mut cnt: libc::size_t = 0;
        let ret = unsafe { launch_activate_socket(cname.as_ptr(), &mut fds, &mut cnt) };
        if ret != 0 || cnt == 0 || fds.is_null() {
            return None;
        }
        let fd = unsafe { *fds };
        unsafe { libc::free(fds as *mut libc::c_void) };
        let std_listener = unsafe {
            std::os::unix::net::UnixListener::from_raw_fd(fd)
        };
        std_listener.set_nonblocking(true).ok()?;
        tokio::net::UnixListener::from_std(std_listener).ok()
    }
}
```

### Pattern 11: OPS-12 Hostname via gethostname()

```rust
// Source: gethostname crate — already in pam-unix-oidc/Cargo.toml
// In pam-unix-oidc/src/audit.rs, replace get_hostname() at line 427:

fn get_hostname() -> String {
    // POSIX gethostname(2) — reliable in containers and minimal environments.
    // Env var UNIX_OIDC_HOSTNAME as operator override (e.g. CNAME vs hostname).
    std::env::var("UNIX_OIDC_HOSTNAME")
        .unwrap_or_else(|_| {
            gethostname::gethostname()
                .to_string_lossy()
                .into_owned()
        })
}
```

### systemd User Service Unit Files

```ini
# contrib/systemd/unix-oidc-agent.socket
[Unit]
Description=OIDC Authentication Agent Socket
Documentation=https://github.com/prodnull/unix-oidc

[Socket]
ListenStream=%t/unix-oidc-agent.sock
SocketMode=0600

[Install]
WantedBy=sockets.target
```

```ini
# contrib/systemd/unix-oidc-agent.service
[Unit]
Description=OIDC Authentication Agent
Documentation=https://github.com/prodnull/unix-oidc
Requires=unix-oidc-agent.socket
After=unix-oidc-agent.socket network-online.target

[Service]
Type=notify
ExecStart=%h/.cargo/bin/unix-oidc-agent serve
Restart=on-failure
RestartSec=5s

# Hardening directives — NIST SP 800-123 least-privilege baseline
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
MemoryDenyWriteExecute=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
PrivateTmp=yes
SystemCallFilter=@system-service @network-io

# Allow writes to agent data and config dirs (required for file storage backend)
ReadWritePaths=%h/.local/share/unix-oidc %h/.config/unix-oidc

[Install]
WantedBy=default.target
```

**Key unit details:**
- `Type=notify` — systemd waits for `READY=1` before marking service active. Without this, `After=unix-oidc-agent.socket` is satisfied before the daemon is ready.
- `%t` — expands to `$XDG_RUNTIME_DIR` (e.g., `/run/user/1000`) in user service context. This is the correct socket directory.
- `%h` — expands to `$HOME` in user service context.
- `ReadWritePaths` — without this, `ProtectSystem=strict` prevents writes to `~/.local/share/` and `~/.config/`, breaking file storage backend and config reload.

### Anti-Patterns to Avoid

- **`ProtectSystem=strict` without `ReadWritePaths`:** File storage backend fails silently; config writes fail. Always add write paths.
- **`sd_notify::notify()` before socket is bound:** systemd marks service ready before it can accept connections. Order: bind socket, validate config, attempt JWKS, THEN send READY=1.
- **`tokio::signal::unix::signal()` registered inside the select! loop:** Signals delivered before registration are lost. Register at start of `run_serve()` before any await.
- **launchd `SockPathName` with systemd-style specifiers like `%uid%`:** launchd does not expand specifiers; the install helper must substitute the real path.
- **`getsockopt SO_PEERCRED` on the listener fd instead of the accepted stream fd:** Must call on the accepted stream.
- **Omitting `Type=notify` when using sd-notify:** `systemctl start` returns immediately; `After=` ordering is not enforced.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| systemd READY=1 notification | Custom write to $NOTIFY_SOCKET | `sd-notify 0.5` | Handles env var not set, null guard, correct socket protocol |
| systemd fd inheritance | Manual LISTEN_FDS parsing | `listenfd 1.0` | Validates LISTEN_PID match; prevents fd hijacking |
| JSON structured logs | Custom serde_json serializer | tracing-subscriber fmt().json() | One-line builder; already a workspace dep |
| Layered config (YAML + env) | Custom merge logic | `figment 0.10` | Identical pattern already established in pam-unix-oidc |
| macOS socket path resolution | Hardcoded /tmp/... | $TMPDIR at install time | macOS sets TMPDIR per-user to sandboxed path; /tmp may be inaccessible |

**Key insight:** Every integration problem in this phase has an existing, tested solution. The work is wiring, not invention.

## Common Pitfalls

### Pitfall 1: ProtectSystem=strict Breaks File Storage Backend

**What goes wrong:** After enabling `ProtectSystem=strict`, the file storage backend (`~/.local/share/unix-oidc/`) becomes read-only. Credential writes silently fail; daemon starts but cannot persist tokens.

**Why it happens:** `ProtectSystem=strict` mounts the entire filesystem read-only except for an explicit `ReadWritePaths` allowlist.

**How to avoid:** Include `ReadWritePaths=%h/.local/share/unix-oidc %h/.config/unix-oidc` in the service unit. Verify with `systemd-analyze security unix-oidc-agent.service`.

**Warning signs:** `unix-oidc-agent status` shows storage backend as "unknown"; login appears to succeed but token is lost on next command.

### Pitfall 2: Signal Handlers Registered Too Late

**What goes wrong:** SIGTERM sent during startup (before the select! loop) is lost. `systemctl stop` hangs; systemd escalates to SIGKILL after `TimeoutStopSec`.

**Why it happens:** `tokio::signal::unix::signal()` only captures signals delivered after registration. The kernel does not queue signals for late receivers.

**How to avoid:** Register both SIGTERM and SIGINT handlers at the very top of `run_serve()`, before any `await` points.

**Warning signs:** `systemctl stop` takes exactly `TimeoutStopSec` seconds (default 90s) before killing the process.

### Pitfall 3: launchd Specifier Not Expanded

**What goes wrong:** Plist template uses `%uid%` or `$XDG_RUNTIME_DIR` literally; launchd creates socket with literal string in path.

**Why it happens:** launchd does not support systemd-style unit specifiers in `SockPathName`.

**How to avoid:** The `unix-oidc-agent install` subcommand reads `std::env::var("TMPDIR")` (which macOS sets per-user) at install time and substitutes the actual socket path before writing the plist.

**Warning signs:** Socket file has literal `%uid%` in path; `launchctl list com.unix-oidc.agent` shows socket error.

### Pitfall 4: MemoryDenyWriteExecute with Hardware Signers

**What goes wrong:** With `--features yubikey`, some PKCS#11 libraries call `mprotect(PROT_WRITE|PROT_EXEC)` internally. The `MemoryDenyWriteExecute=yes` directive blocks this with `SIGSYS`.

**Why it happens:** Certain PKCS#11 implementations use JIT-style code patching.

**How to avoid:** Test all feature combinations (`--features yubikey`, `--features tpm`) under the hardened unit. If crashes occur with hardware signers, document `MemoryDenyWriteExecute=no` as a commented-out override in the unit file.

**Warning signs:** Crash with `SIGSYS` signal when using YubiKey signer; does not occur with software signer.

### Pitfall 5: Peer Credential Check in Containers

**What goes wrong:** In Docker containers without `--pid=host`, `SO_PEERCRED` may return PID 0 or ENOTSUP. If the code fails-closed on PID retrieval failure, legitimate connections are rejected.

**Why it happens:** PID namespace isolation; the host-namespace PID of the peer is not visible inside the container.

**How to avoid:** The security-critical check is UID match, not PID. PID is logged at DEBUG only. The code in `get_peer_credentials()` returns `pid: Option<u32>`; `None` is acceptable. Do not fail-close on missing PID; only fail-close on UID retrieval failure.

**Warning signs:** Connections rejected inside containers even from the same user.

### Pitfall 6: tracing_subscriber Double Init in Tests

**What goes wrong:** Tests that call `init_tracing()` panic: "attempted to set a logger after the logging system was already initialized".

**Why it happens:** `tracing_subscriber` uses a global once-cell; calling `init()` twice panics.

**How to avoid:** Tests should use `tracing_subscriber::fmt().try_init().ok()` (ignoring the error) or the `tracing-test` crate's `#[traced_test]` attribute.

**Warning signs:** Test panic at "a global subscriber has already been set".

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `std::process::exit(0)` in Shutdown IPC handler | `tokio::select!` on SIGTERM in accept loop | Phase 13 | Clean credential cleanup; drain in-flight requests |
| `std::env::var("HOSTNAME")` with fallback | `gethostname::gethostname()` POSIX syscall | Phase 13 | Reliable in containers and minimal environments where env vars are absent |
| Hardcoded `HTTP_TIMEOUT_SECS = 10`, `DEFAULT_CACHE_TTL_SECS = 300` | Configurable `[timeouts]` section | Phase 13 | Operator-tunable for high-latency IdP environments |
| Single `tracing_subscriber::fmt().init()` | Layered registry with JSON auto-detect | Phase 13 | Log aggregation (ELK, Datadog, Splunk) without custom parsers |
| `serde_yaml::from_str()` in `AgentConfig` | `figment` layered loading | Phase 13 | Consistent with pam-unix-oidc; enables env var overrides via `UNIX_OIDC_TIMEOUTS__` prefix |

**Deprecated/outdated:**
- `AgentConfig::from_file()` and `AgentConfig::from_env()` — replaced by `AgentConfig::load()` using figment. The two-method split prevents env var overrides from composing with file config.
- Hardcoded `println!("Press Ctrl+C to stop")` in `run_serve()` — replace with structured tracing log; daemon should not write to stdout when running under systemd.
- Shutdown via IPC `Shutdown` command calling `std::process::exit(0)` — this does not run cleanup. SIGTERM handler is the correct mechanism; the Shutdown IPC command can remain as a convenience that sends SIGTERM to self.

## Open Questions

1. **`tracing-journald` vs JSON stdout under systemd**
   - What we know: systemd captures stdout to journal by default (`StandardOutput=journal` in service unit). JSON structured output in the journal is readable via `journalctl -o json`. This covers basic structured logging needs.
   - What's unclear: `tracing-journald` additionally maps tracing `Level` to `PRIORITY`, adds `SYSLOG_IDENTIFIER`, and emits per-field `TRACING_*` journal keys enabling `journalctl TRACING_TARGET=...` filtering. These are not achievable with JSON-on-stdout.
   - Recommendation: Add `tracing-journald 0.3` as an additional layer activated when `JOURNAL_STREAM` is set. The dependency is 95 lines of safe Rust. Enterprise deployments (SOC2, regulated environments) will want the structured journal metadata. Cost is minimal; benefit is material.

2. **ReadWritePaths under ProtectHome=read-only**
   - What we know: `ProtectHome=read-only` + `ReadWritePaths=%h/.local/share/unix-oidc` should allow writes to the agent's data directory.
   - What's unclear: Whether keyutils user keyring and Secret Service (D-Bus) also need explicit access grants under the hardened unit. D-Bus uses abstract sockets, which `PrivateTmp=yes` does not affect, but `RestrictNamespaces=yes` may interfere.
   - Recommendation: Test D-Bus connectivity under the hardened unit during implementation. If Secret Service fails, add `RestrictNamespaces=~net` (exclude network namespace but allow others) as a fallback.

3. **Install subcommand binary path on macOS**
   - What we know: The launchd plist `ProgramArguments` needs an absolute path. `cargo install` places binaries in `~/.cargo/bin/`; system installs use `/usr/local/bin/`.
   - What's unclear: Which path to use as default in the install helper.
   - Recommendation: Use `std::env::current_exe()` to get the currently-running binary path; this is the correct default. Allow `--binary-path` flag override.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in tests + integration tests |
| Config file | `Cargo.toml` workspace; no separate test config |
| Quick run command | `cargo test -p unix-oidc-agent 2>&1 \| tail -20` |
| Full suite command | `cargo test --workspace 2>&1 \| tail -40` |

### Phase Requirements to Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| OPS-01 | systemd unit file valid syntax and hardening directives present | manual | `systemd-analyze verify contrib/systemd/unix-oidc-agent.service` | ❌ Wave 0 |
| OPS-02 | acquire_listener() falls through to standalone when LISTEN_FDS absent | unit | `cargo test -p unix-oidc-agent test_socket_activation_standalone_fallback` | ❌ Wave 0 |
| OPS-03 | launchd plist generated correctly with real socket path | unit | `cargo test -p unix-oidc-agent test_plist_generation` | ❌ Wave 0 |
| OPS-04 | sd-notify READY called after all three gates | unit | `cargo test -p unix-oidc-agent test_readiness_gate_order` | ❌ Wave 0 |
| OPS-05 | UID mismatch causes connection rejection; UID match accepted | unit | `cargo test -p unix-oidc-agent test_peer_credential_uid_check` | ❌ Wave 0 |
| OPS-06 | Read loop closed after ipc_idle_timeout_secs with no data | unit | `cargo test -p unix-oidc-agent test_ipc_idle_timeout` | ❌ Wave 0 |
| OPS-07 | jwks_http_timeout_secs wired to reqwest client timeout | unit | `cargo test -p unix-oidc-agent test_config_timeouts_defaults` | ❌ Wave 0 |
| OPS-08 | device_flow_http_timeout_secs wired to device flow client | unit | (same test) | ❌ Wave 0 |
| OPS-09 | clock_skew values wired to token validation | unit | (same test) | ❌ Wave 0 |
| OPS-10 | UNIX_OIDC_JWKS_CACHE_TTL env var overrides jwks_cache_ttl_secs | unit | `cargo test -p unix-oidc-agent test_jwks_cache_ttl_env_override` | ❌ Wave 0 |
| OPS-11 | handle_connection span contains request_id, command, peer_pid | unit | `cargo test -p unix-oidc-agent test_request_span_fields` | ❌ Wave 0 |
| OPS-12 | get_hostname() returns syscall result, not env var | unit | `cargo test -p pam-unix-oidc test_get_hostname_syscall` | ❌ Wave 0 |
| OPS-13 | GetProof emits INFO log with username, target, signer_type | integration | `cargo test -p unix-oidc-agent --test daemon_lifecycle test_getproof_logging` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p unix-oidc-agent 2>&1 | tail -20`
- **Per wave merge:** `cargo test --workspace 2>&1 | tail -40`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `unix-oidc-agent/tests/ops_hardening.rs` — new integration test file covering OPS-02 through OPS-13
- [ ] `unix-oidc-agent/src/daemon/peer_cred.rs` — new module for `get_peer_credentials()` (unit-testable via mock fd)
- [ ] Inline tests in `unix-oidc-agent/src/config.rs` for TimeoutsConfig validation
- [ ] `tracing-test = "0.2"` dev-dependency for span field assertions (OPS-11)
- [ ] `pam-unix-oidc/src/audit.rs` test for updated `get_hostname()` (OPS-12)

## Sources

### Primary (HIGH confidence)
- `sd-notify 0.5.0` — `cargo search sd-notify` confirmed version; NotifyState::Ready/Stopping API
- `listenfd 1.0.2` — `cargo search listenfd` confirmed version; ListenFd::from_env() + take_unix_listener() API
- `tracing-journald 0.3.2` — `cargo search tracing-journald` confirmed version
- `figment 0.10.19` — confirmed in `pam-unix-oidc/Cargo.toml`; Env::prefixed().split("__") pattern verified in `pam-unix-oidc/src/policy/config.rs`
- `tokio::signal::unix` — part of `tokio = "1"` features=["full"] already in Cargo.toml; SignalKind::terminate() API
- Codebase read: `unix-oidc-agent/src/main.rs`, `src/config.rs`, `src/daemon/socket.rs`, `src/security.rs`, `pam-unix-oidc/src/audit.rs` lines 427-431, `pam-unix-oidc/src/oidc/jwks.rs` lines 1-50, `unix-oidc-agent/Cargo.toml`
- systemd `Type=notify`, `%t`, `%h` specifiers — systemd.unit(5), systemd.exec(5)
- `launch_activate_socket(3)` — Apple developer documentation (macOS 10.9+)
- `SO_PEERCRED` — Linux socket(7) man page; `getpeereid(3)` — BSD man page

### Secondary (MEDIUM confidence)
- `ProtectSystem=strict` + `ReadWritePaths` interaction — systemd.exec(5) documentation
- `MemoryDenyWriteExecute=yes` safety for pure Rust binaries — systemd security hardening guide
- `JOURNAL_STREAM` env var set by systemd — systemd.exec(5), verified behavior

### Tertiary (LOW confidence)
- `SockPathMode` decimal value 384 for 0600 — standard Unix octal-to-decimal; needs verification via `plutil -lint`
- D-Bus accessibility under `RestrictNamespaces=yes` — needs testing; behavior may vary by systemd version

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all crate versions confirmed via cargo search and existing Cargo.toml
- Architecture: HIGH — patterns drawn from existing codebase + verified API docs
- systemd unit files: HIGH — specifiers and directives from official systemd man pages
- macOS launchd: MEDIUM — launch_activate_socket FFI verified by Apple docs; SockPathMode decimal value needs validation
- Pitfalls: HIGH — drawn from known systemd deployment patterns and codebase analysis

**Research date:** 2026-03-11
**Valid until:** 2026-06-11 (figment, sd-notify, listenfd, tracing-journald are stable; systemd user service patterns are stable)
