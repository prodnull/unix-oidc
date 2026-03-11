# Phase 9: Token Introspection + Session Lifecycle + Token Refresh — Research

**Researched:** 2026-03-11
**Domain:** PAM session lifecycle, OAuth 2.0 RFC 7662 / RFC 7009, Tokio background tasks, tmpfs session records
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Token Introspection (SES-05, SES-06)**
- RFC 7662 introspection is opt-in via `[introspection]` section in policy.yaml (global toggle, not per-provider)
- Default: disabled. When enabled, default fail-open (auth succeeds if introspection endpoint is unreachable)
- Introspection runs at auth time AND periodically during open sessions via the agent daemon
- If introspection returns `active: false`, the agent writes a revocation marker to `/run/unix-oidc/sessions/{id}.revoked` — sshd detects and terminates the session
- The token never leaves the agent for introspection — no new attack surface
- Introspection cache via moka with TTL = `min(configured_ttl, token_exp - now)`, default 60s
- Overhead: one HTTP call per cache TTL per active session (from agent, which already makes HTTP calls for refresh)

**Session Record Lifecycle (SES-01, SES-02, SES-03)**
- `pam_sm_open_session` writes JSON session record to `/run/unix-oidc/sessions/{session_id}.json`
- Record contents (~200 bytes): username, token_jti, token_exp, session_start, client_ip, sshd_pid, issuer
- `pam_sm_close_session` deletes the session record and emits a session-close audit event with duration
- Session ID correlation between authenticate and open_session via PAM environment variable: `pam_putenv("UNIX_OIDC_SESSION_ID=...")` in authenticate, `pam_getenv()` in open_session — works across sshd forks
- `/run/unix-oidc/sessions/` directory: root-owned, mode 0700. Session files: root-owned, mode 0600
- tmpfs loss on reboot accepted: startup scan detects missing session records, emits "session lost to restart" audit events, cleans up agent-side state
- Enables future `unix-oidc sessions list` CLI command

**Auto-Refresh Scheduling (SES-04)**
- Background `tokio::spawn` task in agent daemon, spawned at login
- Sleeps until 80% of token lifetime (configurable: `token_refresh_threshold_percent`, default 80)
- Re-arms after each successful refresh; task cancelled on session close
- On refresh failure: exponential backoff (5s, 10s, 20s, 40s) up to 3 retries; if all fail, log WARN and set `refresh_failed: true` in IPC status responses; session continues until natural expiry
- After successful refresh, run introspection on the new token (if enabled)

**Revocation on Session Close (SES-07, SES-08)**
- PAM `close_session` sends `SessionClosed` IPC message to agent daemon
- Agent immediately ACKs (fire-and-forget) so close_session returns quickly, then spawns tokio task for revocation + cleanup
- Revocation: best-effort RFC 7009 call with 5s timeout; failure logged at WARN
- `pam_sm_close_session` ALWAYS returns PAM_SUCCESS regardless of revocation outcome
- Full credential cleanup on SessionClosed: revoke token → zeroize DPoP signing key → delete refresh token → delete access token → delete token metadata

### Claude's Discretion
- Introspection client implementation details (reqwest client reuse, endpoint discovery from OIDC metadata)
- Stale cache behavior when introspection endpoint is unreachable (serve stale vs fall back to configured mode)
- Exact session record JSON schema field names
- Revocation marker file format and detection mechanism
- IPC protocol extension design for SessionClosed message
- Introspection + refresh task coordination in agent event loop
- Test strategy structure (unit, integration, adversarial)

### Deferred Ideas (OUT OF SCOPE)
- Per-provider introspection config for multi-IdP deployments
- Persistent session records in /var/lib/ for reboot durability
- Configurable revocation failure behavior (strict mode that blocks session teardown)
- `unix-oidc sessions list` CLI command
- Direct sshd signal (SIGTERM) for introspection-triggered session kill
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SES-01 | `pam_sm_open_session` writes session record to tmpfs store (`/run/unix-oidc/sessions/`) | Session record format, atomic write, Unix permissions pattern documented below |
| SES-02 | `pam_sm_close_session` deletes session record and emits session-close audit event with duration | AuditEvent extension pattern, secure file removal documented below |
| SES-03 | Session correlation via `pam_set_data()` between authenticate and open_session calls | Verified: pamsm 0.5 exposes `putenv`/`getenv` (PAM environment), NOT pam_set_data — see pitfall SES-03 below |
| SES-04 | Automatic token refresh in agent daemon at configurable TTL threshold (default 80%) | Tokio background task with AbortHandle / CancellationToken pattern documented |
| SES-05 | Token introspection (RFC 7662) as opt-in validation step with configurable fail-open/fail-closed | Full RFC 7662 request/response format documented; EnforcementMode reuse confirmed |
| SES-06 | Introspection result caching via moka with TTL bounded by min(60s, token exp - now) | moka sync::Cache TTL pattern already used in nonce_cache.rs — identical construction |
| SES-07 | RFC 7009 token revocation on session close (best-effort, 5s timeout) | RFC 7009 POST format documented; revocation_endpoint discovery caveats noted |
| SES-08 | Agent SessionClosed IPC event to schedule orphaned DPoP key cleanup | AgentRequest extension pattern documented; ProtectedSigningKey ZeroizeOnDrop confirmed |
</phase_requirements>

---

## Summary

Phase 9 spans two crates (`pam-unix-oidc` and `unix-oidc-agent`) and three independent feature areas: session record lifecycle (PAM layer), token introspection (RFC 7662 optional validation), and background token refresh with revocation (agent daemon). All three converge at the `pam_sm_close_session` path.

The dominant architectural risk is the PAM session correlation mechanism. The CONTEXT.md decision to use `pam_putenv`/`pam_getenv` is correct: pamsm 0.5's `PamLibExt` trait exposes `putenv(&str)` and `getenv(&str)` methods. The critical pitfall is that `pam_set_data` / `send_data` in pamsm is process-local and does NOT survive sshd's privsep fork between authentication and session management processes. The PAM environment (`pam_putenv`) IS propagated by sshd via `pam_getenvlist` to the session child process — this is the correct mechanism.

The second architectural domain is the agent's background refresh task. The established pattern is `tokio::spawn` returning a `JoinHandle` whose `AbortHandle` is stored in `AgentState` for cancellation on `SessionClosed`. Dropping a `JoinHandle` does NOT cancel the task — `abort()` must be called explicitly. `CancellationToken` from `tokio-util` is an alternative for cooperative cancellation.

For RFC 7662 introspection and RFC 7009 revocation: both endpoints follow identical HTTP POST `application/x-www-form-urlencoded` form patterns already used in `perform_token_refresh()`. The introspection_endpoint and revocation_endpoint are advertised in the OIDC discovery document but not all providers publish them — the client must handle absence gracefully and log a WARN rather than fail.

**Primary recommendation:** Implement session records, IPC extensions, and introspection/revocation as three separate plans within this phase. The moka cache, reqwest blocking client, EnforcementMode, and AuditEvent patterns are all directly reusable from prior phases — no new dependencies are required.

---

## Standard Stack

### Core (already in workspace — no new deps needed)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `moka` | 0.12 | Introspection result TTL cache | Already used for nonce cache (Phase 7) — identical construction pattern |
| `reqwest` (blocking) | 0.11 | HTTP calls for introspection + revocation | Already used in `perform_token_refresh()`; pattern is established |
| `tokio` | 1.x | Background refresh task; `spawn`, `AbortHandle` | Already the agent's async runtime |
| `serde_json` | 1.0 | Session record JSON serialization/deserialization | Already in both crates |
| `pamsm` | 0.5 | PAM bindings — `putenv`, `getenv`, `open_session`, `close_session` stubs | Already the PAM binding crate |
| `parking_lot::RwLock` | 0.12 | Thread-safe AgentState mutation | Established pattern from Phase 6+ |
| `secrecy::SecretString` | 0.10 | Token values in agent — MEM-03 invariant | Already used in AgentState.access_token |
| `std::os::unix::fs::PermissionsExt` | std | Set 0o600/0o700 on session files | stdlib, no dep needed |
| `std::fs` | std | Create dir, write/delete session records | stdlib |
| `tracing` | 0.1 | Structured logging across all new paths | Already project-wide |
| `thiserror` | 1.0 | Error types for new modules | Already project-wide |

### No New Dependencies Required

All required functionality is covered by existing workspace dependencies. This is by design — the session lifecycle, introspection, and revocation patterns all reuse established building blocks.

**The one discretionary question:** Should the exponential backoff in the refresh retry loop be hand-rolled (5s → 10s → 20s → 40s, 3 retries, as specified in CONTEXT.md) or use a crate like `backoff` or `tokio-retry`? Hand-rolling is recommended here because:
- The retry policy is simple, fixed, and already fully specified
- Adding a dep for 4 lines of arithmetic would be over-engineering
- The `backoff` crate adds jitter by default — our specification is deterministic

---

## Architecture Patterns

### Recommended New Module Layout

```
pam-unix-oidc/src/
├── oidc/
│   ├── introspection.rs    # NEW: RFC 7662 client + moka cache
│   └── (existing: dpop.rs, jwks.rs, token.rs, validation.rs)
├── session/
│   └── mod.rs              # NEW: session record read/write/delete + directory init
├── policy/
│   └── config.rs           # EXTEND: add IntrospectionConfig + SessionConfig structs
├── audit.rs                # EXTEND: add SessionOpened, SessionClosed, TokenRevoked, IntrospectionFailed variants
└── lib.rs                  # EXTEND: implement open_session + close_session stubs

unix-oidc-agent/src/daemon/
├── protocol.rs             # EXTEND: add SessionClosed request + SessionAcknowledged response
├── socket.rs               # EXTEND: SessionClosed handler + spawn revocation+cleanup task
│                           #         + spawn auto-refresh background task on login
└── refresh.rs              # NEW (optional extract): background refresh scheduling logic
```

### Pattern 1: Session Record Atomic Write

**What:** Write a JSON session record to tmpfs, set Unix permissions, handle partial failure.
**When to use:** In `pam_sm_open_session`.

```rust
// Source: std::fs + std::os::unix::fs::PermissionsExt
use std::fs::{self, OpenOptions};
use std::os::unix::fs::PermissionsExt;

// Ensure directory exists with 0700 (root-owned).
// Called once at module init; idempotent.
fn ensure_session_dir() -> std::io::Result<()> {
    let dir = std::path::Path::new("/run/unix-oidc/sessions");
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

// Write session record. Use write-then-rename for atomicity.
fn write_session_record(session_id: &str, record: &SessionRecord) -> std::io::Result<()> {
    let path = format!("/run/unix-oidc/sessions/{session_id}.json");
    let tmp_path = format!("{path}.tmp");
    let json = serde_json::to_string(record)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(&tmp_path, json.as_bytes())?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp_path, &path)?;  // atomic on same filesystem
    Ok(())
}
```

**Security note:** Write to `.tmp` then `rename` is atomic on the same filesystem (tmpfs). This prevents `pam_sm_close_session` from seeing a partial record.

### Pattern 2: PAM Environment Variable Session Correlation

**What:** Pass the session ID from `authenticate` to `open_session` via PAM environment (not `pam_set_data`, which is process-local).
**When to use:** The only correct cross-fork correlation mechanism.

```rust
// In authenticate() — after generating session_id:
// pamsm PamLibExt::putenv() is the method name, not pam_putenv
pamh.putenv(&format!("UNIX_OIDC_SESSION_ID={session_id}"))
    .map_err(|e| {
        tracing::warn!(error = ?e, "Failed to set session ID env var");
        PamError::SESSION_ERR
    })?;

// In open_session() — reading back:
let session_id: Option<String> = pamh
    .getenv("UNIX_OIDC_SESSION_ID")
    .ok()
    .flatten()
    .map(|s| s.to_string_lossy().into_owned());
```

**Critical:** `pamsm::PamLibExt::putenv` takes `&str` in `"NAME=VALUE"` format. `getenv` returns `PamResult<Option<&CStr>>`.

### Pattern 3: RFC 7662 Introspection Client

**What:** POST token to introspection endpoint, parse `active` boolean from response.
**When to use:** Called at auth time (if enabled) and periodically from agent daemon.

```rust
// Source: RFC 7662 §2.1 + reqwest blocking pattern from perform_token_refresh()
pub struct IntrospectionClient {
    http_client: reqwest::blocking::Client,
    endpoint: String,
    // client credentials for authenticating to the introspection endpoint
    client_id: String,
    client_secret: Option<SecretString>,
}

impl IntrospectionClient {
    pub fn introspect(&self, token: &str) -> Result<bool, IntrospectionError> {
        // RFC 7662 §2.1: POST with application/x-www-form-urlencoded
        let params = [
            ("token", token),
            ("token_type_hint", "access_token"),
        ];
        let response = self.http_client
            .post(&self.endpoint)
            .basic_auth(&self.client_id,
                        self.client_secret.as_ref().map(|s| s.expose_secret()))
            .form(&params)
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .map_err(IntrospectionError::Http)?;

        let body: serde_json::Value = response.json().map_err(IntrospectionError::Parse)?;
        // RFC 7662 §2.2: "active" is REQUIRED boolean
        Ok(body["active"].as_bool().unwrap_or(false))
    }
}
```

**Important:** The introspection endpoint MUST require client authentication (RFC 7662 §2.1). Use Basic Auth with client_id/client_secret. Never pass the token as a query parameter.

### Pattern 4: moka Introspection Cache (TTL-bounded)

**What:** Cache introspection results to avoid per-request HTTP calls.
**When to use:** Wrap every `IntrospectionClient::introspect()` call.

```rust
// Source: Identical pattern to DPoPNonceCache in nonce_cache.rs
use moka::sync::Cache;
use std::time::Duration;

pub struct IntrospectionCache {
    inner: Cache<String, bool>,  // key: token JTI or fingerprint; value: active
}

impl IntrospectionCache {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            inner: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(ttl_secs))
                .build(),
        }
    }

    /// Effective TTL = min(configured_ttl, token_exp - now).
    /// This ensures cache entries don't outlive the token they represent.
    pub fn get_or_introspect(
        &self,
        cache_key: &str,
        introspect_fn: impl FnOnce() -> Result<bool, IntrospectionError>,
    ) -> Result<bool, IntrospectionError> {
        if let Some(cached) = self.inner.get(cache_key) {
            return Ok(cached);
        }
        let result = introspect_fn()?;
        self.inner.insert(cache_key.to_string(), result);
        Ok(result)
    }
}
```

**Cache key:** Use the token's JTI claim as the cache key (not the raw token — avoids storing sensitive material as a map key). If JTI is absent, use a SHA-256 digest of the token's first 32 bytes.

### Pattern 5: Background Refresh Task with Abort

**What:** `tokio::spawn` a task that sleeps until 80% of token lifetime then refreshes. Store `AbortHandle` in `AgentState` for cancellation on `SessionClosed`.
**When to use:** On successful login in the agent daemon.

```rust
// Source: tokio docs — JoinHandle::abort() is required, drop does NOT cancel
use tokio::task::AbortHandle;

// In AgentState, add:
pub refresh_task: Option<AbortHandle>,

// Spawning the refresh task:
fn spawn_refresh_task(
    state: Arc<RwLock<AgentState>>,
    token_expires: i64,
    threshold_percent: u8,
) -> AbortHandle {
    let handle = tokio::spawn(async move {
        loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let lifetime = token_expires - now;
            let sleep_secs = (lifetime * threshold_percent as i64) / 100;

            if sleep_secs <= 0 {
                tracing::warn!("Token already past refresh threshold, refreshing immediately");
                break;  // fall through to refresh
            }
            tokio::time::sleep(Duration::from_secs(sleep_secs as u64)).await;

            // Exponential backoff retry: 5s, 10s, 20s, 40s
            let mut backoff_secs = 5u64;
            for attempt in 0..=3 {
                match perform_token_refresh(&state).await {
                    Ok((_, new_expires, _)) => {
                        token_expires = new_expires;  // re-arm
                        break;
                    }
                    Err(e) if attempt < 3 => {
                        tracing::warn!(attempt, error = %e, "Token refresh failed, retrying");
                        tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                        backoff_secs *= 2;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "Token refresh failed after 3 retries");
                        // Set refresh_failed flag in state
                        let mut s = state.write().await;
                        s.refresh_failed = true;
                        return;  // task exits; session will expire naturally
                    }
                }
            }
        }
    });
    handle.abort_handle()
}

// Cancellation in SessionClosed handler:
if let Some(handle) = state.refresh_task.take() {
    handle.abort();
}
```

### Pattern 6: RFC 7009 Revocation (Best-Effort)

**What:** POST the access token or refresh token to the revocation endpoint before cleanup.
**When to use:** In the SessionClosed handler, before credential zeroization.

```rust
// Source: RFC 7009 §2.1 — same HTTP form pattern as introspection
async fn revoke_token_best_effort(
    token: &str,
    revocation_endpoint: &str,
    client_id: &str,
    client_secret: Option<&str>,
) {
    let result = tokio::task::spawn_blocking({
        let token = token.to_string();
        let endpoint = revocation_endpoint.to_string();
        let cid = client_id.to_string();
        let secret = client_secret.map(String::from);
        move || -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            let client = reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()?;
            let params = [("token", token.as_str()), ("token_type_hint", "access_token")];
            let mut req = client.post(&endpoint).form(&params);
            if let Some(ref s) = secret {
                req = req.basic_auth(&cid, Some(s.as_str()));
            } else {
                req = req.basic_auth(&cid, None::<&str>);
            }
            let resp = req.send()?;
            if !resp.status().is_success() {
                tracing::warn!(status = %resp.status(), "Revocation endpoint returned non-2xx");
            }
            Ok(())
        }
    }).await;

    match result {
        Ok(Err(e)) => tracing::warn!(error = %e, "Token revocation failed (best-effort)"),
        Err(e) => tracing::warn!(error = %e, "Token revocation task panicked (best-effort)"),
        Ok(Ok(())) => tracing::info!("Token revoked successfully"),
    }
}
```

### Pattern 7: IPC SessionClosed Extension

**What:** Add `SessionClosed` variant to `AgentRequest` and `SessionAcknowledged` to `AgentResponseData`.
**When to use:** PAM `pam_sm_close_session` calls agent; agent ACKs immediately then runs cleanup in background.

```rust
// In protocol.rs — extend AgentRequest:
#[serde(rename = "session_closed")]
SessionClosed {
    session_id: String,
},

// In AgentResponseData — extend enum:
SessionAcknowledged {},

// In socket.rs — handler:
AgentRequest::SessionClosed { session_id } => {
    // ACK immediately — pam_sm_close_session must return quickly
    let response = AgentResponse::Success(AgentResponseData::SessionAcknowledged {});
    send_response(&mut stream, &response).await?;

    // Spawn cleanup task fire-and-forget
    let state = Arc::clone(&self.state);
    tokio::spawn(async move {
        cleanup_session(state, &session_id).await;
    });
    // Do NOT await cleanup here
    return Ok(());
}
```

### Anti-Patterns to Avoid

- **Using `pam_set_data` (`send_data`) for session correlation:** Process-local only. Does not survive sshd's privsep fork between authentication and session open/close. Use `putenv`/`getenv` (PAM environment) instead.
- **Awaiting revocation before returning PAM_SUCCESS:** Blocks session teardown. Fire-and-forget is mandatory per CONTEXT.md and defensive security practice.
- **Caching introspection results by raw token value:** Stores bearer credential as a map key. Cache by JTI claim or SHA-256(token[:32]) instead.
- **Assuming introspection/revocation endpoints exist:** Not all OIDC providers publish `introspection_endpoint` or `revocation_endpoint` in their discovery document. Both must be operator-configured or absent gracefully. Auth0 notably omits `introspection_endpoint` from its discovery document for some configurations.
- **Dropping JoinHandle to cancel background refresh task:** Dropping does NOT cancel a tokio task — the task continues running. Call `handle.abort()` explicitly on `SessionClosed`.
- **Writing session records non-atomically:** Write to `.tmp` then `fs::rename()` — atomic on the same filesystem. Direct writes can be seen in partial state by `close_session`.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| TTL-bounded concurrent cache | Custom HashMap + cleanup thread | `moka::sync::Cache` | moka handles capacity, TTL eviction, concurrent access atomically |
| HTTP client for introspection/revocation | New Client per call | Reuse `reqwest::blocking::Client` built once | Connection pooling, TLS session reuse; building per-call is expensive |
| Token JTI extraction | Custom JWT parser | `jsonwebtoken::decode` (already used) or existing `extract_username_from_token` pattern | JWT parsing is already solved in this codebase |
| Exponential backoff | Crate dependency | 3-line manual calculation (see pattern above) | Policy is fixed and simple; no jitter needed; adding a dep is over-engineering |

**Key insight:** All required infrastructure already exists in the workspace. This phase is primarily about wiring together existing patterns in new call sites.

---

## Common Pitfalls

### Pitfall 1: pam_set_data Does Not Cross sshd Privsep Fork (SES-03 Critical)
**What goes wrong:** Using `send_data`/`retrieve_data` (pamsm's wrapper for `pam_set_data`/`pam_get_data`) to pass session_id from `authenticate` to `open_session`. Both functions appear to work but `open_session` retrieves `None` because sshd forks a privilege-separated child process for session management that does not share the authentication process's PAM handle data store.
**Why it happens:** `pam_set_data` stores data on the `pam_handle_t` struct in memory. When sshd forks for privilege separation, the new process does not inherit the parent's heap, so the pointer is invalid. PAM environment variables (pam_putenv/pam_getenv) are explicitly serialized and propagated by sshd via `pam_getenvlist`.
**How to avoid:** Use `pamh.putenv("UNIX_OIDC_SESSION_ID=<id>")` in `authenticate`, then `pamh.getenv("UNIX_OIDC_SESSION_ID")` in `open_session`. This is the pamsm 0.5 API.
**Warning signs:** `open_session` receives `None` for session_id when sshd is running with privsep (the default since OpenSSH 3.2).

### Pitfall 2: Dropping JoinHandle Does Not Cancel Refresh Task
**What goes wrong:** Storing `Option<JoinHandle<()>>` in AgentState and dropping it on SessionClosed, expecting the refresh task to stop. The task continues running indefinitely, attempting refreshes for a session that no longer exists.
**Why it happens:** tokio's design — dropping a JoinHandle orphans the task, it does not cancel it. This is documented but easy to miss.
**How to avoid:** Store `Option<AbortHandle>` (obtained via `handle.abort_handle()` before storing the JoinHandle) or store the JoinHandle itself and call `.abort()` explicitly. `AbortHandle` is `Clone` and doesn't require owning the task handle.
**Warning signs:** After session close, logs show continued token refresh attempts for the user.

### Pitfall 3: Race Between close_session and Orphan Cleanup Scan
**What goes wrong:** A server restart causes in-memory agent state to be lost. On next startup, an orphan scan removes session records without knowing the corresponding refresh task is gone. If `close_session` subsequently fires (from a session that was open at restart), it finds no session record and fails silently, potentially leaving the IPC notification unhandled.
**Why it happens:** tmpfs is volatile; agent state is in-process. The two are independent stores.
**How to avoid:** `pam_sm_close_session` must read the session record from tmpfs (not from in-memory state) to locate the session. The IPC `SessionClosed` message carries the `session_id` from PAM environment. Agent responds with `SessionAcknowledged` even if the session was already cleaned up — idempotent.
**Warning signs:** `close_session` returns PAM_SUCCESS but logs show "session not found in agent state."

### Pitfall 4: Introspection Cache Key as Raw Token
**What goes wrong:** Using the full access token as the moka cache key. This stores the bearer credential in the cache's key space, where it may appear in debug logs or memory dumps.
**Why it happens:** Convenience — the token is already available at the call site.
**How to avoid:** Extract the `jti` claim from the token (already decoded during validation) and use that as the cache key. JTI is random but not a bearer credential. If JTI is absent (allowed in warn mode per EnforcementMode), use `sha256(token bytes)[..16]` as a compact key.
**Warning signs:** Any log line printing cache state would contain the raw token.

### Pitfall 5: Missing introspection_endpoint in OIDC Metadata
**What goes wrong:** Attempting to auto-discover the introspection endpoint from `.well-known/openid-configuration` fails for Auth0 and some Okta configurations that omit `introspection_endpoint` from their metadata.
**Why it happens:** The `introspection_endpoint` metadata field is defined in RFC 8414 (OAuth Authorization Server Metadata) and OIDC Discovery, but it is OPTIONAL. Not all providers publish it.
**How to avoid:** The introspection endpoint must be explicitly configured in policy.yaml (`[introspection] endpoint = "https://..."`) rather than auto-discovered. Discovery from metadata is a convenience fallback, not the primary path. Log WARN and fall back to configured endpoint if discovery fails.
**Warning signs:** Operators receive "introspection endpoint not found" errors for Auth0 or custom OAuth servers.

### Pitfall 6: Revocation Endpoint Discovery Equally Unreliable
**What goes wrong:** Same problem as pitfall 5 but for `revocation_endpoint`. RFC 7009 §2 explicitly states "the means to obtain the location of the revocation endpoint is out of the scope of this specification." It is not universally published.
**How to avoid:** Revocation endpoint should come from `KEY_TOKEN_METADATA` stored at login time (which already stores `token_endpoint`, `client_id`, etc.). Add `revocation_endpoint` to the metadata stored during device flow. If not available, skip revocation and log WARN.
**Warning signs:** "No revocation endpoint configured" WARN on session close for providers that don't support RFC 7009.

### Pitfall 7: pam_sm_close_session Blocking on Revocation
**What goes wrong:** PAM's close_session path is called during SSH disconnect. If it blocks on a 5s timeout waiting for the IdP revocation endpoint, users observe a 5-second lag at logout — or worse, intermittent hangs if the IdP is slow.
**How to avoid:** The CONTEXT.md design is correct: PAM sends `SessionClosed` IPC, waits only for the ACK (not the revocation), and returns PAM_SUCCESS immediately. Revocation runs in a background tokio task. The 5s timeout is on the revocation HTTP call, not on the PAM return.
**Warning signs:** SSH disconnects taking >1 second when IdP is slow or unreachable.

---

## Code Examples

### Session Record JSON Schema

```rust
// Source: CONTEXT.md locked decisions — operational-grade record (~200 bytes)
#[derive(Debug, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub username: String,
    pub token_jti: Option<String>,
    pub token_exp: i64,           // Unix timestamp
    pub session_start: i64,       // Unix timestamp
    pub client_ip: Option<String>,
    pub sshd_pid: u32,
    pub issuer: String,
}

// Example JSON:
// {"session_id":"unix-oidc-18d4f2a3b4c-a7f3e2d1c0b9a8f7",
//  "username":"alice","token_jti":"abc123","token_exp":1741709400,
//  "session_start":1741705800,"client_ip":"10.0.0.5","sshd_pid":12345,
//  "issuer":"https://idp.example.com/realms/corp"}
```

### New Audit Event Variants

```rust
// Source: Extend audit.rs following existing AuditEvent pattern

#[serde(rename = "SESSION_OPENED")]
SessionOpened {
    timestamp: String,
    session_id: String,
    username: String,
    client_ip: Option<String>,
    host: String,
    token_exp: i64,
},

#[serde(rename = "SESSION_CLOSED")]
SessionClosed {
    timestamp: String,
    session_id: String,
    username: String,
    host: String,
    duration_secs: i64,
},

#[serde(rename = "TOKEN_REVOKED")]
TokenRevoked {
    timestamp: String,
    session_id: String,
    username: String,
    host: String,
    outcome: String,  // "success" | "failed" | "skipped"
    reason: Option<String>,
},

#[serde(rename = "INTROSPECTION_FAILED")]
IntrospectionFailed {
    timestamp: String,
    session_id: Option<String>,
    username: Option<String>,
    host: String,
    reason: String,
    enforcement: String,  // "strict" | "warn" (disabled never reaches this path)
},
```

### New Policy Config Sections

```rust
// Source: CONTEXT.md — extend pam-unix-oidc/src/policy/config.rs
// Follow IntrospectionConfig + SessionConfig pattern; use EnforcementMode reuse

/// Introspection configuration for [introspection] policy.yaml section.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct IntrospectionConfig {
    /// Enable token introspection. Default: false.
    pub enabled: bool,
    /// Introspection endpoint URL. Must be configured when enabled=true.
    pub endpoint: Option<String>,
    /// Fail-open (auth succeeds) or fail-closed when endpoint unreachable.
    /// Default: warn (fail-open with log).
    pub enforcement: EnforcementMode,
    /// Cache TTL seconds. Actual TTL = min(cache_ttl_secs, token_exp - now).
    /// Default: 60.
    pub cache_ttl_secs: u64,
}

impl Default for IntrospectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            enforcement: EnforcementMode::Warn,
            cache_ttl_secs: 60,
        }
    }
}

/// Session management configuration for [session] policy.yaml section.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionConfig {
    /// Token refresh threshold (0–100). Default: 80 (refresh at 80% of lifetime).
    pub token_refresh_threshold_percent: u8,
    /// Path to session store directory. Default: /run/unix-oidc/sessions.
    pub session_dir: String,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            token_refresh_threshold_percent: 80,
            session_dir: "/run/unix-oidc/sessions".to_string(),
        }
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Bearer tokens — anyone with token can use it | DPoP-bound tokens (RFC 9449) — token bound to key pair | Phase 7 complete | Already implemented; revocation is defense-in-depth on top |
| Session ID only in PAM item data | PAM environment variable for cross-fork correlation | This phase | Correct mechanism for sshd privsep; pam_set_data is process-local |
| Manual HTTP client rebuild per call | Reqwest client with connection pooling | Established | Reuse blocking Client across introspection/revocation calls |
| No token revocation | RFC 7009 best-effort revocation on session close | This phase | Defense in depth; doesn't block teardown |
| Static token lifetime | Auto-refresh at configurable threshold | This phase | Prevents mid-session expiry on long SSH sessions |

**Deprecated/outdated:**
- `pam_set_data`/`pam_get_data` for cross-process PAM state: Only correct within the same process. Not viable for sshd privsep. Use PAM environment (`pam_putenv`/`pam_getenv`).

---

## Open Questions

1. **Revocation endpoint storage in KEY_TOKEN_METADATA**
   - What we know: `KEY_TOKEN_METADATA` already stores `token_endpoint`, `client_id`, `client_secret`, `refresh_token`, `signer_type`. The revocation endpoint is not currently stored.
   - What's unclear: Is the revocation endpoint always the same domain as the token endpoint (usually yes, but not guaranteed)? Can it be derived from OIDC metadata at session-close time?
   - Recommendation: Add `revocation_endpoint` as an optional field in the metadata JSON written at login. Load from OIDC discovery during device flow. If absent, skip revocation with WARN. No schema migration needed — JSON is schema-less and the field is optional.

2. **Introspection during periodic background check — agent or PAM?**
   - What we know: CONTEXT.md says introspection runs at auth time (PAM layer) AND periodically from the agent daemon.
   - What's unclear: The PAM module is a shared library loaded in the sshd process; it has no background thread. The periodic check must be in the agent daemon. The revocation marker file (`{id}.revoked`) is the signal path from agent back to sshd.
   - Recommendation: Plan design should make clear that the PAM layer only does introspection at `pam_sm_authenticate` time. Periodic introspection during open sessions is entirely in the agent's background loop. The `.revoked` marker file is detected by a future `pam_sm_acct_mgmt` hook (not implemented in this phase per deferred items).

3. **Revocation marker detection mechanism**
   - What we know: CONTEXT.md marks this as Claude's Discretion. The `.revoked` marker file approach is preferred over direct sshd signal.
   - What's unclear: The detection mechanism is not yet specified. Options: (a) PAM `acct_mgmt` hook that checks for the marker on each sudo/privilege elevation (deferred), (b) pam_session keepalive hook, (c) ForceCommand wrapper.
   - Recommendation: For this phase, implement only the marker file creation (agent writes `{id}.revoked`). Do NOT implement detection — that is per the deferred section. Document the marker format and intended future consumer. The revocation marker file is complete data-plane groundwork; detection is deferred.

---

## Validation Architecture

`workflow.nyquist_validation` is `true` in `.planning/config.json` — include this section.

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test harness + `cargo test` |
| Config file | Cargo.toml `[dev-dependencies]` + `#[cfg(test)]` modules in-source |
| Quick run command | `cargo test -p pam-unix-oidc --features test-mode 2>&1 \| tail -20` |
| Full suite command | `cargo test --workspace --features test-mode 2>&1 \| tail -30` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SES-01 | `open_session` writes JSON record to `/run/unix-oidc/sessions/{id}.json` with 0600 permissions | unit | `cargo test -p pam-unix-oidc --features test-mode session::tests` | ❌ Wave 0 |
| SES-01 | Directory creation with 0700 permissions if absent | unit | `cargo test -p pam-unix-oidc --features test-mode session::tests::test_ensure_dir` | ❌ Wave 0 |
| SES-02 | `close_session` deletes session record, emits SessionClosed audit event with duration | unit | `cargo test -p pam-unix-oidc --features test-mode session::tests::test_close_session` | ❌ Wave 0 |
| SES-03 | Session ID correlation via putenv/getenv — ID set in authenticate is readable in open_session | unit (pamsm mock) | `cargo test -p pam-unix-oidc --features test-mode lib::tests::test_session_id_correlation` | ❌ Wave 0 |
| SES-04 | Refresh task spawned at login, cancelled on SessionClosed | unit (tokio-test) | `cargo test -p unix-oidc-agent daemon::refresh_task_tests` | ❌ Wave 0 |
| SES-04 | Refresh at 80% of token lifetime threshold | unit | `cargo test -p unix-oidc-agent daemon::tests::test_refresh_threshold` | ❌ Wave 0 |
| SES-04 | Exponential backoff: 5s, 10s, 20s, 40s; max 3 retries | unit | `cargo test -p unix-oidc-agent daemon::tests::test_refresh_backoff` | ❌ Wave 0 |
| SES-05 | Introspection returns false → auth fails in strict mode | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests::test_inactive_token_strict` | ❌ Wave 0 |
| SES-05 | Introspection endpoint unreachable → auth succeeds in warn mode (fail-open) | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests::test_endpoint_unreachable_warn` | ❌ Wave 0 |
| SES-05 | Introspection disabled → no HTTP call made | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests::test_disabled` | ❌ Wave 0 |
| SES-06 | Cache hit prevents second introspection HTTP call | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests::test_cache_hit` | ❌ Wave 0 |
| SES-06 | Cache TTL capped at min(configured, token_exp - now) | unit | `cargo test -p pam-unix-oidc --features test-mode oidc::introspection::tests::test_cache_ttl_capped` | ❌ Wave 0 |
| SES-07 | Revocation HTTP call made on session close; failure does not block PAM_SUCCESS | unit | `cargo test -p unix-oidc-agent daemon::tests::test_revocation_best_effort` | ❌ Wave 0 |
| SES-07 | Revocation skipped gracefully when no endpoint configured | unit | `cargo test -p unix-oidc-agent daemon::tests::test_revocation_no_endpoint` | ❌ Wave 0 |
| SES-08 | SessionClosed IPC: agent ACKs immediately, spawns background cleanup | unit | `cargo test -p unix-oidc-agent daemon::tests::test_session_closed_ack` | ❌ Wave 0 |
| SES-08 | DPoP signing key zeroized on SessionClosed (ZeroizeOnDrop) | unit | `cargo test -p unix-oidc-agent crypto::tests::test_key_zeroize_on_drop` | ❌ (may exist, verify) |

### Adversarial Tests (Required per STATE.md pending directive)

| Scenario | Test Type | Target |
|----------|-----------|--------|
| Forged session record (wrong owner, wrong permissions) | unit | `session::tests::test_reject_forged_record` |
| Replayed introspection result after token revocation | unit | `oidc::introspection::tests::test_stale_cache_after_revocation` |
| Introspection cache poisoning (active=false cached, token re-issued) | unit | `oidc::introspection::tests::test_cache_invalidation` |
| Concurrent open/close race (open_session + close_session simultaneously) | unit | `session::tests::test_concurrent_open_close` |
| Agent restart mid-session (orphan record cleanup) | integration | manual or `cargo test --features test-mode integration::test_orphan_cleanup` |
| Very short token lifetime (< 10s total) | unit | `daemon::tests::test_short_lifetime_token` |
| close_session called before open_session record exists | unit | `session::tests::test_close_without_open` |

### Sampling Rate
- **Per task commit:** `cargo test -p pam-unix-oidc --features test-mode && cargo test -p unix-oidc-agent 2>&1 | tail -10`
- **Per wave merge:** `cargo test --workspace --features test-mode 2>&1 | tail -20`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `pam-unix-oidc/src/session/mod.rs` — covers SES-01, SES-02 (new module, no file)
- [ ] `pam-unix-oidc/src/oidc/introspection.rs` — covers SES-05, SES-06 (new module)
- [ ] `unix-oidc-agent/src/daemon/socket.rs` test additions — covers SES-04, SES-07, SES-08

---

## Sources

### Primary (HIGH confidence)

- RFC 7662 (OAuth 2.0 Token Introspection) — https://www.rfc-editor.org/rfc/rfc7662.html — §2.1 request format, §2.2 response fields, §2.3 security requirements
- RFC 7009 (OAuth 2.0 Token Revocation) — https://datatracker.ietf.org/doc/html/rfc7009 — §2 endpoint, §2.1 request format, note on discovery being "out of scope"
- pamsm 0.5 docs — https://docs.rs/pamsm/0.5.0/pamsm/trait.PamLibExt.html — confirmed `putenv(&str)` and `getenv(&str)` method signatures; `send_data`/`retrieve_data` (pam_set_data) also present
- moka 0.12 docs — https://docs.rs/moka/latest/moka/sync/struct.Cache.html — sync Cache builder, TTL, max_capacity
- tokio::task docs — https://docs.rs/tokio/latest/tokio/task/ — JoinHandle::abort(), AbortHandle, dropping JoinHandle does NOT cancel task
- std::os::unix::fs::PermissionsExt — https://doc.rust-lang.org/std/os/unix/fs/trait.PermissionsExt.html — `from_mode(0o600)` pattern
- Codebase: `pam-unix-oidc/src/security/nonce_cache.rs` — moka sync::Cache construction pattern for introspection cache
- Codebase: `unix-oidc-agent/src/daemon/socket.rs:414-553` — perform_token_refresh() — reqwest blocking pattern for introspection/revocation
- Codebase: `unix-oidc-agent/src/daemon/protocol.rs` — AgentRequest/AgentResponse extension pattern for SessionClosed
- Codebase: `pam-unix-oidc/src/audit.rs` — AuditEvent extension pattern for new session/introspection events
- Codebase: `pam-unix-oidc/src/policy/config.rs` — EnforcementMode, figment-based config, Default impls pattern

### Secondary (MEDIUM confidence)

- OpenSSH privsep + pam_getenvlist propagation: confirmed indirectly via web search noting "child's environment is set to the current PAM environment list as returned by pam_getenvlist(3)." Multiple sources confirm pam_set_data is process-local and fails across sshd forks.
- Auth0 missing introspection_endpoint: https://community.auth0.com/t/missing-token-introspection-endpoint-in-openid-configuration/105916 — confirms not all providers publish this field
- tokio task cancellation patterns blog: https://cybernetist.com/2024/04/19/rust-tokio-task-cancellation-patterns/ — drop vs abort semantics

### Tertiary (LOW confidence)

- Web search confirms `revocation_endpoint` not universal — RFC 7009 itself says discovery is out of scope; "better-auth" GitHub issue confirms some providers lack it

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all dependencies already in workspace; no new deps needed
- Architecture: HIGH — patterns directly derived from existing codebase (nonce_cache.rs, socket.rs, protocol.rs, audit.rs)
- Pitfalls: HIGH — pam_set_data cross-fork failure is verified by multiple sources; tokio abort vs drop is documented in tokio official docs
- RFC compliance: HIGH — RFC 7662 and RFC 7009 read directly from rfc-editor.org
- Test map: MEDIUM — test module paths are proposed based on established project patterns; exact paths subject to planner discretion

**Research date:** 2026-03-11
**Valid until:** 2026-06-11 (stable RFCs; moka/tokio APIs stable; pamsm 0.5 API stable)
