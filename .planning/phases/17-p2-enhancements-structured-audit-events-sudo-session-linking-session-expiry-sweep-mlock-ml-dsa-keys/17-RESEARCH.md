# Phase 17: P2 Enhancements — Research

**Researched:** 2026-03-13
**Domain:** Rust async daemon observability, session hygiene, PQC memory protection
**Confidence:** HIGH — all findings are from direct codebase inspection

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions
- Structured audit events use tracing with a dedicated `audit` target (filterable via tracing-subscriber)
- Audit events include: event_type, timestamp, session_id, username, outcome, and event-specific fields
- JSON-serializable for SIEM ingestion (already have JSON tracing from Phase 13)
- Audit events are INFO level minimum — never filtered by default log level
- Parent SSH session_id must be propagated to sudo step-up IPC messages
- The CIBA poll result must carry the parent session_id for correlation
- Audit events for step-up must include both sudo_session_id and parent_session_id
- Session expiry sweep is a periodic background task in agent daemon (Tokio interval)
- Scan /run/unix-oidc/sessions/ for expired session files (check token_exp from session record)
- Configurable sweep interval (default: 5 minutes)
- Must handle partial/corrupt session files gracefully (warn + remove)
- Must not race with active session close operations (file lock or atomic check)
- ML-DSA-65 key material must be mlock'd like EC keys in ProtectedSigningKey
- HybridPqcSigner holds both EC and ML-DSA keys — both must be protected
- Best-effort mlock (warn on failure, same as EC path)
- Zeroize on drop must be verified for ML-DSA key types

### Claude's Discretion
- Internal implementation details of sweep scheduling
- Audit event field naming conventions (follow existing tracing patterns)
- Whether sweep uses inotify/kqueue or simple polling (polling chosen — inotify deferred)

### Deferred Ideas (OUT OF SCOPE)
- Audit event forwarding to external SIEM (future ops milestone)
- inotify-based session file watching (polling is sufficient for MVP)
</user_constraints>

---

## Summary

Phase 17 extends the agent daemon and PAM module with four focused enhancements. All four areas are already partially scaffolded; this phase completes what is missing.

**Structured audit events (OBS-1):** The PAM crate (`pam-unix-oidc/src/audit.rs`) has an `AuditEvent` enum with syslog and file-based delivery. The agent daemon (`unix-oidc-agent`) has Phase 13 tracing spans with `request_id`, `command`, `peer_pid` fields. The gap is that the agent emits *operational* log lines (e.g., `info!("DPoP proof requested")`) but not *audit-targeted* structured events with a dedicated `target` field that can be routed independently in tracing-subscriber. The planner needs to add `tracing::info!(target: "unix_oidc_audit", ...)` calls at five agent-side event points.

**Sudo session linking (OBS-3):** `StepUp` IPC message currently carries `username`, `command`, `hostname`, `method`, `timeout_secs` but has **no `parent_session_id` field**. `SudoContext.session_id` is a locally-generated UUID for the sudo flow, unrelated to the SSH parent session. The SSH parent `session_id` is in the PAM environment (written by `pam_sm_open_session` via `pam_set_data()`/`pam_putenv()`). It must be threaded through: PAM sudo.rs → StepUp IPC message → PendingStepUp state → poll_ciba → StepUpOutcome::Complete → StepUpComplete response.

**Session expiry sweep:** `SessionRecord` has a `token_exp: i64` field. The sweep must: periodically read all `*.json` files in `/run/unix-oidc/sessions/`, deserialize each, compare `token_exp` against `now()`, and delete expired ones. The existing `delete_session_record()` function is reusable. Race condition: the agent processes `SessionClosed` IPC and calls cleanup_session, which does NOT delete session files (PAM's `pam_sm_close_session` deletes them). The sweep runs in the agent, which does not write or delete session files — these come from the PAM module in sshd. Since sshd and agent are different processes, there is no mutex/file-lock shared between them; the sweep must use atomic check-then-delete (check existence, delete — rename(2) was already used for writes but not needed here; simple unlink is sufficient since the sweep only deletes, not writes).

**mlock ML-DSA keys:** `HybridPqcSigner` holds `pq_key: ml_dsa::SigningKey<MlDsa65>` and `pq_seed: Zeroizing<[u8; 32]>`. The struct itself lives on the Rust stack (no Box). The EC component is already Box-protected via `Box<ProtectedSigningKey>`. The ML-DSA key material needs mlock applied to the `HybridPqcSigner` allocation itself — which means the struct must be Boxed and mlock'd over the whole allocation, mirroring `ProtectedSigningKey::new_inner()`. The `ml-dsa 0.1.0-rc.7` crate has a `zeroize` feature and the Cargo.lock confirms `zeroize` is in its dependency tree — so `ZeroizeOnDrop` is available for `SigningKey<MlDsa65>` when the `zeroize` feature is enabled. Cargo.toml already has `features = ["zeroize"]` for the `ml-dsa` dep.

**Primary recommendation:** Each enhancement is a focused, self-contained change. Work in the order: (1) mlock ML-DSA (simplest, pure memory safety), (2) structured audit events (new tracing calls), (3) sudo session linking (IPC protocol extension), (4) session expiry sweep (new background task). No external library additions needed.

---

## Standard Stack

### Core (already in workspace)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `tracing` | workspace | Structured events | Already used; target-filtered subscriber is the audit routing mechanism |
| `tokio` | 1 | Interval-based sweep task | Already the async runtime |
| `serde_json` | 1.0 | JSON session record parse | Already used in session/mod.rs |
| `libc` | 0.2 | mlock/munlock syscalls | Already used in protected_key.rs |
| `ml-dsa` | 0.1.0-rc.7 | ML-DSA-65 key type | Already present with `zeroize` feature |
| `zeroize` | 1 | Zeroizing wrapper | Already in Cargo.toml with `derive` feature |

### No New Dependencies
All four enhancements use only existing crate dependencies. The `ml-dsa` crate already has `features = ["zeroize"]` in `unix-oidc-agent/Cargo.toml`. No additions to `Cargo.toml` are needed.

---

## Architecture Patterns

### Pattern 1: Tracing `target` for Audit Routing

**What:** `tracing::info!(target: "unix_oidc_audit", ...)` emits an event with a custom target. In tracing-subscriber, this target can be filtered via `EnvFilter` directives (`unix_oidc_audit=info`) independently of the module-level filter. The JSON formatter serializes the target field, so SIEM consumers can filter on `"target": "unix_oidc_audit"`.

**When to use:** For all five agent-side audit points: GetProof (authentication), Refresh (token refresh), SessionClosed (session lifecycle), StepUp/StepUpComplete/StepUpTimedOut (step-up).

**Pattern (from existing OPS-13 tracing in socket.rs):**
```rust
// Existing operational log (keep as-is):
info!(
    username = %state_read.username.as_deref().unwrap_or("unknown"),
    target = %target,
    signer_type = %state_read.signer_type.as_deref().unwrap_or("unknown"),
    "DPoP proof requested"
);

// New audit event (add alongside):
tracing::info!(
    target: "unix_oidc_audit",
    event_type = "authentication",
    session_id = %session_id,    // from GetProof context or state
    username = %username,
    outcome = "success",
    signer_type = %signer_type,
    "AGENT_AUTH"
);
```

**Key constraint:** Audit events are INFO level minimum. The existing `EnvFilter::new("unix_oidc_agent=info,warn")` in `main.rs::init_tracing()` will already pass them. The `target:` argument overrides the automatic module path.

### Pattern 2: Tokio Interval Sweep Task

**What:** `tokio::time::interval(Duration::from_secs(sweep_interval_secs))` produces a ticker that can be `select!`'d in the `serve_with_listener` loop or spawned as a separate `tokio::spawn` task.

**Recommended:** Spawn as a separate task (same pattern as `spawn_refresh_task`) so it does not block the accept loop.

```rust
// In serve() or serve_with_listener():
let sweep_state_clone = Arc::clone(&self.state);
let sweep_dir = self.session_dir.clone(); // new field on AgentServer
tokio::spawn(async move {
    session_expiry_sweep(sweep_state_clone, sweep_dir, sweep_interval).await;
});
```

The sweep function itself:
```rust
pub async fn session_expiry_sweep(
    _state: Arc<RwLock<AgentState>>,  // for future use (metrics)
    session_dir: String,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // skip first immediate tick
    loop {
        ticker.tick().await;
        sweep_expired_sessions(&session_dir).await;
    }
}
```

**Race condition mitigation:** `sweep_expired_sessions` reads each `*.json` file, parses `token_exp`, and if expired, calls `fs::remove_file`. The only writer of these files is `pam_sm_open_session` (PAM, in sshd process). The only other deleters are `pam_sm_close_session` (PAM, in sshd process) and this sweep. Since rename(2) is used on write (atomic), the sweep's `remove_file` on a fully-written file is safe. If `pam_sm_close_session` deletes the file concurrently with the sweep, `remove_file` returns `ENOENT` — handle this as `Ok(None)` not as an error (same as existing `delete_session_record` behavior).

**Corrupt file handling:** `serde_json::from_str` returns `Err` for malformed JSON. Pattern: log `warn!(session_id = %name, "corrupt session file; removing")` then call `fs::remove_file`. Never `unwrap`.

### Pattern 3: Parent Session ID Threading

**Current flow (OBS-3 gap):**

```
pam_sm_authenticate()       → writes session_id to PAM env via pam_putenv("UNIX_OIDC_SESSION_ID=...")
pam_sm_open_session()       → reads it back; writes SessionRecord (session_id field)
sudo auth (authenticate_sudo) → calls perform_step_up_via_ipc()
  ↳ perform_step_up_via_ipc()  → sends StepUp { username, command, hostname, method, timeout_secs }
                                   NO parent_session_id field here
```

**Fix:** Read `UNIX_OIDC_SESSION_ID` from PAM environment inside `authenticate_sudo` or `perform_step_up_via_ipc`, add it to the StepUp message, thread it through `PendingStepUp`, include it in `StepUpComplete`.

**Specific changes required:**
1. `AgentRequest::StepUp` — add `parent_session_id: Option<String>` field
2. `pam-unix-oidc/src/sudo.rs::perform_step_up_via_ipc` — read `UNIX_OIDC_SESSION_ID` from PAM env or `std::env::var`, pass in `step_up_msg`
3. `PendingStepUp` struct — add `parent_session_id: Option<String>`
4. `handle_step_up` in socket.rs — capture it from the message, store in PendingStepUp
5. `poll_ciba` — needs to receive `parent_session_id` and include it in `StepUpOutcome::Complete`
6. `StepUpOutcome::Complete` — add `parent_session_id: Option<String>`
7. `AgentResponseData::StepUpComplete` — already has `session_id` (the CIBA session); add `parent_session_id: Option<String>`
8. Audit event for step-up completion in `handle_step_up_result` — emit both IDs

**Reading parent session_id in PAM sudo context:** The PAM sudo module runs in the sshd process where `UNIX_OIDC_SESSION_ID` was set by `pam_sm_open_session` via `pam_putenv`. In `authenticate_sudo`, the `pam_handle` is available; use `pam_getenv(pamh, "UNIX_OIDC_SESSION_ID")` (or `std::env::var` if the PAM module exports it to the process environment). Check existing usage in `pam_sm_open_session` to confirm whether it uses `pam_putenv` (PAM internal) or a process-level `setenv`.

### Pattern 4: mlock for HybridPqcSigner

**Current state:** `HybridPqcSigner` is a plain struct, not Boxed. The EC component (`Box<ProtectedSigningKey>`) is already mlock'd by `ProtectedSigningKey::new_inner()`. The ML-DSA component (`pq_key: ml_dsa::SigningKey<MlDsa65>`) lives as a field inside the unboxed `HybridPqcSigner` — wherever that struct lives (stack or heap).

**Required change:** Box `HybridPqcSigner` and mlock the entire allocation, similar to `ProtectedSigningKey::new_inner()`.

```rust
impl HybridPqcSigner {
    fn new_inner(
        ec_key: Box<ProtectedSigningKey>,
        pq_key: ml_dsa::SigningKey<MlDsa65>,
        pq_vk: ml_dsa::VerifyingKey<MlDsa65>,
        pq_seed: Zeroizing<[u8; 32]>,
    ) -> Box<Self> {
        let thumbprint = Self::compute_composite_thumbprint(&ec_key, &pq_vk);
        let mut boxed = Box::new(Self {
            ec_key,
            pq_key,
            pq_vk,
            thumbprint,
            pq_seed,
            _mlock_guard: None,   // new field
        });

        // SAFETY: Box allocation is stable; guard stored inside same Box.
        let struct_bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
                &mut *boxed as *mut Self as *mut u8,
                std::mem::size_of::<Self>(),
            )
        };
        let guard = unsafe { try_mlock(struct_bytes) };
        if guard.is_some() {
            tracing::debug!("HybridPqcSigner mlock'd ({} bytes)", std::mem::size_of::<Self>());
        } else {
            tracing::debug!("HybridPqcSigner mlock skipped (unavailable or EPERM)");
        }
        boxed._mlock_guard = guard;
        boxed
    }
}
```

**ZeroizeOnDrop for ML-DSA:** The `ml-dsa` crate (0.1.0-rc.7) has `zeroize` in its dependency list (confirmed from Cargo.lock). With `features = ["zeroize"]` active (already set in Cargo.toml), `ml_dsa::SigningKey<MlDsa65>` implements `ZeroizeOnDrop`. This means dropping `HybridPqcSigner` automatically zeroes the ML-DSA key bytes.

**Verification step:** Add a compile-time assertion or doc comment noting the ZeroizeOnDrop dependency: `static_assertions::assert_impl_all!(ml_dsa::SigningKey<ml_dsa::MlDsa65>: zeroize::ZeroizeOnDrop);`. (The `static_assertions` crate is not currently in the workspace — use a `#[test]` that drops the key and checks behavior instead, mirroring the existing `test_key_material_zeroed_after_drop` test in `protected_key.rs`.)

**Constructor signature change:** `generate()` and `from_key_bytes()` currently return `Self`. They must change to `Box<Self>`. This is a breaking change to the public API of `HybridPqcSigner`. Check all callers:
- `unix-oidc-agent/src/main.rs` (pqc feature branch in login flow)
- Any tests in `pqc_signer.rs` that bind `let signer = HybridPqcSigner::generate()`

### Anti-Patterns to Avoid

- **Using `tracing::event!(target: "unix_oidc_audit", ...)` at DEBUG level:** Audit events must be INFO or above so they are not filtered by default log level (`unix_oidc_agent=info`).
- **Blocking the sweep on individual file errors:** Each corrupt/unreadable file should `warn!` and continue to the next file; do not return early from the sweep loop.
- **Adding `parent_session_id` as a required field in StepUp:** Make it `Option<String>` — older PAM module versions that don't set it should not break the protocol. Agent treats `None` as "no parent session known."
- **Trying to mlock `pq_vk` (verifying key) separately:** The whole `HybridPqcSigner` Box mlock covers all fields including `pq_vk`. Do not add additional mlock calls for sub-fields.
- **Spawning the sweep task before the socket is bound:** Sweep task should start after `acquire_listener()` succeeds (same as signal handlers in the current `serve_with_listener` pattern).

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Audit event routing | Custom log file writer in agent | `tracing::info!(target: "unix_oidc_audit", ...)` | JSON tracing subscriber already routes by target; no new writer needed |
| File listing for sweep | Custom directory iteration | `std::fs::read_dir` | Standard library; sufficient for polling approach |
| Session file locking | Advisory flock(2) | Atomic check on `token_exp` field + ENOENT tolerance | No shared lock domain between sshd and agent; ENOENT on delete is the correct race condition handler |
| ML-DSA key size at compile time | `ML_DSA_65_KEY_SIZE` const | `std::mem::size_of::<ml_dsa::SigningKey<MlDsa65>>()` | Size determined by type system; const is unnecessary |
| Parent session ID generation | New UUID in sudo.rs | Read existing `UNIX_OIDC_SESSION_ID` from PAM env | Session ID already generated in `pam_sm_open_session` — reuse it |

---

## Common Pitfalls

### Pitfall 1: Tracing `target` Field Collision with Span Fields
**What goes wrong:** A span's inherited `target` field (the module path) can shadow a manually set `target:` argument in some subscriber configurations.
**Why it happens:** The `target` in `tracing::info!(target: "foo", ...)` is the event's *module target*, not a structured field. It replaces the automatic module path, not a data field named "target."
**How to avoid:** Use `target: "unix_oidc_audit"` as the first argument to the macro (before field list), not as a named field. The existing OPS-13 log in `socket.rs` already uses `target = %target` as a *field* (the target server). Do not confuse these two uses of the word "target."
**Warning signs:** JSON output shows `"target": "some::module::path"` instead of `"target": "unix_oidc_audit"`.

### Pitfall 2: `Option<String>` vs Required Field in Protocol Serde
**What goes wrong:** Adding `parent_session_id: Option<String>` to `AgentRequest::StepUp` with `#[serde(skip_serializing_if = "Option::is_none")]` means old PAM module (without the field) sends JSON without it, and the new agent deserializes correctly as `None`.
**Why it happens:** Without `skip_serializing_if`, the field serializes as `null`, which some clients may reject.
**How to avoid:** Use both `#[serde(skip_serializing_if = "Option::is_none")]` and `#[serde(default)]` to ensure backward compatibility in both directions.

### Pitfall 3: Race Between Sweep and pam_sm_close_session
**What goes wrong:** Sweep reads a file (token_exp in future), PAM deletes it before sweep removes it, sweep gets ENOENT on `remove_file`.
**Why it happens:** Both sshd and agent sweep run as root but are separate processes with no shared lock.
**How to avoid:** Treat `ENOENT` from `fs::remove_file` as success in the sweep (the file was already cleaned up by PAM). `delete_session_record()` already handles this pattern — the sweep should use the same function or replicate its ENOENT tolerance.

### Pitfall 4: mlock Size After Boxed Struct Gains New Fields
**What goes wrong:** `std::mem::size_of::<HybridPqcSigner>()` used in the mlock call changes when `_mlock_guard: Option<MlockGuard>` is added as a field — `MlockGuard` contains a raw pointer and usize, adding 16 bytes (on 64-bit). This is fine because `new_inner()` computes the size after the full struct is boxed.
**Why it happens:** The size calculation happens at `Box::new()` creation, which sets the final layout. No manual size constant is needed.
**How to avoid:** Always use `std::mem::size_of::<Self>()` inside `new_inner`, never a hardcoded constant.

### Pitfall 5: Sweep Interval Config Not Wired to AgentConfig
**What goes wrong:** Sweep interval hardcoded in the sweep task spawn instead of read from `AgentConfig`.
**Why it happens:** Easy to forget to add the new field to `TimeoutsConfig` in `config.rs`.
**How to avoid:** Add `sweep_interval_secs: u64` (default: 300) to `TimeoutsConfig` with a `default_sweep_interval()` fn, following the exact pattern of existing fields like `ipc_idle_timeout_secs`. Pass it to `AgentServer` via a `with_sweep_interval()` builder, parallel to `with_idle_timeout()`.

### Pitfall 6: `StepUpComplete` Serde Discriminant After Adding `parent_session_id`
**What goes wrong:** `StepUpComplete { acr, session_id }` uses `session_id` as its untagged serde discriminant (it's the unique field not present in other variants). Adding `parent_session_id: Option<String>` does not break this — `Option<String>` fields can be `null` without affecting discriminant resolution.
**Why it happens:** Untagged serde matches the first variant whose required fields are present. `session_id` (always present) continues to discriminate `StepUpComplete` correctly.
**How to avoid:** Add `parent_session_id` with `#[serde(skip_serializing_if = "Option::is_none", default)]`. No re-ordering of variants needed.

---

## Code Examples

### Audit Event Pattern (tracing target)
```rust
// Source: tracing docs — https://docs.rs/tracing/latest/tracing/macro.info.html
// target: argument routes the event to a named subscriber filter bucket.
// This pattern is used in addition to (not instead of) existing operational logs.
tracing::info!(
    target: "unix_oidc_audit",
    event_type = "authentication",
    outcome = "success",
    username = %username,
    session_id = %session_id_or_unknown,
    signer_type = %signer_type,
    "AGENT_AUTH_SUCCESS"
);

tracing::info!(
    target: "unix_oidc_audit",
    event_type = "step_up_complete",
    outcome = "success",
    username = %username,
    sudo_session_id = %sudo_session_id,
    parent_session_id = ?parent_session_id,  // Option — debug format
    acr = ?acr,
    "AGENT_STEP_UP_COMPLETE"
);
```

### Session Expiry Sweep (core loop)
```rust
// Pattern: iterate directory, parse records, delete expired ones.
// ENOENT on remove_file is treated as success (concurrent PAM delete).
async fn sweep_expired_sessions(session_dir: &str) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let entries = match std::fs::read_dir(session_dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(error = %e, session_dir, "Sweep: failed to read session directory");
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "Sweep: unreadable session file");
                continue;
            }
        };
        let record: pam_unix_oidc::session::SessionRecord = match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    path = %path.display(),
                    "Sweep: corrupt session file; removing"
                );
                let _ = std::fs::remove_file(&path);
                continue;
            }
        };
        if record.token_exp < now {
            tracing::info!(
                session_id = %record.session_id,
                username = %record.username,
                token_exp = record.token_exp,
                "Sweep: removing expired session record"
            );
            match std::fs::remove_file(&path) {
                Ok(()) | Err(_) => {} // ENOENT = concurrent delete = fine
            }
        }
    }
}
```

### Protocol Extension for Parent Session ID
```rust
// In daemon/protocol.rs — AgentRequest::StepUp
#[serde(rename = "step_up")]
StepUp {
    username: String,
    command: String,
    hostname: String,
    method: String,
    timeout_secs: u64,
    // OBS-3: parent SSH session_id for audit correlation.
    // Optional for backward compat with older PAM module versions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    parent_session_id: Option<String>,
},

// In AgentResponseData::StepUpComplete
StepUpComplete {
    acr: Option<String>,
    session_id: String,
    // OBS-3: echoed back from StepUp request for PAM-side audit correlation.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    parent_session_id: Option<String>,
},
```

### HybridPqcSigner Constructor Return Type Change
```rust
// Before:
pub fn generate() -> Self { ... }
pub fn from_key_bytes(ec_bytes: &[u8], pq_seed_bytes: &[u8]) -> Result<Self, SignerError> { ... }

// After:
pub fn generate() -> Box<Self> {
    Self::new_inner(
        ProtectedSigningKey::generate(),
        /* pq_key, pq_vk, pq_seed from OsRng */
    )
}

pub fn from_key_bytes(ec_bytes: &[u8], pq_seed_bytes: &[u8]) -> Result<Box<Self>, SignerError> {
    let ec_key = ProtectedSigningKey::from_bytes(ec_bytes)?;
    /* reconstruct pq_key/vk from seed */
    Ok(Self::new_inner(ec_key, pq_key, pq_vk, seed_bytes))
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| File-based audit log + syslog (pam audit.rs) | tracing target routing (agent-side) | Phase 17 (new) | Agent events now filterable in JSON output pipelines |
| Sudo session_id is standalone UUID | Sudo session_id linked to parent SSH session_id | Phase 17 (new) | End-to-end audit correlation for privilege escalation events |
| No session expiry cleanup fallback | Sweep task removes orphaned expired records | Phase 17 (new) | Prevents /run/unix-oidc/sessions/ accumulation from crashed sshd |
| ML-DSA key on heap, no mlock | ML-DSA key mlock'd alongside EC key | Phase 17 (new) | Prevents PQC key material from being swapped to disk |

---

## Open Questions

1. **Where exactly does the parent session_id live in PAM sudo context?**
   - What we know: `pam_sm_open_session` writes `UNIX_OIDC_SESSION_ID` via `pam_putenv()` (PAM-internal env, not process env). Sudo authentication runs during `pam_sm_authenticate` for the sudo PAM stack, which is a separate PAM handle from the sshd session PAM handle.
   - What's unclear: When `authenticate_sudo` is called from the sudo PAM plugin, does `UNIX_OIDC_SESSION_ID` from the *sshd* PAM handle propagate to the *sudo* PAM handle's environment, or is it only available as a real process environment variable?
   - Recommendation: Check `pam-unix-oidc/src/lib.rs` for how `pam_sm_authenticate` is wired for the sudo pam stack. If the session ID is only in PAM-internal env (not exported to process env), the sudo path may need to read it from a different mechanism (e.g., `std::env::var("UNIX_OIDC_SESSION_ID")` if pam_sm_open_session also calls `setenv`).

2. **AgentServer session_dir field: hardcoded or config-driven?**
   - What we know: `/run/unix-oidc/sessions/` is the default (from CLAUDE.md and session/mod.rs constant in pam crate). The sweep needs to know this path.
   - What's unclear: Is there a config field for `session_dir` in `AgentConfig`? Currently the agent does not read session files at all.
   - Recommendation: Add `session_dir: String` (default: `/run/unix-oidc/sessions/`) to `AgentConfig` and wire it to `AgentServer`. The sweep only reads; it does not need write access to the session dir.

3. **ml_dsa::SigningKey<MlDsa65> ZeroizeOnDrop guarantee depth**
   - What we know: Cargo.lock confirms `zeroize` is in ml-dsa's dep tree. `features = ["zeroize"]` is set in Cargo.toml.
   - What's unclear: Whether `ml_dsa::SigningKey<MlDsa65>` derives `ZeroizeOnDrop` at the outermost type level, or whether it only implements `Zeroize` (the fallible, explicit version). The distinction matters for `Drop`-based automatic zeroing.
   - Recommendation: Add a test that uses `drop_in_place` + reads the memory (same pattern as `test_key_material_zeroed_after_drop` in `protected_key.rs`) to verify bytes change after drop. This is the same pattern already used for EC keys.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | cargo test (workspace-level) |
| Config file | none (standard cargo test) |
| Quick run command | `cargo test -p unix-oidc-agent --lib` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| ID | Behavior | Test Type | Automated Command | File Exists? |
|----|----------|-----------|-------------------|-------------|
| OBS-1 audit events | Tracing events emit with `target: "unix_oidc_audit"` and required fields | unit | `cargo test -p unix-oidc-agent test_audit_events` | ❌ Wave 0 |
| OBS-3 session linking | `StepUp` message carries `parent_session_id`; `StepUpComplete` echoes it | unit | `cargo test -p unix-oidc-agent test_step_up_parent_session_id` | ❌ Wave 0 |
| Sweep nominal | Expired session file removed after sweep | unit | `cargo test -p unix-oidc-agent test_sweep_removes_expired` | ❌ Wave 0 |
| Sweep corrupt | Corrupt JSON file removed with warn, loop continues | unit | `cargo test -p unix-oidc-agent test_sweep_removes_corrupt` | ❌ Wave 0 |
| Sweep ENOENT race | ENOENT on remove_file treated as success | unit | `cargo test -p unix-oidc-agent test_sweep_concurrent_delete` | ❌ Wave 0 |
| mlock ML-DSA | `HybridPqcSigner::generate()` returns `Box<Self>`; mlock attempted | unit | `cargo test -p unix-oidc-agent --features pqc test_hybrid_signer_boxed` | ❌ Wave 0 |
| ML-DSA ZeroizeOnDrop | Key bytes change after drop | unit | `cargo test -p unix-oidc-agent --features pqc test_ml_dsa_zeroize_on_drop` | ❌ Wave 0 |
| Protocol backward compat | StepUp without `parent_session_id` still deserializes | unit | `cargo test -p unix-oidc-agent test_step_up_deserialization_backward_compat` | ❌ Wave 0 |
| Sweep config | `sweep_interval_secs` defaults to 300; env override works | unit | `cargo test -p unix-oidc-agent test_sweep_interval_config` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p unix-oidc-agent --lib`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `unix-oidc-agent/src/daemon/sweep.rs` — session expiry sweep task (new module)
- [ ] `unix-oidc-agent/src/daemon/audit.rs` — audit event helper functions (new module, or inline in socket.rs)
- [ ] Tests for all items above (co-located in each module's `#[cfg(test)]` block)
- No new framework install needed — `tempfile` crate already in dev-dependencies

---

## Sources

### Primary (HIGH confidence)
- Direct codebase inspection of `/unix-oidc-agent/src/crypto/protected_key.rs` — mlock pattern
- Direct codebase inspection of `/unix-oidc-agent/src/crypto/pqc_signer.rs` — HybridPqcSigner structure
- Direct codebase inspection of `/unix-oidc-agent/src/daemon/protocol.rs` — IPC protocol
- Direct codebase inspection of `/unix-oidc-agent/src/daemon/socket.rs` — handle_step_up, handle_connection
- Direct codebase inspection of `/pam-unix-oidc/src/audit.rs` — existing AuditEvent enum
- Direct codebase inspection of `/pam-unix-oidc/src/session/mod.rs` — SessionRecord structure
- Direct codebase inspection of `/pam-unix-oidc/src/sudo.rs` — SudoContext, perform_step_up_via_ipc
- Direct inspection of `/unix-oidc-agent/Cargo.toml` — ml-dsa features = ["zeroize"] confirmed
- Direct inspection of `/Cargo.lock` — ml-dsa 0.1.0-rc.7 has zeroize in dependency tree confirmed
- tracing docs (https://docs.rs/tracing) — `target:` argument behavior is stable API

### Secondary (MEDIUM confidence)
- `ml-dsa 0.1.0-rc.7` zeroize feature: confirmed by Cargo.lock deps, not verified by reading the crate source. Implementation of `ZeroizeOnDrop` vs `Zeroize` on `SigningKey<MlDsa65>` is an open question (see Open Questions #3).

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all libraries already in workspace
- Architecture: HIGH — patterns derived from existing code in same codebase
- Pitfalls: HIGH — derived from code inspection of existing patterns and serde behavior
- ML-DSA ZeroizeOnDrop depth: MEDIUM — Cargo.lock confirms zeroize dep but source not verified

**Research date:** 2026-03-13
**Valid until:** 2026-04-13 (stable codebase, no fast-moving external deps for these features)
