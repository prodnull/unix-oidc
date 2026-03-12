# Phase 14: Critical Integration Bug Fixes — Research

**Researched:** 2026-03-11
**Domain:** Rust IPC protocol correctness, PAM keyboard-interactive / SSH_ASKPASS integration, clock-skew config threading, dead-code cleanup
**Confidence:** HIGH — all findings sourced from direct code inspection of the affected files

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SES-04 | Automatic token refresh at configurable TTL threshold | Cleanup path (cleanup_session) never fires because IPC newline is missing; auto-refresh abort on SessionClosed is broken |
| SES-07 | RFC 7009 token revocation on session close | revoke_token_best_effort() is called from cleanup_session(), which never fires — revocation is silently skipped |
| SES-08 | Agent SessionClosed IPC event to schedule orphaned DPoP key cleanup | The IPC message reaches the socket but BufReader::read_line() blocks forever; cleanup_session() never dispatches |
| SEC-05 | Server-side DPoP nonce issuance per RFC 9449 §8 with PAM challenge delivery | The PAM side issues nonces correctly; the SSH client side has no handler to intercept DPOP_NONCE: prompts and call GetProof with the extracted nonce |
| OPS-09 | Configurable clock skew tolerance (default 5s future / 60s staleness) | Agent side is wired correctly; PAM module's lib.rs hardcodes clock_skew_future_secs=5 and ValidationConfig uses hardcoded 60 — operator config is ignored on the PAM side |
</phase_requirements>

---

## Summary

Phase 14 addresses four concrete bugs identified in the v2.0 milestone audit. Three are integration-layer defects where code that was implemented in isolation (PAM module, agent daemon, agent CLI) was never wired together. One is a dead-code / lint hazard. All four fixes are surgical — no architectural changes, no new dependencies.

**Bug 1 (Critical, SES-04/07/08):** `notify_agent_session_closed()` in `pam-unix-oidc/src/lib.rs` sends a JSON line without a trailing `\n`. The agent's `BufReader::read_line()` in `socket.rs` blocks until the 2-second PAM write timeout fires. The complete line is never received; `cleanup_session()` never runs. Token revocation, DPoP key zeroization, and refresh-task abort are all silently skipped on every session close.

**Bug 2 (Critical, SEC-05):** The PAM module's `issue_and_deliver_nonce()` sends `DPOP_NONCE:<value>` to the SSH client via keyboard-interactive round 1, then waits for a `DPOP_PROOF:` response in round 2. No code in `unix-oidc-agent` intercepts the `DPOP_NONCE:` prompt and calls `GetProof` with the extracted nonce. With `dpop_required=Strict` (the safe-default when no policy.yaml exists), every SSH login fails because the proof is always empty.

**Bug 3 (Minor, OPS-09):** `TimeoutsConfig.clock_skew_future_secs` and `clock_skew_staleness_secs` are wired only in the agent binary. The PAM module's `pam_sm_authenticate()` hardcodes `clock_skew_future_secs: 5` in the `DPoPAuthConfig` literal at `lib.rs:207` and `ValidationConfig::from_env()` hardcodes `clock_skew_tolerance_secs: 60`. Operator config changes have no effect on PAM-path clock skew.

**Bug 4 (Minor, cleanup):** `socket.rs:1605` contains an `.unwrap()` on a `HashMap::get()` that violates `deny(clippy::unwrap_used)` in the agent crate. `DPoPAuthConfig::from_env()` in `auth.rs` is never called in production paths and documents env vars that are dead.

**Primary recommendation:** Fix Bug 1 (append `\n`), implement Bug 2 (SSH_ASKPASS nonce handler), wire Bug 3 (read clock_skew from PolicyConfig), remove Bug 4 (safe HashMap get, remove or call from_env).

---

## Standard Stack

### Core (no changes needed)
| Crate | Version | Purpose | Notes |
|-------|---------|---------|-------|
| `tokio` | existing | Async agent runtime | BufReader::read_line semantics verified below |
| `serde_json` | existing | IPC JSON framing | Protocol already correct except missing `\n` |
| `figment` | existing | Layered config | PolicyConfig already uses this; PAM path needs same pattern |

### No New Dependencies
All four fixes use only the existing crate graph. The SSH_ASKPASS handler needs `std::env` and existing agent code.

---

## Architecture Patterns

### Bug 1 Pattern: IPC newline termination

**What the code does now (`lib.rs:674-680`):**
```rust
// pam-unix-oidc/src/lib.rs — notify_agent_session_closed()
let msg = format!(
    r#"{{"action":"session_closed","session_id":"{}"}}"#,
    session_id
);
stream.write_all(msg.as_bytes())  // NO trailing \n
```

**What the agent expects (`socket.rs:463`):**
```rust
// unix-oidc-agent/src/daemon/socket.rs — handle_connection()
let n = match tokio::time::timeout(idle_timeout, reader.read_line(&mut line)).await { ... }
```

`BufReader::read_line()` accumulates bytes until `\n` or EOF. Without `\n`, it blocks until the 2-second PAM write timeout fires. The agent never sees a complete line and never dispatches the `SessionClosed` handler.

**Correct pattern (used in sudo.rs via `send_ipc_message()`):**
```rust
// pam-unix-oidc/src/sudo.rs:396-410 — send_ipc_message()
fn send_ipc_message(stream: &mut UnixStream, msg: &AgentMessage) -> Result<(), SudoError> {
    let json = serde_json::to_string(msg)?;
    stream.write_all(json.as_bytes())?;
    stream.write_all(b"\n")?;  // <-- correct termination
    Ok(())
}
```

**Fix:** One-line change. After `stream.write_all(msg.as_bytes())` in `notify_agent_session_closed()`, add `stream.write_all(b"\n")` with the same error-handling pattern (WARN + return on error).

**Confidence:** HIGH. Root cause confirmed by direct code inspection. Behavior of `BufReader::read_line()` is documented in the Rust standard library: it reads until `\n` (inclusive) or EOF.

---

### Bug 2 Pattern: SSH keyboard-interactive nonce handler

#### How SSH keyboard-interactive + PAM works

When `sshd` uses keyboard-interactive auth (`KbdInteractiveAuthentication yes`), it runs the PAM conversation. Each `pamh.conv()` call produces one prompt that sshd forwards to the SSH client. The SSH client delivers these prompts either:

1. **Interactive TTY:** Displayed directly; user types a response.
2. **`SSH_ASKPASS` mode:** When `SSH_ASKPASS` is set in the environment and there is no TTY (or `SSH_ASKPASS_REQUIRE=force`), SSH spawns the `SSH_ASKPASS` binary, passes the prompt text as the first argv argument, and reads the response from its stdout.

The `unix-oidc-agent` binary is designed to serve as `SSH_ASKPASS`. It already handles the `OIDC Token:` prompt (round 0 in the current flow). Phase 7's `issue_and_deliver_nonce()` added two new rounds:
- Round 1: PAM sends `DPOP_NONCE:<nonce_value>` with `PROMPT_ECHO_ON`
- Round 2: PAM asks `DPOP_PROOF: ` with `PROMPT_ECHO_OFF`; agent must respond with the proof

#### What is missing

`unix-oidc-agent` has no subcommand or code path that:
1. Receives a prompt string as argv[1] (SSH_ASKPASS invocation style)
2. Parses it to distinguish `DPOP_NONCE:`, `DPOP_PROOF: `, and `OIDC Token:` prompts
3. For `DPOP_NONCE:` — extracts the nonce, stores it in memory or temp file for the next invocation
4. For `DPOP_PROOF: ` — calls `AgentClient::get_proof()` with the stored nonce, prints token+proof to stdout

#### Nonce state transfer between two SSH_ASKPASS invocations

`SSH_ASKPASS` is invoked as a separate child process for each prompt round. There is no shared in-process state between the `DPOP_NONCE:` invocation (round 1) and the `DPOP_PROOF:` invocation (round 2). The nonce extracted in round 1 must be persisted somewhere accessible in round 2.

Options:
| Approach | Pros | Cons |
|----------|------|------|
| `UNIX_OIDC_DPOP_NONCE` env var (inherited) | Simple; no file I/O | Does not work — env vars do not propagate from child to parent or to a sibling child process |
| tmpfile at predictable path | Simple | Race condition if two SSH sessions occur simultaneously; requires cleanup |
| Per-session tmpfile keyed by `$SSH_CLIENT` or `$$` | Avoids races | `$$` is the SSH parent PID, available in environment |
| Agent IPC: store nonce via a `SetNonce` IPC call | Centralized; agent manages state | Requires new IPC message type |

**Recommended approach:** Per-session tmpfile keyed by parent PID. `SSH_ASKPASS` children inherit the parent's `$$` PID via `$SSH_ASKPASS_NONCE_KEY` (set by a wrapper) or via `$PPID` in the child. In practice, the simplest reliable mechanism is a predictable-but-unique path like `/tmp/.unix-oidc-nonce-${PPID}`, where `PPID` is the PID of the SSH client process. The PPID is the same for both SSH_ASKPASS invocations within one connection.

An alternative that avoids filesystem state: **inline the nonce into the session by returning it from round 1 and threading it into the `GetProof` IPC request.** Since both rounds are sub-processes of the same SSH client, they can share state via a temp file keyed on `$PPID`. This is the simplest, most reliable approach.

#### Subcommand design

Add a new `SshAskpass` subcommand (or `Askpass`) that:
1. Reads `argv[1]` as the prompt string.
2. If prompt starts with `DPOP_NONCE:`:
   - Extract the nonce value (everything after `DPOP_NONCE:`).
   - Write nonce to `/tmp/.unix-oidc-nonce-${PPID}` (0600 mode).
   - Print empty line to stdout (PAM ignores round-1 response).
   - Exit 0.
3. If prompt is `DPOP_PROOF: ` (or matches known DPoP proof prompt):
   - Read nonce from `/tmp/.unix-oidc-nonce-${PPID}`.
   - Delete the tmpfile.
   - Call `AgentClient::get_proof(target, "SSH", Some(nonce))`.
   - Print `dpop_proof` to stdout.
   - Also store `token` somewhere for round 0 (OIDC Token prompt) — see note below.
   - Exit 0.
4. If prompt is `OIDC Token: ` or similar:
   - Call `AgentClient::get_proof(target, "SSH", None)` and print token.
   - OR read previously cached token from tmpfile if available.

**Ordering note:** The current PAM flow is: `DPOP_NONCE:` round (1) → `DPOP_PROOF:` round (2) → `OIDC Token:` round (3 via `get_auth_token()`). Wait — re-reading `lib.rs`:

```
authenticate():
  1. issue_and_deliver_nonce()     → DPOP_NONCE:<value> (PROMPT_ECHO_ON)
  2. conv("DPOP_PROOF: ", ...)    → waits for proof (PROMPT_ECHO_OFF)
  3. get_auth_token()             → "OIDC Token: " (PROMPT_ECHO_OFF)
```

So the order is: nonce → proof → token. The agent needs the nonce at proof time, and the proof+token are independent. The `GetProof` IPC returns both `token` and `dpop_proof` together, so round 2 can retrieve both from the agent and cache the token locally for round 3.

**Confidence:** HIGH for the SSH_ASKPASS mechanism; MEDIUM for the specific tmpfile approach (alternative: the agent could expose a `StoreNonce`/`ConsumeNonce` IPC pair, but that adds IPC surface).

#### Environment variable configuration for SSH_ASKPASS

The user configures `~/.ssh/config` or uses `SSH_ASKPASS=unix-oidc-agent ssh-askpass`. The agent binary needs to respond correctly. A dedicated subcommand (`unix-oidc-agent ssh-askpass`) is cleaner than trying to auto-detect the invocation mode.

---

### Bug 3 Pattern: Threading clock_skew through PAM config

**Current state in `pam-unix-oidc/src/lib.rs:202-211`:**
```rust
let dpop_config = DPoPAuthConfig {
    target_host: gethostname::gethostname().to_string_lossy().to_string(),
    max_proof_age: 60,              // hardcoded
    clock_skew_future_secs: 5,     // hardcoded
    require_nonce: true,
    expected_nonce: None,
    require_dpop_for_bound_tokens: true,
};
```

**Current state in `pam-unix-oidc/src/oidc/validation.rs:106`:**
```rust
clock_skew_tolerance_secs: 60,  // hardcoded default; "callers wiring AgentConfig should pass..."
```

**Where the config lives:** `unix-oidc-agent/src/config.rs:TimeoutsConfig` has `clock_skew_future_secs` (default 5) and `clock_skew_staleness_secs` (default 60). This is agent-only config loaded by the agent binary. The PAM module has no `AgentConfig`.

**Correct fix:** Add clock_skew fields to `PolicyConfig` so they are readable from `/etc/unix-oidc/policy.yaml` by the PAM module. `PolicyConfig` already uses figment and is loaded in `authenticate()` via `PolicyConfig::from_env()`.

Two sub-options:
1. Add `timeouts` section to `PolicyConfig` mirroring `TimeoutsConfig` fields relevant to PAM. This gives operators a single config file for PAM.
2. Add env var overrides `UNIX_OIDC_CLOCK_SKEW_FUTURE_SECS` and `UNIX_OIDC_CLOCK_SKEW_STALENESS_SECS` that `DPoPAuthConfig::from_env()` reads. This is the minimal change.

**Recommended:** Option 1 — add a `timeouts` struct to `PolicyConfig` with `clock_skew_future_secs` and `clock_skew_staleness_secs` fields (default same values). Wire them through `authenticate()` into `DPoPAuthConfig` and `ValidationConfig`. This aligns with the existing figment pattern and matches how the agent handles the same concern.

The `DPoPAuthConfig::from_env()` dead code issue is resolved simultaneously: either call it (now that it reads real config), or delete it and replace with direct construction from `PolicyConfig`.

**Confidence:** HIGH. The fix path is well-defined by existing patterns in the codebase.

---

### Bug 4 Pattern: socket.rs:1605 unwrap()

**Location:** `unix-oidc-agent/src/daemon/socket.rs:1605`

```rust
// Inside: handle handle_step_up_result() (called from handle_request)
if !is_finished {
    let state_read = state.read().await;
    let pending = state_read.pending_step_ups.get(&correlation_id).unwrap();  // <-- unwrap
    ...
}
```

**Why this is safe-but-wrong:** The outer `is_finished` gate was derived from `state_read.pending_step_ups.contains_key(&correlation_id)`. Between the `contains_key` check and the `.get().unwrap()`, the state lock was dropped and re-acquired. This is a TOCTOU window — another task could theoretically remove the entry. The comment at line 1288 was misread in the audit; the actual unwrap is at line 1605.

**Fix:** Replace `.get(&correlation_id).unwrap()` with `.get(&correlation_id).ok_or_else(|| ...)` and propagate as an error response, or use `if let Some(pending) = state_read.pending_step_ups.get(&correlation_id)` with an else branch that returns an already-consumed error response.

**`DPoPAuthConfig::from_env()` dead code:** The function exists at `auth.rs:239-263` and reads env vars (`UNIX_OIDC_DPOP_MAX_AGE`, `UNIX_OIDC_DPOP_REQUIRE_NONCE`, `UNIX_OIDC_DPOP_REQUIRE_FOR_BOUND`) that are documented but never actually consulted. `lib.rs:204-211` builds `DPoPAuthConfig` via struct literal. After Bug 3 is fixed, `from_env()` should either be replaced by a constructor that takes `&PolicyConfig` values, or removed entirely. Retaining dead `pub fn from_env()` misleads operators into thinking these env vars are honored.

**Confidence:** HIGH. `#![deny(clippy::unwrap_used)]` is active in the agent crate — this unwrap would fail CI if clippy runs on the affected code path with the deny attribute active.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| IPC newline termination | Custom framing protocol | Append `b"\n"` — already used everywhere else | The fix is one line; `send_ipc_message()` in sudo.rs is the reference |
| Nonce state persistence between SSH_ASKPASS invocations | Custom keyring store | Per-session tmpfile keyed by `$PPID` | Minimal, correct for ephemeral nonces; tmpfile lifetime matches SSH connection |
| Clock skew config in PAM | New config parser | Extend `PolicyConfig` with a `timeouts` sub-struct | Figment already handles this; maintains single-file ops model |

---

## Common Pitfalls

### Pitfall 1: Fixing only the send side of Bug 1

**What goes wrong:** Add `\n` to `notify_agent_session_closed()` but forget to verify the ACK read path. The ACK read uses a raw `stream.read(&mut ack)` (up to 64 bytes). If the agent now sends a well-formed ACK JSON `+ "\n"`, the PAM side reads the entire response including the trailing newline — this is fine. But verify that the PAM side does not need to parse the ACK; it currently only checks `Ok(0)` vs `Ok(_)` and ignores content.

**How to avoid:** Read the ACK handling code at `lib.rs:689-698` before touching anything. The current code is correct for best-effort; no change needed to the ACK reader.

### Pitfall 2: SSH_ASKPASS tmpfile race conditions

**What goes wrong:** Two simultaneous SSH sessions from the same user create nonce tmpfiles that collide if keyed only by UID. Using `/tmp/.unix-oidc-nonce-${PPID}` is safe because each SSH session has a unique client PID.

**How to avoid:** Key the tmpfile by `std::os::unix::process::parent_id()` (the PPID of the `SSH_ASKPASS` child). This is the PID of the `ssh` client process — unique per session.

**Warning signs:** Tests that run multiple SSH sessions in parallel from the same test process will share PPID and collide. Use a unique prefix in tests.

### Pitfall 3: DPoPAuthConfig::from_env() is pub — external callers

**What goes wrong:** If any external integration test or external crate imports `DPoPAuthConfig::from_env()`, removing it is a breaking change.

**How to avoid:** Check all call sites with `grep -rn "from_env" pam-unix-oidc/`. Current search shows zero call sites in production paths. The function is pub but appears unused outside tests. Safe to replace or remove.

### Pitfall 4: clock_skew config extension must preserve backward compat

**What goes wrong:** Adding a `timeouts` section to `PolicyConfig` with `#[serde(default)]` is required. A v1.0 `policy.yaml` that lacks the `timeouts:` key must still load successfully and use the defaults (5s future, 60s staleness).

**How to avoid:** Use `#[serde(default)]` on the new struct and `impl Default` with the same values as the hardcoded constants. Figment's `Serialized::defaults()` + `Yaml::file()` pattern handles this correctly.

### Pitfall 5: `PROMPT_ECHO_ON` round receives whatever the user (or agent) types

**What goes wrong:** PAM sends `DPOP_NONCE:<value>` with `PROMPT_ECHO_ON`, which means the user's terminal echoes the response. If the agent writes an empty line as the round-1 response, that is correct — the round-1 response is ignored by the server. But if the agent writes the nonce value back (as an ack), that also works and matches existing test assertions at `lib.rs:1062`.

**How to avoid:** Round-1 response can be empty string or the nonce itself — server ignores it. Agent should return empty string for cleanliness (no echo of nonce in terminal).

---

## Code Examples

### Fix 1: SessionClosed newline (one line)
```rust
// pam-unix-oidc/src/lib.rs — notify_agent_session_closed()
// After: stream.write_all(msg.as_bytes()) ...
// Add:
if let Err(e) = stream.write_all(b"\n") {
    tracing::warn!(
        error = %e,
        session_id = %session_id,
        "Failed to send session_closed IPC newline to agent"
    );
    return;
}
```

### Fix 2: SSH_ASKPASS subcommand skeleton
```rust
// unix-oidc-agent/src/main.rs — new SshAskpass subcommand
/// Handle SSH keyboard-interactive prompts (invoked as SSH_ASKPASS).
///
/// SSH spawns SSH_ASKPASS with the prompt string as argv[1].
/// This subcommand interprets three prompt types:
///   DPOP_NONCE:<nonce>  — store nonce for next invocation; respond empty
///   DPOP_PROOF: <...>   — retrieve proof from agent using stored nonce
///   OIDC Token: <...>   — retrieve token from agent
SshAskpass {
    /// The prompt string from SSH keyboard-interactive conversation
    prompt: String,
},
```

```rust
async fn run_ssh_askpass(prompt: String) -> anyhow::Result<()> {
    let ppid = std::os::unix::process::parent_id();
    let nonce_path = std::env::temp_dir().join(format!(".unix-oidc-nonce-{ppid}"));

    if let Some(nonce) = prompt.strip_prefix("DPOP_NONCE:") {
        // Round 1: store nonce, respond with empty string (server ignores response)
        std::fs::write(&nonce_path, nonce.trim())?;
        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&nonce_path, std::fs::Permissions::from_mode(0o600))?;
        }
        println!();  // empty response
        return Ok(());
    }

    if prompt.trim_start().starts_with("DPOP_PROOF") {
        // Round 2: read stored nonce, call GetProof, print dpop_proof
        let nonce = std::fs::read_to_string(&nonce_path)
            .ok()
            .map(|s| s.trim().to_string());
        let _ = std::fs::remove_file(&nonce_path);  // best-effort cleanup

        let target = get_target_from_env()?;  // SSH_CLIENT or UNIX_OIDC_TARGET
        let client = AgentClient::default();
        match client.get_proof(&target, "SSH", nonce.as_deref()).await? {
            AgentResponse::Success(AgentResponseData::Proof { dpop_proof, .. }) => {
                println!("{dpop_proof}");
            }
            other => anyhow::bail!("Unexpected agent response: {:?}", other),
        }
        return Ok(());
    }

    // Default: treat as token prompt
    let target = get_target_from_env().unwrap_or_default();
    let client = AgentClient::default();
    match client.get_proof(&target, "SSH", None).await? {
        AgentResponse::Success(AgentResponseData::Proof { token, .. }) => {
            println!("{token}");
        }
        _ => anyhow::bail!("Agent not logged in"),
    }
    Ok(())
}
```

### Fix 3: PolicyConfig timeouts extension
```rust
// pam-unix-oidc/src/policy/config.rs — new struct
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PamTimeoutsConfig {
    /// Clock skew tolerance for DPoP proofs issued slightly in the future (seconds).
    /// Default matches unix-oidc-agent TimeoutsConfig::clock_skew_future_secs.
    pub clock_skew_future_secs: u64,
    /// Maximum proof age and token expiry skew tolerance (seconds).
    /// Default matches unix-oidc-agent TimeoutsConfig::clock_skew_staleness_secs.
    pub clock_skew_staleness_secs: u64,
}

impl Default for PamTimeoutsConfig {
    fn default() -> Self {
        Self { clock_skew_future_secs: 5, clock_skew_staleness_secs: 60 }
    }
}
```

```rust
// In PolicyConfig struct — add field:
#[serde(default)]
pub timeouts: PamTimeoutsConfig,
```

```rust
// In PolicyConfig::load_from() — add "timeouts" to figment only() list:
.merge(Env::prefixed("UNIX_OIDC_").split("__").only(&[
    "security_modes", "cache", "identity", "introspection", "session", "timeouts",
]))
```

```rust
// In lib.rs authenticate() — wire into DPoPAuthConfig:
let timeouts = PolicyConfig::from_env()
    .map(|p| p.timeouts)
    .unwrap_or_default();

let dpop_config = DPoPAuthConfig {
    target_host: gethostname::gethostname().to_string_lossy().to_string(),
    max_proof_age: timeouts.clock_skew_staleness_secs,
    clock_skew_future_secs: timeouts.clock_skew_future_secs,
    require_nonce: true,
    expected_nonce: None,
    require_dpop_for_bound_tokens: true,
};
```

Also wire `clock_skew_tolerance_secs` into `ValidationConfig` after it is constructed from env:
```rust
config.clock_skew_tolerance_secs = timeouts.clock_skew_staleness_secs as i64;
```

### Fix 4: socket.rs:1605 safe HashMap get
```rust
// unix-oidc-agent/src/daemon/socket.rs — replace:
let pending = state_read.pending_step_ups.get(&correlation_id).unwrap();

// With:
let Some(pending) = state_read.pending_step_ups.get(&correlation_id) else {
    // TOCTOU: entry was removed between the is_finished check and this read.
    return AgentResponse::error("Step-up result already consumed", "STEP_UP_CONSUMED");
};
```

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | Rust built-in test (`cargo test`) |
| Config file | none (inline `#[test]` and `#[tokio::test]`) |
| Quick run command | `cargo test -p pam-unix-oidc -- --test-threads=1` |
| Full suite command | `cargo test --workspace -- --test-threads=1` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SES-08 | SessionClosed IPC dispatches cleanup_session() within 100ms (not 2s timeout) | integration | `cargo test -p unix-oidc-agent --test daemon_lifecycle -- session_closed` | ❌ Wave 0 |
| SES-07 | revoke_token_best_effort called from cleanup path (not skipped) | unit | `cargo test -p unix-oidc-agent -- test_cleanup_session_fires` | ❌ Wave 0 |
| SEC-05 | SSH_ASKPASS nonce handler: DPOP_NONCE prompt stores nonce; DPOP_PROOF prompt calls GetProof with nonce | unit | `cargo test -p unix-oidc-agent -- test_ssh_askpass_nonce_flow` | ❌ Wave 0 |
| OPS-09 | PolicyConfig timeouts wire to DPoPAuthConfig clock_skew fields | unit | `cargo test -p pam-unix-oidc -- test_clock_skew_from_policy_config` | ❌ Wave 0 |
| OPS-09 | clock_skew_tolerance_secs in ValidationConfig comes from policy, not hardcoded | unit | `cargo test -p pam-unix-oidc -- test_validation_config_clock_skew_from_policy` | ❌ Wave 0 |
| cleanup | socket.rs HashMap lookup does not panic | unit | `cargo test -p unix-oidc-agent -- test_step_up_result_toctou_safe` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** `cargo test -p pam-unix-oidc -- --test-threads=1` and `cargo test -p unix-oidc-agent -- --test-threads=1`
- **Per wave merge:** `cargo test --workspace -- --test-threads=1 && cargo clippy --workspace -- -D warnings`
- **Phase gate:** Full suite green + clippy clean before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] Test for SessionClosed IPC newline fix — verify `cleanup_session()` dispatch timing in `daemon_lifecycle.rs`
- [ ] Unit test for `run_ssh_askpass()` nonce store/retrieve flow (mock filesystem ops)
- [ ] Unit test for `PamTimeoutsConfig` deserialization and clock_skew threading
- [ ] Unit test for socket.rs safe HashMap get (no panic on missing key)

---

## Open Questions

1. **SSH_ASKPASS target resolution**
   - What we know: `run_get_proof()` in `main.rs` requires `--target` (a hostname). In `SSH_ASKPASS` mode, there is no CLI arg for the target; SSH passes only the prompt string as argv[1].
   - What's unclear: How does the SSH_ASKPASS handler know the target hostname? Options: (a) `$SSH_CLIENT` env var contains `<source_ip> <source_port> <dest_port>` — not the hostname; (b) `UNIX_OIDC_TARGET` env var set by the user in `~/.ssh/config`; (c) use `gethostname()` of the server (wrong — we're on the client); (d) defer target to the server via DPoP `htu` claim.
   - Recommendation: Accept `UNIX_OIDC_TARGET` env var as a fallback. The PAM module on the server side sets `expected_target = gethostname()`, so the client's target value must match. This is set via `~/.ssh/config`: `SetEnv UNIX_OIDC_TARGET=server.example.com`.

2. **DPoPAuthConfig::from_env() disposition**
   - What we know: It is `pub`, referenced in test code comments, and documents env vars that are currently dead.
   - What's unclear: Is there external tooling (integration tests, CI scripts) that relies on `UNIX_OIDC_DPOP_MAX_AGE` etc. being honored?
   - Recommendation: Replace `from_env()` with `from_policy(policy: &PolicyConfig) -> Self` and keep `from_env()` as a deprecated wrapper that calls it with defaults, or remove entirely if no external callers.

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Hardcoded 2s PAM timeout absorbs IPC failure | `\n` fix makes cleanup reliable | Phase 14 | SES-07/08 work as designed |
| SSH login with DPoP disabled or Warn only | Full E2E with nonce handler | Phase 14 | SEC-05 complete; TEST-01/02 unblocked |
| clock_skew only in agent config | clock_skew in both agent + PAM policy | Phase 14 | OPS-09 fully satisfied |

---

## Sources

### Primary (HIGH confidence)
- Direct inspection of `pam-unix-oidc/src/lib.rs:638-700` — `notify_agent_session_closed()` body
- Direct inspection of `unix-oidc-agent/src/daemon/socket.rs:450-520` — `handle_connection()` BufReader loop
- Direct inspection of `unix-oidc-agent/src/daemon/socket.rs:1600-1615` — `pending_step_ups` unwrap
- Direct inspection of `pam-unix-oidc/src/auth.rs:200-265` — `DPoPAuthConfig` and `from_env()`
- Direct inspection of `pam-unix-oidc/src/lib.rs:200-216` — hardcoded clock_skew in `DPoPAuthConfig` literal
- Direct inspection of `pam-unix-oidc/src/oidc/validation.rs:95-107` — hardcoded `clock_skew_tolerance_secs: 60`
- Direct inspection of `unix-oidc-agent/src/daemon/socket.rs:771-797` — `AgentClient::send()` correctly appends `\n`
- Direct inspection of `pam-unix-oidc/src/sudo.rs:396-410` — `send_ipc_message()` reference implementation
- `.planning/v2.0-MILESTONE-AUDIT.md` — authoritative bug descriptions with file locations

### Secondary (MEDIUM confidence)
- Rust standard library docs for `BufRead::read_line`: reads until `\n` inclusive or EOF; without `\n` on a non-EOF stream, blocks indefinitely.
- OpenSSH `SSH_ASKPASS` mechanism: invoked per-prompt as `SSH_ASKPASS <prompt>`, reads response from stdout. Documented in `ssh(1)` manpage.

---

## Metadata

**Confidence breakdown:**
- Bug 1 (SessionClosed newline): HIGH — exact line identified, single-line fix
- Bug 2 (SSH nonce handler): HIGH for mechanism; MEDIUM for tmpfile key strategy (PPID approach is solid but open question on target hostname remains)
- Bug 3 (clock_skew wiring): HIGH — fix path clear, existing figment pattern applies
- Bug 4 (unwrap + dead code): HIGH — lint violation and dead code confirmed by inspection

**Research date:** 2026-03-11
**Valid until:** Until code changes; this is a point-in-time code audit, not ecosystem research
