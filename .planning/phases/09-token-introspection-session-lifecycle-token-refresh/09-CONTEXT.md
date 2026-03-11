# Phase 9: Token Introspection + Session Lifecycle + Token Refresh - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

SSH sessions have bounded lifetimes tied to token validity. Revoked tokens are detected within the introspection cache TTL. The agent auto-refreshes tokens before mid-session expiry. Implements SES-01 through SES-08.

Requirements: SES-01, SES-02, SES-03, SES-04, SES-05, SES-06, SES-07, SES-08

</domain>

<decisions>
## Implementation Decisions

### Token Introspection (SES-05, SES-06)
- RFC 7662 introspection is opt-in via `[introspection]` section in policy.yaml (global toggle, not per-provider)
- Default: disabled. When enabled, default fail-open (auth succeeds if introspection endpoint is unreachable)
- Introspection runs at auth time AND periodically during open sessions via the agent daemon
- If introspection returns `active: false`, the agent writes a revocation marker to `/run/unix-oidc/sessions/{id}.revoked` — sshd detects and terminates the session
- The token never leaves the agent for introspection — no new attack surface
- Introspection cache via moka with TTL = `min(configured_ttl, token_exp - now)`, default 60s
- Overhead: one HTTP call per cache TTL per active session (from agent, which already makes HTTP calls for refresh)

### Session Record Lifecycle (SES-01, SES-02, SES-03)
- `pam_sm_open_session` writes JSON session record to `/run/unix-oidc/sessions/{session_id}.json`
- Record contents (operational-grade): username, token_jti, token_exp, session_start, client_ip, sshd_pid, issuer (~200 bytes)
- `pam_sm_close_session` deletes the session record and emits a session-close audit event with duration
- Session ID correlation between authenticate and open_session via PAM environment variable: `pam_putenv("UNIX_OIDC_SESSION_ID=...")` in authenticate, `pam_getenv()` in open_session — works across sshd forks
- `/run/unix-oidc/sessions/` directory: root-owned, mode 0700. Session files: root-owned, mode 0600
- tmpfs loss on reboot accepted: startup scan detects missing session records, emits "session lost to restart" audit events, cleans up agent-side state. Sessions are bounded by token expiry regardless
- Enables future `unix-oidc sessions list` CLI command for operational dashboards

### Auto-Refresh Scheduling (SES-04)
- Background `tokio::spawn` task in agent daemon, spawned at login
- Sleeps until 80% of token lifetime (configurable: `token_refresh_threshold_percent` in agent config, default 80)
- Re-arms after each successful refresh; task cancelled on session close
- On refresh failure: exponential backoff (5s, 10s, 20s, 40s) up to 3 retries; if all fail, log WARN and set `refresh_failed: true` flag in IPC status responses; session continues until token expires naturally
- After successful refresh, run introspection on the new token (if introspection is enabled) to verify the account is still active — catches the narrow race where an account is disabled between refresh grant and introspection check

### Revocation on Session Close (SES-07, SES-08)
- PAM `close_session` sends `SessionClosed` IPC message to agent daemon
- Agent immediately ACKs the IPC (fire-and-forget) so close_session returns quickly, then spawns a tokio task for revocation + cleanup
- Revocation: best-effort RFC 7009 call with 5s timeout; failure logged at WARN with reason (timeout, HTTP error, IdP doesn't support revocation)
- `pam_sm_close_session` ALWAYS returns PAM_SUCCESS regardless of revocation outcome — never block session teardown
- Full credential cleanup on SessionClosed: revoke token (best-effort) → zeroize DPoP signing key → delete refresh token → delete access token → delete token metadata. Next login starts completely fresh
- Aligns with CLAUDE.md memory protection invariants (ZeroizeOnDrop, secure delete)

### Claude's Discretion
- Introspection client implementation details (reqwest client reuse, endpoint discovery from OIDC metadata)
- Stale cache behavior when introspection endpoint is unreachable (serve stale vs fall back to configured mode)
- Exact session record JSON schema field names
- Revocation marker file format and detection mechanism (PAM account management hook vs periodic checker)
- IPC protocol extension design for SessionClosed message
- Introspection + refresh task coordination in agent event loop
- Test strategy structure (unit, integration, adversarial)

</decisions>

<specifics>
## Specific Ideas

- Standing directive: ultra secure, standards/best practice compliant, enterprise ready, fully audited and tested
- Exhaustive testing for EVERY feature: positive paths, negative paths, adversarial scenarios (forged session records, replayed revocation calls, introspection cache poisoning, timing attacks on marker files), edge cases (very short token lifetimes, concurrent session open/close, agent restart mid-session)
- Design philosophy consistency check: every decision should be what someone who knows the project philosophy ("security should not be annoying," conservative defaults, defense in depth with graceful degradation) would naturally expect
- Follow RFC 7662 (introspection) and RFC 7009 (revocation) precisely
- Match patterns established in Phases 6-8: EnforcementMode, figment config, moka caches, parking_lot, structured tracing, deny(clippy::unwrap_used)

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `generate_ssh_session_id()` (`pam-unix-oidc/src/security/session.rs`): CSPRNG session ID generation — ready to use for session records
- `perform_token_refresh()` (`unix-oidc-agent/src/daemon/socket.rs:414-553`): Full refresh flow — add scheduling wrapper
- `AgentRequest::Refresh` / `AgentResponseData::Refreshed` (`protocol.rs`): Existing refresh IPC — extend for SessionClosed
- `DPoPNonceCache` (`nonce_cache.rs`): moka cache pattern — reference for introspection cache
- `AuditEvent` variants (`audit.rs`): Pattern for SessionOpened/SessionClosed events; `SshLoginSuccess` already includes `session_id`
- `EnforcementMode` (`config.rs`): Reuse for introspection fail-open/fail-closed configuration
- `AgentState.token_expires` (`socket.rs`): Token expiry already tracked — use for refresh threshold calculation
- `KEY_TOKEN_METADATA` storage key: Already stores token_endpoint, client_id, refresh_token — revocation endpoint can be added here
- `ProtectedSigningKey` (`unix-oidc-agent/src/crypto/protected_key.rs`): ZeroizeOnDrop — cleanup on SessionClosed

### Established Patterns
- `moka::sync::Cache` for TTL-bounded caches (nonce cache: 100k capacity, 60s TTL)
- `parking_lot::RwLock` for thread-safe state
- `deny(clippy::unwrap_used, clippy::expect_used)` — all new code must comply
- figment-based config with env var overrides (`UNIX_OIDC_` prefix)
- `thiserror` for error types, `tracing` for structured logging
- PAM conversation via PROMPT_ECHO_ON/OFF (established in nonce delivery, Phase 7)
- SecretString for token values (MEM-03)

### Integration Points
- `pam-unix-oidc/src/lib.rs:313-319`: `open_session()` and `close_session()` stubs — implement here
- `unix-oidc-agent/src/daemon/protocol.rs`: Add `SessionClosed` request variant and `SessionAcknowledged` response
- `unix-oidc-agent/src/daemon/socket.rs`: Add SessionClosed handler, spawn revocation + cleanup task
- `pam-unix-oidc/src/policy/config.rs`: Add `[introspection]` and `[session]` config sections
- `pam-unix-oidc/src/audit.rs`: Add `SessionOpened`, `SessionClosed`, `TokenRevoked`, `IntrospectionFailed` variants
- New module: `pam-unix-oidc/src/oidc/introspection.rs` — RFC 7662 client
- `pam-unix-oidc/src/lib.rs`: authenticate() must call `pam_putenv("UNIX_OIDC_SESSION_ID=...")` for SES-03 correlation

</code_context>

<deferred>
## Deferred Ideas

- Per-provider introspection config for multi-IdP deployments — extend when multi-provider support matures
- Persistent session records in /var/lib/ for reboot durability — tmpfs + orphan cleanup is sufficient for v2.0
- Configurable revocation failure behavior (strict mode that blocks session teardown) — too risky, revisit only if compliance requires it
- `unix-oidc sessions list` CLI command — enabled by operational session records, implement in a future operational tooling phase
- Direct sshd signal (SIGTERM) for introspection-triggered session kill — marker file approach is cleaner and doesn't require privilege escalation

</deferred>

---

*Phase: 09-token-introspection-session-lifecycle-token-refresh*
*Context gathered: 2026-03-10*
