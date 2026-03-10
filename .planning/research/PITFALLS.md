# Domain Pitfalls: Production Hardening and Enterprise Auth on Existing OIDC PAM

**Domain:** OIDC PAM module and agent daemon — adding CIBA, FIDO2/WebAuthn step-up, session lifecycle, configurable security modes, username mapping, group policies, and operational readiness to an existing system
**Researched:** 2026-03-10
**Milestone:** v2.0 Production Hardening and Enterprise Readiness
**Confidence:** HIGH (primary sources: OpenID CIBA Core 1.0 spec, RFC 9449, libfido2 docs, systemd man pages, verified against live codebase)

---

## Critical Pitfalls

Mistakes that cause lockouts, panics in PAM, silent security regressions, or backward-incompatible deployments.

---

### Pitfall 1: CIBA Polling Blocks the PAM Thread — Causing sshd Connection Timeout

**What goes wrong:**
PAM's `authenticate()` function is called synchronously from sshd. `sshd` has a hard `LoginGraceTime` (default: 120 seconds, configurable). CIBA's backchannel authentication endpoint returns `auth_req_id`, then the client polls the token endpoint on a timer until the user approves on their phone. If the CIBA polling loop runs on the PAM thread using `std::thread::sleep()` — as the current device flow polling in `device_flow/client.rs` does (line 129: `std::thread::sleep(current_interval)`) — the PAM thread blocks for the entire challenge duration.

This works for Device Flow because Device Flow is user-interactive: the user sees the code, acts immediately. CIBA push auth targets phones; push delivery may be delayed by GCM/APNs 30–60 seconds. If the IdP uses long-polling (returning after auth, not immediately), the PAM thread can block for 60–120+ seconds, triggering sshd's `LoginGraceTime` timeout. sshd terminates the connection, the user is disconnected, and the CIBA request is orphaned in the IdP.

**Why it happens:**
The existing polling pattern in `DeviceFlowClient::poll_for_token()` uses `reqwest::blocking` with `std::thread::sleep()`. This is acceptable for device flow (user-driven, short loops) but is architecturally wrong for CIBA where the IdP may use long-poll responses of 30+ seconds. The `SudoConfig.challenge_timeout` is currently 60 seconds — but that is the total allowed, not a per-poll ceiling.

The OpenID CIBA Core 1.0 spec (§7.3) says the authorization server may respond to a poll request after waiting up to `expires_in` seconds. In long-poll mode, a single HTTP GET can block for the full expiry interval.

**Codebase location:** `pam-unix-oidc/src/device_flow/client.rs:129` (sleep pattern), `pam-unix-oidc/src/approval/provider.rs:175–218` (trait-level polling loop). Any CIBA implementation that reuses this polling trait will inherit the blocking problem.

**How to avoid:**
1. Implement CIBA polling in the agent daemon (`unix-oidc-agent`), not in the PAM module. The PAM module asks the agent "start CIBA challenge for user X", then polls the agent's local socket (fast, local IPC) for a resolved/rejected status. The agent handles the slow IdP polling asynchronously in its tokio runtime.
2. Cap the PAM-side poll interval at 2–3 seconds against the local agent socket. The agent's tokio task handles the IdP-side long-poll off the PAM thread.
3. If CIBA must run in-process (no agent), use `std::thread::spawn` to run the polling loop on a separate thread and join with a hard timeout. Never block the PAM thread with network I/O for more than 5 seconds without returning `PamError::AUTH_ERR`.
4. Set a sane `LoginGraceTime 120` minimum in the deployment documentation — users must know that CIBA requires extended grace time.

**Warning signs:**
- Any `std::thread::sleep` call in a code path reachable from `PamServiceModule::authenticate()` with a delay exceeding 5 seconds
- `reqwest::blocking::Client` used inside PAM for CIBA polling (blocking HTTP on the PAM thread)
- `challenge_timeout` set higher than `LoginGraceTime` in sshd

**Phase to address:** The phase implementing CIBA step-up. Must be the first design decision, before any code is written for CIBA.

---

### Pitfall 2: WebAuthn in SSH Requires a Relay — There Is No Browser

**What goes wrong:**
WebAuthn/FIDO2 authentication (`StepUpMethod::Fido2` in `policy/rules.rs:27`) requires a relying party (RP) client to call `navigator.credentials.get()` in a browser context, which triggers OS/browser interaction with the CTAP2 authenticator. In an SSH session, there is no browser. The WebAuthn ceremony cannot be initiated directly from the PAM module or the agent daemon.

A common mistake is to implement FIDO2 step-up using `libfido2`'s assertion flow directly (CTAP2 over USB/NFC) and claim this is "WebAuthn." It is not — CTAP2 direct assertion lacks the origin binding and RP ID verification that WebAuthn provides. An SSH-side implementation using libfido2 assertion calls a different security model than browser WebAuthn and will not be interoperable with standard WebAuthn RP verification libraries.

The `StepUpMethod::Fido2` variant exists in the codebase today but has no implementation behind it (it is parsed from policy YAML but no `ApprovalProvider` dispatches on it). This is the right state — but any implementation must choose one of two valid patterns, not a third "looks like WebAuthn but isn't" pattern.

**Valid approaches (HIGH confidence):**
1. **CIBA + Authenticator App Fallback:** For IdPs that support CIBA + FIDO2 authentication on the authenticator app (Okta Verify, Microsoft Authenticator), initiate CIBA from the PAM side and let the IdP orchestrate the FIDO2 challenge on the user's device. The PAM module never touches CTAP2. This is the right pattern for enterprise IdPs.
2. **SSH FIDO2 keys (ssh-keygen -t ed25519-sk):** OpenSSH natively supports FIDO2-resident keys. Users generate `ed25519-sk` keys; sshd verifies them. This is entirely orthogonal to OIDC — it is a separate SSH key type, not OIDC step-up. Do not conflate this with the OIDC/DPoP flow.
3. **Direct CTAP2 libfido2 assertion for LOCAL authenticator only:** If the user has a FIDO2 security key physically connected to the server (unusual for SSH), libfido2 can generate and verify an assertion. This is a niche deployment model and must be explicitly documented as "local hardware key required on server."

**How to avoid:**
- Do not implement `Fido2` as a direct CTAP2 call from the PAM module unless the deployment model explicitly requires a hardware key attached to the server.
- The recommended implementation for `StepUpMethod::Fido2` in this system is: initiate CIBA with `acr_values=phr` (phishing-resistant) and let the IdP drive FIDO2 on the user's device. The CIBA result carries a token with `acr=phr`; the PAM module validates the ACR claim.
- Mark `StepUpMethod::Fido2` as `/// Requires CIBA with phishing-resistant ACR. See docs/step-up-fido2.md.` in the policy rules docs.

**Warning signs:**
- Any import of `libfido2`, `fido2-rs`, or `ctap-hid-fido2` crates in the PAM module crate (`pam-unix-oidc/Cargo.toml`)
- Any code that attempts to open a USB HID device (`/dev/hidraw*`) from within `authenticate()`

**Phase to address:** Phase implementing IdP-agnostic step-up. Architecture decision document required before implementation.

---

### Pitfall 3: `.expect()` in PAM-Reachable Code Paths Causes Total Lockout

**What goes wrong:**
`CLAUDE.md` states "No panics in PAM paths." The codebase currently has four `.expect()` calls reachable from PAM module code:

- `pam-unix-oidc/src/device_flow/client.rs:32` — `Client::builder().build().expect("Failed to create HTTP client")` — in `DeviceFlowClient::new()`
- `pam-unix-oidc/src/device_flow/client.rs:51` — same pattern in `DeviceFlowClient::with_endpoints()`
- `pam-unix-oidc/src/security/session.rs:74` — `getrandom::fill(&mut bytes).expect("secure random number generation failed")` — called from `generate_ssh_session_id()`, called from `authenticate()`
- `pam-unix-oidc/src/oidc/dpop.rs:282` — `SystemTime::now().duration_since(UNIX_EPOCH).expect("system time before UNIX epoch")`

When v2.0 adds CIBA and session lifecycle code, new `reqwest::blocking` clients and getrandom calls will be introduced. If the same `.expect()` pattern is reused, any panic from network setup failure (invalid TLS config, exhausted file descriptors), entropy failure (in constrained container environments), or clock skew causes the PAM module to `abort()`, which kills the sshd process. The user is immediately disconnected. If this happens during an SSH session to a server without break-glass access, the server becomes inaccessible until the next reboot or a local console login.

**Why it happens:**
`reqwest::blocking::Client::builder().build()` can theoretically fail if TLS initialization fails (missing system CA bundle, invalid proxy configuration). In practice this almost never panics on a well-configured system, so developers treat the `.expect()` as documentation of "this should never fail." In PAM, "should never" is not good enough — edge cases in container environments (missing CA bundles, low file descriptor limits) can trigger these paths.

**How to avoid:**
1. Search for `.expect(` in all files under `pam-unix-oidc/src/` before any new feature is merged. Replace every `.expect()` with `map_err(|e| PamError::SERVICE_ERR)` or equivalent, logging the error with `tracing::error!()` first.
2. For `getrandom` failure in session ID generation: return a timestamp-only session ID (lower entropy, but safe) rather than panicking. Alternatively, log the error and return `PamError::SERVICE_ERR`.
3. For `reqwest` client construction: return `Err(AuthError::Config(...))` and let the PAM entry point translate it to `PamError::SERVICE_ERR`.
4. Add a `#![deny(clippy::unwrap_used, clippy::expect_used)]` lint to `pam-unix-oidc/lib.rs` — Clippy can enforce this automatically on new code.
5. When introducing CIBA or session store clients in v2.0, all HTTP client construction must use `?` propagation, never `.expect()`.

**Warning signs:**
- Any `.expect(` in `pam-unix-oidc/src/` outside of `#[cfg(test)]` blocks
- New Cargo.toml dependencies (reqwest, tokio, custom HTTP clients) added to `pam-unix-oidc` without a corresponding panic audit

**Phase to address:** Phase 1 of v2.0 (PAM hardening / panic elimination). Must be completed before any other v2.0 feature work begins.

---

### Pitfall 4: Token Introspection on Every PAM Authentication Kills IdP Under Load

**What goes wrong:**
Adding RFC 7662 token introspection to the PAM module — to get real-time revocation status — means an HTTP call to the IdP's introspection endpoint on every `authenticate()` invocation. On a server with 50 concurrent SSH connections, that is 50 concurrent introspection requests per second during peak login. IdPs enforce rate limits on introspection; Okta, for example, enforces per-client rate limits that can be as low as 600 req/min per application.

Beyond rate limiting: if the IdP is temporarily unavailable (planned maintenance, network partition), every SSH login fails simultaneously. This is a catastrophic failure mode — the entire server becomes inaccessible to all users at once. The current JWKS caching in `oidc/jwks.rs` (5-minute TTL) survives IdP outages gracefully; introspection without caching does not.

**Why it happens:**
Developers adding introspection often implement it as a synchronous call in the `authenticate()` hot path without caching, because "we need current revocation status." The design tension is real — caching introspection results reduces freshness — but the correct resolution is not "cache nothing" but "cache with a short TTL tuned to the organization's revocation SLA."

The current JTI cache (`security/jti_cache.rs`) is local, in-process, bounded at 100k entries. A similar pattern works for introspection results.

**How to avoid:**
1. Implement an introspection result cache keyed by token JTI with a configurable TTL (default: 60 seconds). Token expiry provides the ultimate freshness bound — a revoked token cached for 60 seconds is valid at most 60 seconds longer than intended.
2. On introspection endpoint failures (network error, HTTP 5xx), fall back to local JWT signature verification (the current behavior). Log at `WARN` level. Do not fail authentication because the introspection endpoint is unreachable.
3. Enforce introspection TTL < token TTL. Never cache an introspection result past the token's own `exp` claim.
4. Make introspection opt-in via policy config (e.g., `ssh_login.introspection: enabled|disabled|best_effort`). Default to `disabled` to preserve the existing behavior and not break deployments that rely on local JWT verification only.
5. The JWKS `RwLock<Option<CachedJwks>>` pattern in `oidc/jwks.rs` is a correct model for the introspection cache.

**Warning signs:**
- `reqwest::blocking` introspection call added directly to `oidc/validation.rs` without a cache
- No circuit-breaker or fallback-to-local behavior when introspection endpoint is unreachable
- Introspection TTL not bounded by token `exp`

**Phase to address:** Phase implementing session lifecycle / token introspection.

---

### Pitfall 5: PAM Session Store Requires Cross-Invocation Shared State — PAM Reinitializes Every Time

**What goes wrong:**
PAM invokes the module's `authenticate()`, `setcred()`, `open_session()`, and `close_session()` functions as separate processes or separate `dlopen()` calls with no shared state between them. A session store that holds state in module-level `static` (e.g., a `Lazy<RwLock<HashMap<...>>>` for session IDs) works within a single process but is not visible to other sshd worker processes.

sshd with `UsePrivilegeSeparation yes` (the modern default) uses a privilege-separated architecture: the pre-authentication monitor runs as root; after authentication the unprivileged child handles the session. PAM is typically called from the monitor process. Storing session state in the monitor's memory makes it invisible to the session process and to the next incoming connection's monitor process.

The current `security/session.rs` generates session IDs but does not persist them anywhere. When `open_session()` is called after `authenticate()`, the session ID generated in `authenticate()` is gone.

**How to avoid:**
1. Any persistent session store must be out-of-process: a file under `/run/unix-oidc/sessions/` (root-owned, mode 0700), or a socket-based call to the `unix-oidc-agent` daemon. Do not attempt to share state via module statics across PAM invocations from different sshd processes.
2. Pass session correlation ID via PAM data (the `pam_set_data()` / `pam_get_data()` API, available through the `pamsm` crate's `pamh.set_data()` / `pamh.get_data()` if exposed). PAM data is shared between calls within the same PAM handle (same sshd session), but not across processes.
3. For session revocation state: write a minimal record to a tmpfs file on `authenticate()` success, check/delete it on `close_session()`. The file path must include the session ID and be race-condition safe (use `O_CREAT | O_EXCL` for creation).
4. For `RwLock<HashMap>` singleton caches (JTI cache, rate limiter) already in the codebase: these work correctly because all PAM calls for a given sshd connection use the same process. They do not work for cross-connection correlation. Document this boundary explicitly.

**Warning signs:**
- Session state stored in `static Lazy<...>` that is expected to be visible to `open_session()` after a different `authenticate()` call
- Session ID written to memory in `authenticate()` and expected to be readable in `close_session()` without using `pam_set_data()`

**Phase to address:** Phase implementing full session lifecycle.

---

### Pitfall 6: Configurable Security Modes — Making Strict the Default Silently Breaks Existing Deployments

**What goes wrong:**
Issue #10 (configurable security modes: strict/warn/disabled) specifies adding enforcement levels to checks like JTI presence, DPoP binding, and ACR verification. If the v2.0 config parser makes `strict` the new default for any check that was previously `warn`, every existing deployment without a `policy.yaml` expressing the old behavior will start rejecting tokens that were previously accepted.

Concrete example: the current `ValidationConfig.enforce_jti` field in `oidc/validation.rs:64` defaults to `true`. But the env variable `UNIX_OIDC_DISABLE_JTI_CHECK=true` implies some operators turned off JTI enforcement for compatibility. If v2.0 adds a `jti_enforcement = "strict"` config field and defaults it to `strict`, operators who relied on the env variable workaround will find their logins broken after upgrading.

**Why it happens:**
Security teams want stricter defaults. But "stricter defaults on upgrade" violates the principle of conservative deployment: changes to a PAM module should never lock out users without explicit operator action. The existing `policy.yaml` schema (`PolicyConfig` in `policy/config.rs`) already uses `#[serde(default)]` on all structs — this is correct. The trap is adding new fields whose semantic default is stricter than the v1.0 implicit behavior.

**How to avoid:**
1. Rule: new security mode fields must default to the v1.0 behavior (warn/permissive), not to the desired future secure default. Document in code: `// Default matches v1.0 behavior — see Issue #10 migration guide`.
2. Provide a migration guide in `docs/` that lists every new config field, its default value, and its recommended production value. Operators opt in to strict mode deliberately.
3. For the `break_glass` config section: `BreakGlassConfig.enabled` defaults to `false`. Wiring break-glass enforcement in v2.0 must not change this default or add any behavior when `enabled = false`. Currently the struct is parsed but has no code acting on it. Adding enforcement code that triggers when `enabled = false` (e.g., "break-glass not configured — deny root access") would be a breaking change.
4. In `#[serde(default)]` structs, always implement `Default` explicitly and document the security rationale for each default value. Do not rely on `#[derive(Default)]` unless the defaults have been explicitly verified to match v1.0 semantics.

**Warning signs:**
- A new `SecurityMode` enum that derives `Default` to `Strict` without a backward-compat audit
- `break_glass` enforcement code that fires when `enabled = false` or `local_account = None`
- The `grace_period` field (referenced in `CLAUDE.md` but absent from `PolicyConfig` in `config.rs`) being added with a non-zero default that changes auth timing behavior

**Phase to address:** Phase implementing configurable security modes (Issue #10).

---

### Pitfall 7: policy.yaml Backward Compatibility — Unknown Fields Must Not Cause Parse Failure

**What goes wrong:**
`serde_yaml` with `#[serde(default)]` accepts missing fields gracefully. But `serde_yaml::from_str` with a strict `Deserialize` derive will return an error if the YAML contains a field not present in the Rust struct. This means adding new policy fields in v2.0 breaks operators who wrote forward-compatible YAML (e.g., a v2.0 `policy.yaml` deployed to a server still running v1.0 PAM) AND breaks v1.0 operators who add v2.0 fields before upgrading the binary.

Specifically: `PolicyConfig`, `SshConfig`, `SudoConfig`, and `BreakGlassConfig` all use `#[serde(default)]` but do not use `#[serde(deny_unknown_fields)]`, which means unknown fields are currently silently ignored by serde_yaml. This is the correct behavior. The trap is accidentally adding `#[serde(deny_unknown_fields)]` to any of these structs while cleaning up code.

The reverse is also dangerous: if v2.0 removes a field from the struct (e.g., removing the `CommandRule.pattern` field and renaming it), existing policy.yaml files that reference the old field name will lose their configuration silently (serde ignores unknown fields, the new field defaults to empty/false).

**How to avoid:**
1. Never add `#[serde(deny_unknown_fields)]` to any `PolicyConfig` struct or its sub-structs.
2. When renaming a config field, use `#[serde(alias = "old_name")]` for at least one major version before removing the old name.
3. Add a YAML schema validation step (via a `unix-oidc-agent validate-config` command) that warns about deprecated field names without rejecting the config.
4. Write a test that loads a v1.0-style `policy.yaml` (no v2.0 fields) against the v2.0 `PolicyConfig` struct and verifies it deserializes without error and with correct defaults.
5. Write a test that loads a v2.0-style `policy.yaml` (all new fields) against the v1.0 `PolicyConfig` struct (via a snapshot of the v1.0 struct) and verifies it also deserializes without error (the v1.0 binary ignores new fields).

**Warning signs:**
- `#[serde(deny_unknown_fields)]` appearing anywhere in `pam-unix-oidc/src/policy/`
- Field renames without `#[serde(alias)]`
- Tests that only test the happy path of config loading, not the cross-version compat path

**Phase to address:** Every phase that modifies `PolicyConfig`. Backward-compat tests should be added in the first phase that touches the config schema.

---

### Pitfall 8: SO_PEERCRED for IPC Hardening Has Different APIs on Linux vs macOS

**What goes wrong:**
The `unix-oidc-agent` socket (`daemon/socket.rs`) currently does not validate the peer UID on incoming connections. The socket is `0600` (owner-only), which provides filesystem-level access control, but does not cryptographically prevent another process running as the same UID from connecting.

When v2.0 adds explicit peer credential validation (IPC hardening), the natural approach is to use `SO_PEERCRED`. On Linux, `SO_PEERCRED` is set via `getsockopt(fd, SOL_SOCKET, SO_PEERCRED, ...)` and returns a `struct ucred { pid, uid, gid }`. On macOS (and BSD), the equivalent is `getpeereid(fd, &euid, &egid)` or `LOCAL_PEERCRED` via `getsockopt(fd, SOL_LOCAL, LOCAL_PEERCRED, ...)`. These are different syscalls, different struct layouts, and different socket option levels.

The Rust `nix` crate exposes `nix::sys::socket::sockopt::PeerCredentials` on Linux; for macOS, `nix` 0.28+ exposes `peer_pid_privilege` via `LOCAL_PEERCRED`. The tokio `UnixStream` does not expose peer credentials directly — raw fd access is required.

**How to avoid:**
1. Use conditional compilation: `#[cfg(target_os = "linux")]` for `SO_PEERCRED` and `#[cfg(target_os = "macos")]` for `getpeereid`. PostgreSQL's `src/port/getpeereid.c` is a reference implementation of the portable pattern.
2. The `nix` crate (already a transitive dependency via `libc`) is the correct abstraction layer. Do not call `libc::getsockopt` directly.
3. On macOS, `getpeereid` returns `(euid, egid)` — no PID. The agent socket is user-local so UID check is sufficient for the threat model.
4. Implement as a utility function `fn verify_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<(), IpcError>` with platform-specific cfg blocks, tested on both Linux and macOS in CI.
5. Note: peer credential checking verifies the UID at the time of `connect()`, not at the time of each request. A process that drops privileges after connecting would pass the check. For the agent's threat model (same-user IPC), this is acceptable.

**Warning signs:**
- `SO_PEERCRED` used unconditionally without `#[cfg(target_os = "linux")]`
- `getpeereid` called without checking that the `nix` version supports it
- Peer credential logic added only to Linux without a macOS path (the agent supports macOS)

**Phase to address:** Phase implementing IPC hardening.

---

### Pitfall 9: systemd Dependency Ordering — Agent Daemon May Not Be Ready When PAM Runs

**What goes wrong:**
If the `unix-oidc-agent` daemon is managed as a systemd user service (`systemctl --user start unix-oidc-agent`), it starts when the user's first session is created. The PAM module runs during session creation — before the user service manager is guaranteed to be started. This creates a startup ordering race: PAM calls the agent socket, the socket does not yet exist, and PAM falls back to an error.

On RHEL 9, systemd user instances are not started until `pam_systemd.so` completes. If `pam_unix_oidc.so` runs before `pam_systemd.so` in `/etc/pam.d/sshd`, the user session manager is not initialized, `XDG_RUNTIME_DIR` is not set, and `AgentServer::default_socket_path()` (which falls back to `/tmp` when `XDG_RUNTIME_DIR` is unset) may resolve to the wrong path.

Additionally, systemd socket activation (`Type=socket`) could theoretically be used to auto-start the agent on first connection. But socket-activated services require the service to be ready to accept and handle the request synchronously — the OIDC login flow requires network access and user interaction, neither of which can be pre-warmed by socket activation.

**How to avoid:**
1. The agent daemon should be started at user login (via `pam_exec.so` or a PAM session module that forks the daemon), not as a `systemctl --user` service triggered by PAM itself. The agent should be a long-running per-user daemon started once at first login, not per-SSH-connection.
2. The PAM module must handle "agent not running" gracefully: if the agent socket is absent or refuses connection, fall back to `PamError::AUTH_ERR` with a user-visible message ("Run 'unix-oidc-agent login' to authenticate"), not a panic or hang.
3. For `XDG_RUNTIME_DIR` resolution: `AgentServer::default_socket_path()` already handles the missing env var (falls back to `/tmp`). Ensure the PAM module and the agent use the same path resolution function — a mismatch causes "agent not found" errors that are hard to diagnose.
4. If using systemd socket activation for the agent, set `After=network-online.target` and ensure the socket unit creates `XDG_RUNTIME_DIR` before the service starts.
5. Document the exact PAM stack order in `/etc/pam.d/sshd` in the deployment guide: `pam_systemd.so` must appear before `pam_unix_oidc.so` in the `session` stack.

**Warning signs:**
- `XDG_RUNTIME_DIR` assumed to be set without a fallback in socket path resolution (currently handled correctly but could regress)
- Agent socket path hardcoded in the PAM module (not using the same resolution as the agent daemon)
- PAM module that hangs waiting for agent connection without a timeout

**Phase to address:** Phase implementing systemd/launchd operational readiness.

---

### Pitfall 10: Username Mapping Creates Silent Identity Confusion Under Race Conditions

**What goes wrong:**
Username mapping (e.g., Azure AD UPN `alice@corp.com` → Unix user `alice`, or `preferred_username` → POSIX user lookup via SSSD) has two failure modes:

1. **Many-to-one collision:** Two IdP users map to the same Unix username (e.g., `alice@sales.corp.com` and `alice@engineering.corp.com` both map to `alice`). The current `pam_user != result.username` check in `lib.rs:98` catches the case where the PAM user doesn't match the token user, but only if the comparison is done after mapping. If mapping is applied to the token claim before comparison, and two different token users map to the same `alice`, the wrong token can authenticate.
2. **Mapping function failure is treated as deny:** If the SSSD lookup or custom mapping function fails (e.g., SSSD is temporarily unavailable), and the code returns `AuthError::UserNotFound`, users are denied during SSSD outages. This is technically correct (don't let unknown users in) but can be operationally catastrophic if SSSD is the source of truth for all users — an SSSD outage locks out all users simultaneously.

The current `sssd/user.rs` lookup is synchronous and has no timeout. A slow SSSD response blocks the PAM thread.

**How to avoid:**
1. Username mapping must be applied consistently: either compare raw claims (token `preferred_username` == PAM user), or compare after mapping (mapped Unix username == PAM user). Never mix. Document which comparison point is used.
2. Add a timeout to SSSD lookups (max 5 seconds) using `std::thread` + channel, or move the lookup to a separate thread. The current blocking `nss` lookup in `sssd/user.rs` has no timeout.
3. For mapping tables: implement a uniqueness check at config load time — if two IdP identities map to the same Unix user, reject the config with a clear error rather than silently creating an ambiguous mapping.
4. Consider a configurable `on_mapping_failure: deny | allow_if_exists_locally` policy. `deny` is secure; `allow_if_exists_locally` is a reasonable operational fallback that does not depend on SSSD availability for locally-provisioned users.

**Warning signs:**
- `sssd/user.rs` with no timeout on the NSS lookup
- Username comparison done before vs. after mapping is inconsistent in different code paths
- No test for the "two IdP users map to same Unix user" collision case

**Phase to address:** Phase implementing username mapping and group policies.

---

## Technical Debt Patterns

Shortcuts that seem reasonable but create long-term problems in this specific system.

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| `.expect()` in PAM code paths for "can't happen" cases | Simpler code, clear failure mode | Panic in sshd = user lockout; one bad server state bricks auth | Never in PAM paths; acceptable in agent CLI paths |
| Reusing `reqwest::blocking` for CIBA polling (same pattern as Device Flow) | Minimal new code | Blocks PAM thread; can trigger sshd LoginGraceTime cutoff | Never for CIBA in PAM; only for agent-side background polling |
| Global static `JwksProvider` singleton | Simple initialization | Not refreshable without restart; shared across threads without explicit ownership | Acceptable only if TTL-based refresh is implemented (currently is) |
| Introspection without caching | Always-fresh revocation status | N x concurrent logins → N introspection requests/sec; IdP rate-limit → all logins fail | Never; always cache with TTL bounded by token `exp` |
| Defaulting new security mode config fields to `strict` | Correct secure default for new deployments | Breaks existing deployments on upgrade without operator action | Never; always default to v1.0 behavior, let operators opt in |
| `pam_set_data()` for cross-function session state | Simpler than external storage | Session state visible only within same PAM handle; `close_session()` may run in different process | Acceptable for within-session state; not for cross-connection correlation |
| Hardcoding Keycloak-specific endpoint paths in `DeviceFlowClient::new()` | Works for current Keycloak CI environment | Breaks all non-Keycloak IdPs at device flow init | Never in new code; existing `DeviceFlowClient::new()` at `device_flow/client.rs:33` already has this issue and must be fixed |

---

## Integration Gotchas

Common mistakes when connecting to external services in this domain.

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| CIBA endpoint | Polling at fixed interval, ignoring `interval` in auth response | Honor the `interval` field from the CIBA auth response; implement `slow_down` backoff as spec requires (OpenID CIBA Core 1.0 §7.3) |
| CIBA endpoint | Using POLL mode; expecting all IdPs to support it | Not all IdPs support POLL mode; Okta supports PUSH only. Detect via discovery (`backchannel_token_delivery_modes_supported`). Plan for PUSH-only IdPs |
| Token introspection | Using client_credentials to authenticate to introspection endpoint | Many IdPs require `client_assertion` (JWT-based client auth) for confidential clients; `client_secret_post` is deprecated in many deployments |
| SSSD | Calling `getpwnam()` synchronously in PAM | `getpwnam()` blocks until SSSD responds; no timeout; SSSD outage = PAM thread hangs indefinitely |
| Keycloak device flow | Building endpoint as `{issuer}/protocol/openid-connect/auth/device` | This is Keycloak-specific. Other IdPs use `device_authorization_endpoint` from OIDC discovery. Must use discovery in production code |
| Auth0 CIBA | Assuming standard `/bc-authorize` endpoint | Auth0 uses `/oauth/bc-authorize`; differs from the CIBA spec's recommended path |
| macOS Keychain (agent) | Testing Keychain backend in CI | macOS Keychain prompts in non-interactive contexts; use mock backend (established pitfall from v1.0 PITFALLS.md, still applies here) |

---

## Performance Traps

Patterns that work at small scale but fail as login volume grows.

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Per-login introspection (no cache) | IdP rate limits trigger; all logins fail simultaneously | Cache introspection results keyed by JTI with configurable TTL (default 60s) | At ~10 concurrent logins/second on a shared server |
| JWKS re-fetch on every login (cache miss storm) | JWKS endpoint overwhelmed during key rotation; all logins fail | The current `DEFAULT_CACHE_TTL_SECS = 300` is good; but the `RwLock` in `oidc/jwks.rs` is not stampede-protected: all threads that miss the cache simultaneously fetch JWKS | Under concurrent login burst (50+ simultaneous SSH connections) |
| `RwLock<HashMap>` JTI cache under high concurrency | Lock contention; P99 latency spikes during high-concurrency login events | The current `global_jti_cache()` uses `std::sync::RwLock`. This is fine for moderate load. For high-scale deployments, a sharded cache is needed — but that is explicitly out of scope (distributed JTI cache is v2.1+) | At ~1000+ concurrent login events/minute on a single server |
| SSSD lookup with no timeout (existing code) | PAM thread hangs indefinitely when SSSD is slow; SSH connections stack up until `sshd` runs out of file descriptors | Add 5-second timeout to SSSD lookup; return `AuthError::UserResolution` on timeout | When SSSD is degraded (e.g., LDAP network partition) |
| reqwest blocking client per request (current pattern in `device_flow/client.rs`) | Per-request TLS handshake overhead | Re-use HTTP client (already done via struct member); do not create new `Client::builder().build()` per auth attempt | Not a performance issue in current code; would become one if client creation is moved inside the auth loop |

---

## Security Mistakes

Domain-specific security issues when adding v2.0 features to this codebase.

| Mistake | Risk | Prevention |
|---------|------|------------|
| Accepting CIBA `auth_req_id` from client-controlled input without binding to session | Token swapping — a valid `auth_req_id` from another user's CIBA session is substituted | Bind `auth_req_id` to the PAM session (pam_set_data) and verify the resulting token's `sub` matches the initiating PAM user |
| Caching introspection "active=true" past token `exp` | Accepting expired token as valid after revocation check | Enforce cache TTL ≤ (token `exp` - now). Never cache past token expiry |
| `break_glass.requires` field parsed but not enforced | Break-glass account accessible without the required second factor | Any code path for break-glass bypass must enforce `requires` (e.g., YubiKey OTP) before granting access. The current `BreakGlassConfig` struct stores `requires` but nothing acts on it |
| Adding `ACR` value check as a new HARD-FAIL without migration | Deployments where IdP returns no ACR claim are locked out on upgrade | New ACR enforcement must default to WARN mode (per Issue #10 migration pattern); escalate to HARD-FAIL only when operator sets `strict` |
| Token in `AgentResponseData::Proof.token` field sent over Unix socket without framing | Token visible in process listing if socket path leaks to low-privilege process | Socket is already `0600`; this is acceptable. Do not add `SO_REUSEADDR` or change socket permissions for convenience |
| Adding `introspect` command to agent IPC protocol that returns raw token state | IPC protocol expansion increases attack surface from any same-UID process | New IPC commands must be audited for information disclosure; the `Status` response already leaks `thumbprint` and `username` — ensure new introspection responses do not leak `sub` or claim values |

---

## "Looks Done But Isn't" Checklist

Things that appear complete but are missing critical pieces for v2.0 features.

- [ ] **CIBA implementation:** The `StepUpMethod::Push` variant exists in policy YAML parsing but has no `ApprovalProvider` implementation. Dispatching to `Push` without an implementation silently falls through — verify that unimplemented step-up methods return `PamError::AUTH_ERR`, not `PamError::SUCCESS`.
- [ ] **FIDO2/WebAuthn step-up:** `StepUpMethod::Fido2` exists in rules but has no implementation and no documentation of the intended deployment model. Must be documented as "CIBA with phishing-resistant ACR" before v2.0 ships.
- [ ] **Break-glass enforcement:** `BreakGlassConfig` is parsed and stored in `PolicyConfig` but nothing in `auth.rs` or `lib.rs` acts on it. "Break-glass is configured" != "break-glass is enforced."
- [ ] **Configurable security modes:** `ValidationConfig` has `enforce_jti` bool but no `SecurityMode` enum for warn/strict/disabled. The Issue #10 config shape is not yet implemented.
- [ ] **Username mapping:** The `extract_username_from_token()` function in `daemon/socket.rs` supports multiple claim fallbacks. The PAM module's username comparison at `lib.rs:98` directly compares `result.username` with the PAM user. There is no configurable mapping table between IdP claim values and Unix usernames.
- [ ] **Group policy enforcement:** `PolicyConfig` has no `groups` or `required_groups` field. SSH access control by IdP group membership is not implemented.
- [ ] **Session revocation:** `close_session()` in `lib.rs:188` returns `PamError::SUCCESS` unconditionally. No session cleanup, no revocation notification to IdP.
- [ ] **Token refresh in PAM context:** The PAM module validates tokens but does not refresh expired ones. If a user's token expires during a long-running SSH session, the next `pam_authenticate()` call (e.g., on sudo) will fail. Decide whether refresh is the agent's responsibility or the PAM module's.
- [ ] **Keycloak-specific endpoint hardcoding:** `DeviceFlowClient::new()` builds the device authorization endpoint as `{issuer}/protocol/openid-connect/auth/device`. This is Keycloak-specific. IdP-agnostic step-up requires using OIDC discovery to resolve `device_authorization_endpoint`.
- [ ] **DPoP nonce issuance (RFC 9449 §8):** The PAM module's DPoP validation does not issue server-selected nonces. Without nonce binding, a captured DPoP proof is replayable on the same URI within its `iat`/`exp` window even if the JTI has not been seen. The JTI cache mitigates this but nonce binding is the RFC-recommended defense.

---

## Recovery Strategies

When pitfalls occur despite prevention, how to recover.

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| PAM panic causes sshd crash → locked out | HIGH | Use break-glass account (local password + YubiKey OTP per `break_glass` config); console/IPMI access; revert PAM config with `sed -i 's/^auth.*pam_unix_oidc/#&/' /etc/pam.d/sshd` |
| Introspection DoS — all logins failing | MEDIUM | Set `introspection: disabled` in policy.yaml (if feature is opt-in as recommended); reload PAM config; logins resume using local JWT verification |
| New strict default breaks existing deployment on upgrade | MEDIUM | Roll back to previous package version; add explicit permissive config values; re-upgrade. If `#[serde(default)]` is respected, adding missing fields to policy.yaml restores behavior |
| CIBA polling blocks PAM thread → sshd timeout | MEDIUM | Disable CIBA step-up method in policy.yaml; set `allowed_methods: [device_flow]` as fallback |
| Username mapping collision locks legitimate user | MEDIUM | Temporarily set `allow_if_exists_locally` fallback policy; fix IdP claim or mapping table; re-enable strict mapping |
| Session store file under `/run/unix-oidc/` fills tmpfs | LOW | `rm -rf /run/unix-oidc/sessions/` (safe — stale session files have no auth effect); adjust session TTL cleanup interval |
| Agent socket path mismatch (PAM can't find daemon) | LOW | Check `XDG_RUNTIME_DIR` in sshd environment; verify agent and PAM use same `default_socket_path()` logic; restart agent with explicit `--socket` arg |

---

## Pitfall-to-Phase Mapping

How roadmap phases should address these pitfalls.

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| `.expect()` panics in PAM paths | Phase 1: PAM panic elimination | `grep -r '\.expect(' pam-unix-oidc/src/` returns zero results outside `#[cfg(test)]`; clippy lint `deny(expect_used)` passes |
| CIBA polling blocks PAM thread | Phase implementing CIBA step-up — architecture decision before first line of code | Load test: 50 concurrent SSH connections with CIBA challenges; none trigger sshd LoginGraceTime timeout |
| WebAuthn has no browser in SSH | Phase implementing FIDO2 step-up — ADR required first | No libfido2/ctap crate appears in `pam-unix-oidc/Cargo.toml`; Fido2 documented as "CIBA+ACR" pattern |
| Introspection DoS under load | Phase implementing token introspection | Integration test: introspection endpoint returns HTTP 429; PAM falls back to local JWT verification without error |
| PAM session store cross-invocation state | Phase implementing session lifecycle | Functional test: `authenticate()` + `open_session()` + `close_session()` across process boundaries; session ID correlates correctly |
| Config mode defaults break existing deployments | Phase implementing Issue #10 security modes | Test: v1.0 `policy.yaml` (no new fields) loads against v2.0 code with expected permissive behavior |
| policy.yaml backward compat | Every phase touching `PolicyConfig` | Test: v1.0 YAML loads without error against v2.0 struct; v2.0 YAML loads without error against v1.0 struct |
| SO_PEERCRED portability | Phase implementing IPC hardening | Build and test peer credential validation on both Linux (Ubuntu 22.04) and macOS CI targets |
| systemd ordering race | Phase implementing systemd/launchd operational readiness | Integration test: fresh user login with agent not yet started; PAM returns graceful error, not hang |
| Username mapping identity confusion | Phase implementing username mapping | Unit test: two IdP users with same mapped Unix username → config validation error at load time |

---

## Sources

- OpenID Connect Client-Initiated Backchannel Authentication Flow Core 1.0 (CIBA spec, §7.3 polling): https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- RFC 9449 DPoP — server nonce issuance (§8): https://www.rfc-editor.org/rfc/rfc9449#section-8
- RFC 7662 OAuth 2.0 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662
- RFC 8628 OAuth 2.0 Device Authorization Grant — `slow_down` handling: https://www.rfc-editor.org/rfc/rfc8628
- libfido2 — direct CTAP2 assertion (not WebAuthn): https://developers.yubico.com/libfido2/
- WebAuthn Level 2 specification — Relying Party context requirement: https://www.w3.org/TR/webauthn-2/
- pam_set_data(3) man page — PAM data sharing within handle: https://man7.org/linux/man-pages/man3/pam_set_data.3.html
- SO_PEERCRED Linux man page — unix(7): https://man7.org/linux/man-pages/man7/unix.7.html
- getpeereid macOS man page: https://www.unix.com/man-page/osx/3/getpeereid
- PostgreSQL portable getpeereid.c reference: https://github.com/postgres/postgres/blob/master/src/port/getpeereid.c
- systemd socket activation — dependency ordering: https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html
- Okta CIBA — PUSH only, not POLL mode: https://learning.okta.com/first-look-client-initiated-backchannel-authentication-flow
- serde_yaml unknown fields — default behavior (fields silently ignored without deny_unknown_fields): https://docs.rs/serde_yaml/latest/serde_yaml/

---

*Pitfalls research for: Production hardening and enterprise auth features on an existing OIDC PAM + agent system*
*Researched: 2026-03-10*
*Supersedes: v1.0 PITFALLS.md (key protection hardening)*
