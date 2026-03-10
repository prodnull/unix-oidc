# Technology Stack: v2.0 Production Hardening & Enterprise Readiness

**Project:** unix-oidc — v2.0 Milestone
**Researched:** 2026-03-10
**Scope:** CIBA push auth, FIDO2/WebAuthn server-side verification, token introspection/revocation, session lifecycle, configurable security modes, systemd/launchd service integration
**Note:** This file covers ONLY new dependencies for v2.0. The v1.0 stack (p256, jsonwebtoken, reqwest, keyring, zeroize, secrecy, cryptoki, tss-esapi, etc.) is validated and unchanged — see prior STACK.md snapshot in git history.

---

## Recommended Stack — New Additions Only

### 1. CIBA Client Flow (RFC OIDC CIBA Core 1.0)

**Verdict: Implement directly with existing `reqwest` + `oauth2` 5.0.0. Do NOT add a CIBA-specific crate.**

No Rust crate implements the CIBA client flow as of 2026-03-10. The `openidconnect` 4.0.1 crate (by the same author as `oauth2` 5.0.0) does not include CIBA endpoints. This is confirmed by reviewing the crates.io search results — no CIBA-specific crate has material adoption.

CIBA poll mode (the correct mode for a non-interactive PAM client) consists of exactly two HTTP interactions:

1. `POST /bc-authorize` — sends `login_hint`, `scope`, `client_id`, `binding_message`, receives `auth_req_id` + `expires_in` + `interval`
2. `POST /token` with `grant_type=urn:openid:params:grant-type:ciba` and `auth_req_id` — polls until `authorization_pending` resolves to tokens or `expired_token`

Both are plain `application/x-www-form-urlencoded` POST requests. The existing `reqwest::Client` already handles this. Add `oauth2 = "5.0.0"` for strongly-typed token response parsing and introspection support (see Domain 3).

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `oauth2` | **5.0.0** | Typed OAuth2 token responses, introspection (RFC 7662), revocation (RFC 7009) — works with existing `reqwest` 0.11 | HIGH |

**Why oauth2 5.0.0 (not 4.x):** 5.0.0 is the current stable release (26M total downloads, Rust 1.65 MSRV). It includes built-in `introspect()` method against RFC 7662 endpoints and typed `TokenIntrospectionResponse`. The CIBA HTTP calls themselves are custom (not covered by oauth2 crate helpers) but the token response type deserialization is directly reusable.

**CIBA polling loop design:** The agent spawns a `tokio::task` that polls on the `interval` returned by `/bc-authorize` (minimum 30 seconds per the OpenID CIBA Core spec, §7.3). The task sends a `tracing` event at each poll cycle and wakes the waiting PAM conversation when tokens arrive. Maximum wait is bounded by `expires_in` from the initial response. The PAM module side sets a hard timeout (configurable, default 120 s) and returns `PAM_AUTH_ERR` if no token arrives before expiry.

**Reqwest version note:** Both crates in the workspace pin `reqwest = "0.11"`. Do NOT upgrade to 0.12 in this milestone — the 0.11→0.12 TLS layer change (rustls 0.22 upgrade) requires audit of all `ClientBuilder` configurations and SSRF redirect-disable settings. Upgrade is a separate hardening item.

---

### 2. FIDO2 / WebAuthn Server-Side Assertion Verification

**Verdict: Use `webauthn-rs` 0.5.4 (high-level safe API). Do NOT use `webauthn-rs-core` directly.**

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `webauthn-rs` | **0.5.4** | Server-side WebAuthn assertion verification (W3C WebAuthn Level 3+) | HIGH |

**Why webauthn-rs:**
- Current stable: 0.5.4 (released December 2024; 0.5.2 released July 2025 per search results — version numbering is per-release, 0.5.4 is latest as of 2026-03-10 per `cargo search`).
- Security-audited by SUSE Product Security. The library explicitly states it follows W3C WebAuthn Level 3+ processing and enforces constraints beyond the spec's minimum security requirements.
- The high-level `webauthn-rs` crate (not `webauthn-rs-core`) enforces correct credential state machine usage at the type level — prevents the sharp-edge misuse patterns that the core API exposes.
- Maintained by the `kanidm` project (production identity management system), giving it a real-world deployment track record.
- Only supports secure cryptographic primitives — does not accept weak algorithms that an attacker might negotiate.
- Android Safety Net attestation removed January 2025 (the correct security decision).

**Integration pattern for PAM step-up (non-HTTP context):**

WebAuthn assertions require a challenge issued by the relying party and signed by the authenticator. In a PAM context, the challenge flow is:

```
PAM module (server side)          Agent daemon (client side)         User's FIDO2 device
  |                                    |                                    |
  |-- IPC: request step-up ---------->|                                    |
  |                                    |-- challenge = Uuid::new_v4() ---> |
  |<-- IPC: challenge returned --------|                                    |
  |                                    |                                    |
  |  (challenge stored in              |-- platform WebAuthn client ------> |
  |   session store with TTL)          |<-- authenticator response ---------|
  |                                    |                                    |
  |<-- IPC: assertion response --------|                                    |
  |                                    |                                    |
  |  webauthn.finish_passkey_authentication(response, &auth_state) ------> |
  |  (auth_state retrieved from session store by challenge id)             |
```

The `webauthn-rs` `Webauthn` struct is built with `WebauthnBuilder::new(rp_id, rp_origin)`. For SSH authentication context, `rp_id` is the server hostname and `rp_origin` is a synthetic `unix://hostname` URI (WebAuthn Level 3 explicitly supports non-HTTPS origins for device-bound scenarios).

**Challenge state persistence:** The `PasskeyAuthentication` state returned by `start_passkey_authentication()` MUST be stored server-side (in the session store, keyed by challenge UUID, TTL 60 s). Storing it client-side defeats WebAuthn's security guarantees. See Domain 4 (session store).

**Credential storage:** The `Passkey` struct (serializable via serde) for each enrolled user is stored in the per-user credential file (JSON, 0600, under `/var/lib/unix-oidc/webauthn/<username>/`). Do not store in the OIDC token cache.

**Feature flags:**

```toml
# unix-oidc-agent/Cargo.toml
[features]
webauthn = ["dep:webauthn-rs"]

[dependencies]
webauthn-rs = { version = "0.5.4", optional = true, features = ["danger-allow-state-serialisation"] }
```

`danger-allow-state-serialisation` is required to serialize `PasskeyAuthentication` state for cross-process storage (PAM module to agent IPC). The feature name is intentionally alarming — the danger is storing state insecurely (client side), not serialization itself.

**What NOT to use:**
- `passkey` / `passkey-authenticator` 0.5.0 — these are client-side (authenticator) crates for building passkey software implementations, not server-side assertion verifiers. Wrong direction.
- `webauthn-rs-core` directly — exposes unsafe low-level API with many footguns. The high-level `webauthn-rs` wraps it correctly.

---

### 3. Token Introspection (RFC 7662) and Revocation (RFC 7009)

**Verdict: Use `oauth2` 5.0.0 for typed introspection. For revocation, use existing `reqwest` with manual POST.**

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `oauth2` | **5.0.0** | `introspect()` method against RFC 7662 endpoint; typed response (active, exp, sub, scope, etc.) | HIGH |

The `oauth2` 5.0.0 crate provides:
- `Client::introspect(token)` — queries `set_introspection_uri()` per RFC 7662
- `TokenIntrospectionResponse` trait — `is_active()`, `exp()`, `sub()`, `scope()`, `username()`
- `Client::revoke_token(token)` — posts to RFC 7009 revocation endpoint
- Typed token responses with `set_introspection_uri()` and `set_revocation_uri()`

**Security consideration:** Per RFC 7662, introspection endpoints require client authentication. The PAM module authenticates as a `client_credentials` client. Ensure `set_introspection_uri()` uses the same HTTPS base as the `iss` claim to prevent SSRF to attacker-controlled endpoints. Configure `reqwest::Client` with `redirect::Policy::none()` before calling introspection.

**When to introspect vs. cache:** Token signature verification (offline) should be the primary validation path — introspection involves a network call per authentication event. Introspection is appropriate for: (1) session revocation checks on sensitive operations, (2) refreshing cached token status after TTL expires, (3) explicit "is this token still valid?" queries before granting long-duration access. Cache introspection responses for the `expires_in` duration returned by the introspection response.

---

### 4. Session Lifecycle Store

**Verdict: Use `moka` 0.12.14 (async TTL cache). Do NOT use `tower-sessions`, `dashmap`, or a custom `HashMap`.**

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `moka` | **0.12.14** | In-memory async TTL cache with per-entry expiry, TinyLFU eviction — for challenge state, token cache, introspection cache | HIGH |

**Why moka:**
- `moka::future::Cache<K, V>` integrates natively with tokio. No background threads (removed in 0.12.0) — driven by the tokio runtime.
- Per-entry TTL — each cache entry carries its own expiry, eliminating the need for a background janitor task. Challenge states expire in 60 s; cached tokens expire at their `exp` claim; introspection responses expire at their `expires_in`.
- TinyLFU eviction policy — bounded size prevents memory exhaustion under load (DoS protection).
- API mirrors `std::collections::HashMap` for insertion/retrieval; async-aware for use in `async fn` PAM flows.
- Widely used in production Rust systems (inspired by Java Caffeine, extensively deployed in TiKV ecosystem).
- 0.12.14 is the current stable release.

**Why not dashmap 7.0.0-rc2:** dashmap is still in release-candidate for 7.x; the stable series is 5.x. More critically, dashmap provides no TTL mechanism — implementing TTL cleanup manually over a `DashMap` requires a background tokio task and atomic timestamps, recreating moka's wheel at lower quality. For a security cache (JTI replay protection, challenge state), unbounded growth is a DoS vector; moka's capacity bound is a first-class feature.

**Why not tower-sessions:** tower-sessions is an HTTP middleware abstraction for web frameworks. The unix-oidc session store is internal to the agent daemon, not tied to HTTP request/response cycles. Using tower-sessions would import axum/tower dependencies into a PAM-adjacent binary — inappropriate dependency weight.

**Session types to cache:**

```toml
# unix-oidc-agent/Cargo.toml
moka = { version = "0.12.14", features = ["future"] }
```

```rust
// Challenge state: keyed by challenge UUID, TTL 60s
moka::future::Cache<Uuid, PasskeyAuthentication>

// Active session: keyed by session_id (UUID), TTL = token exp
moka::future::Cache<Uuid, SessionRecord>

// Introspection result: keyed by token hash, TTL = min(resp.expires_in, 300s)
moka::future::Cache<[u8; 32], IntrospectionResult>
```

`SessionRecord` holds: user identity (sub, preferred_username), IdP-issued claims, DPoP binding thumbprint, auth method (password/CIBA/WebAuthn), auth time, step-up auth time if applicable. This record drives the group policy engine and audit logging.

---

### 5. Configurable Security Modes

**Verdict: Use `figment` 0.10.19 for hierarchical config loading. No runtime reload needed for security modes — reload requires restart.**

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `figment` | **0.10.19** | Hierarchical configuration: defaults → `/etc/unix-oidc/config.toml` → env vars (`UNIX_OIDC_*`) | HIGH |

**Why figment (not `config` 0.15.19):**
- Figment 0.10.19 is the de-facto standard for Rocket/axum-adjacent Rust projects. Type-safe extraction via `figment.extract::<AppConfig>()` — compile-time structure validation.
- Layering model directly supports the unix-oidc security mode pattern: compiled-in defaults → site config file → environment overrides. `config` crate is more complex and has historically had soundness issues in earlier versions.
- Zero-cost abstraction: reads config at startup, extracts into a plain `AppConfig` struct. No runtime indirection after startup.
- The existing codebase already uses `serde_yaml` for config parsing; figment replaces that with a cleaner multi-source abstraction (TOML preferred, but YAML provider also available).

**Security mode enum (Issue #10):**

```toml
# /etc/unix-oidc/config.toml
[security]
jti_enforcement = "warn"       # strict | warn | disabled
dpop_required = "strict"       # strict | warn | disabled
acr_enforcement = "warn"       # strict | warn | disabled
revocation_check = "warn"      # strict | warn | disabled
```

```rust
#[derive(Debug, Deserialize, Default)]
pub enum EnforcementMode {
    Strict,
    #[default]
    Warn,
    Disabled,
}
```

**Hard-fail checks are NOT configurable** (per CLAUDE.md security invariants): signature verification, issuer validation, audience validation, expiration, algorithm enforcement. These are never exposed as `EnforcementMode` fields.

**Config reload:** Security mode changes require daemon restart. Do not implement hot reload for security configuration — it creates a TOCTOU window where an attacker who can write the config file could temporarily downgrade enforcement. Signal the operator to restart via `systemctl reload unix-oidc-agent` which triggers clean restart (not SIGHUP in-place reload).

```toml
# Cargo.toml
figment = { version = "0.10.19", features = ["toml", "env"] }
```

---

### 6. systemd / launchd Service Integration

**Verdict: Use `sd-notify` 0.5.0 for systemd. For launchd (macOS), write plist template — no crate needed.**

| Technology | Version | Purpose | Confidence |
|------------|---------|---------|------------|
| `sd-notify` | **0.5.0** | `READY=1`, `WATCHDOG=1`, `STATUS=` notifications to systemd service manager | HIGH |

**Why sd-notify:**
- 0.5.0 is the current stable release. Pure Rust reimplementation of the `sd_notify(3)` protocol — no `libsystemd` shared library dependency (important: the PAM module is a `cdylib` and cannot safely dlopen systemd internals).
- Provides `NotifyState::Ready`, `NotifyState::Watchdog`, `NotifyState::Status(msg)` — the three notifications needed.
- The agent daemon should call `sd_notify(READY=1)` after: IPC socket bound, config validated, initial JWKS fetched. This ensures systemd only routes traffic to the agent after it is genuinely ready.
- `WatchdogSec=30s` in the unit file with `NotifyState::Watchdog` sent every 15 s — if the agent deadlocks or its event loop stalls, systemd restarts it.

**Unit file pattern:**

```ini
[Service]
Type=notify
NotifyAccess=main
WatchdogSec=30
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_IPC_LOCK
```

`CAP_IPC_LOCK` is needed for `mlock(2)` without root. This is the correct, minimal capability grant — not `CAP_SYS_ADMIN`.

**macOS launchd:** The `launchd` (0.1.x) and `raunch` (0.1.x) crates are too limited for this use case — `launchd` only parses plist files, `raunch` only handles socket activation. No crate is needed. Ship a `com.unix-oidc.agent.plist` template in `packaging/macos/` using `plist` crate for validation in CI, hand-authored for deployment.

```toml
# Cargo feature for systemd only (Linux)
[target.'cfg(target_os = "linux")'.dependencies]
sd-notify = "0.5.0"
```

---

## Dependency Summary — New Additions Only

```toml
# workspace Cargo.toml — shared
[workspace.dependencies]
oauth2 = "5.0.0"
moka = { version = "0.12.14", features = ["future"] }
figment = { version = "0.10.19", features = ["toml", "env"] }

# unix-oidc-agent/Cargo.toml
[dependencies]
oauth2.workspace = true
moka.workspace = true
figment.workspace = true

[features]
webauthn = ["dep:webauthn-rs"]

[dependencies.webauthn-rs]
version = "0.5.4"
optional = true
features = ["danger-allow-state-serialisation"]

[target.'cfg(target_os = "linux")'.dependencies]
sd-notify = "0.5.0"

# pam-unix-oidc/Cargo.toml — no new dependencies
# The PAM module validates tokens, reads session state via IPC, applies security modes.
# oauth2 and figment added only if the PAM module reads config directly
# (preferred: PAM module reads from agent IPC to avoid config duplication)
```

---

## Alternatives Considered and Rejected

| Category | Recommended | Alternative | Why Rejected |
|----------|-------------|-------------|--------------|
| WebAuthn | `webauthn-rs` 0.5.4 | `webauthn-rs-core` 0.5.4 | Core crate exposes unsafe API with footguns the high-level crate prevents at the type level; SUSE audit covers both but high-level API is the intended interface |
| WebAuthn client side | — | `passkey-authenticator` 0.5.0 | Client/authenticator crate — wrong direction; we need server-side relying-party verification |
| Session cache | `moka` 0.12.14 | `dashmap` 5.5.3 (stable) | dashmap has no TTL — security caches require bounded TTL to prevent DoS and stale state; implementing TTL over dashmap recreates moka at lower quality |
| Session cache | `moka` 0.12.14 | `tower-sessions` | HTTP framework middleware — imports unnecessary web stack into PAM binary; session model mismatch |
| CIBA | Direct `reqwest` | — | No mature CIBA crate exists in Rust ecosystem; CIBA poll mode is two HTTP calls, not worth a crate |
| Config | `figment` 0.10.19 | `config` 0.15.19 | `config` 0.15.x has historically had panics on certain provider failures; figment is type-safe at extraction time; `config`'s async watch/reload model is unnecessary here |
| systemd | `sd-notify` 0.5.0 | `systemd` / `libsystemd` | `libsystemd` binding requires the C library (`libsystemd.so`), a runtime dependency inappropriate for a PAM module context; `sd-notify` is pure Rust |
| Reqwest upgrade | Stay on 0.11 | `reqwest` 0.12 | 0.11→0.12 TLS layer change requires full audit of all ClientBuilder configurations and SSRF protections; defer to dedicated hardening phase |

---

## What NOT to Add

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `redis` / `sqlx` / any database crate | Session store is per-host, in-process, and bounded by active user count; a PAM binary with a database client is an extreme attack surface expansion | `moka` in-process cache; Redis is a v2.1+ scalability milestone |
| `tower` / `axum` / `actix-web` | The PAM module is a `cdylib`, not an HTTP server; agent IPC is Unix socket, not HTTP | Plain `tokio::net::UnixListener` for IPC |
| `openidconnect` crate for CIBA | `openidconnect` 4.0.1 does not implement CIBA endpoints; adds ~15 transitive dependencies for functionality not used | Direct `reqwest` + `oauth2` for token response parsing |
| Any `async-graphql` or GraphQL | No GraphQL interface required | N/A |
| `tracing-opentelemetry` + collector infra | Out of scope for this milestone; structured `tracing` spans are sufficient for local audit | `tracing` + `tracing-subscriber` (already in workspace) |

---

## Version Compatibility Notes

| Existing | New Addition | Compatibility Status |
|----------|-------------|---------------------|
| `reqwest` 0.11 | `oauth2` 5.0.0 | Compatible — oauth2 5.x ships its own HTTP adapter; the existing `reqwest` 0.11 client is usable via `oauth2::reqwest::async_http_client` (0.11-compatible variant) |
| `serde` 1.0 | `moka` 0.12.14 | Compatible — moka uses serde only for optional serialization of entries, not in the hot path |
| `serde` 1.0 | `webauthn-rs` 0.5.4 | Compatible — Passkey and state types implement `Serialize`/`Deserialize` with serde 1.x |
| `tokio` 1.x | `moka` 0.12.14 | Compatible — `moka::future` is designed for tokio 1.x |
| `p256` 0.13 | `webauthn-rs` 0.5.4 | No direct interaction — webauthn-rs uses `openssl` or `ring` internally for EC ops, not p256; they do not share types and do not conflict |
| `uuid` 1.x | All new crates | Compatible — uuid 1.22.0 in workspace; moka keys and session IDs use `Uuid` |

---

## Security Notes for New Dependencies

1. **`webauthn-rs` OpenSSL dependency:** `webauthn-rs` 0.5.4 has a default dependency on `openssl` for some attestation certificate verification paths. Verify via `cargo tree` that this does not introduce `openssl-sys` into the PAM module (`pam-unix-oidc`). If it does, gate webauthn behind a feature flag and document that the PAM module never links openssl. The agent binary tolerates openssl as it is not a `cdylib`.

2. **Challenge TTL enforcement is mandatory:** A `PasskeyAuthentication` state stored without TTL is a DoS vector (unbounded memory growth) and a replay vector (stale challenges are trivially completable by a resource-constrained attacker who captured a partial ceremony). moka's per-entry TTL at 60 s is the correct mechanism — do not implement a manual cleanup task.

3. **CIBA `binding_message` prevents phishing:** Per OpenID CIBA Core §7.1, include a short human-readable `binding_message` (e.g., `"SSH login from bastion-01"`) in every `/bc-authorize` request. This message is displayed on the user's authentication device, allowing them to recognize and reject unexpected login attempts. This is security-critical, not optional.

4. **oauth2 introspection SSRF guard:** Configure the `reqwest::Client` used for introspection with `redirect::Policy::none()`. An IdP redirecting the introspection endpoint to an attacker-controlled URL is a realistic misconfiguration attack.

5. **figment config file ownership:** The agent startup should `stat()` the config file and refuse to start if it is not owned by root (uid 0) or writable by non-root. A world-writable config file allows unprivileged users to downgrade security modes.

---

## Sources

- crates.io `cargo search` output (verified 2026-03-10): webauthn-rs 0.5.4, oauth2 5.0.0, moka 0.12.14, figment 0.10.19, sd-notify 0.5.0, dashmap 7.0.0-rc2
- webauthn-rs GitHub (kanidm/webauthn-rs) — SUSE audit, Level 3+ compliance, safe API recommendation: https://github.com/kanidm/webauthn-rs
- webauthn-rs authentication use cases (step-up pattern): https://github.com/kanidm/webauthn-rs/blob/master/designs/authentication-use-cases.md
- oauth2-rs RFC 7662 introspection PR merged: https://github.com/ramosbugs/oauth2-rs/pull/117
- oauth2 5.0.0 docs (introspect, revoke, token response): https://docs.rs/oauth2/latest/oauth2/
- moka 0.12.14 — no background threads, per-entry TTL, future::Cache: https://github.com/moka-rs/moka
- OpenID Connect CIBA Core 1.0 — poll mode, bc-authorize, interval: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- RFC 9126 — Pushed Authorization Requests (PAR, distinct from CIBA): https://datatracker.ietf.org/doc/html/rfc9126
- RFC 7662 — OAuth 2.0 Token Introspection: https://datatracker.ietf.org/doc/html/rfc7662
- RFC 7009 — OAuth 2.0 Token Revocation: https://datatracker.ietf.org/doc/html/rfc7009
- sd-notify 0.5.0 — pure Rust, no libsystemd: https://crates.io/crates/sd-notify
- figment 0.10.19 — hierarchical config, TOML/env: https://crates.io/crates/figment
- reqwest 0.11→0.12 TLS layer changes (migration caution): https://github.com/seanmonstar/reqwest/issues/2191

---

*Stack research for: unix-oidc v2.0 Production Hardening & Enterprise Readiness*
*Researched: 2026-03-10*
