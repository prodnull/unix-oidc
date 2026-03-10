# Project Research Summary

**Project:** unix-oidc — v2.0 Production Hardening and Enterprise Readiness
**Domain:** OIDC PAM module + client agent daemon — security completeness and enterprise auth integration
**Researched:** 2026-03-10
**Confidence:** HIGH

## Executive Summary

unix-oidc v2.0 is an extension of a working v1.0 OIDC PAM system (DPoP-bound tokens, hardware signers, storage backends, memory protection) into a production-grade, enterprise-adoptable authentication layer. The research covers six capability domains: CIBA push authentication, FIDO2/WebAuthn step-up, token introspection and revocation, session lifecycle, configurable security enforcement modes, and operational service integration (systemd/launchd). All four research areas converge on a clear build order: security infrastructure first, enterprise identity mapping second, session management third, advanced step-up methods fourth, then operational hardening. The recommended approach is additive — every new component extends the existing validation pipeline rather than replacing it. The v1.0 stack (p256, jsonwebtoken, reqwest, keyring, zeroize, secrecy) is stable and unchanged; v2.0 adds exactly four workspace dependencies: `oauth2 5.0.0`, `moka 0.12.14`, `figment 0.10.19`, and `sd-notify 0.5.0`, plus optional `webauthn-rs 0.5.4` behind a feature flag.

The two dominant architectural risks in v2.0 are both well-understood and have explicit mitigations in the research. First, CIBA polling must live in the agent daemon (not the PAM module) to avoid blocking the PAM thread and triggering sshd's `LoginGraceTime` timeout on slow push delivery. Second, the PAM session store must be out-of-process (tmpfs files under `/run/unix-oidc/sessions/`) because PAM module functions are called from different sshd worker processes and cannot share in-process state across invocations. The FIDO2 path for v2.0 is deliberately narrow: use CIBA with a phishing-resistant ACR value and let the IdP orchestrate FIDO2 — direct CTAP2 in PAM is deferred past v2.0.

A significant portion of the v2.0 work is completing features that exist structurally in the codebase but have no implementation: `open_session`/`close_session` return `PamError::SUCCESS` unconditionally, `StepUpMethod::Fido2` parses but dispatches to nothing, `BreakGlassConfig` is stored but never enforced, and configurable security modes are tracked in Issue #10 but not yet coded. v2.0 is partly finishing in-progress work and partly adding genuinely new capabilities. Four `.expect()` calls exist today in PAM-reachable code paths — panic elimination must be the first task, before any new feature work begins, to avoid shipping a system where a single bad server state bricks the authentication stack.

## Key Findings

### Recommended Stack

The v1.0 dependency set is validated and frozen for v2.0. New additions are minimal and well-justified. `oauth2 5.0.0` provides typed RFC 7662 introspection and RFC 7009 revocation — no CIBA-specific crate exists in the Rust ecosystem, so the two CIBA HTTP calls are implemented directly with the existing `reqwest::Client`. `moka 0.12.14` replaces the need for manual TTL management and is the correct foundation for all security caches (JTI replay, DPoP nonce, challenge state, introspection results). `figment 0.10.19` replaces `serde_yaml` for config loading with a hierarchical TOML/env abstraction that enables the Issue #10 security mode config shape. `sd-notify 0.5.0` is a pure-Rust systemd notification client that avoids linking `libsystemd.so` into the PAM module. `reqwest` stays on 0.11 — the 0.11→0.12 TLS layer change requires a full audit of all `ClientBuilder` configurations and SSRF protections; that upgrade is a separate hardening item.

**Core technologies — new additions only:**
- `oauth2 5.0.0` — typed token introspection (RFC 7662) and revocation (RFC 7009); CIBA token response parsing; compatible with existing `reqwest 0.11`
- `moka 0.12.14` — async TTL cache with per-entry expiry and TinyLFU eviction; replaces manual TTL patterns for all security caches; DoS protection via bounded capacity
- `figment 0.10.19` — hierarchical config loading (TOML defaults → file → env overrides) with type-safe extraction; implements Issue #10 config shape; replaces `serde_yaml`
- `webauthn-rs 0.5.4` (optional, feature-gated) — SUSE-audited server-side WebAuthn RP; required only for direct CTAP2 path deferred to post-v2.0
- `sd-notify 0.5.0` — pure-Rust systemd `READY=1` / `WATCHDOG=1` notifications; Linux-only via `cfg(target_os = "linux")`

### Expected Features

All features split into two tiers based on adoption-blocking criteria. The research identifies features that block production use and features that block organizational adoption — these are distinct barriers.

**Must have — security completeness (blocks production use):**
- DPoP nonce issuance per RFC 9449 §8 — closes the replay window where a captured DPoP proof is replayable within its `iat`/`exp` window even with JTI caching in place
- Configurable security enforcement modes (strict/warn/disabled per check) — enables safe enterprise rollout without breaking existing deployments on upgrade; must default to v1.0 behavior
- Session lifecycle (`pam_sm_open_session` / `pam_sm_close_session`) — closes the gap where tokens remain valid after the SSH session ends
- Token introspection (RFC 7662) — enables immediate revocation effect for terminated employees; must be opt-in with TTL-bounded caching
- Automatic token refresh — prevents mid-session expiry failure for long-running SSH sessions

**Must have — enterprise integration (blocks organizational adoption):**
- Username claim mapping with template transforms — 100% of multi-domain enterprise deployments are blocked; requires uniqueness validation at config load time to prevent many-to-one collisions
- Group-based access policy from OIDC claims — the primary adoption blocker at the organizational level; no comparable PAM-OIDC alternative implements this
- Break-glass account enforcement with audit trail — currently parsed but not enforced; required per NIST SP 800-53 AC-2; CLAUDE.md calls it mandatory

**Should have — advanced auth methods:**
- CIBA poll-mode step-up (IdP-agnostic) — replaces the Keycloak-specific device authorization grant; wider IdP support; better UX via push notification with `binding_message`
- FIDO2/WebAuthn step-up via CIBA ACR delegation — no new crates or credential store; delegates FIDO2 ceremony to the IdP via phishing-resistant ACR claim

**Defer to v2.1+:**
- Distributed JTI cache (Redis/Valkey)
- RFC 8693 token exchange
- SCIM provisioning
- Direct CTAP2 in PAM (requires credential registration store, custom framing protocol, `webauthn-rs` in PAM crate)
- Post-quantum algorithm migration

### Architecture Approach

The v2.0 architecture is a delta on v1.0 with seven new modules, two extended modules, and no structural changes to existing boundaries. The PAM module (`pam-unix-oidc`) gains four new source files: `security_modes.rs` (enforcement enum with `apply()` function), `username_map.rs` (claim transform table), `group_policy.rs` (OIDC group membership rules), and `session_store.rs` (out-of-process session lifecycle via `/run/unix-oidc/sessions/`). The `oidc/` subdirectory gains `introspection.rs` (RFC 7662 client with per-JTI moka cache). The agent daemon gains `daemon/ciba.rs` (CIBA backchannel + poll loop) and optional `daemon/webauthn.rs` (challenge state store for the future direct WebAuthn path). The key architectural decision: CIBA polling runs entirely in the agent daemon — PAM sends `StepUp { method: Ciba }` over the Unix socket and blocks on fast local IPC, not on the slow IdP network call. Session state goes into tmpfs files, not in-process statics, because PAM `open_session` and `close_session` run in different sshd worker processes.

**Major components:**
1. `security_modes.rs` (new) — single `Enforcement::apply()` function called by all configurable checks; prevents enforcement logic from being scattered across `validation.rs`, `dpop.rs`, and `auth.rs`
2. `oidc/introspection.rs` (new) — RFC 7662 client with `moka`-backed per-JTI cache; supplement to local JWT validation, never a replacement; `fail_open` default preserves IdP-downtime resilience
3. `session_store.rs` (new) — out-of-process session records via tmpfs; `SessionStore` trait with `InMemorySessionStore` implementation accepts future `RedisBackend` at v2.1+ without changing callers
4. `username_map.rs` + `group_policy.rs` (new) — claim transform and access gate between token extraction and `getpwnam_r` lookup; must execute in order (map first, evaluate group membership second)
5. `daemon/ciba.rs` (new) — `CibaClient` with `start_backchannel()` + poll loop; binds step-up result to PAM via `StepUpComplete` IPC response; `binding_message` field on every backchannel request (security-critical per CIBA Core §7.1)

### Critical Pitfalls

1. **CIBA polling blocks the PAM thread** — `reqwest::blocking` in the PAM module for CIBA will trigger sshd's `LoginGraceTime` timeout on delayed push delivery. Four `.expect()` calls exist today in PAM-reachable code. Mitigation: implement CIBA in the agent daemon; PAM polls the local Unix socket at 2–3 second intervals; add `#![deny(clippy::unwrap_used, clippy::expect_used)]` to `pam-unix-oidc/lib.rs` before any new feature work.

2. **PAM session store cross-invocation state** — `open_session()` and `close_session()` run in different sshd worker processes; `static Lazy<RwLock<HashMap>>` state from `authenticate()` is invisible to them. Mitigation: write session records to tmpfs files (`/run/unix-oidc/sessions/<username>-<session-id>`, `O_CREAT | O_EXCL`); pass session correlation ID via `pam_set_data()` within the same PAM handle.

3. **Config mode defaults breaking existing deployments on upgrade** — new `SecurityMode` fields that default to `strict` rather than the v1.0 `warn` behavior will break every existing deployment without an explicit `policy.yaml` entry. Mitigation: all new security mode fields must `#[serde(default)]` to the v1.0 behavior; document defaults vs. recommended production values in a migration guide.

4. **Introspection DoS under load** — uncached introspection at every `authenticate()` will hit IdP rate limits at ~10 concurrent logins/second. Mitigation: opt-in via policy config (default `disabled`); cache results in `moka` keyed by JTI with TTL bounded by `min(60s, token exp - now)`; `fail_open` when introspection endpoint is unreachable.

5. **Username mapping many-to-one collision** — two IdP users mapping to the same Unix username allows one user's token to authenticate as another. Mitigation: reject the config at load time if any two IdP identities map to the same Unix user; apply mapping consistently before all comparison points (never compare raw claims against mapped identities at different callsites).

## Implications for Roadmap

Based on combined research, eight phases are recommended. The dependency graph from FEATURES.md and the build order from ARCHITECTURE.md are in agreement on sequencing.

### Phase 1: PAM Panic Elimination + Security Mode Infrastructure

**Rationale:** Two independent foundational items that must land before anything else. Panic elimination is a hard prerequisite for all PAM work — any `.expect()` introduced by new features must not exist at merge time. The security mode infrastructure is a hard prerequisite for every subsequent feature that needs an enforcement level. Build it first so all new features are born configurable.
**Delivers:** Zero `.expect()` in PAM-reachable code; `#![deny(clippy::unwrap_used, clippy::expect_used)]` lint active; `Enforcement { Strict, Warn, Disabled }` enum with `apply()` wired into existing JTI, DPoP, ACR, and auth_time checks; `figment`-based config loading replacing `serde_yaml`; `[security_modes]` section in `policy.yaml` schema; backward-compat test: v1.0 policy YAML loads against v2.0 struct with expected defaults
**Addresses:** Configurable security enforcement modes (Issue #10); existing panic exposure in `device_flow/client.rs`, `security/session.rs`, `oidc/dpop.rs`
**Avoids:** Pitfall 3 (`.expect()` panics causing user lockout); Pitfall 6 (strict defaults breaking existing deployments); Pitfall 7 (policy.yaml backward compat — `#[serde(deny_unknown_fields)]` must never appear)
**Stack:** `figment 0.10.19`

### Phase 2: DPoP Nonce Issuance (RFC 9449 §8)

**Rationale:** Closes the most specific DPoP security gap — captured proofs are replayable within their `iat`/`exp` window even with JTI caching. Small, contained scope. Independent of all other new features. High security value before any enterprise users are onboarded.
**Delivers:** `nonce_store::issue_nonce()` / `consume_nonce()` in `dpop.rs`; PAM challenge phase issues a 128-bit server nonce; `validate_dpop_proof()` verifies nonce; nonce single-use (added to JTI cache after consume); nonce TTL 60s via `moka`; client retry cycle on `use_dpop_nonce`-equivalent error
**Addresses:** DPoP nonce issuance; closes replay window gap from the PITFALLS "Looks Done But Isn't" list
**Avoids:** DPoP replay attacks between JTI issuance and expiry
**Stack:** `moka 0.12.14`

### Phase 3: Username Mapping + Group-Based Access Policy + Break-Glass Enforcement

**Rationale:** The primary adoption blocker at enterprise scale. Username mapping is a prerequisite for group policy (group checks use the mapped identity). Break-glass is a peer access-control feature that belongs in the same phase. Neither item blocks PAM session work or step-up.
**Delivers:** `username_map.rs` (static exact match, regex with capture group, identity fallback; uniqueness check at config load time); `group_policy.rs` (`groups` claim → PAM allow-list, configurable `login_groups` / `sudo_groups`); break-glass enforcement wired in `auth.rs` (skip OIDC for configured usernames, pass to next PAM module, emit audit event); SSSD lookup timeout (5s); mapping applied consistently before all username comparison points
**Addresses:** Username claim mapping; group-based access policy; break-glass account enforcement (moves from "parsed but not enforced" to enforced)
**Avoids:** Pitfall 10 (username collision identity confusion); SSSD blocking PAM thread indefinitely
**Stack:** No new dependencies; uses `figment` config from Phase 1

### Phase 4: Token Introspection (RFC 7662)

**Rationale:** Independent of step-up flows; depends on Phase 1 (security modes) and Phase 2 (moka). Enables immediate revocation detection. Must be opt-in with caching built from day one — retrofitting caching after a rate-limit incident is harder than building it correctly initially.
**Delivers:** `oidc/introspection.rs` with `check_active()` and per-JTI `moka` cache (TTL bounded by `min(60s, token exp - now)`); `IntrospectionConfig` in `ValidationConfig`; wired as optional final step in `validation.rs::validate()`; `SecurityModes.introspection` from Phase 1; SSRF guard (`redirect::Policy::none()` on introspection client); configurable `fail_open` (default) / `fail_closed` behavior; `oauth2 5.0.0` `introspect()` method for typed response
**Addresses:** Token introspection (RFC 7662); RFC 7009 revocation endpoint configuration
**Avoids:** Pitfall 4 (introspection DoS — opt-in default, always cached, fail-open)
**Stack:** `oauth2 5.0.0`, `moka 0.12.14`

### Phase 5: Session Lifecycle (open_session / close_session + Token Refresh)

**Rationale:** Depends on resolved username (Phase 3) and auth metadata (Phases 1–2). Must use out-of-process tmpfs storage due to PAM privilege separation model. Also enables automatic token refresh — refresh needs a session context to know whether the session is still open.
**Delivers:** `session_store.rs` (`SessionStore` trait + tmpfs-backed `FileSessionStore` under `/run/unix-oidc/sessions/`); `lib.rs::open_session()` writes `SessionRecord` (session_id, username, uid, token_jti, dpop_thumbprint, acr, opened_at, source_ip); `lib.rs::close_session()` deletes record, emits audit event with session duration, calls RFC 7009 revocation endpoint (best-effort, 5s timeout); session correlation via `pam_set_data()` within same PAM handle; automatic token refresh as background agent task (fires at 80% of TTL elapsed, uses stored refresh token)
**Addresses:** Session lifecycle; automatic token refresh; RFC 7009 revocation on close; closes the "token valid after SSH session ends" gap
**Avoids:** Pitfall 5 (cross-invocation session state — tmpfs files survive across sshd worker processes); post-logout token validity gap
**Stack:** No new dependencies; uses `moka` for in-agent refresh scheduling

### Phase 6: CIBA Poll-Mode Step-Up

**Rationale:** Requires IPC protocol extensions, security modes (Phase 1), and the full validation pipeline (Phases 3–4). CIBA is the primary new interactive auth method and the correct IdP-agnostic replacement for the Keycloak-specific device authorization grant. Must be agent-side to avoid blocking the PAM thread.
**Delivers:** `daemon/ciba.rs` — `CibaClient`, `start_backchannel()`, poll loop with `interval` / `slow_down` backoff, `expires_in` bounds, `auth_req_id` binding to PAM session; IPC protocol extensions (`StepUp`, `StepUpPending`, `StepUpComplete`); `sudo.rs` dispatches `StepUp { method: Ciba }` over Unix socket; `binding_message` field on every backchannel request (phishing prevention, security-critical); PAM hard timeout configurable (default 120s); Keycloak-specific device flow endpoint hardcoding replaced with OIDC discovery `device_authorization_endpoint`
**Addresses:** CIBA poll-mode step-up; replaces Keycloak-specific device authorization grant; closes Keycloak endpoint hardcoding issue from PITFALLS checklist
**Avoids:** Pitfall 1 (CIBA blocking PAM thread — agent-side polling); Pitfall 2 (WebAuthn in SSH — defer FIDO2 ceremony to IdP); integration gotcha (honor `interval` field, implement `slow_down` backoff)
**Stack:** `oauth2 5.0.0` (CIBA token response parsing); `reqwest 0.11` (existing)

### Phase 7: FIDO2 Step-Up via CIBA ACR Delegation

**Rationale:** CIBA infrastructure from Phase 6 is the prerequisite. This phase is a configuration-level addition — add `Fido2ViaIdp` to `StepUpMethod`, dispatch as `StepUp { method: Ciba, acr_required: "phr" }`, validate ACR in returned token. No new crates. No credential store. Minimal implementation risk; clean milestone boundary from Phase 6.
**Delivers:** `StepUpMethod::Fido2ViaIdp` in `policy/rules.rs`; `sudo.rs` dispatch with configurable phishing-resistant ACR value (e.g., `urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO`); documentation in `docs/step-up-fido2.md` explaining the CIBA+ACR delegation pattern; `StepUpMethod::Fido2` annotated as "delegates to CIBA+ACR, not direct CTAP2" to prevent future misimplementation
**Addresses:** FIDO2 step-up (via IdP delegation); closes the unimplemented `StepUpMethod::Fido2` gap without introducing `libfido2` or `webauthn-rs` into the PAM crate
**Avoids:** Pitfall 2 (libfido2/ctap crates in `pam-unix-oidc/Cargo.toml`)

### Phase 8: Operational Hardening (systemd / launchd + IPC Security)

**Rationale:** Operational hardening does not block correctness or security features in Phases 1–7. Ships as a late milestone item. Can be developed in parallel with Phase 7 by a second contributor.
**Delivers:** Socket activation support (`SD_LISTEN_FDS` detection via `tokio-listener`) with standalone fallback; `deploy/systemd/unix-oidc-agent.socket` and `.service` unit files (`NoNewPrivileges=yes`, `ProtectSystem=strict`, `MemoryDenyWriteExecute=yes`, `AmbientCapabilities=CAP_IPC_LOCK`, `WatchdogSec=30`, `Restart=on-failure`); `deploy/launchd/com.unix-oidc.agent.plist` template; `sd-notify 0.5.0` `READY=1` after IPC socket bound + config validated + initial JWKS fetched; per-platform `SO_PEERCRED` (Linux) / `getpeereid` (macOS) peer UID validation on IPC socket; `figment` config file ownership check (refuse to start if config not owned by uid 0); PAM stack order documented in deployment guide (`pam_systemd.so` before `pam_unix_oidc.so` in session stack)
**Addresses:** systemd/launchd service integration; IPC peer credential hardening; explicit socket-activation deployment path; READY=1 correctness
**Avoids:** Pitfall 8 (SO_PEERCRED portability — platform-conditional compilation); Pitfall 9 (systemd ordering race — documented PAM stack order)
**Stack:** `sd-notify 0.5.0` (Linux only); `nix` crate (existing transitive) for peer credentials

### Phase Ordering Rationale

- **Phases 1–2 are prerequisites for everything.** Panic elimination is a hard prerequisite for shipping any new PAM code. Security mode infrastructure is a hard prerequisite for any feature that needs an enforcement level. Both are low-complexity and high-leverage.
- **Phase 3 before Phase 5** because session records must contain the resolved local username, not the raw IdP claim. Group policy also determines whether a session is permitted to open.
- **Phase 4 before Phase 5** because introspection results are most meaningful within a session context, and Phase 5 wires the RFC 7009 revocation call that introspection informs.
- **Phase 6 after Phases 1–4** because CIBA introduces a new IPC protocol extension, a new network-calling module in the agent, and a new error path in `sudo.rs`. All of these touch code that must already have configurable enforcement and username-aware logging.
- **Phase 7 is a trivial follow-on to Phase 6** — same IPC, same token validation pipeline, different ACR value. Separate phase gives a clean milestone boundary and allows CIBA to ship and be validated in production before committing the FIDO2 ACR configuration.
- **Phase 8 is pure operational work** with no functional dependencies on Phases 1–7. It can run in parallel with Phase 7.

### Research Flags

Phases likely needing `/gsd:research-phase` during planning:

- **Phase 6 (CIBA):** IdP-specific endpoint discovery needs verification before writing the CIBA client. Okta supports PUSH mode only, not POLL — detection via `backchannel_token_delivery_modes_supported` from OIDC discovery is required. Auth0 uses `/oauth/bc-authorize` (non-standard path). Azure AD CIBA is preview-tier. Each IdP needs a test matrix entry. Recommend a focused research pass on IdP compatibility matrix and the `slow_down` backoff behavior differences across IdPs.
- **Phase 8 (systemd/launchd):** The exact PAM stack order fix for RHEL 9 (`pam_systemd.so` before `pam_unix_oidc.so` in the session stack) needs verification on each target platform. Socket activation deployment model has a known ordering race on RHEL 9. Recommend a research pass focused on the deployment guide section for each target distro.

Phases with well-documented patterns (skip research-phase):

- **Phase 1 (panic elimination + security modes):** Direct code modification. The `figment` integration pattern is documented and stable. `Enforcement` enum is fully specified in ARCHITECTURE.md.
- **Phase 2 (DPoP nonce):** RFC 9449 §8 is unambiguous. The IPC `nonce: Option<String>` field already exists in `GetProof`. Purely mechanical.
- **Phase 3 (username mapping + group policy):** Claim transform and POSIX group membership check. Multiple reference implementations exist (`pam_oidc`, `pam-keycloak-oidc`). Standard serde + regex patterns.
- **Phase 4 (introspection):** RFC 7662 is clear. `oauth2 5.0.0` `introspect()` is documented. Caching pattern mirrors the existing `global_jti_cache()`.
- **Phase 5 (session lifecycle):** Linux PAM `open_session`/`close_session` API is documented. Tmpfs file pattern is standard. `SessionStore` trait design is fully specified in ARCHITECTURE.md.
- **Phase 7 (FIDO2 via CIBA ACR):** Trivial extension of Phase 6. One enum variant + ACR config field + documentation.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | All recommended crates verified via `cargo search` 2026-03-10; version compatibility confirmed against existing workspace deps; `webauthn-rs` SUSE audit documented; `reqwest 0.11` stay rationale is explicit |
| Features | HIGH | Table-stakes features sourced from RFC primary sources (RFC 9449, RFC 7662, RFC 7009, CIBA Core 1.0, NIST SP 800-53). CIBA/FIDO2 PAM integration patterns rated MEDIUM — novel application of well-specified protocols in a non-HTTP context |
| Architecture | HIGH | Based on direct codebase inspection (`lib.rs`, `auth.rs`, `dpop.rs`, `device_flow/client.rs`, `security/session.rs`, `policy/config.rs`). Anti-patterns identified from live code, not theoretical. Build order validated against feature dependency graph |
| Pitfalls | HIGH | Critical pitfalls sourced from primary specs (CIBA Core 1.0 §7.3, RFC 9449 §8, WebAuthn Level 2, pam_set_data(3) man page) and direct code inspection (`.expect()` locations, `close_session()` no-op, Keycloak endpoint hardcoding) |

**Overall confidence:** HIGH

### Gaps to Address

- **Okta CIBA PUSH-only constraint:** Okta's CIBA implementation supports PUSH mode only, not POLL. The CIBA client must detect `backchannel_token_delivery_modes_supported` from OIDC discovery and return a clear error when poll mode is unsupported. Verify current Okta CIBA docs during Phase 6 planning — this constraint may have changed since research.
- **`reqwest 0.11` SSRF configuration audit:** Before Phase 4 (introspection), audit the existing JWKS `ClientBuilder` configuration in `oidc/jwks.rs` to confirm `redirect::Policy::none()` or equivalent is already in place. The introspection client should match or exceed that configuration.
- **`figment` config file ownership portability:** The recommended `stat()` ownership check (reject config not owned by uid 0) uses `std::os::unix::fs::MetadataExt::uid()`, which is Unix-only. Not a v2.0 concern but worth noting if a Windows cross-compilation target is ever added.
- **macOS WebAuthn credential storage CI behavior:** If Phase 7+ ever requires `webauthn-rs` credential storage in the agent keyring, the existing v1.0 pitfall (macOS Keychain prompts in non-interactive CI) applies. Address with the same mock-backend approach used for OAuth token storage.

## Sources

### Primary (HIGH confidence)
- RFC 9449 — OAuth 2.0 DPoP, §8 server nonce: https://www.rfc-editor.org/rfc/rfc9449
- RFC 7662 — OAuth 2.0 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662
- RFC 7009 — OAuth 2.0 Token Revocation: https://www.rfc-editor.org/rfc/rfc7009
- RFC 6749 §6 — Refreshing an Access Token: https://www.rfc-editor.org/rfc/rfc6749#section-6
- OpenID CIBA Core 1.0 — §7.3 poll mode, `auth_req_id`, `binding_message`: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- W3C WebAuthn Level 2: https://www.w3.org/TR/webauthn-2/
- NIST SP 800-53 Rev. 5, AC-2 (Account Management): https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- webauthn-rs (kanidm, SUSE product security audit): https://github.com/kanidm/webauthn-rs
- oauth2 5.0.0 docs (introspect, revoke, CIBA token response): https://docs.rs/oauth2/latest/oauth2/
- moka 0.12.14 (per-entry TTL, future::Cache, TinyLFU eviction): https://github.com/moka-rs/moka
- figment 0.10.19 (TOML/env layering, type-safe extraction): https://crates.io/crates/figment
- sd-notify 0.5.0 (pure Rust, no libsystemd dependency): https://crates.io/crates/sd-notify
- pam_set_data(3) Linux man page — PAM data sharing within handle: https://man7.org/linux/man-pages/man3/pam_set_data.3.html
- SO_PEERCRED Linux man page — unix(7): https://man7.org/linux/man-pages/man7/unix.7.html

### Secondary (MEDIUM confidence)
- Keycloak CIBA design (poll mode supported): https://github.com/keycloak/keycloak-community/blob/main/design/client-initiated-backchannel-authentication-flow.md
- Auth0 CIBA (enterprise tier, `/oauth/bc-authorize` non-standard path): https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
- Okta DPoP nonce requirement: https://developer.okta.com/docs/guides/dpop/nonoktaresourceserver/main/
- Yubico pam-u2f (reference PAM + FIDO2 implementation): https://developers.yubico.com/pam-u2f/
- Salesforce pam_oidc (Go template username mapping reference): https://github.com/salesforce/pam_oidc
- PostgreSQL portable getpeereid.c (SO_PEERCRED portability reference): https://github.com/postgres/postgres/blob/master/src/port/getpeereid.c
- systemd socket activation documentation: https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html

### Tertiary (LOW confidence — validate before implementation)
- Okta CIBA PUSH-only constraint (may have changed): https://learning.okta.com/first-look-client-initiated-backchannel-authentication-flow — verify current Okta developer docs during Phase 6 planning

---
*Research completed: 2026-03-10*
*Ready for roadmap: yes*
