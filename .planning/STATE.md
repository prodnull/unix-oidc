---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Production Hardening & Enterprise Readiness
status: verifying
stopped_at: Completed 15-02-PLAN.md
last_updated: "2026-03-12T20:05:51.356Z"
last_activity: 2026-03-12 — Phase 15 Plan 01 complete; all three test scripts verified passing locally against live Keycloak 26.2; CI check job unblocked from formatting/compilation errors; CI token-exchange job pending resolution of pre-existing unwrap_used violations
progress:
  total_phases: 11
  completed_phases: 9
  total_plans: 25
  completed_plans: 25
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** v2.0 — Phase 11: Implementation Completion

## Current Position

Phase: 15 of 15 (Phase 11 Verification & Traceability)
Plan: 01 of 02 (completed)
Status: Phase 15 Plan 01 complete — Phase 15 Plan 02 pending (VERIFICATION.md creation)
Last activity: 2026-03-12 — Phase 15 Plan 01 complete; all three test scripts verified passing locally against live Keycloak 26.2; CI check job unblocked from formatting/compilation errors; CI token-exchange job pending resolution of pre-existing unwrap_used violations

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**
- Total plans completed: 12
- Average duration: ~15m
- Total execution time: ~3h (v1.0)

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| v1.0 Phases 1-5 | 12 | ~3h | ~15m |

**Recent Trend:**
- Last 5 plans: 35m, 45m, 10m, 2m, 1m
- Trend: variable (hardware backend work was heavier)

*Updated after each plan completion*
| Phase 06 P01 | 20 | 2 tasks | 10 files |
| Phase 06 P02 | 270 | 1 tasks | 2 files |
| Phase 06 P03 | 803 | 2 tasks | 4 files |
| Phase 07-dpop-nonce-issuance P01 | 45 | 2 tasks | 7 files |
| Phase 07-dpop-nonce-issuance P02 | 3 | 1 tasks | 1 files |
| Phase 07-dpop-nonce-issuance P02 | 3 | 2 tasks | 1 files |
| Phase 08-username-mapping-group-policy-break-glass P01 | 560 | 3 tasks | 10 files |
| Phase 08-username-mapping-group-policy-break-glass P02 | 310 | 2 tasks | 3 files |
| Phase 08-username-mapping-group-policy-break-glass P03 | 252 | 2 tasks | 3 files |
| Phase 09 P01 | 428 | 2 tasks | 5 files |
| Phase 09 P02 | 259 | 2 tasks | 4 files |
| Phase 09 P03 | 600 | 2 tasks | 4 files |
| Phase 10-ciba-step-up-fido2-acr-delegation P01 | 10 | 2 tasks | 5 files |
| Phase 10-ciba-step-up-fido2-acr-delegation P02 | 277 | 2 tasks | 5 files |
| Phase 10-ciba-step-up-fido2-acr-delegation P03 | 90 | 2 tasks | 4 files |
| Phase 11-implementation-completion P01 | 175 | 2 tasks | 3 files |
| Phase 11 P02 | 150 | 2 tasks | 2 files |
| Phase 13-operational-hardening P01 | 14 | 3 tasks | 10 files |
| Phase 13-operational-hardening P02 | 8 | 2 tasks | 6 files |
| Phase 13-operational-hardening P04 | 9 | 2 tasks | 3 files |
| Phase 13 P03 | 331 | 2 tasks | 4 files |
| Phase 13-operational-hardening P05 | 8 | 2 tasks | 5 files |
| Phase 14-critical-integration-bug-fixes P02 | 12 | 1 tasks | 2 files |
| Phase 14-critical-integration-bug-fixes P01 | 10 | 2 tasks | 5 files |
| Phase 15-phase-11-verification-traceability P01 | 120 | 2 tasks | 6 files |
| Phase 15 P02 | 3 | 2 tasks | 3 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [v2.0 roadmap]: figment 0.10.19 replaces serde_yaml for config loading — enables Issue #10 security mode config shape
- [v2.0 roadmap]: moka 0.12.14 chosen for all TTL caches (JTI replay, DPoP nonce, introspection results)
- [v2.0 roadmap]: CIBA polling must live in agent daemon, not PAM thread — avoids sshd LoginGraceTime timeout
- [v2.0 roadmap]: PAM session store uses tmpfs files under /run/unix-oidc/sessions/ — pam_sm_open_session and pam_sm_close_session run in different sshd worker processes
- [v2.0 roadmap]: FIDO2 step-up via CIBA ACR delegation only — no libfido2/webauthn-rs in PAM crate; direct CTAP2 deferred to v2.1+
- [v2.0 roadmap]: reqwest stays on 0.11 — 0.11→0.12 TLS layer change requires full ClientBuilder audit; separate hardening item
- [Phase 06]: parking_lot is unconditional production dep (not feature flag); getrandom errors map to AuthError::Config; DeviceFlowClient constructors return Result
- [Phase 06-02]: EnforcementMode uses hand-rolled Deserialize to reject invalid strings with clear error; Option<SecurityModes> in PolicyConfig preserves v1.0 backward compat; Env::prefixed().only() prevents UNIX_OIDC_TEST_MODE from polluting config parse
- [Phase 06]: ValidationConfig.enforce_jti: bool replaced by jti_enforcement: EnforcementMode — removes UNIX_OIDC_DISABLE_JTI_CHECK env var in favour of policy.yaml enforcement
- [Phase 06]: Replay detection hard-fail in all modes; missing JTI configurable but replayed JTI never configurable (CLAUDE.md invariant)
- [Phase 06]: deny(clippy::unwrap_used, clippy::expect_used) activated crate-wide in lib.rs; test modules have allow attribute; ENV_MUTEX migrated to parking_lot::Mutex
- [Phase 07-dpop-nonce-issuance]: moka Cache.remove() is atomic single-use primitive for nonce consume; no TOCTOU
- [Phase 07-dpop-nonce-issuance]: validate_dpop_proof() returns DPoPProofResult{thumbprint,nonce} to decouple binding check from cache consumption
- [Phase 07-dpop-nonce-issuance]: Nonce replay is always hard-fail; missing nonce enforcement respects dpop_required mode (strict/warn/disabled)
- [Phase 07-dpop-nonce-issuance]: Safe-default Strict enforcement when policy file absent; orphaned nonces expire via TTL; single auth dispatch routes both strict+no-proof and has-proof through authenticate_with_dpop()
- [Phase 07-dpop-nonce-issuance]: issue_and_deliver_nonce() extracted as named helper in lib.rs; orphaned nonces handled by TTL eviction; dpop_proof.is_some() || mode==Strict routes both cases through authenticate_with_dpop()
- [Phase 08-01]: Groups resolved from NSS (SSSD/FreeIPA), never from token claims — avoids Entra group overage and multi-IdP format inconsistencies
- [Phase 08-01]: groups_enforcement defaults to Warn; empty allowed_groups always permits (backward compat invariant for v1.0 deployments)
- [Phase 08-01]: Regex (?P<username>...) validated at config load (not auth time); macOS getgrouplist returns Some for unknown users — enforcement-mode logic tested via simulation helper
- [Phase 08-02]: Break-glass check is unconditionally FIRST in authenticate() before rate limiting; authenticate_with_config gains optional mapper param (None=backward compat); sudo group check before device flow initiation; empty sudo_groups skips NSS lookup
- [Phase 08-username-mapping-group-policy-break-glass]: check_collision_safety() hard-fail gatekeeper wraps validate_collision_safety() warnings as Err — single source of heuristics, unconditional non-configurable fail same class as signature verification
- [Phase 09]: Session correlation via PAM putenv/getenv is best-effort: failure never fails auth; AuthResult gains token_exp and token_issuer fields for open_session use
- [Phase 09]: Session records 0600 root; session directory 0700 root; atomic write-then-rename on same filesystem; path-traversal validation on session_id
- [Phase 09]: notify_agent_session_closed uses blocking std UnixStream with 2s timeout; socket via UNIX_OIDC_AGENT_SOCKET env or XDG_RUNTIME_DIR fallback
- [Phase 09]: Inactive (active=false) results not cached — revoked tokens re-checked every auth attempt rather than blocked for full cache TTL
- [Phase 09]: IntrospectionConfig gains client_secret field (RFC 7662 §2.1 requirement); default None for backward compat
- [Phase 09]: SessionAcknowledged uses acknowledged:bool discriminant field + placed before Ok{} in untagged AgentResponseData enum to prevent serde collision
- [Phase 09]: spawn_refresh_task() exported pub; cleanup_session() is module-private — only handle_connection calls it
- [Phase 09]: revocation_endpoint stored in token metadata at login (from OIDC discovery) and preserved across refresh — cleanup_session() reads without re-discovery
- [Phase 10-01]: OidcDiscovery made pub with token_endpoint required and all CIBA/device-flow fields optional via serde(default)
- [Phase 10-01]: ACR validation hard-fail always (no EnforcementMode) — security invariant; phrh satisfies phr but not reverse
- [Phase 10-01]: CibaClient is parameter-builder only, no HTTP — keeps PAM crate free of async I/O for CIBA
- [Phase 10-01]: CIBA_GRANT_TYPE uses urn:openid:params not urn:ietf:params per CIBA Core 1.0 §2; binding_message strips args for security
- [Phase 10-ciba-step-up-fido2-acr-delegation]: StepUpPending placed before Refreshed in untagged AgentResponseData — both have expires_in; unique poll_interval_secs field discriminates correctly when tried first
- [Phase 10-ciba-step-up-fido2-acr-delegation]: DeviceFlowClient::from_discovery() is IdP-agnostic constructor using OIDC discovery endpoints; from_discovery() preferred over new() for all non-Keycloak IdPs
- [Phase 10-03]: PAM IPC pattern: short 2s-timeout blocking calls per poll cycle; CIBA 120s loop runs in agent Tokio runtime — avoids SSH LoginGraceTime race
- [Phase 10-03]: challenge_timeout default raised from 60s to 120s (STP-07) to accommodate typical CIBA push notification round-trip
- [Phase 10-03]: login_hint uses Unix username directly; IdP must accept username-based login_hint; config enhancement deferred (RESEARCH.md Open Question #1)
- [Phase 11-01]: CLIENT_SECRET default in test_dpop_binding.sh uses unix-oidc-test-secret matching realm JSON, not plan-specified test-secret
- [Phase 11]: Shutdown lifecycle test sends command without reading response; polls try_wait for process exit
- [Phase 13-operational-hardening]: figment UNIX_OIDC_TIMEOUTS__FIELD pattern (double-underscore) for nested env var overrides; UNIX_OIDC_JWKS_CACHE_TTL preserved as legacy direct override
- [Phase 13-operational-hardening]: DPoPAuthConfig::clock_skew_future_secs added to thread value to DPoPConfig without changing authenticate_with_dpop() signature
- [Phase 13-operational-hardening]: get_hostname() now uses gethostname(2) syscall; HOSTNAME/HOST env vars removed; UNIX_OIDC_HOSTNAME preserved for CNAME/container override scenarios
- [Phase 13-operational-hardening]: sd-notify 0.5 API is notify(&[NotifyState]) not notify(bool, &[...]) — acquire_listener exported for Gate 1 ordering before AgentServer creation
- [Phase 13-operational-hardening]: run_credential_cleanup() at shutdown skips keyring deletion (restart should find existing creds); SessionClosed IPC handles full deletion
- [Phase 13-operational-hardening]: Shutdown IPC uses libc::kill(SIGTERM) to route through graceful shutdown path instead of process::exit(0)
- [Phase 13-operational-hardening]: install subcommand derives socket path from $TMPDIR (macOS per-user temp dir) for multi-user isolation
- [Phase 13-operational-hardening]: plist template embedded via include_str!() at compile time — no runtime dependency on contrib/ directory
- [Phase 13-operational-hardening]: launchd_socket::take() returns None on ESRCH (not under launchd) — fallthrough to standalone is correct behavior
- [Phase 13]: idle_timeout stored in AgentServer as Duration field with with_idle_timeout() builder; default 60s; per-read timeout (not per-connection total) wraps each read_line call
- [Phase 13]: main.rs captures ipc_idle_timeout_secs from AgentConfig::load() at Gate 2; fallback to 60s if config load fails
- [Phase 13]: init_tracing() uses try_init() — prevents double-registration panics; tracing-journald gated to Linux cfg; peer_pid forwarded to handle_connection (no second syscall); extract_jwk_from_proof() NOT instrumented (untrusted input); GetProof INFO log emitted before signer check
- [Phase 14-critical-integration-bug-fixes]: askpass.rs is a binary module (mod askpass in main.rs); uses unix_oidc_agent:: prefix for daemon types; PPID keying prevents cross-session collision; token cached between DPOP_PROOF and OIDC Token rounds via tmpfile
- [Phase 14]: DPoPAuthConfig::from_env() dead code removed; from_policy(&PolicyConfig) is the replacement
- [Phase 14]: PamTimeoutsConfig in PolicyConfig is single source of truth for PAM clock skew — wired to both DPoPAuthConfig.max_proof_age and ValidationConfig.clock_skew_tolerance_secs
- [Phase 14]: TOCTOU guard in handle_step_up_result returns STEP_UP_CONSUMED at second HashMap::get() to distinguish concurrent consumption from unknown correlation ID
- [Phase 15-01]: Keycloak 26 V2 standard token exchange works WITHOUT audience parameter — sending audience=target triggers "Client not allowed to exchange"; infers audience from client's configured scope
- [Phase 15-01]: tss-esapi v7.6 API breaks: EccScheme in structures (not interface_types::algorithm), PersistentTpmHandle in handles, Provision in interface_types::resource_handles, Public is enum with named-field variants (not Public::unique() method), tss_esapi::constants::tpm removed
- [Phase 15-01]: Bash $(cat) in command substitution corrupts binary bytes containing backslash sequences — always use direct pipe for binary data (EC coordinates, SHA-256 digests, ECDSA signatures)
- [Phase 15-01]: DER ECDSA signature OFFSET must be 6 (skip SEQUENCE header 30 XX = 4 hex, then INTEGER tag 02 = 2 hex) — OFFSET=4 reads INTEGER tag as R length
- [Phase 15-01]: Pre-existing unwrap_used violations in pam-unix-oidc audit.rs, ciba/client.rs, ciba/types.rs, device_flow/client.rs, sudo.rs block CI check job — require dedicated lint-fix phase
- [Phase 15]: TEST-01/TEST-02 traceability Phase column set to Phase 11 (implementation), not Phase 15 (verification)
- [Phase 15]: CI token-exchange job blocked by pre-existing unwrap_used violations; local Keycloak evidence sufficient to close TEST-01/TEST-02

### Pending Todos

- [Global]: Every phase must include adversarial/negative tests (malformed tokens, replayed nonces, forged claims, timing attacks, resource exhaustion) — not just happy-path tests
- [Docs]: Create `docs/standards-compliance-matrix.md` — centralized RFC/NIST/standards tracker for publications (whitepapers, conference talks, WG outreach, blog posts). Currently refs scattered across ADRs, code comments, security guide, REQUIREMENTS.md. Need section-level RFC coverage map, NIST/SOC2 cross-refs, implementation status. `docs/ietf/` dir exists but empty. Full inventory in project memory `standards-tracking.md`.

### Blockers/Concerns

- [Phase 10 - pre-planning flag]: Okta CIBA supports PUSH mode only, not POLL — detect via backchannel_token_delivery_modes_supported from OIDC discovery; verify current Okta docs during Phase 10 planning (may have changed since research 2026-03-10)
- [Phase 11 - pre-planning flag]: PAM stack order fix for RHEL 9 (pam_systemd.so before pam_unix_oidc.so) needs platform verification; socket activation has known ordering race on RHEL 9

## Session Continuity

Last session: 2026-03-12T20:05:51.354Z
Stopped at: Completed 15-02-PLAN.md
Resume file: None
