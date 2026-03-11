# Requirements: unix-oidc v2.0

**Defined:** 2026-03-10
**Core Value:** DPoP private keys must be protected at rest, in memory, and on deletion — because a stolen DPoP key defeats the entire proof-of-possession security model that distinguishes unix-oidc from bearer-token systems.

## v2.0 Requirements

Requirements for production hardening and enterprise readiness. Each maps to roadmap phases.

### Security Foundations

- [x] **SEC-01**: All `.expect()` and `.unwrap()` calls removed from PAM-reachable code paths
- [x] **SEC-02**: `#![deny(clippy::expect_used, clippy::unwrap_used)]` lint active in `pam-unix-oidc`
- [x] **SEC-03**: Configurable enforcement modes (strict/warn/disabled) for JTI, DPoP requirement, ACR/AMR claims
- [x] **SEC-04**: figment-based config loading with backward-compatible defaults matching v1.0 behavior
- [x] **SEC-05**: Server-side DPoP nonce issuance per RFC 9449 §8 with PAM challenge delivery
- [x] **SEC-06**: DPoP nonce single-use enforcement and TTL-bounded moka cache
- [x] **SEC-07**: JTI cache size aligned between code and documentation (resolve 10k vs 100k)

### Enterprise Identity

- [x] **IDN-01**: Username claim mapping with configurable claim source (sub, email, preferred_username, custom)
- [x] **IDN-02**: Username transform functions (strip domain suffix, regex with capture group, lowercase)
- [x] **IDN-03**: Username uniqueness validation at config load time to prevent many-to-one collisions
- [x] **IDN-04**: Group-based login access policy from OIDC groups claim with configurable allow-list
- [x] **IDN-05**: Group-based sudo access policy (sudo_groups) gating step-up authorization
- [x] **IDN-06**: Break-glass account enforcement — skip OIDC for configured accounts, pass to next PAM module
- [x] **IDN-07**: Break-glass audit event emitted on every break-glass authentication

### Session & Token Lifecycle

- [x] **SES-01**: `pam_sm_open_session` writes session record to tmpfs store (`/run/unix-oidc/sessions/`)
- [x] **SES-02**: `pam_sm_close_session` deletes session record and emits session-close audit event with duration
- [x] **SES-03**: Session correlation via `pam_set_data()` between authenticate and open_session calls
- [x] **SES-04**: Automatic token refresh in agent daemon at configurable TTL threshold (default 80%)
- [x] **SES-05**: Token introspection (RFC 7662) as opt-in validation step with configurable fail-open/fail-closed
- [x] **SES-06**: Introspection result caching via moka with TTL bounded by min(60s, token exp - now)
- [x] **SES-07**: RFC 7009 token revocation on session close (best-effort, 5s timeout)
- [x] **SES-08**: Agent SessionClosed IPC event to schedule orphaned DPoP key cleanup

### Step-Up Authentication

- [x] **STP-01**: CIBA poll-mode step-up implemented in agent daemon (not PAM thread)
- [x] **STP-02**: CIBA binding_message carries the command being authorized for phishing context
- [x] **STP-03**: CIBA backchannel discovery from IdP OIDC metadata (backchannel_authentication_endpoint)
- [x] **STP-04**: FIDO2 step-up via CIBA ACR delegation (request phishing-resistant ACR from IdP)
- [x] **STP-05**: Step-up IPC protocol extensions (StepUp, StepUpPending, StepUpComplete messages)
- [x] **STP-06**: IdP discovery-based endpoint resolution replacing Keycloak-hardcoded device flow URLs
- [x] **STP-07**: Configurable step-up timeout for CIBA polling (default 120s)

### Test Completion

- [ ] **TEST-01**: Token exchange tests (shell + Python) wired into CI via `docker-compose.token-exchange.yaml` with DPoP cnf.jkt rebinding validation
- [ ] **TEST-02**: DPoP-bound access token E2E — Keycloak test realm configured with `dpop.bound.access.tokens: true`; CI test validates cnf.jkt thumbprint match
- [x] **TEST-03**: Cross-language DPoP interop tests (Rust/Go/Python) running in CI via `dpop-cross-language-tests/`
- [x] **TEST-04**: Agent daemon lifecycle integration test — start daemon, send IPC commands, validate responses, clean shutdown

### Integration Testing

- [ ] **INT-01**: CIBA-enabled Keycloak test realm with poll-mode backchannel auth, ACR LoA mapping, and Admin API auto-approval in CI
- [ ] **INT-02**: Step-up IPC full-flow integration test using wiremock-rs mock CIBA endpoint (StepUp -> StepUpPending -> poll -> StepUpComplete)
- [ ] **INT-03**: Break-glass fallback test — OIDC unavailable, local auth succeeds, OIDC recovery on IdP restart
- [ ] **INT-04**: ACR validation against live Keycloak tokens with configured ACR LoA mapping (optional FIDO2 simulation)

### Operational Readiness

- [x] **OPS-01**: systemd user service unit with hardening directives (NoNewPrivileges, ProtectSystem, MemoryDenyWriteExecute)
- [x] **OPS-02**: systemd socket activation support with standalone fallback
- [x] **OPS-03**: launchd plist template for macOS agent daemon
- [x] **OPS-04**: sd-notify READY=1 after socket bind + config validation + initial JWKS fetch
- [x] **OPS-05**: SO_PEERCRED (Linux) / getpeereid (macOS) peer UID validation on IPC socket
- [x] **OPS-06**: IPC idle timeout (configurable, default 60s) to prevent Tokio task leaks
- [x] **OPS-07**: Configurable JWKS HTTP timeout (default 10s, operator-tunable)
- [x] **OPS-08**: Configurable device flow HTTP timeout (default 30s, operator-tunable)
- [x] **OPS-09**: Configurable clock skew tolerance (default 5s future / 60s staleness)
- [x] **OPS-10**: Configurable JWKS cache TTL wired to env var (default 300s)
- [ ] **OPS-11**: Tracing spans across full authentication flow (JWKS fetch, validation, DPoP verify, user lookup)
- [x] **OPS-12**: Audit hostname resolution via gethostname() syscall instead of env vars
- [ ] **OPS-13**: Proof request logging at INFO level (username, target, signer type)

## Future Requirements (v2.1+)

### Scalability

- **SCALE-01**: Distributed JTI cache backend (Redis/Valkey) for multi-node deployments
- **SCALE-02**: VDI/agent socket forwarding mechanism

### Token Exchange

- **TXEX-01**: RFC 8693 token exchange for service-to-service delegation
- **TXEX-02**: Agent-to-server token exchange flow (see ADR-005)

### Provisioning

- **PROV-01**: SCIM endpoint for automated user provisioning
- **PROV-02**: Group sync from IdP to local system

### Advanced Auth

- **AUTH-01**: Direct CTAP2/WebAuthn in PAM with credential registration store
- **AUTH-02**: Post-quantum algorithm migration (ML-DSA-65 alongside ES256)

## Out of Scope

| Feature | Reason |
|---------|--------|
| CIBA ping/push modes | Require HTTP notification endpoint — structurally incompatible with PAM module |
| Interactive PIN/OTP in PAM auth | Unreliable under non-interactive SSH (BatchMode, ProxyJump, scripts) |
| Browser WebAuthn at PAM | PAM is non-browser; CTAP2 is the correct non-browser analog (deferred to v2.1) |
| Agent forwarding | Breaks proof-of-possession threat model — remote host gains the private key |
| Distributed JTI cache | High operational complexity; per-node LRU is correct for v2.0 single-host model |
| Token exchange (RFC 8693) | Separate milestone per user instruction; see ADR-005 |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SEC-01 | Phase 6 | Complete |
| SEC-02 | Phase 6 | Complete |
| SEC-03 | Phase 6 | Complete |
| SEC-04 | Phase 6 | Complete |
| SEC-07 | Phase 6 | Complete |
| SEC-05 | Phase 7 | Complete |
| SEC-06 | Phase 7 | Complete |
| IDN-01 | Phase 8 | Complete |
| IDN-02 | Phase 8 | Complete |
| IDN-03 | Phase 8 | Complete |
| IDN-04 | Phase 8 | Complete |
| IDN-05 | Phase 8 | Complete |
| IDN-06 | Phase 8 | Complete |
| IDN-07 | Phase 8 | Complete |
| SES-01 | Phase 9 | Complete |
| SES-02 | Phase 9 | Complete |
| SES-03 | Phase 9 | Complete |
| SES-04 | Phase 9 | Complete |
| SES-05 | Phase 9 | Complete |
| SES-06 | Phase 9 | Complete |
| SES-07 | Phase 9 | Complete |
| SES-08 | Phase 9 | Complete |
| STP-01 | Phase 10 | Complete |
| STP-02 | Phase 10 | Complete |
| STP-03 | Phase 10 | Complete |
| STP-04 | Phase 10 | Complete |
| STP-05 | Phase 10 | Complete |
| STP-06 | Phase 10 | Complete |
| STP-07 | Phase 10 | Complete |
| TEST-01 | Phase 11 | Pending |
| TEST-02 | Phase 11 | Pending |
| TEST-03 | Phase 11 | Complete |
| TEST-04 | Phase 11 | Complete |
| INT-01 | Phase 12 | Pending |
| INT-02 | Phase 12 | Pending |
| INT-03 | Phase 12 | Pending |
| INT-04 | Phase 12 | Pending |
| OPS-01 | Phase 13 | Complete |
| OPS-02 | Phase 13 | Complete |
| OPS-03 | Phase 13 | Complete |
| OPS-04 | Phase 13 | Complete |
| OPS-05 | Phase 13 | Complete |
| OPS-06 | Phase 13 | Complete |
| OPS-07 | Phase 13 | Complete |
| OPS-08 | Phase 13 | Complete |
| OPS-09 | Phase 13 | Complete |
| OPS-10 | Phase 13 | Complete |
| OPS-11 | Phase 13 | Pending |
| OPS-12 | Phase 13 | Complete |
| OPS-13 | Phase 13 | Pending |

**Coverage:**
- v2.0 requirements: 50 total
- Mapped to phases: 50
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-10*
*Last updated: 2026-03-10 — traceability populated by v2.0 roadmap creation*
