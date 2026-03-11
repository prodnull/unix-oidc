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
- [ ] **SES-04**: Automatic token refresh in agent daemon at configurable TTL threshold (default 80%)
- [ ] **SES-05**: Token introspection (RFC 7662) as opt-in validation step with configurable fail-open/fail-closed
- [ ] **SES-06**: Introspection result caching via moka with TTL bounded by min(60s, token exp - now)
- [ ] **SES-07**: RFC 7009 token revocation on session close (best-effort, 5s timeout)
- [ ] **SES-08**: Agent SessionClosed IPC event to schedule orphaned DPoP key cleanup

### Step-Up Authentication

- [ ] **STP-01**: CIBA poll-mode step-up implemented in agent daemon (not PAM thread)
- [ ] **STP-02**: CIBA binding_message carries the command being authorized for phishing context
- [ ] **STP-03**: CIBA backchannel discovery from IdP OIDC metadata (backchannel_authentication_endpoint)
- [ ] **STP-04**: FIDO2 step-up via CIBA ACR delegation (request phishing-resistant ACR from IdP)
- [ ] **STP-05**: Step-up IPC protocol extensions (StepUp, StepUpPending, StepUpComplete messages)
- [ ] **STP-06**: IdP discovery-based endpoint resolution replacing Keycloak-hardcoded device flow URLs
- [ ] **STP-07**: Configurable step-up timeout for CIBA polling (default 120s)

### Operational Readiness

- [ ] **OPS-01**: systemd user service unit with hardening directives (NoNewPrivileges, ProtectSystem, MemoryDenyWriteExecute)
- [ ] **OPS-02**: systemd socket activation support with standalone fallback
- [ ] **OPS-03**: launchd plist template for macOS agent daemon
- [ ] **OPS-04**: sd-notify READY=1 after socket bind + config validation + initial JWKS fetch
- [ ] **OPS-05**: SO_PEERCRED (Linux) / getpeereid (macOS) peer UID validation on IPC socket
- [ ] **OPS-06**: IPC idle timeout (configurable, default 60s) to prevent Tokio task leaks
- [ ] **OPS-07**: Configurable JWKS HTTP timeout (default 10s, operator-tunable)
- [ ] **OPS-08**: Configurable device flow HTTP timeout (default 30s, operator-tunable)
- [ ] **OPS-09**: Configurable clock skew tolerance (default 5s future / 60s staleness)
- [ ] **OPS-10**: Configurable JWKS cache TTL wired to env var (default 300s)
- [ ] **OPS-11**: Tracing spans across full authentication flow (JWKS fetch, validation, DPoP verify, user lookup)
- [ ] **OPS-12**: Audit hostname resolution via gethostname() syscall instead of env vars
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
| SES-04 | Phase 9 | Pending |
| SES-05 | Phase 9 | Pending |
| SES-06 | Phase 9 | Pending |
| SES-07 | Phase 9 | Pending |
| SES-08 | Phase 9 | Pending |
| STP-01 | Phase 10 | Pending |
| STP-02 | Phase 10 | Pending |
| STP-03 | Phase 10 | Pending |
| STP-04 | Phase 10 | Pending |
| STP-05 | Phase 10 | Pending |
| STP-06 | Phase 10 | Pending |
| STP-07 | Phase 10 | Pending |
| OPS-01 | Phase 11 | Pending |
| OPS-02 | Phase 11 | Pending |
| OPS-03 | Phase 11 | Pending |
| OPS-04 | Phase 11 | Pending |
| OPS-05 | Phase 11 | Pending |
| OPS-06 | Phase 11 | Pending |
| OPS-07 | Phase 11 | Pending |
| OPS-08 | Phase 11 | Pending |
| OPS-09 | Phase 11 | Pending |
| OPS-10 | Phase 11 | Pending |
| OPS-11 | Phase 11 | Pending |
| OPS-12 | Phase 11 | Pending |
| OPS-13 | Phase 11 | Pending |

**Coverage:**
- v2.0 requirements: 42 total (note: original count of 37 was incorrect; full enumeration gives 42)
- Mapped to phases: 42
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-10*
*Last updated: 2026-03-10 — traceability populated by v2.0 roadmap creation*
