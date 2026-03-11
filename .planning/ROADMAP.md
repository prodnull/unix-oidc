# Roadmap: unix-oidc

## Milestones

- ✅ **v1.0 Client-Side Key Protection Hardening** — Phases 1-5 (shipped 2026-03-10)
- 📋 **v2.0 Production Hardening & Enterprise Readiness** — Phases 6-13 (planned)

## Phases

<details>
<summary>✅ v1.0 Client-Side Key Protection Hardening (Phases 1-5) — SHIPPED 2026-03-10</summary>

- [x] Phase 1: Memory Protection Hardening (4/4 plans) — completed 2026-03-10
- [x] Phase 2: Storage Backend Wiring (3/3 plans) — completed 2026-03-10
- [x] Phase 3: Hardware Signer Backends (3/3 plans) — completed 2026-03-10
- [x] Phase 4: Fix Hardware Signer Refresh Persistence (1/1 plan) — completed 2026-03-10
- [x] Phase 5: Audit Documentation Cleanup (1/1 plan) — completed 2026-03-10

Full details: `.planning/milestones/v1.0-ROADMAP.md`

</details>

### 📋 v2.0 Production Hardening & Enterprise Readiness (Planned)

**Milestone Goal:** Eliminate every security gap, doc/code mismatch, and operational deficiency to make unix-oidc production-deployable at enterprise scale.

**Testing mandate:** Every phase must include comprehensive tests for both happy paths and adversarial inputs. Security features require negative tests (malformed tokens, replayed nonces, forged claims, timing attacks, resource exhaustion). Plans must allocate explicit testing tasks — not just implementation.

- [x] **Phase 6: PAM Panic Elimination + Security Mode Infrastructure** - Remove all `.expect()`/`.unwrap()` from PAM-reachable paths and wire configurable strict/warn/disabled enforcement modes (completed 2026-03-10)
- [x] **Phase 7: DPoP Nonce Issuance** - Implement server-side DPoP nonces per RFC 9449 §8 to close the proof-replay window (completed 2026-03-10)
- [x] **Phase 8: Username Mapping + Group Policy + Break-Glass** - Enterprise identity integration: claim transforms, group-based access control, and break-glass enforcement (completed 2026-03-10)
- [x] **Phase 9: Token Introspection + Session Lifecycle + Token Refresh** - Full session management: RFC 7662 introspection, open/close session records, RFC 7009 revocation, and automatic token refresh (completed 2026-03-11)
- [x] **Phase 10: CIBA Step-Up + FIDO2 via ACR Delegation** - IdP-agnostic step-up authentication via CIBA poll mode and FIDO2 through phishing-resistant ACR claim delegation (completed 2026-03-11)
- [ ] **Phase 11: Implementation Completion** - Wire existing but unwired test assets into CI, fill DPoP-bound token E2E gaps, cross-language interop in CI, agent daemon lifecycle test
- [ ] **Phase 12: Rigorous Integration Testing** - CIBA live IdP test infrastructure, step-up IPC full-flow, break-glass fallback, FIDO2 authenticator simulation
- [x] **Phase 13: Operational Hardening** - systemd/launchd service integration, IPC security, configurable timeouts, tracing spans, and audit fixes (completed 2026-03-11)

## Phase Details

### Phase 6: PAM Panic Elimination + Security Mode Infrastructure
**Goal**: The PAM module can never panic on malformed input or unexpected server state; every configurable security check has an enforcement level that defaults to v1.0 behavior
**Depends on**: Phase 5 (v1.0 complete)
**Requirements**: SEC-01, SEC-02, SEC-03, SEC-04, SEC-07
**Success Criteria** (what must be TRUE):
  1. A PAM authentication attempt with any combination of malformed token, missing claims, or corrupt config produces an error return code — never a process panic or abort
  2. The `#![deny(clippy::unwrap_used, clippy::expect_used)]` lint is active on `pam-unix-oidc` and the crate compiles clean
  3. An operator can set `jti_enforcement = "strict"` in `policy.yaml` and authentication with a missing JTI claim is rejected; setting `"warn"` logs a warning and passes
  4. A v1.0 `policy.yaml` file (no `[security_modes]` section) loads successfully against the v2.0 config struct with behavior identical to v1.0
  5. The JTI cache size is consistent between code and documentation (10k vs 100k discrepancy resolved and committed)
**Plans:** 3/3 plans complete

Plans:
- [ ] 06-01-PLAN.md — parking_lot migration + panic elimination (SEC-01, SEC-07)
- [ ] 06-02-PLAN.md — SecurityModes/CacheConfig types + figment config loading (SEC-03, SEC-04)
- [ ] 06-03-PLAN.md — Wire enforcement modes into validation + deny lint activation (SEC-02, SEC-03)

### Phase 7: DPoP Nonce Issuance
**Goal**: The server issues a fresh single-use nonce with every DPoP challenge, making captured DPoP proofs unreplayable even within their `iat`/`exp` window
**Depends on**: Phase 6
**Requirements**: SEC-05, SEC-06
**Success Criteria** (what must be TRUE):
  1. A DPoP proof replayed after its nonce has been consumed is rejected with a distinct error, even if the proof's `iat`/`exp` and JTI are valid
  2. Each PAM authentication challenge carries a server-generated nonce that the client must include in its DPoP proof
  3. Nonces expire after 60 seconds; a proof bearing an expired nonce is rejected
**Plans:** 2/2 plans complete

Plans:
- [ ] 07-01-PLAN.md — DPoP nonce cache (moka-backed), nonce generation, CacheConfig extension, enforcement mode threading (SEC-05, SEC-06)
- [ ] 07-02-PLAN.md — Two-round PAM conversation for nonce challenge/response + human verification (SEC-05)

### Phase 8: Username Mapping + Group Policy + Break-Glass
**Goal**: Enterprise deployments can map IdP claim values to local Unix usernames, restrict login to specific OIDC groups, and rely on break-glass accounts being enforced with an audit trail
**Depends on**: Phase 6
**Requirements**: IDN-01, IDN-02, IDN-03, IDN-04, IDN-05, IDN-06, IDN-07
**Success Criteria** (what must be TRUE):
  1. An IdP user whose `email` claim is `alice@corp.example` can authenticate as local user `alice` when the strip-domain transform is configured, without any manual `authorized_keys` entry
  2. A user not in the configured `login_groups` list is denied SSH access even with a valid OIDC token; the denial is logged with the user's groups claim
  3. Two IdP identities that would map to the same Unix username cause the daemon to refuse to start with a clear config error, preventing identity collision
  4. A `sudo` attempt by a user not in `sudo_groups` is denied at the PAM step-up gate
  5. Authentication as a break-glass account bypasses OIDC entirely, passes to the next PAM module, and emits an audit log entry recording the break-glass event
**Plans:** 3/3 plans complete

Plans:
- [x] 08-01-PLAN.md — Config types, identity mapper, collision detection, NSS groups, TokenClaims, audit event (IDN-01, IDN-02, IDN-03, IDN-04, IDN-05, IDN-06, IDN-07)
- [x] 08-02-PLAN.md — Wire break-glass, mapper, group policy into auth/sudo flows (IDN-01, IDN-02, IDN-04, IDN-05, IDN-06, IDN-07)
- [x] 08-03-PLAN.md — Enforce collision hard-fail in collision.rs and auth.rs (IDN-03)

### Phase 9: Token Introspection + Session Lifecycle + Token Refresh
**Goal**: SSH sessions have bounded lifetimes tied to token validity; revoked tokens take effect within the introspection cache TTL; the agent refreshes tokens before mid-session expiry
**Depends on**: Phase 7, Phase 8
**Requirements**: SES-01, SES-02, SES-03, SES-04, SES-05, SES-06, SES-07, SES-08
**Success Criteria** (what must be TRUE):
  1. When an employee's account is disabled at the IdP and introspection is enabled, their next authentication attempt fails (within the introspection cache TTL, default 60s)
  2. After SSH session close, a session record is removed from `/run/unix-oidc/sessions/` and a revocation request is sent to the IdP (best-effort)
  3. An SSH session open at minute 0 with a 60-minute token is still alive at minute 50 because the agent automatically refreshed the token at the 80% threshold
  4. A server restart that loses in-process state does not prevent `pam_sm_close_session` from locating and closing the session record written by `pam_sm_open_session`
  5. When the introspection endpoint is unreachable, authentication succeeds (fail-open default) and a warning is logged
**Plans:** 3/3 plans complete

Plans:
- [ ] 09-01-PLAN.md — Config types, session record module, audit events, PAM open/close_session with putenv/getenv correlation (SES-01, SES-02, SES-03)
- [ ] 09-02-PLAN.md — RFC 7662 introspection client + moka cache, wired into authenticate() (SES-05, SES-06)
- [ ] 09-03-PLAN.md — Agent IPC SessionClosed, auto-refresh background task, RFC 7009 revocation, credential cleanup (SES-04, SES-07, SES-08)

### Phase 10: CIBA Step-Up + FIDO2 via ACR Delegation
**Goal**: Users can approve privileged operations via a push notification to their phone or a FIDO2 authenticator, with the step-up flow handled entirely in the agent daemon so the PAM module never blocks
**Depends on**: Phase 9
**Requirements**: STP-01, STP-02, STP-03, STP-04, STP-05, STP-06, STP-07
**Success Criteria** (what must be TRUE):
  1. A `sudo` command triggers a push notification to the user's phone via CIBA; approving it on the phone completes the `sudo` within the configurable timeout (default 120s) without the SSH session timing out
  2. The push notification message contains the command being authorized (e.g., "Approve: sudo systemctl restart nginx on server-01"), giving the user phishing context
  3. The CIBA backchannel endpoint is discovered from the IdP's OIDC metadata, not hardcoded to a Keycloak URL
  4. Configuring `step_up_method = "fido2"` triggers a CIBA request with a phishing-resistant ACR value; the resulting token's `acr` claim is validated to confirm the IdP honored the request
  5. When a step-up request times out, the `sudo` attempt is denied and the user sees an actionable message
**Plans:** 3/3 plans complete

Plans:
- [ ] 10-01-PLAN.md — OIDC discovery extension + CIBA types/client + ACR validation (STP-02, STP-03, STP-04)
- [ ] 10-02-PLAN.md — Step-up IPC protocol messages + DeviceFlowClient discovery fix (STP-05, STP-06)
- [ ] 10-03-PLAN.md — Agent CIBA handler + PAM sudo step-up wiring (STP-01, STP-07)

### Phase 11: Implementation Completion
**Goal**: All existing but unwired test assets run in CI; DPoP-bound token validation is verified end-to-end against Keycloak; cross-language DPoP interop tests are automated; the agent daemon has a lifecycle integration test
**Depends on**: Phase 10
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04
**Success Criteria** (what must be TRUE):
  1. `test_token_exchange.sh` runs as a CI job using `docker-compose.token-exchange.yaml` and validates DPoP cnf.jkt rebinding
  2. The `unix-oidc-test` Keycloak realm issues DPoP-bound access tokens (`cnf.jkt` present) and the PAM module validates the thumbprint match in a CI integration test
  3. `dpop-cross-language-tests/run-cross-language-tests.sh` runs in CI and validates Rust/Go/Python interop
  4. An integration test starts the agent daemon, sends IPC commands (Status, GetProof, Shutdown), and validates responses
**Plans:** 1/2 plans executed

Plans:
- [ ] 11-01-PLAN.md — Token exchange CI wiring + DPoP-bound token E2E validation (TEST-01, TEST-02)
- [ ] 11-02-PLAN.md — Cross-language DPoP interop CI job + agent daemon lifecycle test (TEST-03, TEST-04)

### Phase 12: Rigorous Integration Testing
**Goal**: New test infrastructure validates the critical paths that currently have zero integration coverage — CIBA backchannel, step-up IPC full flow, break-glass failover, and optionally FIDO2 authenticator simulation
**Depends on**: Phase 11
**Requirements**: INT-01, INT-02, INT-03, INT-04
**Success Criteria** (what must be TRUE):
  1. A CIBA-enabled Keycloak realm exists in CI; an integration test initiates a backchannel auth request, auto-approves via Admin API, polls for token, and validates the ACR claim
  2. An integration test exercises the full step-up IPC flow (PAM sends StepUp -> agent spawns CIBA poll -> agent returns StepUpPending -> PAM polls StepUpResult -> StepUpComplete) using wiremock-rs as the IdP
  3. With Keycloak stopped, a break-glass account can still authenticate via local PAM; OIDC login fails gracefully (no hang/crash); restarting Keycloak restores OIDC
  4. ACR validation is tested against live tokens from Keycloak with ACR LoA mapping configured
**Plans**: TBD

### Phase 13: Operational Hardening
**Goal**: The agent daemon ships with production-ready service integration, peer-authenticated IPC, configurable network and cache parameters, and structured observability
**Depends on**: Phase 9
**Requirements**: OPS-01, OPS-02, OPS-03, OPS-04, OPS-05, OPS-06, OPS-07, OPS-08, OPS-09, OPS-10, OPS-11, OPS-12, OPS-13
**Success Criteria** (what must be TRUE):
  1. The agent daemon can be installed and started via `systemctl --user enable --now unix-oidc-agent` on Ubuntu 22.04 and RHEL 9 without manual socket creation
  2. A process running as a different UID is rejected when it attempts to connect to the agent's IPC socket
  3. An operator can set `jwks_cache_ttl_secs = 600` in config and verify via structured logs that JWKS fetches occur at that interval
  4. A complete authentication flow (JWKS fetch → token validation → DPoP verify → user lookup) produces correlated tracing spans visible in a single trace
  5. The macOS agent daemon starts automatically at login via the provided launchd plist without manual configuration
**Plans:** 5/5 plans complete

Plans:
- [ ] 13-01-PLAN.md — Configurable timeouts (figment) + audit hostname fix (OPS-07, OPS-08, OPS-09, OPS-10, OPS-12)
- [ ] 13-02-PLAN.md — systemd service units + socket activation + sd-notify + graceful shutdown (OPS-01, OPS-02, OPS-04)
- [ ] 13-03-PLAN.md — IPC peer authentication + idle timeout (OPS-05, OPS-06)
- [ ] 13-04-PLAN.md — launchd plist template + install/uninstall subcommands (OPS-03)
- [ ] 13-05-PLAN.md — Tracing instrumentation + JSON output + GetProof logging (OPS-11, OPS-13)

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Memory Protection Hardening | v1.0 | 4/4 | Complete | 2026-03-10 |
| 2. Storage Backend Wiring | v1.0 | 3/3 | Complete | 2026-03-10 |
| 3. Hardware Signer Backends | v1.0 | 3/3 | Complete | 2026-03-10 |
| 4. Fix Hardware Signer Refresh Persistence | v1.0 | 1/1 | Complete | 2026-03-10 |
| 5. Audit Documentation Cleanup | v1.0 | 1/1 | Complete | 2026-03-10 |
| 6. PAM Panic Elimination + Security Mode Infrastructure | 3/3 | Complete   | 2026-03-10 | - |
| 7. DPoP Nonce Issuance | 2/2 | Complete   | 2026-03-10 | - |
| 8. Username Mapping + Group Policy + Break-Glass | 3/3 | Complete   | 2026-03-10 | - |
| 9. Token Introspection + Session Lifecycle + Token Refresh | 3/3 | Complete   | 2026-03-11 | - |
| 10. CIBA Step-Up + FIDO2 via ACR Delegation | 3/3 | Complete   | 2026-03-11 | - |
| 11. Implementation Completion | 1/2 | In Progress|  | - |
| 12. Rigorous Integration Testing | v2.0 | 0/? | Not started | - |
| 13. Operational Hardening | 5/5 | Complete   | 2026-03-11 | - |
