# Roadmap: unix-oidc

## Milestones

- ✅ **v1.0 Client-Side Key Protection Hardening** — Phases 1-5 (shipped 2026-03-10)
- ✅ **v2.0 Production Hardening & Enterprise Readiness** — Phases 6-17 (shipped 2026-03-13)
- 🚧 **v2.1 Integration Testing Infrastructure** — Phases 18-22 (in progress)

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

<details>
<summary>✅ v2.0 Production Hardening & Enterprise Readiness (Phases 6-17) — SHIPPED 2026-03-13</summary>

- [x] Phase 6: PAM Panic Elimination + Security Mode Infrastructure (3/3 plans) — completed 2026-03-10
- [x] Phase 7: DPoP Nonce Issuance (2/2 plans) — completed 2026-03-10
- [x] Phase 8: Username Mapping + Group Policy + Break-Glass (3/3 plans) — completed 2026-03-10
- [x] Phase 9: Token Introspection + Session Lifecycle + Token Refresh (3/3 plans) — completed 2026-03-11
- [x] Phase 10: CIBA Step-Up + FIDO2 via ACR Delegation (3/3 plans) — completed 2026-03-11
- [x] Phase 11: Implementation Completion (2/2 plans) — completed 2026-03-11
- [x] Phase 12: Rigorous Integration Testing — superseded by Phase 16
- [x] Phase 13: Operational Hardening (5/5 plans) — completed 2026-03-11
- [x] Phase 14: Critical Integration Bug Fixes (2/2 plans) — completed 2026-03-12
- [x] Phase 15: Phase 11 Verification + Traceability Fix (2/2 plans) — completed 2026-03-12
- [x] Phase 16: Rigorous Integration Testing (Gap Closure) (3/3 plans) — completed 2026-03-12
- [x] Phase 17: P2 Enhancements (3/3 plans) — completed 2026-03-13

Full details: see Phase Details section below (preserved for reference).

</details>

### 🚧 v2.1 Integration Testing Infrastructure (In Progress)

**Milestone Goal:** Full E2E integration tests with real OIDC signature verification and real IdP integration — no TEST_MODE bypasses anywhere in the critical path.

**Testing mandate:** Every phase must include watertight test coverage: happy path, negative/adversarial inputs (malformed tokens, replayed proofs, wrong issuers, forged claims), degraded mode (IdP unreachable, missing optional claims, clock skew), and observability (all auth events produce structured audit events).

- [x] **Phase 18: Blocker Fixes + E2E Infrastructure** - Fix four pre-existing bugs and stand up the real-signature compose stack (completed 2026-03-13)
- [x] **Phase 19: Playwright Device Flow Automation** - Automate Keycloak browser consent for headless CI (completed 2026-03-13)
- [ ] **Phase 20: Full SSH E2E Test + CI Integration** - Partial: token test exists but SSH→PAM chain, audit log verification, negative E2E tests, and CI job not yet wired
- [x] **Phase 21: Multi-IdP Configuration** - PAM module supports multiple issuers with per-issuer policy config (completed 2026-03-13)
- [x] **Phase 22: Entra ID Integration** - Azure Entra bearer-only integration with RS256 validation and UPN mapping (completed 2026-03-13)
- [ ] **Phase 23: Integration Gap Fixes** - Multi-issuer DPoP nonce consumption + Entra policy fixture test coverage (gap closure from v2.1 audit)

## Phase Details

### Phase 18: Blocker Fixes + E2E Infrastructure
**Goal**: All pre-existing bugs that prevent real-signature testing are fixed; the real-signature compose stack is running with correct issuer alignment, no TEST_MODE, and a verified agent binary
**Depends on**: Phase 17 (v2.0 complete)
**Requirements**: BFIX-01, BFIX-02, BFIX-03, BFIX-04, INFR-01, INFR-02, INFR-03, INFR-04
**Success Criteria** (what must be TRUE):
  1. Running `docker compose -f docker-compose.e2e.yaml up` brings Keycloak 26.4 to healthy state; a token acquired from within the compose network carries `iss: http://keycloak:8080/realms/unix-oidc` (verified via `jq -r '.iss'` on the decoded access token)
  2. `docker compose exec test-host-e2e unix-oidc-agent --version` exits 0; the binary is on PATH inside the test-host container
  3. The device flow token polling loop sends a fresh `DPoP:` proof header per poll iteration; a token acquired via device flow within the compose network contains a `cnf.jkt` claim (DPoP-bound, not plain bearer)
  4. `pam_sm_close_session` sends the `SessionClosed` IPC message with a trailing newline; the agent's `read_line` unblocks immediately instead of hanging until the 2-second timeout
  5. A sentinel CI step (`docker exec test-host-e2e env | grep UNIX_OIDC_TEST_MODE` exits non-zero) confirms TEST_MODE is absent from the real-signature test environment
**Plans**: N/A (implemented in single commit 9bfd4d3)

### Phase 19: Playwright Device Flow Automation
**Goal**: The Device Authorization Grant browser consent step is automated headlessly so CI can complete device flow without human interaction
**Depends on**: Phase 18
**Requirements**: PLAY-01, PLAY-02, PLAY-03
**Success Criteria** (what must be TRUE):
  1. Running `npx playwright test tests/device-flow.spec.ts` against a live Keycloak 26.4 instance navigates to the verification URI, submits credentials, and exits 0 after Keycloak confirms device activation — without any human interaction
  2. The Playwright spec and the shell token poll loop coordinate via a tmpfile: the shell writes the `verification_uri_complete`, Playwright polls for the file, navigates, and completes consent; the shell poll loop then receives the token
  3. The same spec runs unmodified on a GitHub Actions ubuntu-latest runner in headless mode without `--no-sandbox` flags (Playwright runs on the GHA host, not inside Docker)
**Plans**: N/A (implemented in single commit 9bfd4d3)

### Phase 20: Full SSH E2E Test + CI Integration
**Goal**: A complete SSH authentication chain — device flow token acquisition, agent serve, SSH with SSH_ASKPASS, PAM conversation, JWKS signature verification, session open — runs without TEST_MODE and is gated in CI
**Depends on**: Phase 18, Phase 19
**Requirements**: E2E-01, E2E-02, E2E-03, CI-01, CI-02
**Success Criteria** (what must be TRUE):
  1. `test/tests/test_keycloak_real_sig.sh` completes the full chain (agent login via device flow + Playwright → agent serve → `SSH_ASKPASS=unix-oidc-agent` → SSH → PAM validates real EC signature from Keycloak 26.4 JWKS → shell access granted) and exits 0
  2. The auth log inside the test-host container contains a structured audit event with `event_type=auth_success` and `issuer=http://keycloak:8080/realms/unix-oidc` for the successful authentication
  3. Negative tests confirm the security perimeter: a token signed with a wrong key is rejected (`Authentication failed`); a token from a wrong issuer is rejected; a replayed DPoP proof on the second SSH attempt is rejected
  4. The `keycloak-e2e` CI job in `.github/workflows/ci.yml` depends on `build-matrix`, restores the release artifact, starts the e2e stack, runs the SSH E2E test, and reports pass/fail on every push to main
**Plans**: Partial (E2E stubs exist, CI job and full SSH chain TBD)

### Phase 21: Multi-IdP Configuration
**Goal**: The PAM module supports multiple OIDC issuers simultaneously, each with independent DPoP enforcement, claim mapping, ACR mapping, and group mapping; unknown issuers are rejected; missing optional fields fall back safely
**Depends on**: Phase 18
**Requirements**: MIDP-01, MIDP-02, MIDP-03, MIDP-04, MIDP-05, MIDP-06, MIDP-07, MIDP-08
**Success Criteria** (what must be TRUE):
  1. A `policy.yaml` with two `issuers[]` entries (Keycloak and a second issuer) loads without error; tokens from either issuer authenticate successfully; a token from a third unlisted issuer is rejected with a logged "unknown issuer" error
  2. Setting `dpop_enforcement: strict` on one issuer and `dpop_enforcement: disabled` on another causes DPoP-bound tokens to be required only from the strict issuer; the disabled issuer accepts plain bearer tokens
  3. A user whose Keycloak `preferred_username` is `alice@corp.example` authenticates as local user `alice` when the issuer's claim mapping sets `strip_domain: true`; a second issuer with no strip_domain config uses the raw claim value unchanged
  4. The JWKS cache maintains independent entries keyed by issuer URL; fetching a JWKS for one issuer does not evict or overwrite the cache entry for another issuer
  5. An `issuers[]` entry that omits optional fields (no `acr_mapping`, no `group_mapping`) loads successfully with safe defaults and logs a WARN; authentication against that issuer still succeeds
**Plans:** 3/3 plans complete

Plans:
- [ ] 21-01-PLAN.md — IssuerConfig types + JWKS registry + config validation (MIDP-01, MIDP-02, MIDP-03, MIDP-04, MIDP-05, MIDP-08)
- [ ] 21-02-PLAN.md — Multi-issuer auth routing + JTI scoping + PAM wiring (MIDP-06, MIDP-07)
- [ ] 21-03-PLAN.md — Integration test suite + workspace regression gate (MIDP-01..08)

### Phase 22: Entra ID Integration
**Goal**: Tokens issued by Azure Entra ID (RS256, bearer-only, tenant-specific issuer, UPN claim) authenticate successfully through the PAM module; the integration test runs in CI gated on secrets
**Depends on**: Phase 20, Phase 21
**Requirements**: ENTR-01, ENTR-02, ENTR-03, ENTR-04, ENTR-05, CI-03
**Success Criteria** (what must be TRUE):
  1. OIDC discovery against the Entra tenant endpoint returns a valid JWKS URI; the PAM module fetches the JWKS and validates an RS256-signed Entra access token without error
  2. A user whose Entra `preferred_username` is `alice@corp.example` authenticates as local user `alice` when the Entra issuer config sets `strip_domain: true`; the full auth chain produces a structured audit event with the mapped username
  3. Bearer-only mode (no `cnf.jkt` assertion, `dpop_required: off` in the Entra issuer config) produces a successful authentication with a complete audit trail; no DPoP-related errors appear in the log
  4. The `entra-integration` CI job in `provider-tests.yml` runs only when `secrets.ENTRA_TENANT_ID` is available; it exits 0 on a successful auth and reports structured results; negative test confirms a token from a different tenant is rejected
**Plans:** 3/3 plans complete

Plans:
- [ ] 22-01-PLAN.md — expected_audience + allow_unsafe_identity_pipeline + Entra fixture + setup guide (ENTR-01, ENTR-03, ENTR-04)
- [ ] 22-02-PLAN.md — Entra live integration test suite (ENTR-02, ENTR-03, ENTR-04, ENTR-05)
- [ ] 22-03-PLAN.md — ROPC token script + CI job in provider-tests.yml (CI-03, ENTR-05)

### Phase 23: Integration Gap Fixes (Multi-Issuer Nonce + Entra Fixture)
**Goal**: Fix two cross-phase integration bugs found by v2.1 milestone audit: multi-issuer DPoP nonce consumption (security) and Entra policy fixture test coverage
**Depends on**: Phase 21, Phase 22
**Requirements**: MIDP-02 (integration fix), ENTR-01 (integration fix)
**Gap Closure:** Closes 2 integration gaps from v2.1 audit
**Success Criteria** (what must be TRUE):
  1. `apply_per_issuer_dpop()` calls `global_nonce_cache().consume()` for the multi-issuer path; a replayed DPoP proof in the multi-issuer auth flow is rejected even when its `iat`/`exp` and JTI are valid
  2. A non-`#[ignore]` integration test loads `policy-entra.yaml` via `PolicyConfig::load_from()` and validates deserialization; breaking the YAML structure causes a test failure
**Plans:** 1 plan

Plans:
- [ ] 23-01-PLAN.md — Multi-issuer DPoP nonce consumption fix + Entra fixture deserialization test (MIDP-02, ENTR-01)

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Memory Protection Hardening | v1.0 | 4/4 | Complete | 2026-03-10 |
| 2. Storage Backend Wiring | v1.0 | 3/3 | Complete | 2026-03-10 |
| 3. Hardware Signer Backends | v1.0 | 3/3 | Complete | 2026-03-10 |
| 4. Fix Hardware Signer Refresh Persistence | v1.0 | 1/1 | Complete | 2026-03-10 |
| 5. Audit Documentation Cleanup | v1.0 | 1/1 | Complete | 2026-03-10 |
| 6. PAM Panic Elimination + Security Mode Infrastructure | v2.0 | 3/3 | Complete | 2026-03-10 |
| 7. DPoP Nonce Issuance | v2.0 | 2/2 | Complete | 2026-03-10 |
| 8. Username Mapping + Group Policy + Break-Glass | v2.0 | 3/3 | Complete | 2026-03-10 |
| 9. Token Introspection + Session Lifecycle + Token Refresh | v2.0 | 3/3 | Complete | 2026-03-11 |
| 10. CIBA Step-Up + FIDO2 via ACR Delegation | v2.0 | 3/3 | Complete | 2026-03-11 |
| 11. Implementation Completion | v2.0 | 2/2 | Complete | 2026-03-11 |
| 12. Rigorous Integration Testing | v2.0 | 0/? | Superseded by Phase 16 | - |
| 13. Operational Hardening | v2.0 | 5/5 | Complete | 2026-03-11 |
| 14. Critical Integration Bug Fixes | v2.0 | 2/2 | Complete | 2026-03-12 |
| 15. Phase 11 Verification + Traceability Fix | v2.0 | 2/2 | Complete | 2026-03-12 |
| 16. Rigorous Integration Testing (Gap Closure) | v2.0 | 3/3 | Complete | 2026-03-12 |
| 17. P2 Enhancements | v2.0 | 3/3 | Complete | 2026-03-13 |
| 18. Blocker Fixes + E2E Infrastructure | v2.1 | N/A (single commit) | Complete | 2026-03-13 |
| 19. Playwright Device Flow Automation | v2.1 | N/A (single commit) | Complete | 2026-03-13 |
| 20. Full SSH E2E Test + CI Integration | v2.1 | 0/? | Partial (E2E stubs, no CI job) | - |
| 21. Multi-IdP Configuration | v2.1 | 3/3 | Complete | 2026-03-13 |
| 22. Entra ID Integration | v2.1 | 3/3 | Complete | 2026-03-13 |
| 23. Integration Gap Fixes | v2.1 | 0/1 | Planned | - |

---

## v2.0 Phase Details (Reference — Shipped 2026-03-13)

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
- [x] 06-01-PLAN.md — parking_lot migration + panic elimination (SEC-01, SEC-07)
- [x] 06-02-PLAN.md — SecurityModes/CacheConfig types + figment config loading (SEC-03, SEC-04)
- [x] 06-03-PLAN.md — Wire enforcement modes into validation + deny lint activation (SEC-02, SEC-03)

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
- [x] 07-01-PLAN.md — DPoP nonce cache (moka-backed), nonce generation, CacheConfig extension, enforcement mode threading (SEC-05, SEC-06)
- [x] 07-02-PLAN.md — Two-round PAM conversation for nonce challenge/response + human verification (SEC-05)

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
- [x] 09-01-PLAN.md — Config types, session record module, audit events, PAM open/close_session with putenv/getenv correlation (SES-01, SES-02, SES-03)
- [x] 09-02-PLAN.md — RFC 7662 introspection client + moka cache, wired into authenticate() (SES-05, SES-06)
- [x] 09-03-PLAN.md — Agent IPC SessionClosed, auto-refresh background task, RFC 7009 revocation, credential cleanup (SES-04, SES-07, SES-08)

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
- [x] 10-01-PLAN.md — OIDC discovery extension + CIBA types/client + ACR validation (STP-02, STP-03, STP-04)
- [x] 10-02-PLAN.md — Step-up IPC protocol messages + DeviceFlowClient discovery fix (STP-05, STP-06)
- [x] 10-03-PLAN.md — Agent CIBA handler + PAM sudo step-up wiring (STP-01, STP-07)

### Phase 11: Implementation Completion
**Goal**: All existing but unwired test assets run in CI; DPoP-bound token validation is verified end-to-end against Keycloak; cross-language DPoP interop tests are automated; the agent daemon has a lifecycle integration test
**Depends on**: Phase 10
**Requirements**: TEST-01, TEST-02, TEST-03, TEST-04
**Success Criteria** (what must be TRUE):
  1. `test_token_exchange.sh` runs as a CI job using `docker-compose.token-exchange.yaml` and validates DPoP cnf.jkt rebinding
  2. The `unix-oidc-test` Keycloak realm issues DPoP-bound access tokens (`cnf.jkt` present) and the PAM module validates the thumbprint match in a CI integration test
  3. `dpop-cross-language-tests/run-cross-language-tests.sh` runs in CI and validates Rust/Go/Python interop
  4. An integration test starts the agent daemon, sends IPC commands (Status, GetProof, Shutdown), and validates responses
**Plans:** 2/2 plans complete

Plans:
- [x] 11-01-PLAN.md — Token exchange CI wiring + DPoP-bound token E2E validation (TEST-01, TEST-02)
- [x] 11-02-PLAN.md — Cross-language DPoP interop CI job + agent daemon lifecycle test (TEST-03, TEST-04)

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
- [x] 13-01-PLAN.md — Configurable timeouts (figment) + audit hostname fix (OPS-07, OPS-08, OPS-09, OPS-10, OPS-12)
- [x] 13-02-PLAN.md — systemd service units + socket activation + sd-notify + graceful shutdown (OPS-01, OPS-02, OPS-04)
- [x] 13-03-PLAN.md — IPC peer authentication + idle timeout (OPS-05, OPS-06)
- [x] 13-04-PLAN.md — launchd plist template + install/uninstall subcommands (OPS-03)
- [x] 13-05-PLAN.md — Tracing instrumentation + JSON output + GetProof logging (OPS-11, OPS-13)

### Phase 14: Critical Integration Bug Fixes
**Goal**: Fix the two critical cross-phase integration bugs that break E2E flows (SessionClosed IPC newline, SSH DPoP nonce handler) and wire clock skew config to PAM module
**Depends on**: Phase 13
**Requirements**: SEC-05 (integration fix), SES-04, SES-07, SES-08 (integration fix), OPS-09 (PAM-side wiring)
**Gap Closure:** Closes integration and flow gaps from v2.0 audit
**Success Criteria** (what must be TRUE):
  1. `pam_sm_close_session` sends SessionClosed IPC with trailing `\n`; agent's `cleanup_session()` fires within 100ms (not after 2s timeout)
  2. SSH login with `dpop_required=Strict` completes successfully — the SSH client bridges the PAM `DPOP_NONCE:` prompt to the agent's `GetProof` IPC
  3. `clock_skew_future_secs` and `clock_skew_staleness_secs` from operator config are read by the PAM module's `ValidationConfig`, not hardcoded
  4. socket.rs:1288 unwrap() replaced with safe pattern; `DPoPAuthConfig::from_env()` dead code removed or wired
**Plans:** 2/2 plans complete

Plans:
- [x] 14-01-PLAN.md — SessionClosed IPC newline fix + clock skew config wiring + socket.rs unwrap cleanup (SES-04, SES-07, SES-08, OPS-09)
- [x] 14-02-PLAN.md — SSH_ASKPASS nonce handler subcommand (SEC-05)

### Phase 15: Phase 11 Verification + Traceability Fix
**Goal**: Verify Phase 11 work is genuinely complete, update traceability, and close the verification gap
**Depends on**: Phase 14
**Requirements**: TEST-01, TEST-02
**Gap Closure:** Closes verification gaps from v2.0 audit
**Success Criteria** (what must be TRUE):
  1. TEST-01 and TEST-02 are verified: test scripts exist, run, and pass (or are confirmed incomplete and re-planned)
  2. REQUIREMENTS.md traceability shows correct status for TEST-01 and TEST-02
  3. Phase 11 has a VERIFICATION.md
  4. ROADMAP.md Phase 11 status reflects reality
**Plans:** 2/2 plans complete

Plans:
- [x] 15-01-PLAN.md — Local + CI verification of TEST-01/TEST-02 (TEST-01, TEST-02)
- [x] 15-02-PLAN.md — VERIFICATION.md + traceability audit (TEST-01, TEST-02)

### Phase 16: Rigorous Integration Testing (Gap Closure)
**Goal**: Build the integration test infrastructure that Phase 12 was meant to deliver — CIBA live IdP, step-up IPC full-flow, break-glass failover, and ACR validation
**Depends on**: Phase 14, Phase 15
**Requirements**: INT-01, INT-02, INT-03, INT-04
**Gap Closure:** Closes all orphaned Phase 12 requirements from v2.0 audit
**Success Criteria** (what must be TRUE):
  1. A CIBA-enabled Keycloak realm exists in CI; an integration test initiates a backchannel auth request, auto-approves via Admin API, polls for token, and validates the ACR claim
  2. An integration test exercises the full step-up IPC flow (PAM sends StepUp -> agent spawns CIBA poll -> agent returns StepUpPending -> PAM polls StepUpResult -> StepUpComplete) using wiremock-rs as the IdP
  3. With Keycloak stopped, a break-glass account can still authenticate via local PAM; OIDC login fails gracefully (no hang/crash); restarting Keycloak restores OIDC
  4. ACR validation is tested against live tokens from Keycloak with ACR LoA mapping configured
**Plans:** 3/3 plans complete

Plans:
- [x] 16-01-PLAN.md — CIBA-enabled Keycloak realm + docker-compose + CI job + ACR validation (INT-01, INT-04)
- [x] 16-02-PLAN.md — Step-up IPC full-flow integration test with wiremock-rs (INT-02)
- [x] 16-03-PLAN.md — Break-glass fallback + OIDC failure graceful degradation (INT-03)

### Phase 17: P2 Enhancements: structured audit events, sudo session linking, session expiry sweep, mlock ML-DSA keys
**Goal:** Agent daemon emits structured audit events for SIEM ingestion, sudo step-up sessions link to parent SSH sessions for end-to-end audit correlation, orphaned session records are automatically reaped, and ML-DSA key material is mlock'd to prevent swap exposure
**Requirements**: OBS-1, OBS-3, SES-09, MEM-07
**Depends on:** Phase 16
**Success Criteria** (what must be TRUE):
  1. Agent daemon emits `tracing::info!(target: "unix_oidc_audit", ...)` events at five event points (auth, refresh, session close, step-up initiate, step-up complete/timeout) with event_type, username, outcome fields
  2. StepUp IPC carries optional parent_session_id from the SSH session; StepUpComplete echoes it back; step-up audit events include both sudo and parent session IDs
  3. A background sweep task removes expired session records from /run/unix-oidc/sessions/ at a configurable interval (default 5 minutes); corrupt files are removed with a warning
  4. HybridPqcSigner::generate() returns Box<Self> with mlock applied to the allocation; ML-DSA key bytes are verified to zero on drop
**Plans:** 3/3 plans complete

Plans:
- [x] 17-01-PLAN.md — mlock ML-DSA key material in HybridPqcSigner (MEM-07)
- [x] 17-02-PLAN.md — Session expiry sweep background task + config (SES-09)
- [x] 17-03-PLAN.md — Structured audit events + sudo session linking (OBS-1, OBS-3)
