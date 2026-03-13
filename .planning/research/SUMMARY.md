# Project Research Summary

**Project:** unix-oidc v2.1 Integration Testing Infrastructure
**Domain:** E2E integration testing — real OIDC IdPs, cryptographic DPoP validation, CI automation
**Researched:** 2026-03-13
**Confidence:** HIGH (codebase inspected directly; stack versions API-verified; Entra constraints confirmed via Microsoft Learn)

---

## Executive Summary

The unix-oidc v2.1 milestone is a testing infrastructure upgrade, not a product feature milestone. The production PAM module and agent daemon are correct. The problem is that CI has been running with `UNIX_OIDC_TEST_MODE=true` set globally in `docker-compose.test.yaml`, which completely bypasses signature verification, DPoP proof validation, and issuer enforcement. Every integration test has been passing green against a code path that is explicitly documented as "bypass all cryptographic verification." The v2.1 goal is to eliminate that bypass and replace it with a real end-to-end test: device flow token acquisition with DPoP binding, automated browser consent, real Keycloak JWT signature verification, and PAM session establishment — without TEST_MODE anywhere in the path.

Three pre-existing bugs block all real-signature testing and must be fixed before any other work in this milestone can produce meaningful results. The Keycloak issuer URL is misaligned between the container network and PAM configuration (`KC_HOSTNAME=localhost` → `iss: http://localhost:8080/...` vs. PAM `OIDC_ISSUER=http://keycloak:8080/...`), causing every real-signature test to fail at issuer validation before signature verification is even reached. The unix-oidc-agent binary is not installed in the test-host container, so the SSH_ASKPASS token delivery mechanism is unavailable. The agent's device flow token polling loop sends no `DPoP:` header, so Keycloak — configured with `dpop.bound.access.tokens=true` — either rejects the token request or issues a plain bearer token without `cnf.jkt`, making DPoP end-to-end validation impossible. These three fixes are independent of each other and can be developed in parallel, but all three are hard blockers.

The recommended architecture introduces a parallel compose stack (`docker-compose.e2e.yaml`) that aligns the issuer URL via `KC_HOSTNAME=keycloak`, a derived test-host image with the agent binary installed and no TEST_MODE, and a proper `@playwright/test` spec for headless browser automation in GitHub Actions. Keycloak must be upgraded from 24.0 to 26.4: DPoP was a preview feature in 24.x with undefined `cnf.jkt` behavior in device flow — this version is why existing DPoP tests have been unreliable. Azure Entra ID integration is explicitly bearer-only scope for this milestone because Entra does not implement RFC 9449 DPoP (it uses Microsoft's proprietary SHR mechanism); the PAM config fixture for Entra tests must have `dpop_required` set to `off`.

---

## Key Findings

### Recommended Stack

The v1.0/v2.0 stack (Rust, tokio, p256, keyring, tracing, Docker Compose) is unchanged and validated. The v2.1 additions are narrowly scoped to testing infrastructure. The most consequential upgrade is Keycloak from 24.0 to 26.4: DPoP was announced as GA in Keycloak 26.4 (released September 2025, announcement October 2025). The currently pinned `quay.io/keycloak/keycloak:24.0` has DPoP as an unfinished preview with undefined `cnf.jkt` behavior in device flow — meaning existing DPoP tests have been running against an IdP that does not reliably produce DPoP-bound tokens.

**Core new technologies:**
- **Keycloak 26.4** (`quay.io/keycloak/keycloak:26.4`): first GA DPoP release; required for reliable `cnf.jkt` in device flow access tokens; upgrade from 24.0 is mandatory for any meaningful DPoP test
- **`@playwright/test` 1.58.2**: headless Chromium for Device Authorization Grant (RFC 8628) browser automation in CI; replaces the current interactive MCP session pattern which does not work in GitHub Actions; existing `demo/` directory already has Playwright installed at 1.48
- **Node.js 24.x LTS**: Playwright runtime; use `node-version: lts/*` in GitHub Actions
- **`testcontainers` 0.27.1** (Rust): per-test Keycloak container lifecycle inside `#[tokio::test]`; enables isolated Rust integration tests gated with `#[ignore = "requires Docker"]`
- **`reqwest` 0.13.2**: workspace-wide upgrade from 0.11; required for testcontainers async integration; audit all JWKS client `redirect::Policy::none()` and TLS configurations during upgrade

**What NOT to use:**
- `UNIX_OIDC_TEST_MODE=true` in any new test (defeats the entire purpose of this milestone)
- Keycloak 24.0 for DPoP tests (preview feature, `cnf.jkt` behavior undefined in device flow)
- ROPC (`grant_type=password`) as a device flow substitute (deprecated in OAuth 2.1, bypasses MFA, will break as IdPs disable it)
- Mock OIDC servers as primary integration backend (cannot reproduce real DPoP token shapes, Keycloak quirks, or RS256 key infrastructure)

### Expected Features

Research identifies six P1 features that must land to close the v2.1 milestone, and four P2/P3 features for subsequent work. Every P1 item addresses a current gap that either produces false green CI results or blocks the real-signature test path entirely.

**Must have (P1 — blocks milestone closure):**
- Issuer URL fix (`KC_HOSTNAME=keycloak` in new compose stack) — every real-signature test fails at issuer validation without this
- Agent binary installed in test-host container — SSH_ASKPASS token delivery mechanism is unavailable without it
- DPoP header added to device flow token poll in `run_login()` — Keycloak rejects or issues plain bearer without it
- `UNIX_OIDC_TEST_MODE` removed from `docker-compose.test.yaml` test-host environment — current source of false green
- Playwright device flow spec (`device-flow.spec.ts`) wired into CI — replaces interactive MCP session instructions that do not work in GitHub Actions
- Full SSH E2E test without TEST_MODE (`test_keycloak_real_sig.sh`) — the milestone deliverable

**Should have (P2 — enterprise value, this milestone if time permits):**
- Entra ID integration tests (gated on CI secrets, bearer-only scope, tenant-specific issuer, `dpop_required: off`)
- Entra UPN claim mapping validation (`strip_domain: true` end-to-end)
- Negative rejection test suite (expired token, wrong issuer, missing `cnf.jkt`)

**Defer (v2.2+):**
- Multi-IdP CI matrix (Keycloak + Entra parallel job) — blocked on Entra integration being stable first
- Google Cloud Identity, Okta integration tests — community testing priority
- RFC 8693 token exchange for service delegation

### Architecture Approach

The v2.1 architecture introduces a fourth compose stack isolated from the three existing stacks. The existing `docker-compose.test.yaml` (Keycloak 24, TEST_MODE) is left completely untouched — contributors relying on the TEST_MODE path are unaffected. A new `docker-compose.e2e.yaml` provides an aligned-issuer Keycloak 26.4 instance with `KC_HOSTNAME=keycloak`, a derived `Dockerfile.test-host-e2e` with the agent binary installed and no TEST_MODE, and the same OpenLDAP/SSSD user directory. Playwright runs on the GitHub Actions host directly (not inside Docker) to avoid Chromium sandbox failures in container environments. The agent login step runs via `docker compose exec` inside the compose network so Docker DNS resolves `keycloak` correctly for the device flow token endpoint URL, which must match the `htu` claim in the DPoP proof.

**Major components:**
1. `docker-compose.e2e.yaml` — new real-signature stack; Keycloak 26.4, `KC_HOSTNAME=keycloak`, no TEST_MODE, port 9000 exposed for `/health/ready`
2. `Dockerfile.test-host-e2e` — derived from existing test-host; installs agent binary from volume mount (`./target/release:/opt/unix-oidc:ro`)
3. `test/e2e/playwright/` — `@playwright/test` spec for headless device flow consent; coordinates with shell poll loop via tmpfile
4. `unix-oidc-agent/src/main.rs` `run_login()` — one location (lines 842-857) to add `DPoP:` header inside the poll loop; proof must be generated fresh per iteration (RFC 9449 §4.2 JTI uniqueness)
5. `pam-unix-oidc/src/lib.rs` `notify_agent_session_closed()` — one-line fix: append `\n` to IPC message so agent's `BufReader::read_line()` unblocks
6. `.github/workflows/ci.yml` `keycloak-e2e` job — downloads `build-matrix` artifact (avoids fourth parallel build), starts e2e stack, runs SSH E2E test

### Critical Pitfalls

1. **TEST_MODE contamination produces false green** — If `UNIX_OIDC_TEST_MODE=true` propagates into the real-signature CI job (e.g., from a copy-pasted compose file), the PAM module bypasses all crypto and tests pass trivially. Warning sign: real-signature test passes in under 2 seconds, or passes with an obviously forged token. Prevention: separate compose file with the variable absent; sentinel assertion at the top of every real-sig test script (`docker exec test-host env | grep -c UNIX_OIDC_TEST_MODE && exit 1`).

2. **Keycloak issuer URL mismatch** — `KC_HOSTNAME=localhost` in the existing stack causes tokens to carry `iss: http://localhost:8080/...` while PAM expects `http://keycloak:8080/...`. OpenID Connect Core 1.0 §3.1.3.7 requires exact string match. The error message "invalid issuer" looks like a PAM config problem, not a Keycloak hostname problem. `KC_HOSTNAME_STRICT=false` does not help — it relaxes redirect URI checking, not the issuer field. Prevention: use a dedicated compose stack with `KC_HOSTNAME=keycloak`; add `127.0.0.1 keycloak` to CI runner `/etc/hosts`; do not modify the existing stack.

3. **Agent missing DPoP header in device flow token poll** — `run_login()` poll loop (lines 842-857) sends no `DPoP:` header. RFC 9449 §4.2 and `draft-parecki-oauth-dpop-device-flow` require a fresh proof per token request. Keycloak with `dpop.bound.access.tokens=true` either rejects the request (`{"error":"invalid_request"}`) or issues a plain bearer token without `cnf.jkt`. Either way, the DPoP validation path is never exercised. Proof must be generated inside the loop — generating once before the loop and reusing it causes RFC 9449 JTI replay rejection on the second poll attempt. Prevention: fix `run_login()` before enabling DPoP enforcement in the test realm.

4. **Entra ID lacks RFC 9449 DPoP** — Entra ID implements Signed HTTP Request (SHR), not RFC 9449. No `cnf.jkt` claim is emitted. Any test asserting DPoP binding for Entra tokens will always fail. Setting `dpop_required=strict` in the Entra test fixture causes 100% rejection. This is a Microsoft platform constraint, not a PAM module bug. Prevention: design Entra integration tests for bearer-only flows; set `dpop_required: off` in the Entra PAM config fixture; document explicitly.

5. **Keycloak TCP health check races past realm import** — Port 8080 opens before `--import-realm` finishes. `wait-for-healthy.sh` exits 0, CI proceeds, and the OIDC discovery endpoint returns 404 for 10-30 seconds. Tests fail with confusing "Realm does not exist" curl errors; the job flakes intermittently and succeeds on re-run. Prevention: change health check to `curl -sf http://localhost:9000/health/ready`; expose port 9000; set `start_period: 60s`.

---

## Implications for Roadmap

Research resolves to a four-phase sequential structure plus one optional parallel phase, all driven by hard dependencies. Phases 1-3 are infrastructure and prerequisite fixes. Phase 4 is the first phase that produces demonstrably new test coverage. Phase 5 (Entra ID) is independent of Phase 4 and can overlap.

### Phase 1: Blocker Fixes

**Rationale:** Three independent bugs each prevent any real-signature test from producing a meaningful result. Until all three are fixed, even a correctly designed E2E test will fail at the first validation step. These fixes are the entire prerequisite for everything else in the milestone. They are independent and can be developed in parallel within the phase.

**Delivers:**
- `docker-compose.e2e.yaml` with Keycloak 26.4, `KC_HOSTNAME=keycloak`, port 9000 exposed
- `test/fixtures/keycloak/e2e-realm.json` with `deviceAuthorizationGrantEnabled: true` (boolean, not string attribute)
- Agent binary installed in `test/docker/entrypoint.sh` (copy from volume mount to `/usr/local/bin/unix-oidc-agent`)
- DPoP header added to device flow poll inside the loop in `unix-oidc-agent/src/main.rs`
- `notify_agent_session_closed()` newline fix in `pam-unix-oidc/src/lib.rs`
- Keycloak health check upgraded from TCP to `/health/ready` endpoint with `start_period: 60s`
- `UNIX_OIDC_TEST_MODE` removed from `test-host` service in `docker-compose.test.yaml`; sentinel assertion wired

**Addresses:** Pitfalls 1-3, 5, 6 (issuer mismatch, missing DPoP header, health check race, TEST_MODE contamination)

**Avoids:** Building Playwright automation or the SSH E2E test before the infrastructure is correct; both would fail for reasons unrelated to the test code itself.

### Phase 2: E2E Infrastructure Validation

**Rationale:** After Phase 1 fixes, the compose stack must be verified to be internally consistent before Playwright and the SSH E2E test are built on top of it. Discovering an infrastructure gap mid-Playwright implementation wastes effort on a problem that belongs to the infrastructure layer.

**Delivers:**
- `docker-compose.e2e.yaml up` confirmed healthy; Keycloak tokens carry `iss: http://keycloak:8080/...` (verified via `jq -r '.iss'` on decoded token)
- `test-host-e2e` container confirms `unix-oidc-agent --version` responds correctly
- Agent acquires token from within the compose network via `docker compose exec` — token response contains `cnf.jkt` (DPoP-bound, not plain bearer)
- Sentinel assertion CI step confirmed working (fails if `UNIX_OIDC_TEST_MODE` is set)
- `Dockerfile.test-host-e2e` derived from existing test-host; no TEST_MODE in environment

**Addresses:** Pitfall 2 (establishes SSH_ASKPASS as the mandatory token injection path — PAM conv buffer is ~512 bytes and cannot carry a ~1400-byte JWT)

### Phase 3: Playwright Device Flow Automation

**Rationale:** The Device Authorization Grant (RFC 8628) requires browser consent. Playwright is the only way to automate this step in headless CI. The current `run-e2e-tests.sh` emits structured text instructions for Claude Code's interactive MCP session — this pattern does not work in GitHub Actions where no process interprets stdout. This phase produces a standalone Playwright spec that completes Keycloak consent autonomously.

**Delivers:**
- `test/e2e/playwright/package.json`, `playwright.config.ts`, `tests/device-flow.spec.ts`
- Tmpfile coordination: shell script writes `verification_uri_complete`, Playwright polls for file, navigates, completes consent, exits 0 after Keycloak "device activated" confirmation
- GitHub Actions step sequence: npm ci → `npx playwright install chromium --with-deps --only-shell` → run spec concurrently with shell poll loop
- Playwright runs on GHA host (not inside Docker container) — avoids Chromium sandbox failures inside containers

**Addresses:** Pitfall 7 (Playwright Chromium sandbox — host execution avoids `--no-sandbox` requirement)

**Uses:** `@playwright/test` 1.58.2, Node.js 24.x LTS, headless Chromium only

### Phase 4: Full SSH E2E Test and CI Job

**Rationale:** With Phases 1-3 complete, all prerequisites exist for the milestone deliverable: a complete SSH authentication chain exercised without TEST_MODE. This phase is the actual v2.1 closure criterion.

**Delivers:**
- `test/tests/test_keycloak_real_sig.sh`: agent login (device flow + Playwright) → agent serve → `SSH_ASKPASS=unix-oidc-agent` → SSH → PAM validates real EC signature → session opens
- PAM log confirms "Authentication successful" with Keycloak real key, not TEST_MODE bypass
- `keycloak-e2e` CI job in `.github/workflows/ci.yml`: `needs: [check, build-matrix]`; restores artifact; starts e2e stack; runs test
- Negative test: wrong-issuer token rejected — confirms acceptance test is not vacuously true
- `"Looks Done But Isn't"` checklist from PITFALLS.md verified item by item

**Addresses:** Core milestone goal — exercises DPoP binding, JWKS verification, issuer validation, and session establishment as a single authenticated chain

### Phase 5: Entra ID Integration (P2 — can overlap with Phase 4)

**Rationale:** Entra ID integration has constraints that require careful fixture design (no DPoP, tenant-specific issuer, RS256 not ES256, no `verification_uri_complete`). It is gated on external secrets and matches the existing Auth0/Google pattern in `provider-tests.yml`. It is independent of Phase 4 and can be developed in parallel.

**Delivers:**
- `test/tests/test_entra_integration.sh`: OIDC discovery + JWKS fetch + RS256 token signature verification + `preferred_username` UPN claim mapping
- `entra-integration` job in `provider-tests.yml` (gated on `secrets.ENTRA_TENANT_ID`)
- Entra-specific PAM config fixture: `dpop_required: off`, tenant-specific issuer (`/{tenant-id}/v2.0`), `strip_domain: true`

**Addresses:** Pitfalls 4, 8 (Entra DPoP absence and tenant-specific issuer requirements)

**Constraint:** Explicitly bearer-only; zero assertions on `cnf.jkt` or `token_type: DPoP` for Entra tokens. Entra DPoP absence is a Microsoft platform constraint, not a bug.

### Phase Ordering Rationale

- Phase 1 must precede everything because all three bugs it fixes are independent prerequisite conditions. A test built before all three are fixed will produce misleading failure signals at infrastructure boundaries.
- Phase 2 must precede Phase 3 because Playwright depends on the agent login succeeding inside the compose network, which depends on the DPoP header fix and issuer alignment from Phase 1.
- Phase 3 must precede Phase 4 because the SSH E2E test requires automated browser consent; without Playwright, device flow waits indefinitely for a human to complete the browser step.
- Phase 5 is independent of Phase 4 and can run in parallel. The Entra test harness pattern mirrors the Keycloak pattern; doing Phase 4 first means the pattern is already understood.

### Research Flags

**Phases needing no additional research (patterns fully specified in research files):**
- Phase 1: All three bugs identified with file paths and line numbers; fixes are specified with code snippets
- Phase 2: Compose configuration patterns derived directly from existing token-exchange and CIBA stacks
- Phase 3: Playwright device flow pattern fully specified in ARCHITECTURE.md including TypeScript spec skeleton and GHA YAML
- Phase 4: SSH E2E test sequence specified in ARCHITECTURE.md Data Flow section with exact command sequence

**Phases that may need targeted verification during implementation:**
- Phase 1 (realm JSON): The e2e-realm.json must set `deviceAuthorizationGrantEnabled: true` as a boolean field. In Keycloak 26.x the boolean field may take precedence over the string attribute `oauth2.device.authorization.grant.enabled: "true"` — verify against the 26.4 Admin REST API before assuming the existing realm JSON imports cleanly.
- Phase 3 (Playwright selectors): The TypeScript spec uses `#username`, `#password`, `[type=submit]` selectors. Verify against the actual Keycloak 26.4 login page HTML — Keycloak changed login form attributes between 24 and 26.
- Phase 5 (Entra app registration): The "Allow public client flows" toggle location in Azure portal may differ from what documentation shows; verify against live portal before writing token acquisition assertions.

---

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | Keycloak 26.4 DPoP GA confirmed via official release announcement; all Rust crate versions API-verified on crates.io; Playwright version verified on npm; reqwest 0.13.2 breaking changes documented |
| Features | HIGH | Feature gaps verified via direct codebase inspection of test scripts, Dockerfile, and compose files; three blocking bugs confirmed in `.planning/v2.0-MILESTONE-AUDIT.md`; Entra DPoP absence confirmed via Microsoft Learn (updated 2025-08-14) |
| Architecture | HIGH | All component responsibilities derived from live codebase with file paths and line numbers; GitHub Actions job graph inspected directly from `.github/workflows/ci.yml`; compose patterns traced from existing token-exchange and CIBA stacks |
| Pitfalls | HIGH | Critical pitfalls verified against live code (TCP health check at compose level, missing DPoP header at specific lines, TEST_MODE env var location); issuer mismatch confirmed by reading both compose file and PAM config; Entra DPoP absence confirmed against Microsoft Learn primary documentation |

**Overall confidence:** HIGH

### Gaps to Address

- **Keycloak 26.4 realm JSON import behavior**: The existing realm JSON sets `dpop.bound.access.tokens: true` as a client attribute string and `deviceAuthorizationGrantEnabled: false` as a boolean (confirmed bug). The new e2e-realm.json must set `deviceAuthorizationGrantEnabled: true` as a boolean — verify this is sufficient for device flow without additional client grant configuration on Keycloak 26.x.

- **reqwest 0.11 → 0.13.2 workspace upgrade scope**: This touches all HTTP client code across the workspace. The JWKS client's `redirect::Policy::none()` and production timeout configurations must be audited and confirmed correct after upgrade. Switch TLS backend from `native-tls` to `rustls-tls` for PAM module builds.

- **Playwright Keycloak 26.x login form selectors**: The spec skeleton uses `#username`, `#password`, `[type=submit]`, and `[name=accept]`. These must be verified against the actual Keycloak 26.4 login and device-activated pages before CI relies on them.

- **Entra ID `preferred_username` in client credentials tokens**: Client credentials tokens may not carry `preferred_username`. If the Entra integration test needs to validate claim mapping, a real user and device flow completion may be required rather than client credentials. Resolve during Phase 5 by checking token claims against a test tenant before writing assertions.

---

## Sources

### Primary (HIGH confidence)
- Keycloak 26.4 DPoP GA announcement — https://www.keycloak.org/2025/10/dpop-support-26-4
- Keycloak 26.4.0 release notes — https://www.keycloak.org/2025/09/keycloak-2640-released
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://datatracker.ietf.org/doc/html/rfc9449
- RFC 8628 — OAuth 2.0 Device Authorization Grant: https://datatracker.ietf.org/doc/html/rfc8628
- OpenID Connect Core 1.0 §3.1.3.7 — exact issuer match: https://openid.net/specs/openid-connect-core-1_0.html
- Microsoft Entra ID — Access token Proof-of-Possession (SHR, not RFC 9449): https://learn.microsoft.com/en-us/entra/msal/javascript/browser/access-token-proof-of-possession (updated 2025-08-14)
- Microsoft Entra ID — Device Code Flow (`verification_uri_complete` not supported): https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
- Microsoft Entra ID — OIDC protocol (issuer URL format, JWKS endpoint, RS256): https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc
- Playwright CI documentation: https://playwright.dev/docs/ci-github-actions
- `testcontainers` 0.27.1 — crates.io API verified
- `reqwest` 0.13.2 — crates.io API verified
- Node.js 24.x LTS — nodejs.org dist/index.json verified
- draft-parecki-oauth-dpop-device-flow: https://drafts.aaronpk.com/oauth-dpop-device-flow/draft-parecki-oauth-dpop-device-flow.html

### Primary — Codebase Direct Inspection (HIGH confidence)
- `unix-oidc-agent/src/main.rs` lines 842-857 — DPoP header absent from poll POST confirmed
- `pam-unix-oidc/src/lib.rs` lines 772-775 — PAM conv buffer ~512 byte limit documented
- `docker-compose.test.yaml` — `KC_HOSTNAME=localhost`, `UNIX_OIDC_TEST_MODE: "true"`, TCP-only health check confirmed
- `test/tests/test_ssh_oidc_valid.sh` — `UNIX_OIDC_TEST_MODE=true` confirmed
- `test/fixtures/keycloak/unix-oidc-test-realm.json` — `deviceAuthorizationGrantEnabled: false` (bug) confirmed
- `.planning/v2.0-MILESTONE-AUDIT.md` — three blocking bugs authoritative source
- `.github/workflows/ci.yml` — job graph, artifact upload pattern inspected

### Secondary (MEDIUM confidence)
- Keycloak device flow design spec — https://github.com/keycloak/keycloak-community/blob/main/design/oauth2-device-authorization-grant.md
- Playwright sandbox issue in containers — https://github.com/microsoft/playwright/issues/1977
- MSAL-JS DPoP issue (2023, unresolved) — https://github.com/AzureAD/microsoft-authentication-library-for-js/issues/5979 (supports Entra DPoP absence finding but is unresolved; the Microsoft Learn primary source is the authoritative signal)

---

*Research completed: 2026-03-13*
*Ready for roadmap: yes*
