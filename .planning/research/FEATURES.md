# Feature Research: v2.1 E2E Integration Testing

**Domain:** E2E integration testing infrastructure — OIDC PAM module with real IdPs, no TEST_MODE
**Researched:** 2026-03-13
**Confidence:** HIGH for Keycloak/device-flow patterns (codebase examined directly); MEDIUM-HIGH for Entra ID (verified against official Microsoft Learn docs 2025-2026)

> **Scope note:** This file covers features NEW to the v2.1 milestone only — real-signature E2E
> testing, device flow automation, and Entra ID integration. Features already shipped (PAM module
> validation logic, agent daemon, DPoP proof generation, existing shell test suite, docker-compose
> environment) are not re-catalogued. See `FEATURES.md` revision dated 2026-03-10 for v2.0 features.

---

## Existing Test Infrastructure (Do Not Rebuild)

Direct codebase inspection identified these as already present and working.

| Existing Asset | What It Covers | Gap |
|----------------|----------------|-----|
| `test_keycloak_reachable.sh` | Container networking | None |
| `test_sssd_user.sh` | LDAP user lookup | None |
| `test_get_token.sh` | ROPC token acquisition | ROPC is deprecated; does not exercise device flow |
| `test_dpop_binding.sh` | DPoP proof → cnf.jkt via ROPC | Does not use device flow; client-only, no PAM validation |
| `test_dpop_e2e.sh` | Cross-language DPoP + unit tests | No real SSH E2E; relies on TEST_MODE |
| `test_ssh_oidc_valid.sh` | SSH + PAM | Uses `UNIX_OIDC_TEST_MODE=true`; bypasses all crypto |
| `test_break_glass_fallback.sh` | IdP-down → local account | Passes; no changes needed |
| `test_ciba_integration.sh` | CIBA + ACR validation | Passes; no changes needed |
| `test_sudo_step_up.sh` | Sudo step-up IPC | Passes; no changes needed |
| `demo/tests/*.spec.ts` | Playwright demo for recordings | Demo tool only; not wired into CI |
| `test/scripts/test-device-flow.sh` | Device flow smoke test | Step 2 uses ROPC (not device flow completion); Step 3 correctly gets `authorization_pending` but never completes the flow |
| `docker-compose.test.yaml` | Keycloak 24, OpenLDAP, test-host | `UNIX_OIDC_TEST_MODE=true` is set globally |

**Three pre-identified bugs that block real-signature tests** (from `.planning/v2.0-MILESTONE-AUDIT.md`):
1. Issuer URL mismatch: `docker-compose.test.yaml` sets `OIDC_ISSUER=http://keycloak:8080/realms/unix-oidc-test` but PAM rejects tokens if the issuer claim doesn't match.
2. Agent binary missing in test-host: the SSH_ASKPASS handler cannot work without the agent daemon inside the container.
3. DPoP binding absent from device-flow token request: Keycloak (with `dpop.bound.access.tokens=true`) rejects token requests that lack a `DPoP:` proof header.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features a credible OIDC PAM module's CI must have. Missing any → enterprise evaluators reject the project or must do their own validation.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| Real-signature Keycloak tests (TEST_MODE off) | `UNIX_OIDC_TEST_MODE` is documented as a security bypass that must not appear in production; CI that uses it only validates token parsing, not the actual signature verification path that matters | MEDIUM | Requires fixing the three pre-identified bugs: issuer URL, agent binary, DPoP in device-flow. Once fixed, existing shell tests pass without TEST_MODE. |
| Full SSH E2E: agent login → serve → SSH_ASKPASS → PAM → JWKS verify | The entire authentication chain must be exercised together; no partial-path test can substitute because the failure modes are at integration points between components | HIGH | Flow: `unix-oidc-agent login` (device flow with DPoP) → token stored in agent → `unix-oidc-agent serve` → `SSH_ASKPASS` program set → `ssh testuser@test-host` → PAM module reads token via SSH_ASKPASS → validates against Keycloak JWKS → session opens. Must run entirely inside docker-compose network. |
| DPoP binding in device-flow token request | Device flow is the primary token acquisition path in production; tests that bypass it do not exercise the code path users actually hit | MEDIUM | Agent must include `DPoP: <proof>` header in the `POST /token` request with `grant_type=urn:ietf:params:oauth:grant-type:device_code`. The DPoP proof's `htu` claim must match the token endpoint URL exactly. |
| Issuer URL fixture fix | PAM module performs exact string comparison of `iss` claim against configured issuer; mismatch causes every real-signature test to fail at issuer validation | LOW | Two valid approaches: (a) set `KC_HOSTNAME=keycloak` so Keycloak embeds the container hostname in tokens; (b) PAM config maps `http://keycloak:8080/realms/unix-oidc-test` as the expected issuer. Option (a) is cleaner — no config divergence between test and production. |
| CI gate: no TEST_MODE in integration containers | TEST_MODE bypass is so dangerous that CI should assert its absence before running integration tests | LOW | Add a pre-test step: `docker compose exec test-host env | grep -c UNIX_OIDC_TEST_MODE && exit 1`. Fails fast if TEST_MODE is set. |
| Agent binary in test-host container | SSH_ASKPASS handler is the agent binary; without it inside the container, the PAM keyboard-interactive conversation has nowhere to send the token | LOW | `docker-compose.test.yaml` already mounts `./target/release:/opt/unix-oidc:ro`. The agent binary just needs to be at a known path (`/usr/local/bin/unix-oidc-agent`) and the entrypoint script must symlink or copy it. |

### Differentiators (Competitive Advantage)

Features that distinguish unix-oidc's testing story. Competitors (`pam-keycloak-oidc`, `oidc-pam`, `pam_oidc`) have no automated E2E CI with real IdPs.

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| Playwright-based device flow automation | Device Authorization Grant (RFC 8628) requires a browser step: user visits `verification_uri`, enters `user_code`, authenticates. Playwright automates this step, enabling fully automated CI without ROPC (deprecated) or client-credentials (not representative) shortcuts. | HIGH | Pattern: (1) `POST /realms/{realm}/protocol/openid-connect/auth/device` → get `device_code`, `verification_uri`, `user_code`; (2) Playwright navigates to `verification_uri`, fills `user_code`, clicks submit, fills credentials, clicks approve; (3) shell loop polls `POST /token` with `grant_type=device_code` until success or `expired_token` error. Infrastructure already present: `demo/` directory has `playwright.config.ts` and playwright-core in `node_modules`. Keycloak's device activation page is standard HTML — straightforward to automate. |
| Azure Entra ID integration tests | Enterprise buyers evaluate against their existing Entra ID tenant; no Entra test coverage means they must validate the PAM module themselves. Documented Entra support in CI is a meaningful adoption differentiator. | HIGH | See Entra ID analysis section below. Requires external secrets (tenant ID, client ID, client secret). Run as separate CI job gated on `secrets.ENTRA_TENANT_ID`. |
| Negative test suite: real-signature rejections | Tests that only verify the happy path give false confidence about the PAM module's security. Rejection tests with real tokens (wrong issuer, expired, missing `cnf.jkt`) verify the actual enforcement paths. | MEDIUM | For expired tokens: Keycloak short-lived token (e.g., `accessTokenLifespan=10s`) + wait. For wrong issuer: register a second Keycloak realm, get a token from it, present to PAM configured for the first realm. For missing `cnf.jkt`: use a non-DPoP client to get a bearer token, present to PAM with `dpop_required=strict`. |
| Entra claim mapping validation | Entra `preferred_username` contains a UPN (`alice@corp.com`), not a Unix username (`alice`). Demonstrating automated end-to-end authentication with Entra, including UPN stripping, proves the PAM module is enterprise-ready for Entra deployments. | MEDIUM | Requires: claim mapping config (`strip_domain: true`) in PAM module, Entra test user with UPN matching an SSSD-provisioned Unix account, or a custom claim containing the Unix username. Dependency: claim mapping config must exist in PAM module (v2.0 feature). |
| Multi-IdP CI matrix | A CI matrix with Keycloak + Entra in the same workflow produces auditable evidence of cross-IdP compatibility — useful for conference talks, whitepapers, and enterprise proof-of-concept engagements. | HIGH | Keycloak: local docker-compose, no secrets needed. Entra: external, gated on CI secrets. Matrix job prevents one IdP's changes from silently breaking the other. |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| ROPC as permanent device-flow substitute | Simple: one curl call, synchronous, no browser automation needed | ROPC (`grant_type=password`) is deprecated in OAuth 2.1 (draft). Keycloak 24+ disables it by default for public clients; Entra ID has disabled it for new tenants since 2022. More critically: ROPC bypasses MFA, meaning tests that use it don't cover the MFA step that real users hit. Tests built on ROPC break silently when IdP policy changes. | Playwright device flow automation for interactive tests; client-credentials for machine-to-machine test token issuance where the user-auth flow is not under test. |
| Mock OIDC server (e.g., `oidc-server-mock`) as primary integration backend | Fast, no external dependencies, fully deterministic | Defeats the purpose of this milestone. Mock servers cannot reproduce real IdP signature formats, DPoP nonce behavior, claim shapes, error responses, or Keycloak-specific quirks. The entire point of v2.1 is real-signature testing — a mock reverts to the same testing quality as TEST_MODE. Mock OIDC is valid for PAM unit tests (validation.rs tests that test parsing logic in isolation); not for integration tests. | Use real Keycloak in docker-compose for Keycloak integration tests; real Entra for Entra tests. |
| Running SSH E2E from the host machine | Seems simpler — just `ssh localhost -p 2222` | PAM runs inside the container with its own OIDC_ISSUER, LDAP, and SSSD config. The SSH_ASKPASS program must also be inside the container (or reachable via a shared socket). Credential passing from host to container creates IPC complexity that does not match production topology. Port 2222 mapping introduces NAT edge cases. | Run the SSH client from a dedicated `ssh-client` container in the same docker-compose network — matches production topology exactly. |
| Interactive browser in headful mode in CI | Some OAuth flows genuinely need a browser | CI environments are headless; GitHub Actions and most CI systems do not have a display server. A test that requires a visible browser blocks indefinitely. | Playwright in headless mode completes device flow automation without a visible UI. Keycloak's device activation page is simple enough that `page.fill()` + `page.click()` covers it completely. |
| Entra ID DPoP (RFC 9449) enforcement | Natural expectation given the project's core feature is RFC 9449 DPoP | Entra ID does NOT support RFC 9449 DPoP. Microsoft implements a proprietary "Signed HTTP Request" (SHR) mechanism — not the DPoP header, not the `cnf.jkt` claim. Source: [Microsoft Learn MSAL JS, 2025-08-14](https://learn.microsoft.com/en-us/entra/msal/javascript/browser/access-token-proof-of-possession). Setting `dpop_required: strict` in the PAM config for an Entra test will cause every Entra token to be rejected because `cnf.jkt` is absent. | Entra integration tests must use `dpop_required: warn` or `off`. Document this limitation explicitly as a known Entra constraint, not a PAM module bug. |
| VDI/agent forwarding across SSH hops | Users want to reuse a token on remote hosts after an SSH hop | Explicitly out of scope in PROJECT.md. Also breaks the DPoP threat model: the DPoP private key is the proof-of-possession credential; forwarding it to another host means that host now possesses the key, undermining the binding. | ProxyJump for multi-hop connectivity; RFC 8693 token exchange (v2.2 milestone) for service delegation. |

---

## Feature Dependencies

```
[Full SSH E2E test (no TEST_MODE)]
    requires --> [Issuer URL fix]
    requires --> [Agent binary in test-host]
    requires --> [DPoP binding in device-flow token request]
    requires --> [Playwright device flow automation] (provides the token without ROPC)
    produces --> [Real-signature validation path is exercised in CI]

[Playwright device flow automation]
    requires --> [Keycloak device activation page accessible from test network]
    enhances --> [Full SSH E2E test]
    enables  --> [Device flow automation reusable for Entra tests]

[Entra ID integration tests]
    requires --> [Entra app registration (external, tenant-specific)]
    requires --> [Claim mapping config in PAM module (v2.0 feature)]
    requires --> [PAM config fixture: dpop_required=off for Entra]
    requires --> [CI secrets: ENTRA_TENANT_ID, ENTRA_CLIENT_ID, ENTRA_CLIENT_SECRET]

[Entra claim mapping validation]
    requires --> [Entra ID integration tests]
    requires --> [strip_domain claim transform in PAM config]

[Negative rejection test suite]
    requires --> [Real-signature Keycloak tests passing]
    requires --> [Second Keycloak realm for wrong-issuer test]

[CI gate: TEST_MODE=false]
    requires --> [docker-compose.test.yaml updated to remove UNIX_OIDC_TEST_MODE=true]
    should run before --> [Full SSH E2E test]

[Multi-IdP CI matrix]
    requires --> [Keycloak E2E tests passing]
    requires --> [Entra ID integration tests passing]
```

### Dependency Notes

- **Three bugs must be fixed before any real-signature test can pass.** They are independent of each other but all three are blocking. Fix order does not matter technically; issuer URL is the lowest effort and should go first to unblock the others.
- **Playwright is already installed** in `demo/node_modules`; no new tooling is needed. The CI job just needs a step that runs `npx playwright test` against a device-flow-specific spec instead of the demo spec.
- **Entra DPoP conflict is definitive and documented.** This is not a gap in the PAM module — it is an Entra limitation. A separate PAM config fixture for Entra tests is mandatory; trying to share the Keycloak fixture (which has DPoP required) will cause all Entra tests to fail.
- **Negative tests depend on the real-signature path being established first.** There is no point writing rejection tests if the acceptance path is still using TEST_MODE.

---

## MVP Definition

### Launch With (must land to close the v2.1 milestone)

- [ ] **Issuer URL fix** — `KC_HOSTNAME=keycloak` in docker-compose or PAM config `issuer` mapped to container URL. Without this, every real-signature test fails at the first validation step.
- [ ] **Agent binary in test-host** — `unix-oidc-agent` present at `/usr/local/bin/unix-oidc-agent` inside test-host container. The existing volume mount `./target/release:/opt/unix-oidc:ro` provides the binary; entrypoint.sh just needs to symlink it.
- [ ] **DPoP binding in device-flow token request** — Agent's `login()` sends `DPoP: <proof>` header with the device-flow `POST /token`. Proof's `htu` = token endpoint URL; `htm` = "POST"; fresh `jti` and `iat`.
- [ ] **TEST_MODE removed from docker-compose.test.yaml** — Delete `UNIX_OIDC_TEST_MODE: "true"` from `test-host` environment block. Add CI pre-flight assertion.
- [ ] **Playwright device flow spec** — A `tests/device-flow.spec.ts` (or `test/scripts/playwright-device-flow.sh` that calls playwright) that completes the Keycloak activation page using a headless browser.
- [ ] **Full SSH E2E test** — `test_ssh_e2e_real_sig.sh`: starts agent, runs login (device flow via Playwright-completed code), starts agent serve, sets SSH_ASKPASS, SSHes to test-host, verifies session opens and PAM log shows "Authentication successful" without TEST_MODE.

### Add After Validation (v2.1.x, if time permits this milestone)

- [ ] **Entra ID integration tests** — Trigger: Keycloak E2E is green. Requires: Entra app registration, CI secrets, `dpop_required=off` fixture.
- [ ] **Entra claim mapping validation** — Trigger: Entra tests in CI. UPN stripping verified end-to-end.
- [ ] **Negative rejection test suite** — Trigger: real-signature path established. Three tests: expired, wrong-issuer, missing `cnf.jkt`.

### Future Consideration (v2.2+)

- [ ] **Multi-IdP CI matrix** — Keycloak + Entra in a parallel matrix job. Blocked on Entra integration being stable first.
- [ ] **Google Cloud Identity / Okta** — Community testing priority. Okta supports RFC 9449 DPoP natively.

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Issuer URL fix | HIGH | LOW | P1 |
| Agent binary in test-host | HIGH | LOW | P1 |
| DPoP binding in device-flow token request | HIGH | MEDIUM | P1 |
| TEST_MODE removed from docker-compose | HIGH | LOW | P1 |
| Playwright device flow spec | HIGH | MEDIUM | P1 |
| Full SSH E2E test (no TEST_MODE) | HIGH | HIGH | P1 |
| CI gate: TEST_MODE=false assertion | MEDIUM | LOW | P1 |
| Entra ID integration tests | HIGH | HIGH | P2 |
| Entra claim mapping validation | MEDIUM | MEDIUM | P2 |
| Negative rejection test suite | MEDIUM | MEDIUM | P2 |
| Multi-IdP CI matrix | MEDIUM | HIGH | P3 |

**Priority key:**
- P1: Unblocks the milestone — must land before v2.1 is closed
- P2: Enterprise value — add in this milestone if time permits, else v2.1.x
- P3: Future milestone

---

## Entra ID Integration Analysis

This section warrants separate treatment because Entra has the most non-obvious constraints and the highest setup cost.

### What Works

| Capability | Status | Source |
|------------|--------|--------|
| OIDC discovery | Works | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` |
| JWKS endpoint | Works | `https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` |
| Token signature verification (RS256) | Works | PAM module JWKS validation is algorithm-agnostic |
| Device Authorization Grant (RFC 8628) | Works | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/devicecode` |
| `preferred_username` optional claim | Works (with config) | Must be added to app manifest `optionalClaims.accessToken`; contains UPN, not Unix username |
| `sub` claim | Always present | UUID — not usable as Unix username without a mapping table |
| `acr`/`amr` claims | Present | Values differ from Keycloak conventions; ACR test fixture needs adjustment |

### What Does NOT Work

| Capability | Status | Authoritative Source |
|------------|--------|----------------------|
| RFC 9449 DPoP (`cnf.jkt` claim) | NOT SUPPORTED | [Microsoft Learn MSAL JS, updated 2025-08-14](https://learn.microsoft.com/en-us/entra/msal/javascript/browser/access-token-proof-of-possession): Entra uses Signed HTTP Request (SHR), not RFC 9449 DPoP. `cnf.jkt` is not emitted. |
| `preferred_username` as Unix username (direct) | NOT DIRECT | UPN format (`alice@corp.com`) requires `strip_domain: true` transform |
| Guest user `preferred_username` | UNRELIABLE | Guest format: `foo_hometenant.com#EXT#@resourcetenant.com`; Unix derivation requires additional mapping logic |
| `upn` claim in v2.0 tokens by default | Absent | Must be added as optional claim via app manifest |

### Required PAM Config Fixture for Entra Tests

```yaml
# /etc/unix-oidc/config-entra.yaml — used ONLY in Entra integration test containers
oidc:
  issuer: "https://login.microsoftonline.com/{tenant_id}/v2.0"
  client_id: "{client_id}"
  audience: "{client_id}"

security:
  dpop_required: "off"      # Entra does not support RFC 9449 DPoP
  jti_enforcement: "warn"   # Entra access tokens may omit jti

claim_mapping:
  username_claim: "preferred_username"
  strip_domain: true         # alice@corp.com -> alice
```

### Required Entra App Registration Settings

| Setting | Value | Why |
|---------|-------|-----|
| Platform | Public client / Mobile+Desktop | Device flow requires public client |
| Device code flow | Enabled | Authentication > Advanced settings > Allow public client flows |
| Optional claim: `preferred_username` | Added to access token | Needed for username mapping; absent by default in v2.0 tokens |
| Scope | `api://{client_id}/ssh.access` or `openid profile` | PAM must request a scope that returns `preferred_username` |
| Test user | UPN matching SSSD-provisioned Unix account | E.g., `testuser@{tenant}.onmicrosoft.com` → Unix `testuser` |

### Entra CI Job Structure

```yaml
# .github/workflows/ci.yml addition
entra-integration:
  if: secrets.ENTRA_TENANT_ID != ''
  runs-on: ubuntu-latest
  env:
    ENTRA_TENANT_ID: ${{ secrets.ENTRA_TENANT_ID }}
    ENTRA_CLIENT_ID: ${{ secrets.ENTRA_CLIENT_ID }}
    ENTRA_CLIENT_SECRET: ${{ secrets.ENTRA_CLIENT_SECRET }}
  steps:
    - name: Run Entra integration tests
      run: test/tests/test_entra_oidc.sh
```

Gating on `secrets.ENTRA_TENANT_ID != ''` ensures the job is skipped for forks and community PRs that lack the secrets, without failing the CI run.

---

## Sources

**Official documentation (HIGH confidence):**
- [Microsoft Learn: OIDC on Entra ID](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc) — issuer URL format (`https://login.microsoftonline.com/{tenant}/v2.0`), JWKS endpoint, discovery document (updated 2026-01-09)
- [Microsoft Learn: Optional claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims-reference) — `preferred_username` behavior, guest UPN format, `upn` as optional claim (updated 2025-10-02)
- [Microsoft Learn: Access token Proof-of-Possession (MSAL JS)](https://learn.microsoft.com/en-us/entra/msal/javascript/browser/access-token-proof-of-possession) — confirms Entra uses SHR (Signed HTTP Request), NOT RFC 9449 DPoP; `cnf.jkt` is not emitted (updated 2025-08-14)
- [Playwright: Authentication docs](https://playwright.dev/docs/auth) — session state caching, CI token management best practices
- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628) — device flow protocol, polling mechanics, error codes

**Keycloak documentation (MEDIUM confidence):**
- [Keycloak device code flow](https://www.janua.fr/device-code-flow-in-keycloak/) — device endpoint, user code activation page URL, polling mechanics
- [Keycloak device flow design](https://github.com/keycloak/keycloak-community/blob/main/design/oauth2-device-authorization-grant.md) — Keycloak-specific implementation notes

**Codebase (HIGH confidence — direct inspection):**
- `test/scripts/test-device-flow.sh` — existing ROPC-based device flow shortcut; confirmed gap
- `test/tests/test_dpop_binding.sh` — existing DPoP binding test; confirmed uses ROPC not device flow
- `test/tests/test_ssh_oidc_valid.sh` — confirmed uses `UNIX_OIDC_TEST_MODE=true`
- `docker-compose.test.yaml` — confirmed `UNIX_OIDC_TEST_MODE: "true"` in test-host environment
- `demo/tests/*.spec.ts` — confirmed Playwright infrastructure exists but is demo-only
- `.planning/v2.0-MILESTONE-AUDIT.md` — three pre-identified blocking bugs confirmed

---

*Feature research for: unix-oidc v2.1 E2E Integration Testing milestone*
*Researched: 2026-03-13*
