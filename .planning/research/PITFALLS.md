# Pitfalls Research

**Domain:** E2E Integration Testing Infrastructure — Real IdP Integration, Playwright CI Automation, Entra ID
**Researched:** 2026-03-13
**Milestone:** v2.1 Integration Testing Infrastructure
**Confidence:** HIGH (critical pitfalls verified against live codebase + RFC/official Microsoft docs; Entra DPoP gap confirmed via Microsoft Learn)

---

## Critical Pitfalls

Mistakes that produce false green test results, silently bypass cryptographic verification, or permanently block a test phase from making progress.

---

### Pitfall 1: Keycloak Issues Tokens With the Wrong Issuer for the PAM Validator

**What goes wrong:**

The current `docker-compose.test.yaml` sets `KC_HOSTNAME=localhost` so that demo recordings and Playwright browser automation can reach `http://localhost:8080`. Keycloak 24+ bakes that hostname into the `iss` field of every token it issues. Tokens contain `iss: http://localhost:8080/realms/unix-oidc-test`. The PAM module inside the `test-host` container is configured with `OIDC_ISSUER=http://keycloak:8080/realms/unix-oidc-test`. Issuer validation is an exact string match (required by OpenID Connect Core 1.0 §3.1.3.7). It fails on every real-signature test. This is exactly the known issue described in `PROJECT.md`.

**Why it happens:**

Keycloak derives the issuer from its frontend hostname setting, not from who made the request. The Docker internal service name `keycloak` and the host-visible `localhost` are different strings. Two callers — the Playwright browser on the host and the PAM module inside a container — cannot both satisfy a single `KC_HOSTNAME` setting without a split-brain issuer.

**How to avoid:**

Pick one canonical issuer URL and make all callers use it. The correct CI option is:

1. Set `KC_HOSTNAME=keycloak` in `docker-compose.test.yaml` so tokens carry `iss: http://keycloak:8080/...`.
2. On the CI runner host, add `127.0.0.1 keycloak` to `/etc/hosts` (one-line step in the GitHub Actions workflow).
3. Playwright navigates to `http://keycloak:8080/...` — same URL, same issuer, no mismatch.
4. PAM config keeps `OIDC_ISSUER=http://keycloak:8080/realms/unix-oidc-test` — already correct.

Do not attempt to fix this with `KC_HOSTNAME_STRICT=false` — that relaxes the redirect URI check, not the issuer field.

**Warning signs:**

- Integration test log: `Invalid issuer: expected http://keycloak:8080/... got http://localhost:8080/...`
- Decoded token shows `"iss":"http://localhost:8080/realms/unix-oidc-test"` while PAM config says `keycloak:`
- `test_keycloak_reachable.sh` passes; `test_ssh_oidc_valid.sh` fails immediately at the validation step

**Phase to address:** Phase 1 of v2.1 (issuer URL normalization) — must be resolved before any real-signature E2E test can produce a meaningful result.

---

### Pitfall 2: PAM Conversation Buffer Silently Truncates JWTs

**What goes wrong:**

The PAM `conv()` call for `PROMPT_ECHO_OFF` passes through OpenSSH's keyboard-interactive handler, which copies the response into a stack buffer. The codebase documents this at `lib.rs:772`: "PAM conversation has a ~512 byte buffer limit." A Keycloak JWT with standard claims (sub, iss, aud, iat, exp, jti, preferred_username, cnf.jkt) encodes to 1,200–1,600 bytes. The token is silently truncated. `is_jwt()` returns false on the truncated string (missing third `.`-separated segment). The auth attempt fails with "no token found" — not "token validation failed" — making the failure mode look like a configuration problem rather than a size problem.

**Why it happens:**

Any E2E test that injects the token via environment variable `OIDC_TOKEN` into the test-host container and then expects PAM to pick it up through the keyboard-interactive conversation path will fail, even though token acquisition succeeded. The two mechanisms — env-based injection and conv()-based collection — are independent code paths and neither path is active unless the right guard variable (`UNIX_OIDC_TEST_MODE` or `UNIX_OIDC_ACCEPT_PAM_ENV`) is also set.

**How to avoid:**

The production real-signature E2E test path must use the `unix-oidc-agent` + SSH_ASKPASS mechanism:

1. The agent daemon runs inside (or alongside) the test-host container with a live token.
2. SSH connects with `SSH_ASKPASS=/path/to/unix-oidc-agent-askpass` set in the client's environment.
3. The agent's `askpass.rs` intercepts the `OIDC Token:` prompt and returns the full JWT without size constraint.
4. `UNIX_OIDC_TEST_MODE` must be absent.

Treat `conv()` as a debugging path only. Never write a real-signature E2E test that routes the token through `conv()`.

**Warning signs:**

- E2E test fails with "no JWT token found in any source" while `OIDC_TOKEN` is set in the environment
- PAM log: `Warning: Token may be truncated (NNN bytes). PAM conversation has a ~512 byte limit.`
- Test acquires a token successfully but auth still fails — likely truncation

**Phase to address:** Phase 1 (pre-conditions for real-signature E2E) — establish the correct token injection path before writing the test.

---

### Pitfall 3: Agent Device Flow Token Polling Sends No DPoP Proof Header

**What goes wrong:**

The agent's polling loop (`main.rs` lines 842–857) builds `token_params` with `grant_type`, `device_code`, and `client_id`. No `DPoP:` header is attached to the `http_client.post(&token_endpoint).form(&token_params)` call. When the Keycloak realm has `dpop.bound.access.tokens: true`, the token endpoint rejects every poll request with HTTP 400 and `"error":"invalid_request"` (or `"use_dpop_nonce"` if a nonce was already issued). The polling loop hits the unrecognized error branch and exits immediately. From the user's perspective, device flow authentication silently fails after they complete the browser step.

**Why it happens:**

The draft `draft-parecki-oauth-dpop-device-flow` specifies that the client must include a DPoP proof in both the device authorization request and every subsequent token poll, binding the proof to the same key used in the initial request. This draft postdates the initial agent implementation. The omission is a known gap in `PROJECT.md`.

**How to avoid:**

Fix the agent before writing DPoP device flow E2E tests:

1. At the start of the `login` subcommand, retrieve the existing `DPoPSigner` from `AgentState` (the key is already generated and stored).
2. In the device authorization request, generate a DPoP proof with `htm=POST`, `htu=<device_endpoint>`, fresh `jti` and `iat`, and attach it as the `DPoP:` request header.
3. In each poll iteration, generate a new DPoP proof with `htm=POST`, `htu=<token_endpoint>`, new `jti` and `iat`. If the previous poll response contained `WWW-Authenticate: DPoP error="use_dpop_nonce", nonce="..."`, include that nonce as the `nonce` claim in the next proof.
4. The Keycloak test realm for DPoP tests must have `dpop.bound.access.tokens: true` on the client.

Do not run the DPoP device flow E2E test against the DPoP-enabled realm until this fix is merged and deployed into the test container.

**Warning signs:**

- Device flow authentication fails immediately after the user approves in the browser
- Keycloak server log: `DPoP proof required` or `use_dpop_nonce`
- Poll response: `{"error":"invalid_request","error_description":"DPoP proof required"}`

**Phase to address:** Phase 1 of v2.1 (agent DPoP fix) — must be complete before DPoP-bound device flow E2E tests run.

---

### Pitfall 4: Azure Entra ID Does Not Implement RFC 9449 DPoP

**What goes wrong:**

Any test asserting `cnf.jkt` in an Entra ID access token will always fail. Entra ID implements PoP via Signed HTTP Request (SHR), defined by IETF draft `draft-ietf-oauth-signed-http-request`, not RFC 9449. The difference is not cosmetic: SHR tokens use a different proof structure, different header names, and do not produce `cnf.jkt` in the access token. The unix-oidc PAM module looks for `cnf.jkt` (RFC 9449 §6) and verifies the proof in `Authorization: DPoP` format. Entra tokens have no `cnf.jkt`. A PAM validator configured with `dpop_required=Strict` will reject every Entra token.

**Why it happens:**

Entra ID's PoP implementation predates RFC 9449 and is Windows-ecosystem-centric (WAM broker, MSAL). Microsoft added RFC 9449 DPoP support for specific scenarios in MSAL.js v2 (browser/web app flows), but this requires the consuming API to also be Entra-registered and DPoP-aware. The device authorization grant in Entra ID does not produce DPoP-bound tokens, regardless of what the client sends. The official Microsoft device code flow documentation lists no DPoP parameters, and the token response uses `token_type: Bearer`.

**How to avoid:**

Design the Entra ID integration test tier for bearer-token flows only:

1. Test OIDC discovery, JWKS fetching, RS256/EC256 signature verification, `preferred_username` claim mapping, and `exp` validation — all work normally.
2. Do not write any test asserting `cnf.jkt` presence or `token_type: DPoP` for Entra tokens.
3. Set `dpop_required=Warn` (or `Disabled`) in the Entra ID test fixture configuration.
4. Document in the Entra ID integration guide that DPoP binding is a Keycloak-specific feature in the current implementation.
5. Monitor the Entra ID roadmap; if Microsoft ships RFC 9449 for device flow, update accordingly.

**Warning signs:**

- Entra ID test fails with "DPoP binding required but cnf.jkt absent"
- Test fixture config sets `dpop_required: strict` for the Entra integration job
- Test author assumes all OIDC providers support the same token extensions

**Phase to address:** Entra ID integration phase — establish bearer-only test scope in the test plan before writing code.

---

### Pitfall 5: Playwright Hangs Navigating to `verification_uri_complete` Which Entra ID Omits

**What goes wrong:**

The existing `test-device-flow-e2e.sh` exports `VERIFICATION_URI_COMPLETE` and instructs Playwright to navigate directly to it. Entra ID's device authorization response explicitly does not include `verification_uri_complete` — confirmed in current Microsoft documentation: "The `verification_uri_complete` response field is not included or supported at this time." The field is optional in RFC 8628 §3.2. When `jq -r '.verification_uri_complete'` is run on a response without this field, it returns the literal string `null` (not empty). A Playwright test that navigates to `null` either crashes or navigates to a relative URL that makes no sense in the browser context.

**Why it happens:**

The current script was written against Keycloak, which does return `verification_uri_complete`. Entra ID was added later. The field's absence was not accounted for in the shared test infrastructure.

**How to avoid:**

1. Null-check the field before using it: `[ "$VERIFICATION_URI_COMPLETE" = "null" ] || [ -z "$VERIFICATION_URI_COMPLETE" ]`.
2. When absent, fall back to navigating to `verification_uri` and then programmatically filling in the `user_code` field.
3. Write IdP-specific Playwright helpers — Keycloak and Entra ID have different login page DOM structures, different CSRF token patterns, and different consent/device confirmation screens.
4. Add a test-specific assertion that the browser ends up on the "device activated" confirmation page before declaring the browser automation step complete.

**Warning signs:**

- Playwright navigates to URL `null` or `http://localhost:8080/null`
- Browser automation step exits without error but token poll immediately returns `authorization_pending` indefinitely
- Entra ID test hangs until device code expiry

**Phase to address:** Playwright browser automation phase — implement the fallback and per-IdP helpers before any Entra ID test run.

---

### Pitfall 6: TEST_MODE Contamination Produces False Green in Real-Signature CI Jobs

**What goes wrong:**

`docker-compose.test.yaml` sets `UNIX_OIDC_TEST_MODE: "true"` as a container environment variable on `test-host`. If the real-signature CI job reuses this compose file without explicitly unsetting the variable, the PAM module reads the env var, logs a WARNING, and routes token acquisition through the `OIDC_TOKEN` env var path — bypassing the entire `collect token from agent → validate signature → verify DPoP proof` pipeline. Tests pass. The signature verification code path is never exercised. CI reports green on a fundamentally untested path.

**Why it happens:**

Docker Compose environment variables propagate to all services in the file. A copy-paste of the `test-host` service definition for a "real-signature" job inherits `UNIX_OIDC_TEST_MODE: "true"` unless explicitly overridden or the key is absent from the new compose file. The PAM module's check (`std::env::var("UNIX_OIDC_TEST_MODE") == Ok("true")`) is silent from the test's perspective — the warning goes to stderr which CI may not check.

**How to avoid:**

1. Create a separate `docker-compose.e2e.yaml` for real-signature tests with `UNIX_OIDC_TEST_MODE` absent from all service environments.
2. Add a sentinel assertion at the top of every real-signature test script: verify the env var is unset inside the container before proceeding.
3. In the CI workflow YAML, add a step that runs `docker exec test-host env | grep -c UNIX_OIDC_TEST_MODE` and fails the job if the count is nonzero.
4. Build the test-host binary without `--features test-mode` (confirm via `strings` output on the `.so` file that test-mode strings are absent).

**Warning signs:**

- Real-signature test passes in under 2 seconds (signature crypto takes measurable time)
- PAM log from CI: `WARNING: UNIX_OIDC_TEST_MODE is enabled`
- Real-signature test passes even with an obviously invalid token (forged header, wrong signature)

**Phase to address:** Phase 1 (CI job setup) — add the sentinel assertion as the very first step before any other test logic.

---

### Pitfall 7: Playwright Chromium Sandbox Fails Inside Docker Containers

**What goes wrong:**

GitHub Actions runs on Ubuntu workers. Playwright's Chromium requires kernel namespace support (`clone(CLONE_NEWUSER)`) for its process sandbox. Inside a standard Docker container, user namespaces are restricted. Without explicit `--no-sandbox`, Playwright crashes with "No usable sandbox!" With `--no-sandbox`, the browser renderer process has no process isolation — any JavaScript executing in the browser can reach the container's filesystem. For a controlled local Keycloak test this is a low practical risk, but it is a security property that must be an explicit, documented decision, not an accident.

**Why it happens:**

Teams copy Playwright's container workaround (`chromiumSandbox: false`) without understanding its scope, then apply it globally including to jobs that might interact with external URLs.

**How to avoid:**

1. Run Playwright on the GitHub Actions host directly (not inside `test-host`) — the GHA runner has full kernel namespace support and does not need `--no-sandbox`.
2. Playwright on the GHA host can still drive Keycloak at `http://localhost:8080` (forwarded port) or `http://keycloak:8080` (via `/etc/hosts`).
3. If Playwright must run inside a container, use `mcr.microsoft.com/playwright` as the base image — it pre-configures the required kernel capabilities.
4. If `chromiumSandbox: false` must be used: scope it to CI only (`process.env.CI === 'true'`), restrict the automation target to local Keycloak only (no external URLs), and document the decision explicitly in the test config.

**Warning signs:**

- Playwright launch output: "No usable sandbox! If you are running on Linux..."
- `chromiumSandbox: false` set globally in `playwright.config.ts` without a CI guard
- Playwright job runs as root inside a Docker container

**Phase to address:** Playwright CI setup phase — decide the execution model (host vs. container) before writing any Playwright test code.

---

### Pitfall 8: Entra ID Issuer Is Tenant-Specific — `/common` Endpoint Breaks Exact-Match Validation

**What goes wrong:**

The PAM module validates the token `iss` claim as an exact string match against `OIDC_ISSUER`. Entra ID v2.0 tokens carry `iss: https://login.microsoftonline.com/{tenant-UUID}/v2.0`. The `{tenant-UUID}` is the specific tenant's directory ID. If the PAM test config uses the `/common` or `/organizations` discovery endpoint, the `openid-configuration` metadata contains `{tenantid}` as a literal template placeholder. An exact-match comparison of `https://login.microsoftonline.com/common/v2.0` against `https://login.microsoftonline.com/{UUID}/v2.0` always fails. Multi-tenant aware validation requires substituting the `tid` claim from the token into the issuer template before comparing — functionality not currently implemented in the PAM module.

**Why it happens:**

Entra ID's multi-tenant design uses template URLs for shared endpoints. OIDC Core requires exact issuer match. Microsoft's own guidance says validators must perform template substitution. The unix-oidc PAM module's exact-match validator is correct for single-tenant deployments and wrong for `/common`.

**How to avoid:**

1. For Entra ID integration tests, use the tenant-specific discovery endpoint: `https://login.microsoftonline.com/{YOUR_TENANT_ID}/v2.0/.well-known/openid-configuration`.
2. Set `OIDC_ISSUER=https://login.microsoftonline.com/{YOUR_TENANT_ID}/v2.0` in the PAM test fixture.
3. Do NOT use `/common` or `/organizations` endpoints in test fixtures — they require template-aware issuer validation that is not implemented.
4. Document this as a known single-tenant constraint in the Entra ID integration guide.
5. Store the tenant ID in a GitHub Secret (`ENTRA_TENANT_ID`), not hardcoded.

**Warning signs:**

- Entra ID test fails with `Invalid issuer: expected .../common/v2.0 got .../UUID/v2.0`
- Test fixture config has `OIDC_ISSUER=https://login.microsoftonline.com/common/v2.0`
- Decoded token shows `"iss":"https://login.microsoftonline.com/UUID/v2.0"` with a real UUID

**Phase to address:** Entra ID integration phase — set the tenant-specific issuer in all test fixtures before writing token validation assertions.

---

### Pitfall 9: Keycloak TCP Health Check Passes Before Realm Import Completes

**What goes wrong:**

The current `docker-compose.test.yaml` health check uses `exec 3<>/dev/tcp/localhost/8080` — TCP connectivity only. Keycloak opens port 8080 early in its startup sequence, before the `--import-realm` process finishes loading realm JSON files. The `wait-for-healthy.sh` script sees the port open and exits 0. CI proceeds to token acquisition immediately. The OIDC discovery endpoint returns 404 (realm not found) for 10–30 seconds while import is still running. Tests fail with confusing curl errors.

**Why it happens:**

Keycloak 24+ provides a proper readiness endpoint at port 9000 (`/health/ready`) that reflects actual service readiness including realm import. The current compose file does not expose port 9000 and does not use this endpoint. The TCP check is a quick substitute that passes too early.

**How to avoid:**

1. Change the health check command to: `curl -sf http://localhost:9000/health/ready`.
2. Expose port 9000 in the `keycloak` service in `docker-compose.test.yaml`.
3. Add a secondary check in test scripts that polls the realm's OIDC discovery endpoint until it returns 200 before proceeding. This is belt-and-suspenders against any edge cases where the health endpoint reports ready before realm data is fully queryable.
4. Set `start_period: 60s` (current is 30s) — Keycloak import is slower on cold runners.

**Warning signs:**

- First run after `docker compose up` fails with `{"error":"Realm does not exist"}` on the token endpoint
- CI flakes intermittently; re-running the same commit succeeds
- Keycloak logs: `Listening on port 8080` appears 15+ seconds before `Imported realm unix-oidc-test`

**Phase to address:** Phase 1 (test infrastructure setup) — fix the health check before any test is built on top of it, or every subsequent test phase will see phantom flakes.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Keep `UNIX_OIDC_TEST_MODE=true` in integration test containers | Tests pass quickly without fixing issuer mismatch | Never validates real signature path; creates false green confidence | Never — maintain separate compose files for TEST_MODE and real-sig |
| Use `get-test-token.sh` (Resource Owner Password Grant) for all token acquisition in tests | Simple, no browser needed | ROPG is deprecated in OAuth 2.1; does not exercise the device flow code path; will break as IdPs disable it | Only for Keycloak unit-style validation tests; never for device flow E2E |
| Single `docker-compose.test.yaml` for both TEST_MODE and real-sig tests | One file to maintain | `UNIX_OIDC_TEST_MODE` env var bleeds into real-sig jobs if the file is shared | Never — separate compose files per test tier |
| Reuse Playwright auth state files (`playwright/.auth/*.json`) across CI runs | Avoids repeated browser logins | Stale cookies break tests; files accidentally committed expose credentials | Acceptable only with per-run cleanup and strict `.gitignore` |
| Hardcode `localhost:8080` as Keycloak URL in all test scripts | Simple | Breaks inside Docker containers where `localhost` is the container itself | Acceptable in scripts that run exclusively on the CI host (outside Docker) |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Keycloak (Docker) | `KC_HOSTNAME=localhost` — tokens get localhost issuer; PAM inside container fails validation | Set `KC_HOSTNAME` to the Docker service name or a consistent alias reachable from all callers |
| Keycloak (DPoP) | Enable `dpop.bound.access.tokens: true` before fixing agent device flow polling | Fix agent DPoP polling first; enable Keycloak DPoP enforcement only in the final integration test |
| Keycloak (CIBA) | Expecting CIBA endpoint to exist without `--features=ciba` in the start command | Use `start-dev --features=ciba`; verify CIBA endpoint appears in discovery before writing any CIBA test |
| Azure Entra ID | Requesting DPoP-bound tokens with device flow | Entra ID device flow returns `token_type: Bearer`; test bearer flows only |
| Azure Entra ID | Using `/common` discovery endpoint — PAM issuer validation fails | Always use tenant-specific endpoint: `login.microsoftonline.com/{tenant-id}/v2.0` |
| Azure Entra ID | App registration missing "Allow public client flows" toggle | Device flow returns `AADSTS7000218`; enable "Allow public client flows" in the app's Authentication page |
| Azure Entra ID | Navigating Playwright to `verification_uri_complete` which is absent | Check for null; fall back to `verification_uri + ?user_code=X` |
| Playwright / GitHub Actions | Running inside a Docker container — Chromium sandbox fails | Run on GHA host directly, not inside `test-host`; or use `mcr.microsoft.com/playwright` base image |
| SSH_ASKPASS path | Forgetting to copy the agent binary into the test container | Confirm agent binary is at `/usr/local/bin/unix-oidc-agent` in the container; `test_dpop_e2e.sh` step 3b validates this |

---

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Real-signature tests with `UNIX_OIDC_TEST_MODE=true` | All cryptographic validation bypassed; tests green-light unauthenticated access | Add sentinel assertion at start of every real-sig test job; fail immediately if var is set |
| Committing Playwright auth state (`playwright/.auth/*.json`) | Test IdP credentials exposed; session cookies can be replayed | Add `playwright/.auth/` to `.gitignore`; enforce with secret scanning in CI |
| Using production Entra ID tenant for CI tests | CI failure or misconfiguration triggers audit alerts and potential account lockout | Use a dedicated test tenant or dedicated test app registration with test-only users |
| Storing Entra ID credentials as plaintext in compose files | Credentials leak into git history | Always use GitHub Secrets for cloud IdP credentials; Keycloak test realm credentials in compose files are acceptable (ephemeral, non-production) |
| Disabling TLS validation for Keycloak via `REQWEST_INSECURE=1` | JWKS fetch is unprotected; signing keys could be replaced by a MITM | Use HTTP (not disable TLS on a configured HTTPS endpoint); Keycloak in dev mode uses HTTP by default — do not enable HTTPS then disable certificate validation |
| Not verifying `cnf.jkt` thumbprint in the real-signature test | DPoP binding silently untested | Include a negative test: present a token with wrong `cnf.jkt` and assert PAM returns an auth failure |

---

## "Looks Done But Isn't" Checklist

- [ ] **Issuer URL fix:** After changing `KC_HOSTNAME`, confirm the PAM log shows `Authentication successful` — not just that `get-test-token.sh` returns a token (token acquisition and PAM validation are separate steps)
- [ ] **DPoP device flow fix:** After agent sends `DPoP:` header in polling, confirm the token response contains `"token_type":"DPoP"` and the access token payload contains `cnf.jkt` — a 200 from the token endpoint is not sufficient
- [ ] **Playwright browser automation:** After the browser automation step completes login, confirm Playwright waited for the Keycloak "device activated" confirmation page before exiting — the form submit and the device activation redirect are two separate browser transitions
- [ ] **TEST_MODE absent from real-sig job:** After creating the new compose file, confirm `UNIX_OIDC_TEST_MODE` is absent from the running container's env: `docker exec test-host env | grep UNIX_OIDC_TEST_MODE` must return nothing
- [ ] **Entra ID issuer:** After configuring Entra ID test fixtures, confirm the `iss` claim in a real Entra token exactly matches the configured `OIDC_ISSUER` — use `jq -r '.iss'` on the decoded token payload
- [ ] **Keycloak health check:** After updating the health check, confirm CI shows zero "Realm does not exist" 404 errors across 5 consecutive runs on cold runners
- [ ] **Playwright sandbox:** After setting up the Playwright job, confirm it runs without `--no-sandbox` on the GHA runner host — or explicitly document and scope the `chromiumSandbox: false` decision
- [ ] **Break-glass test:** After writing the break-glass fallback test, confirm it was tested with Keycloak actually stopped (not just unconfigured) to validate the PAM stack falls through to local auth

---

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Issuer URL mismatch discovered mid-milestone | MEDIUM | Set `KC_HOSTNAME=keycloak`; update `OIDC_ISSUER` in test fixtures; add `127.0.0.1 keycloak` to GHA `/etc/hosts`; rebuild test container; re-run |
| TEST_MODE contamination found in CI results | HIGH | Invalidate all test results from affected runs; add sentinel assertion; re-run full suite from scratch; note in CHANGELOG |
| Agent missing DPoP header in device flow | MEDIUM | Implement DPoP proof generation in the polling loop using existing `DPoPSigner`; rebuild agent binary; redeploy to test container |
| Playwright crashes on missing `verification_uri_complete` | LOW | Add null guard and fallback URL construction; 15-minute fix |
| Entra ID tests all fail due to `/common` issuer | LOW | Update fixture to use tenant-specific URL; no code change needed |
| Keycloak health check race causes CI flakes | MEDIUM | Replace TCP check with `/health/ready` curl; add discovery endpoint poll in test scripts; increase `start_period` |
| Playwright `--no-sandbox` causes security concern | MEDIUM | Move Playwright execution to GHA host (outside Docker); install deps via `npx playwright install-deps`; remove global `chromiumSandbox: false` |

---

## Pitfall-to-Phase Mapping

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| Keycloak issuer URL mismatch | Phase 1: Issuer URL normalization | PAM log shows `iss=http://keycloak:8080/...`; real-sig test passes without `UNIX_OIDC_TEST_MODE` |
| PAM conv buffer truncates JWT | Phase 1: Token injection path audit | E2E test uses SSH_ASKPASS / agent path; grep confirms `UNIX_OIDC_TEST_MODE` absent from real-sig compose |
| Agent missing DPoP in device flow poll | Phase 1: Agent DPoP fix | Token response contains `"token_type":"DPoP"` and `cnf.jkt`; negative test without DPoP header gets 400 |
| Entra ID lacks RFC 9449 DPoP | Entra ID integration phase | Test plan explicitly scopes to bearer-only; zero assertions on `cnf.jkt` in Entra test cases |
| Playwright missing `verification_uri_complete` | Playwright phase: per-IdP abstraction | Entra ID device flow succeeds using fallback `verification_uri + user_code` path |
| TEST_MODE contamination | Phase 1: CI job setup | Sentinel assertion in every real-sig job; CI step fails if `UNIX_OIDC_TEST_MODE` is set |
| Playwright Chromium sandbox | Playwright phase: CI execution model | Playwright job runs on GHA host; passes without `--no-sandbox` |
| Entra ID tenant-specific issuer | Entra ID integration phase | Fixture uses `/{tenant-id}/v2.0`; PAM issuer config matches token `iss` exactly |
| Keycloak TCP health check race | Phase 1: Test infrastructure setup | Zero "Realm does not exist" flakes in 10 consecutive CI runs; health check uses `/health/ready` |

---

## Sources

- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://datatracker.ietf.org/doc/html/rfc9449
- draft-parecki-oauth-dpop-device-flow — DPoP for the OAuth 2.0 Device Authorization Grant: https://drafts.aaronpk.com/oauth-dpop-device-flow/draft-parecki-oauth-dpop-device-flow.html
- RFC 8628 — OAuth 2.0 Device Authorization Grant (optional `verification_uri_complete`): https://datatracker.ietf.org/doc/html/rfc8628
- OpenID Connect Core 1.0 §3.1.3.7 — exact issuer match required: https://openid.net/specs/openid-connect-core-1_0.html
- Microsoft Entra ID — Device Code Flow (no DPoP, no `verification_uri_complete`): https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code
- Microsoft Entra ID — PoP via SHR (not RFC 9449 DPoP): https://learn.microsoft.com/en-us/entra/msal/dotnet/advanced/proof-of-possession-tokens
- Keycloak hostname configuration and split-brain: https://www.keycloak.org/server/hostname
- Keycloak internal vs external URL discussion: https://github.com/keycloak/keycloak/discussions/35302
- Playwright authentication documentation: https://playwright.dev/docs/auth
- Playwright sandbox issue in containers: https://github.com/microsoft/playwright/issues/1977
- unix-oidc codebase — `pam-unix-oidc/src/lib.rs` lines 772–838 (PAM conv buffer documented)
- unix-oidc codebase — `unix-oidc-agent/src/main.rs` lines 842–857 (missing DPoP header in polling)
- unix-oidc codebase — `docker-compose.test.yaml` (TCP-only health check, TEST_MODE env var)
- unix-oidc codebase — `test/e2e/test-device-flow-e2e.sh` (missing null guard on `verification_uri_complete`)

---

*Pitfalls research for: E2E Integration Testing Infrastructure (real IdPs, Playwright CI, Entra ID) — unix-oidc v2.1 milestone*
*Researched: 2026-03-13*
*Prior PITFALLS.md (v2.0 production hardening) preserved as standalone document if needed*
