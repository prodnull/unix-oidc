# Architecture Research

**Domain:** E2E integration testing infrastructure — unix-oidc v2.1
**Researched:** 2026-03-13
**Confidence:** HIGH (based on direct code inspection of all test infrastructure and v2.0 audit)

---

## Standard Architecture

### System Overview: Current vs. v2.1 Target State

The existing test infrastructure has three separate docker-compose stacks. v2.1 adds a fourth
stack (real-signature E2E) and extends two of the three existing ones. Each stack is purpose-
isolated with its own Docker network and Keycloak instance. Stacks do not share state at runtime.

```
┌──────────────────────────────────────────────────────────────────────────┐
│                     GitHub Actions CI (ci.yml)                           │
│                                                                          │
│  check ──────────────────────────┐                                       │
│  build-matrix (artifact upload) ─┤  ← produces: libpam_unix_oidc.so     │
│  security                        │               unix-oidc-agent         │
│  coverage                        │                                       │
│  dpop-interop ───────────────────┘                                       │
│  msrv / docs / sbom / codeql                                             │
│                                                                          │
│  integration (needs: check)            ← TEST_MODE, existing             │
│  token-exchange (needs: check)         ← existing                        │
│  ciba-integration (needs: check)       ← existing                        │
│  keycloak-e2e (needs: check + build-matrix)  ← NEW: real signatures      │
│                                                                          │
│  provider-tests.yml:                                                     │
│    keycloak / auth0 / google           ← existing                        │
│    entra-integration (secrets-gated)   ← NEW                             │
└──────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│           EXISTING: docker-compose.test.yaml                            │
│           Network: unix-oidc-test                                        │
│                                                                          │
│  keycloak:24        openldap          test-host (Ubuntu 22.04)           │
│  :8080 (host)       :389/:636         :2222 (SSH)                        │
│  KC_HOSTNAME=       osixia 1.5.0      SSSD → openldap                    │
│    localhost                          PAM: pam_env → pam_unix_oidc →     │
│  iss=localhost:8080                         pam_unix                     │
│    [MISMATCH]       ──────────────►  OIDC_ISSUER=keycloak:8080           │
│                                      UNIX_OIDC_TEST_MODE=true            │
│                                      .so volume-mounted from             │
│                                        target/release/                   │
│                                      agent binary: NOT INSTALLED         │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│           EXISTING: docker-compose.token-exchange.yaml                  │
│           Network: token-exchange                                         │
│                                                                          │
│  keycloak:26.2  (features: token-exchange,dpop)                          │
│  :8080/:9000    No KC_HOSTNAME → iss=keycloak:8080 (Docker DNS)          │
│                 Tests call via localhost:8080 (host-mapped)              │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│           EXISTING: docker-compose.ciba-integration.yaml                │
│           Network: ciba-test                                              │
│                                                                          │
│  keycloak:26.2  (features: token-exchange,dpop,ciba)                     │
│  :8080/:9000    No KC_HOSTNAME → iss=keycloak:8080 (Docker DNS)          │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│           NEW: docker-compose.e2e.yaml                                  │
│           Network: unix-oidc-e2e                                          │
│                                                                          │
│  keycloak:26.2  openldap          test-host-e2e (Ubuntu 22.04)           │
│  :8080/:9000    :389/:636         :2222 (SSH)                            │
│  KC_HOSTNAME=   (same image)      SSSD → openldap                        │
│    keycloak                       PAM stack (same config)                │
│  iss=keycloak:                    unix-oidc-agent INSTALLED              │
│    8080 [ALIGNED]                 NO UNIX_OIDC_TEST_MODE                 │
│  features: dpop                   SSH_ASKPASS=unix-oidc-agent configured │
└─────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│           NEW: Entra ID integration (external — no compose stack)       │
│                                                                          │
│  test/tests/test_entra_integration.sh                                    │
│  Live Microsoft OIDC endpoints (secrets-gated in GitHub Actions)         │
│  No DPoP from Entra (Bearer-only for v2.1 scope)                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | Status |
|-----------|----------------|--------|
| `docker-compose.test.yaml` | Primary stack: Keycloak 24 + OpenLDAP + test-host | Existing — TEST_MODE only; issuer mismatch intentionally left |
| `docker-compose.token-exchange.yaml` | Token exchange E2E: Keycloak 26.2 with dpop feature | Existing — unchanged |
| `docker-compose.ciba-integration.yaml` | CIBA + break-glass: Keycloak 26.2 with ciba | Existing — unchanged |
| `test/docker/Dockerfile.test-host` | Ubuntu 22.04 SSH host with PAM stack | Existing — MODIFY: add agent install |
| `test/docker/entrypoint.sh` | Service startup: LDAP wait, SSSD start, PAM install, sshd | Existing — MODIFY: add agent binary install |
| `unix-oidc-agent ssh-askpass` | Bridge PAM keyboard-interactive to agent IPC | Existing (`askpass.rs`) — no changes |
| `unix-oidc-agent/src/main.rs run_login()` | Device flow: authorization + token polling | Existing — MODIFY: add DPoP header to poll |
| `pam-unix-oidc/src/lib.rs notify_agent_session_closed()` | IPC SessionClosed message | Existing — MODIFY: append `\n` |
| `NEW: docker-compose.e2e.yaml` | Real-signature stack: Keycloak 26.2 + aligned issuer + agent | New |
| `NEW: test/docker/Dockerfile.test-host-e2e` | Extends test-host: agent installed, no TEST_MODE | New |
| `NEW: test/fixtures/keycloak/e2e-realm.json` | Keycloak realm with KC_HOSTNAME=keycloak aligned config | New |
| `NEW: test/e2e/playwright/` | Playwright test suite for device flow browser automation | New |
| `NEW: test/tests/test_entra_integration.sh` | Entra ID JWKS + claim mapping + PAM validation | New |
| `NEW: test/tests/test_keycloak_real_sig.sh` | SSH E2E test: agent login → SSH → PAM no TEST_MODE | New |

---

## Recommended Project Structure (Delta for v2.1)

New files slot into existing layout without restructuring:

```
unix-oidc/
├── docker-compose.test.yaml              # unchanged (TEST_MODE stack stays as-is)
├── docker-compose.token-exchange.yaml    # unchanged
├── docker-compose.ciba-integration.yaml  # unchanged
├── docker-compose.e2e.yaml               # NEW: real-signature E2E stack
│
├── test/
│   ├── docker/
│   │   ├── Dockerfile.test-host          # MODIFY: add agent install block
│   │   ├── Dockerfile.test-host-e2e      # NEW: FROM Dockerfile.test-host, no TEST_MODE
│   │   └── entrypoint.sh                 # MODIFY: install agent binary from /opt/unix-oidc/
│   │
│   ├── fixtures/
│   │   └── keycloak/
│   │       ├── unix-oidc-test-realm.json # existing — unchanged
│   │       ├── e2e-realm.json            # NEW: same as test realm but for E2E stack
│   │       └── token-exchange-test-realm.json  # existing — unchanged
│   │
│   ├── scripts/
│   │   ├── run-integration-tests.sh      # MODIFY: add E2E suite invocation (optional flag)
│   │   ├── get-test-token.sh             # unchanged (ROPC flow, host-side)
│   │   └── wait-for-healthy.sh           # unchanged
│   │
│   ├── tests/
│   │   ├── test_ssh_oidc_valid.sh        # MODIFY: use agent path when TEST_MODE=false
│   │   ├── test_dpop_e2e.sh              # MODIFY: full agent→PAM path, no key-gen workaround
│   │   ├── test_keycloak_real_sig.sh     # NEW: agent login + SSH + PAM without TEST_MODE
│   │   ├── test_entra_integration.sh     # NEW: Entra discovery + JWKS + token validation
│   │   └── ...existing tests unchanged...
│   │
│   └── e2e/
│       ├── run-e2e-tests.sh              # MODIFY: invoke Playwright for CI (not just instructions)
│       ├── test-device-flow-e2e.sh       # MODIFY: write URI to tmpfile for Playwright coordination
│       └── playwright/
│           ├── package.json              # NEW: {"devDependencies": {"@playwright/test": "^1.50"}}
│           ├── playwright.config.ts      # NEW: headless Chromium, CI timeouts
│           └── tests/
│               └── device-flow.spec.ts  # NEW: navigate Keycloak login, complete consent
│
└── .github/workflows/
    ├── ci.yml                            # MODIFY: add keycloak-e2e job
    └── provider-tests.yml               # MODIFY: add entra-integration job
```

### Structure Rationale

- **Separate compose file for E2E:** Keeps `docker-compose.test.yaml` working without change.
  Contributors who only have access to Keycloak 24 or need the TEST_MODE path are unaffected.
  The E2E stack uses Keycloak 26.2 (same image as token-exchange) with KC_HOSTNAME=keycloak.

- **Separate Dockerfile for E2E test-host:** The existing Dockerfile hard-wires UNIX_OIDC_TEST_MODE
  in entrypoint.sh via environment passthrough. A derived image (`Dockerfile.test-host-e2e`) omits
  TEST_MODE and installs the agent binary from the volume mount. Both Dockerfiles share the same
  base image layer cache (Ubuntu 22.04 + apt packages).

- **Playwright in `test/e2e/playwright/`:** The existing `run-e2e-tests.sh` emits structured text
  instructions for Claude Code's interactive Playwright MCP session. For CI, a proper `@playwright/test`
  spec in a subdirectory runs headlessly and exits with a pass/fail code. Both coexist.

- **Entra as shell test, not compose:** Entra ID cannot run locally. The test calls live Microsoft
  endpoints, identical in pattern to the existing `auth0` and `google` jobs in `provider-tests.yml`.

---

## Architectural Patterns

### Pattern 1: Issuer URL Alignment via KC_HOSTNAME

**What:** Keycloak embeds its URL in every JWT `iss` claim. The PAM module validates `iss`
against `OIDC_ISSUER`. Mismatch = immediate validation failure.

**The blocker in `docker-compose.test.yaml`:**
```
Keycloak: KC_HOSTNAME=localhost  →  iss=http://localhost:8080/realms/unix-oidc-test
PAM:      OIDC_ISSUER=http://keycloak:8080/realms/unix-oidc-test  (Docker DNS)
Result:   FAIL — strings do not match
```

**Fix in `docker-compose.e2e.yaml`:**
```yaml
keycloak:
  environment:
    KC_HOSTNAME: keycloak          # iss becomes http://keycloak:8080/... (Docker DNS)
    KC_HOSTNAME_PORT: "8080"
    KC_HOSTNAME_STRICT: "false"
    KC_HOSTNAME_STRICT_HTTPS: "false"
    KC_HTTP_ENABLED: "true"

test-host-e2e:
  environment:
    OIDC_ISSUER: "http://keycloak:8080/realms/unix-oidc-test"   # matches KC_HOSTNAME
```

**Do not change `docker-compose.test.yaml`.** Changing KC_HOSTNAME there breaks the TEST_MODE
stack's UI accessibility from the CI host. Instead, accept that the existing stack remains TEST_MODE
only and introduce the aligned issuer in the new E2E compose file.

**Agent login from CI host:** The agent binary runs on the CI runner host, not inside the Docker
network. The CI runner cannot resolve `keycloak` by DNS. Two options:
1. Run `unix-oidc-agent login` via `docker compose exec test-host-e2e` — agent runs inside the
   network where `keycloak` DNS resolves correctly. Preferred for v2.1.
2. Add `extra_hosts: ["keycloak:127.0.0.1"]` to the test-host-e2e service and map port 8080 to
   the host. Agent runs on CI host, resolves `keycloak` via `/etc/hosts`. More complex.

**Trade-offs:** Option 1 (exec inside container) is simpler and avoids port collision with the
existing test stack. Option 2 (host-side agent) exercises the more realistic user deployment
scenario (agent on developer machine, PAM on server).

### Pattern 2: Agent Binary in test-host via Volume Mount

**What:** The test-host mounts `./target/release:/opt/unix-oidc:ro`. The entrypoint copies
`libpam_unix_oidc.so` to `/lib/security/`. The `unix-oidc-agent` binary sits in the same
volume but is never installed.

**Fix in `test/docker/entrypoint.sh`** (applies to both test-host and test-host-e2e):

```bash
# After PAM module install block (line 41)
if [ -f /opt/unix-oidc/unix-oidc-agent ]; then
    cp /opt/unix-oidc/unix-oidc-agent /usr/local/bin/unix-oidc-agent
    chmod 755 /usr/local/bin/unix-oidc-agent
    echo "Agent binary installed: $(unix-oidc-agent --version 2>&1 | head -1)"
fi
```

**SSH_ASKPASS wiring:** The agent's `ssh-askpass` subcommand (`askpass.rs`) already implements
the full three-prompt PAM conversation handler. It is invoked as a subprocess by SSH when:
```bash
export SSH_ASKPASS=/usr/local/bin/unix-oidc-agent
export SSH_ASKPASS_REQUIRE=force
```
These must be set in the E2E test script's environment before invoking `ssh`. They are not
server-side configuration; they are client-side.

**Trade-offs:** The volume mount approach avoids rebuilding Docker images per commit. For CI,
the `build-matrix` job uploads `target/release/` artifacts; the `keycloak-e2e` job restores
them before starting the compose stack. This is the reason `keycloak-e2e` must `needs: build-matrix`.

### Pattern 3: DPoP Header in Device Flow Token Poll

**What:** RFC 9449 §9 requires that when the AS supports DPoP and the client has a DPoP key,
all token requests (including device flow polling) must include a `DPoP` header with a fresh proof.

**The blocker:** `run_login()` in `unix-oidc-agent/src/main.rs` lines 842-857 sends bare
`form(&token_params)` POST requests with no `DPoP` header:

```rust
// Current — missing DPoP header
let response = http_client
    .post(&token_endpoint)
    .form(&token_params)   // no .header("DPoP", ...)
    .send()?;
```

**Consequence:** Keycloak 26.2 with `--features=dpop` will either:
- Issue a plain bearer token without `cnf.jkt` (DPoP binding not enforced at token issuance), or
- Reject the request if the realm is configured to require DPoP on token requests.

Either way, the PAM module's DPoP validation path cannot be exercised end-to-end.

**Fix — generate proof inside the poll loop:**

```rust
// In run_login() poll loop, after computing token_params
let dpop_proof = signer.sign_proof(
    "POST",
    &token_endpoint,
    None,  // no server nonce at device flow token acquisition
)?;

let response = http_client
    .post(&token_endpoint)
    .header("DPoP", dpop_proof)
    .form(&token_params)
    .send()?;
```

**Critical constraint:** The `DPoP` proof must be fresh per request — new `jti` (UUID) and current
`iat`. Generate inside the poll loop, not once before it. The `signer` variable is constructed
before the `spawn_blocking` closure (line 654+) and must be moved into the closure.

**Trade-offs:** This fix enables DPoP-bound tokens from Keycloak. It also means the E2E test
requires the agent to have an active DPoP key before polling (i.e., `run_login` must successfully
initialize the signer, which happens before the polling loop begins).

### Pattern 4: Playwright for Device Flow Automation in CI

**What:** Device flow (RFC 8628) requires a human to open a URL, enter a code, and log in.
In CI this must be automated. The existing `run-e2e-tests.sh` emits structured text instructions
(`PLAYWRIGHT_AUTOMATION_START ... PLAYWRIGHT_AUTOMATION_END`) for Claude Code's interactive MCP
session. This pattern does not work in GitHub Actions.

**Recommended approach:** `@playwright/test` with headless Chromium, coordinated with the shell
poll loop via a tmpfile.

```
Shell script (test-device-flow-e2e.sh)                 Playwright spec (device-flow.spec.ts)
─────────────────────────────────────────              ──────────────────────────────────────
1. POST /auth/device → device_code, user_code,
   verification_uri_complete
2. Write verification_uri_complete to
   /tmp/unix-oidc-e2e-uri                  ────────►  3. Poll /tmp/unix-oidc-e2e-uri until present
                                                       4. Navigate to verification_uri_complete
                                                       5. Fill username: testuser, password: testpass
                                                       6. Click login button
                                                       7. Grant consent if prompted
                                                       8. Wait for "Device Login Successful" page
                                                       9. Exit 0
4. Poll /token with device_code  ◄────────
   (authorization_pending until step 9)
5. Receive token response (after Playwright
   completes consent)
6. Store token, complete login
```

**GitHub Actions integration:**

```yaml
- name: Install Playwright
  run: |
    cd test/e2e/playwright
    npm ci
    npx playwright install --with-deps chromium

- name: Cache Playwright browsers
  uses: actions/cache@v5
  with:
    path: ~/.cache/ms-playwright
    key: playwright-chromium-${{ hashFiles('test/e2e/playwright/package-lock.json') }}

- name: Run E2E test with Playwright
  run: |
    # Start device flow poll (writes URI to tmpfile, polls for token)
    bash test/e2e/test-device-flow-e2e.sh &
    POLL_PID=$!
    # Playwright reads tmpfile and completes browser consent
    npx --prefix test/e2e/playwright playwright test
    wait $POLL_PID
```

**Playwright spec skeleton (`test/e2e/playwright/tests/device-flow.spec.ts`):**

```typescript
import { test, expect } from '@playwright/test';
import * as fs from 'fs';

test('Keycloak device flow consent', async ({ page }) => {
  // Wait for shell script to write the verification URI
  const uriFile = '/tmp/unix-oidc-e2e-uri';
  let verificationUri = '';
  for (let i = 0; i < 30; i++) {
    if (fs.existsSync(uriFile)) {
      verificationUri = fs.readFileSync(uriFile, 'utf-8').trim();
      break;
    }
    await page.waitForTimeout(2000);
  }
  expect(verificationUri).toBeTruthy();

  await page.goto(verificationUri);
  await page.fill('#username', 'testuser');
  await page.fill('#password', 'testpass');
  await page.click('[type=submit]');
  // Keycloak consent page
  await page.click('[name=accept]').catch(() => {}); // optional consent
  await expect(page).toHaveURL(/.*device.*success.*/i, { timeout: 15000 });
});
```

**Trade-offs:** Playwright adds ~2 minutes to CI (browser download + startup). Cache
`~/.cache/ms-playwright` across runs. Use only Chromium (not Firefox/WebKit) to minimize cache size.
Playwright selectors for Keycloak's login form must be verified against Keycloak 26.2's actual HTML
— selector names changed between Keycloak 24 and 26.

### Pattern 5: Entra ID Integration Without Local IdP

**What:** Azure Entra ID cannot run locally. Testing requires a live tenant and app registration.
The v2.1 scope is: OIDC discovery validation, JWKS fetch, token acquisition via client credentials,
PAM module validation of a real Entra JWT.

**Token characteristics for PAM validation (Entra-specific):**
- `iss`: `https://login.microsoftonline.com/{tenant-id}/v2.0` — PAM must be configured with
  this exact string as `OIDC_ISSUER`.
- Algorithm: RS256 (RSA) — Entra does not use EC keys. The PAM JWKS validator already handles
  RSA via `jsonwebtoken`; no code change needed.
- `preferred_username`: UPN format (`user@tenant.onmicrosoft.com`) — requires username mapping
  config to convert to Unix username. Already implemented in v2.0.
- DPoP: Not supported by Entra as of v2.1 scope — configure `dpop_required=Disabled` in the
  test fixture policy.yaml.

**Test script pattern** (mirrors existing `auth0` job in `provider-tests.yml`):

```bash
# test/tests/test_entra_integration.sh
TENANT_ID="${ENTRA_TENANT_ID:?required}"
CLIENT_ID="${ENTRA_CLIENT_ID:?required}"
CLIENT_SECRET="${ENTRA_CLIENT_SECRET:?required}"

# Step 1: OIDC discovery
DISCOVERY=$(curl -sf \
  "https://login.microsoftonline.com/${TENANT_ID}/v2.0/.well-known/openid-configuration")
JWKS_URI=$(echo "$DISCOVERY" | jq -r .jwks_uri)

# Step 2: JWKS validation
KEY_COUNT=$(curl -sf "$JWKS_URI" | jq '.keys | length')
[ "$KEY_COUNT" -gt 0 ] || { echo "FAIL: no keys in JWKS"; exit 1; }

# Step 3: Token acquisition (client credentials — no browser required)
TOKEN_RESPONSE=$(curl -sf -X POST \
  "https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=https://graph.microsoft.com/.default")
ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)

# Step 4: PAM validation (cargo integration test with pre-issued token)
OIDC_ISSUER="https://login.microsoftonline.com/${TENANT_ID}/v2.0" \
OIDC_CLIENT_ID="${CLIENT_ID}" \
OIDC_TOKEN="${ACCESS_TOKEN}" \
cargo test -p pam-unix-oidc --test integration -- entra_token_validates
```

**Limitation:** Client credentials tokens have `sub` = client ID, not a user. `preferred_username`
claim may be absent. The PAM validation test should accept a pre-issued token and verify that
signature and issuer checks pass, without requiring a resolvable Unix user.

**Trade-offs:** Testing without a real user means group policy and username mapping are tested
separately (unit tests). The integration test confirms JWKS signature verification works with
Entra's RS256 keys and issuer string matching works with Entra's `iss` format.

### Pattern 6: PAM Conversation Buffer Constraint

**What:** The PAM keyboard-interactive conversation has a buffer limit, documented in the
codebase at `pam-unix-oidc/src/lib.rs` line 772:
```
// Note: PAM conversation has a ~512 byte buffer limit, which is insufficient
// for JWT tokens (~1400+ bytes). For production use, pass tokens via environment
// variables or use the unix-oidc-agent with SSH_ASKPASS.
```

**Impact on E2E design:** The E2E test must use the agent `ssh-askpass` path, not raw
keyboard-interactive token delivery. The `askpass.rs` handler handles all three prompts:
1. `DPOP_NONCE:<value>` — nonce delivery (short, within buffer)
2. `DPOP_PROOF: ` — DPoP proof (~400-600 bytes, may approach limit depending on claims)
3. `OIDC Token: ` — access token (~1400 bytes, exceeds 512 bytes)

For prompt 3, PAM's `get_auth_token()` falls back to reading from the agent IPC rather than
the PAM conversation buffer when the agent is running. The E2E test must start the agent daemon
(`unix-oidc-agent serve`) before initiating the SSH session so the `GetProof` IPC is available.

**E2E test sequence:**
```bash
# Inside test-host-e2e container:
1. unix-oidc-agent login --issuer http://keycloak:8080/...   # acquire + store token
2. unix-oidc-agent serve &                                    # start IPC daemon
3. export SSH_ASKPASS=/usr/local/bin/unix-oidc-agent
4. export SSH_ASKPASS_REQUIRE=force
5. ssh -o PreferredAuthentications=keyboard-interactive \
       -p 2222 testuser@localhost whoami
```

---

## Data Flow

### Real-Signature SSH Login (v2.1 Target)

```
[Step 1: Token acquisition — inside test-host-e2e container]

unix-oidc-agent login --issuer http://keycloak:8080/realms/unix-oidc-test
    │
    ├── POST /auth/device → device_code, verification_uri_complete
    │   (Playwright completes browser consent at verification_uri_complete)
    │
    ├── Poll /token with DPoP header (NEW — currently missing)
    │   DPoP proof: POST keycloak:8080 no nonce, fresh jti+iat per attempt
    │
    └── receive: access_token with cnf.jkt claim (DPoP-bound)
        store in agent storage (SecretString + ProtectedSigningKey)

[Step 2: Agent daemon]

unix-oidc-agent serve  (background)
    └── listening on Unix socket: /run/user/{uid}/unix-oidc-agent.sock

[Step 3: SSH login flow]

SSH client:
  SSH_ASKPASS=unix-oidc-agent, SSH_ASKPASS_REQUIRE=force
  ssh -o PreferredAuthentications=keyboard-interactive testuser@localhost:2222
      │
      ▼ sshd → PAM keyboard-interactive conversation
      │
PAM round 1: pam_unix_oidc issues nonce via issue_and_deliver_nonce()
  prompt: "DPOP_NONCE:<32-char-nonce>"
      │
SSH spawns: unix-oidc-agent ssh-askpass "DPOP_NONCE:<nonce>"
  askpass.rs: writes nonce to /tmp/.unix-oidc-nonce-{PPID}
  returns: "" (empty — nonce was the notification, not a question)
      │
PAM round 2: prompts "DPOP_PROOF: "
SSH spawns: unix-oidc-agent ssh-askpass "DPOP_PROOF: "
  askpass.rs:
    reads nonce from /tmp/.unix-oidc-nonce-{PPID}
    IPC GetProof { nonce } → agent daemon → DPoP proof + access_token
    writes access_token to /tmp/.unix-oidc-token-{PPID}
  returns: <DPoP-proof-JWT> (~400 bytes)
      │
PAM round 3: prompts "OIDC Token: "
SSH spawns: unix-oidc-agent ssh-askpass "OIDC Token: "
  askpass.rs:
    reads token from /tmp/.unix-oidc-token-{PPID}
  returns: <access-token-JWT> (~1400 bytes)
      │
PAM validates:
  ├── fetch JWKS from http://keycloak:8080/realms/.../protocol/openid-connect/certs
  ├── verify JWT signature with Keycloak's real EC key (no TEST_MODE)
  ├── verify iss == "http://keycloak:8080/realms/unix-oidc-test" (ALIGNED)
  ├── verify DPoP proof: cnf.jkt matches thumbprint, jti not replayed
  ├── verify user exists via SSSD → OpenLDAP → testuser UID
  └── PAM_SUCCESS → sshd grants session
```

### Issuer URL Resolution: Current Stacks vs. E2E Stack

```
EXISTING docker-compose.test.yaml (BROKEN for real-sig, kept as-is):
  Keycloak: KC_HOSTNAME=localhost  →  iss = http://localhost:8080/realms/...
  PAM env:  OIDC_ISSUER=http://keycloak:8080/realms/...
  Result:   MISMATCH — TEST_MODE required to bypass validation

NEW docker-compose.e2e.yaml (ALIGNED):
  Keycloak: KC_HOSTNAME=keycloak   →  iss = http://keycloak:8080/realms/...
  PAM env:  OIDC_ISSUER=http://keycloak:8080/realms/...
  Result:   MATCH — real signature validation works

Agent login (exec inside test-host-e2e):
  Uses Docker DNS: keycloak:8080  →  ALIGNED with token iss claim
  No extra_hosts needed on CI runner
```

### SessionClosed IPC: Current Bug and Fix

```
Current (BROKEN — from v2.0 audit):
  pam-unix-oidc/src/lib.rs notify_agent_session_closed():
    stream.write_all(json_bytes)    ← no trailing \n
    Agent's BufReader::read_line() blocks forever
    cleanup_session() never fires

Fix (one-line change):
  stream.write_all(json_bytes)?;
  stream.write_all(b"\n")?;        ← append newline

Reference: sudo.rs send_ipc_message() already does this correctly
Affected requirements: SES-04, SES-07, SES-08
```

---

## Build Order for v2.1

Dependencies drive the order within and across phases. All phases produce committed, tested code.

### Build Order: Blocker Fixes First (Phase 1 of v2.1)

These fixes are prerequisites for any real-signature E2E test to pass. They are independent of
each other and can be developed in parallel.

```
Fix A: Issuer URL mismatch
  New file: docker-compose.e2e.yaml (KC_HOSTNAME=keycloak)
  New file: test/fixtures/keycloak/e2e-realm.json
  Verify: keycloak container iss claim matches OIDC_ISSUER in test-host env

Fix B: Agent binary not installed
  Modify: test/docker/entrypoint.sh (add unix-oidc-agent install block)
  Verify: docker compose exec test-host unix-oidc-agent --version

Fix C: DPoP header missing from device flow token poll
  Modify: unix-oidc-agent/src/main.rs run_login() poll loop
  Add: .header("DPoP", signer.sign_proof("POST", &token_endpoint, None)?)
  Verify: cargo test -p unix-oidc-agent -- device_flow (existing + new test)

Fix D: SessionClosed IPC missing newline
  Modify: pam-unix-oidc/src/lib.rs notify_agent_session_closed()
  Add: stream.write_all(b"\n")?;
  Verify: cargo test -p pam-unix-oidc -- session_close (new test)
```

### Build Order: Infrastructure (Phase 2 of v2.1)

After blockers are fixed, the E2E infrastructure can be assembled and validated independently
of the full SSH test.

```
Phase 2a: New compose stack validation
  docker-compose.e2e.yaml up
  Verify Keycloak health, LDAP health, test-host-e2e SSH reachable
  Verify iss claim in Keycloak tokens matches OIDC_ISSUER

Phase 2b: Playwright automation
  test/e2e/playwright/ package.json, config, spec
  Verify: Playwright can complete Keycloak login in headless mode
  Verify: tmpfile coordination between shell poll and Playwright works

Phase 2c: Agent login inside container
  docker compose exec test-host-e2e unix-oidc-agent login ...
  Playwright completes consent
  Verify: token acquired with cnf.jkt claim present
```

### Build Order: Full E2E Tests (Phase 3 of v2.1)

```
Phase 3a: SSH E2E with agent + real signatures
  test/tests/test_keycloak_real_sig.sh
  Sequence: agent login → agent serve → SSH with SSH_ASKPASS → PAM validates

Phase 3b: CI job
  .github/workflows/ci.yml: add keycloak-e2e job
  needs: [check, build-matrix]
  Restores build artifacts before starting compose
```

### Build Order: Entra ID (Phase 4 of v2.1)

```
Phase 4: Entra integration (independent of E2E stack)
  test/tests/test_entra_integration.sh
  cargo integration test: entra_token_validates (pre-issued token path)
  .github/workflows/provider-tests.yml: add entra-integration job (secrets-gated)
```

### GitHub Actions Job Graph

```
┌────────┐   ┌─────────────┐
│ check  │   │build-matrix │ (ubuntu-22.04 + ubuntu-24.04 + macos-aarch64)
└───┬────┘   └──────┬──────┘
    │               │ uploads: libpam_unix_oidc.so + unix-oidc-agent
    ▼               ▼
┌──────────────────────────────────────────────────────────────┐
│  integration      token-exchange    ciba-integration          │
│  (TEST_MODE)      (existing)        (existing)               │
│                                                              │
│  keycloak-e2e ─── needs: check + build-matrix               │
│  (NEW: real-sig)  downloads artifact → compose up → E2E      │
└──────────────────────────────────────────────────────────────┘

provider-tests.yml (separate workflow):
  keycloak / auth0 / google (existing)
  entra-integration (NEW, secrets-gated — skipped on fork PRs)
```

**Why `keycloak-e2e` needs `build-matrix`:** The E2E compose stack mounts `./target/release/`
as a volume. In GitHub Actions, each job runs on a fresh runner. The `build-matrix` job for
`ubuntu-22.04` produces the release binaries and uploads them as an artifact. The `keycloak-e2e`
job downloads that artifact and restores it to `target/release/` before `docker compose up`.
This avoids a fourth parallel `cargo build --release` and tests the exact binary the
`build-matrix` job would release.

---

## Integration Points

### New Components Integrate With Existing Architecture

| Boundary | Integration Pattern | Notes |
|----------|---------------------|-------|
| `docker-compose.e2e.yaml` → `test-host-e2e` | Same volume mount: `./target/release:/opt/unix-oidc:ro` | Both binaries present after `build-matrix` artifact restore |
| `test-device-flow-e2e.sh` → Playwright | Tmpfile: shell writes `verification_uri_complete`, Playwright reads | No IPC, no stdout parsing; tmpfile scoped per CI run |
| `unix-oidc-agent ssh-askpass` → PAM prompts | SSH spawns per-prompt; PPID-keyed tmpfiles for nonce/token state | Already implemented in `askpass.rs` — no changes needed |
| Entra test → PAM validation | `cargo test --test integration -- entra_token_validates` with pre-issued token via env | Needs new integration test harness that accepts external token |
| DPoP proof → Keycloak 26.2 `--features=dpop` | `DPoP` header added to device flow token poll `POST` | One-location change in `unix-oidc-agent/src/main.rs` |
| `SessionClosed` IPC → agent `BufReader::read_line()` | Append `\n` to `notify_agent_session_closed()` JSON payload | One-line fix; agent's read_line() will unblock |

### New vs. Modified vs. Unchanged Components

| Component | Action | Why |
|-----------|--------|-----|
| `docker-compose.e2e.yaml` | NEW | Real-signature stack with aligned issuer |
| `test/docker/Dockerfile.test-host-e2e` | NEW | No TEST_MODE, agent binary installed |
| `test/fixtures/keycloak/e2e-realm.json` | NEW | Realm config for KC_HOSTNAME=keycloak stack |
| `test/e2e/playwright/` | NEW | CI-compatible Playwright automation (was manual instructions) |
| `test/tests/test_keycloak_real_sig.sh` | NEW | SSH E2E without TEST_MODE |
| `test/tests/test_entra_integration.sh` | NEW | Entra ID JWKS + token validation |
| `test/docker/entrypoint.sh` | MODIFY | Install agent binary from volume mount |
| `unix-oidc-agent/src/main.rs` `run_login()` | MODIFY | DPoP header in device flow poll |
| `pam-unix-oidc/src/lib.rs` `notify_agent_session_closed()` | MODIFY | Append `\n` to IPC message |
| `.github/workflows/ci.yml` | MODIFY | Add `keycloak-e2e` job |
| `.github/workflows/provider-tests.yml` | MODIFY | Add `entra-integration` job |
| `docker-compose.test.yaml` | UNCHANGED | TEST_MODE stack stays as-is |
| `docker-compose.token-exchange.yaml` | UNCHANGED | No dependency on E2E changes |
| `docker-compose.ciba-integration.yaml` | UNCHANGED | No dependency on E2E changes |
| `unix-oidc-agent/src/askpass.rs` | UNCHANGED | Already implements full 3-prompt handler |
| `pam-unix-oidc/src/oidc/dpop.rs` | UNCHANGED | DPoP validation is correct |
| `pam-unix-oidc/src/oidc/validation.rs` | UNCHANGED | Token validation is correct |

---

## Anti-Patterns

### Anti-Pattern 1: Running Real-Signature Tests Against the Existing Compose Stack

**What people do:** Set `UNIX_OIDC_TEST_MODE=false` in the existing `docker-compose.test.yaml`
environment block and expect real-signature validation to work.

**Why it's wrong:** The issuer URL mismatch (`KC_HOSTNAME=localhost` → `iss=http://localhost:8080/...`
vs. `OIDC_ISSUER=http://keycloak:8080/...`) causes validation to fail at the `iss` string comparison
before signature verification is reached. The failure message "invalid issuer" is misleading when the
root cause is a Keycloak hostname configuration issue. Changing `KC_HOSTNAME` in the existing stack
breaks the existing test suite's assumptions.

**Do this instead:** Introduce `docker-compose.e2e.yaml` with `KC_HOSTNAME=keycloak`. Leave the
existing stack untouched. Both stacks coexist.

### Anti-Pattern 2: Playwright Coordinating Via stdout Parsing

**What people do:** The existing `run-e2e-tests.sh` emits `PLAYWRIGHT_AUTOMATION_START ... END`
blocks. An outer process is expected to parse stdout and execute Playwright commands.

**Why it's wrong:** This is the Claude Code interactive session pattern for developer convenience.
In GitHub Actions, no process interprets stdout. The CI job would see the text and not automate
the browser. The device flow code would time out waiting for consent.

**Do this instead:** A proper `@playwright/test` spec that runs headlessly. Use a tmpfile to
pass the `verification_uri_complete` URL from the shell script to the Playwright spec. Both run
concurrently; Playwright reads the URI file and proceeds autonomously.

### Anti-Pattern 3: Simulating Entra Tokens with Keycloak

**What people do:** Configure Keycloak to issue tokens with Entra-style claims and test Entra
compatibility against that.

**Why it's wrong:** Entra tokens carry Microsoft-specific claims (`tid`, `oid`, `ver`), UPN-format
`preferred_username`, RS256 signatures from Microsoft's key infrastructure, and a tenant-specific
`iss` URL. No local IdP accurately replicates this. A Keycloak fake gives false confidence and
misses real quirks (e.g., Entra's JWKS endpoint rotation schedule, `x5c` certificate chains in
JWKS keys, specific `aud` formats).

**Do this instead:** Test against real Entra endpoints. Gate on GitHub Actions secrets. Accept that
fork PRs cannot run this test (same pattern as Auth0 in the existing `provider-tests.yml`).

### Anti-Pattern 4: Merging Compose Stacks to Reduce Startup Overhead

**What people do:** Combine E2E, token-exchange, and CIBA stacks into a single Keycloak instance
to reduce startup time.

**Why it's wrong:** The base integration stack requires Keycloak 24 (no DPoP feature). The E2E
and token-exchange stacks require Keycloak 26.2 with DPoP. The CIBA stack requires the CIBA
feature. A shared instance would need Keycloak 26.2 with all features, which changes the test
assumptions for the existing Keycloak 24 test suite and creates feature flag conflicts.

**Do this instead:** Keep stacks isolated. In GitHub Actions, jobs run in parallel on separate
runners. The startup overhead is per-job, not sequential across jobs.

### Anti-Pattern 5: Generating DPoP Proof Once Before the Poll Loop

**What people do:** When adding DPoP to the device flow poll, generate a single proof before
the loop and reuse it across all poll attempts.

**Why it's wrong:** RFC 9449 §4.2 requires each proof to have a unique `jti` claim and a current
`iat`. Reusing the same proof is a replay — the authorization server's JTI cache will reject the
second use of the same proof. The poll loop may make 10-30 requests; each needs a fresh proof.

**Do this instead:** Call `signer.sign_proof(...)` inside the poll loop, once per iteration,
immediately before the HTTP POST.

---

## Scaling Considerations

These concern CI scale, not production scale.

| Concern | Current | With v2.1 |
|---------|---------|-----------|
| CI job count | 11 in `ci.yml` + 4 in `provider-tests.yml` | +2 jobs (`keycloak-e2e`, `entra-integration`) |
| CI wall time | ~8 min (integration + token-exchange are critical path) | E2E job: ~10-12 min (Playwright adds 2-3 min) |
| Docker image pull | Keycloak images ~1.2 GB each, pulled fresh per job | No change — consider `docker pull` caching via `actions/cache` on disk |
| Playwright browser | Not used | ~400 MB Chromium; cache `~/.cache/ms-playwright` keyed on Playwright version |
| Artifact dependency | Every job rebuilds from source | `keycloak-e2e` downloads `build-matrix` artifact — eliminates 4th parallel build |
| Keycloak startup | 30s health check per stack | No change — already accounted for |

---

## Sources

- `docker-compose.test.yaml` — direct inspection: KC_HOSTNAME=localhost, UNIX_OIDC_TEST_MODE=true, OIDC_ISSUER=keycloak:8080 (mismatch confirmed)
- `docker-compose.e2e.yaml` (does not exist yet) — pattern derived from token-exchange and ciba stacks
- `test/docker/Dockerfile.test-host` — direct inspection: agent binary absent from install block
- `test/docker/entrypoint.sh` — direct inspection: PAM .so installed, agent binary not installed
- `unix-oidc-agent/src/main.rs` lines 842-857 — direct inspection: DPoP header absent from poll POST
- `unix-oidc-agent/src/askpass.rs` — direct inspection: full 3-prompt handler implemented
- `pam-unix-oidc/src/lib.rs` lines 772-775 — direct inspection: ~512 byte buffer limit documented
- `.planning/v2.0-MILESTONE-AUDIT.md` — authoritative source for IPC missing newline, DPoP nonce handler gap, flow status
- `.github/workflows/ci.yml` — direct inspection: job graph, artifact upload pattern
- `.github/workflows/provider-tests.yml` — direct inspection: auth0/google pattern to replicate for Entra
- RFC 8628 §3.4 (Device Access Token Request): https://www.rfc-editor.org/rfc/rfc8628#section-3.4
- RFC 9449 §4.2 (DPoP Proof JWT Syntax — jti uniqueness): https://www.rfc-editor.org/rfc/rfc9449#section-4.2
- Keycloak 26.2 documentation, KC_HOSTNAME configuration: https://www.keycloak.org/server/hostname
- Playwright `@playwright/test` — headless Chromium in GitHub Actions: https://playwright.dev/docs/ci-github-actions
- Microsoft Entra ID OIDC: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc

---
*Architecture research for: unix-oidc v2.1 E2E integration testing infrastructure*
*Researched: 2026-03-13*
