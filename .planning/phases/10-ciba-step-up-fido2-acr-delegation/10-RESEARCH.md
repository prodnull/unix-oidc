# Phase 10: CIBA Step-Up + FIDO2 via ACR Delegation - Research

**Researched:** 2026-03-10
**Domain:** CIBA (RFC draft / OpenID CIBA Core 1.0), OIDC ACR/EAP ACR Values, PAM IPC extension, Rust async polling
**Confidence:** HIGH (protocol spec verified against openid.net; IdP behavior MEDIUM for non-Keycloak IdPs)

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| STP-01 | CIBA poll-mode step-up implemented in agent daemon (not PAM thread) | Async tokio task in daemon; PAM thread sends IPC StepUp request and receives StepUpPending, polls agent for StepUpComplete |
| STP-02 | CIBA binding_message carries the command being authorized for phishing context | CIBA §7.1 `binding_message` parameter; recommended short plaintext string displayed on authenticator app |
| STP-03 | CIBA backchannel discovery from IdP OIDC metadata (backchannel_authentication_endpoint) | Extend OidcDiscovery struct to include `backchannel_authentication_endpoint` and `backchannel_token_delivery_modes_supported` |
| STP-04 | FIDO2 step-up via CIBA ACR delegation (request phishing-resistant ACR; validate acr claim in result token) | OpenID EAP ACR 1.0 defines `phr`/`phrh` URIs; acr claim validation is RP responsibility post-token |
| STP-05 | Step-up IPC protocol extensions (StepUp, StepUpPending, StepUpComplete messages) | Extend `protocol.rs` AgentRequest/AgentResponse enums; no new socket infrastructure needed |
| STP-06 | IdP discovery-based endpoint resolution replacing Keycloak-hardcoded device flow URLs | `DeviceFlowClient::new()` currently hardcodes `/protocol/openid-connect/auth/device`; must fetch from discovery |
| STP-07 | Configurable step-up timeout for CIBA polling (default 120s) | `SudoConfig.challenge_timeout` already exists (currently used by device flow); extend for CIBA path |
</phase_requirements>

---

## Summary

Phase 10 introduces CIBA (Client-Initiated Backchannel Authentication) poll mode as the step-up mechanism for `sudo` authorization, replacing the interactive device-flow prompt. The critical architectural constraint is that all CIBA polling MUST live in the agent daemon, never in the PAM thread — this prevents `sshd`'s `LoginGraceTime` (and `pam_sm_chauthtok` blocking time) from expiring during the user's approval wait.

The flow is: PAM calls agent via IPC `StepUp` request → agent initiates CIBA backchannel auth request → agent spawns async poll loop → agent immediately returns `StepUpPending{auth_req_id}` to PAM → PAM thread polls agent IPC for `StepUpComplete` or `StepUpTimedOut` → PAM returns PAM_SUCCESS or PAM_AUTH_ERR. The user sees a push notification on their phone (or FIDO2 authenticator prompt from the IdP); they approve; the agent's poll loop receives the token; agent validates ACR claim; agent delivers result to waiting PAM caller.

FIDO2 step-up is not a new client-side transport — there is no libfido2/CTAP2 in this phase. FIDO2 is achieved by ACR delegation: send `acr_values=http://schemas.openid.net/pape/policies/2007/06/phishing-resistant` (phr) or the `phrh` variant to the IdP in the CIBA request, and the IdP's authentication flow triggers FIDO2 on the user's registered authenticator device. The returned token's `acr` claim is then validated to confirm the IdP honored the request.

**Primary recommendation:** Implement `CibaClient` in a new `pam-unix-oidc/src/ciba/` module (discovery, backchannel request, poll loop), extend agent IPC with `StepUp`/`StepUpPending`/`StepUpComplete`/`StepUpTimedOut` messages, and fix `DeviceFlowClient::new()` to use OIDC discovery endpoints.

---

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| reqwest (blocking) | 0.11 (existing) | HTTP for CIBA backchannel request and token polling | Already in pam-unix-oidc; blocking fits PAM's synchronous model for the request phase |
| reqwest (async) | 0.11 (existing in agent) | Async token polling loop in agent daemon | tokio runtime already present in unix-oidc-agent |
| tokio | 1 (existing) | Async poll loop and timeout in agent daemon | Already powering the agent's socket server |
| serde_json | existing | Parse CIBA auth response and token response | Already in use throughout |
| moka | 0.12 (existing) | Not needed for CIBA itself (no new cache) | Agent state holds auth_req_id in memory only |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| tokio::time::interval + tokio::time::timeout | tokio 1 | Drive CIBA poll loop with timeout bound | Used inside the agent's async CibaPoller task |
| uuid | 1 (existing) | Generate correlation IDs for step-up sessions | Already used for session IDs |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Direct CTAP2/libfido2 | ACR delegation via CIBA | Deferred to v2.1; ACR delegation works with any FIDO2-supporting IdP without adding C FFI deps |
| Push/ping CIBA modes | Poll mode only | Push/ping require the PAM host to expose an HTTP endpoint — structurally incompatible |
| New crate for CIBA | Extend existing device_flow module | CIBA is a separate grant type and protocol; a dedicated `ciba/` module keeps concerns separated |

**Installation:** No new dependencies required. All needed libraries are already in Cargo.toml for both crates.

---

## Architecture Patterns

### Recommended Project Structure

New files needed:

```
pam-unix-oidc/src/
├── ciba/
│   ├── mod.rs          # pub use; CibaClient, CibaError
│   ├── client.rs       # CibaClient: discover endpoints, send backchannel request
│   └── types.rs        # BackchannelAuthResponse, CibaTokenResponse, CibaError
├── oidc/
│   └── jwks.rs         # extend OidcDiscovery to include CIBA fields
└── device_flow/
    └── client.rs       # fix: use discovery endpoints instead of hardcoded Keycloak paths (STP-06)

unix-oidc-agent/src/daemon/
├── protocol.rs         # add StepUp, StepUpPending, StepUpComplete, StepUpTimedOut
└── socket.rs           # handle StepUp IPC: spawn CibaPoller task, return StepUpPending
```

### Pattern 1: CIBA Backchannel Request + Poll (Agent-side)

**What:** Agent receives `StepUp` IPC, sends CIBA backchannel auth request to IdP, spawns async poll loop as Tokio task, immediately responds `StepUpPending{auth_req_id, expires_in}`. Poll loop drives token retrieval; when complete, stores result in AgentState for PAM to retrieve via `StepUpResult` IPC.

**When to use:** All `StepUpMethod::Push` and `StepUpMethod::Fido2` step-up flows (both map to CIBA poll mode; the only difference is the `acr_values` parameter sent to the IdP).

**CIBA Backchannel Request (POST):**
```
POST {backchannel_authentication_endpoint}
Content-Type: application/x-www-form-urlencoded

client_id={client_id}
&client_secret={client_secret}         # if confidential client
&scope=openid
&login_hint={username}                 # identifies the end-user to the IdP
&binding_message={short_context_str}   # displayed on authenticator app
&acr_values={acr_uri}                  # optional: phr or phrh for FIDO2
```

**CIBA Backchannel Auth Response (200 OK):**
```json
{
  "auth_req_id": "...",     // opaque; ≥128 bits entropy per spec
  "expires_in": 120,        // seconds until auth_req_id expires
  "interval": 5             // minimum seconds between poll requests
}
```

**CIBA Token Poll Request (POST):**
```
POST {token_endpoint}
Content-Type: application/x-www-form-urlencoded

grant_type=urn:openid:params:grant-type:ciba
&auth_req_id={auth_req_id}
&client_id={client_id}
&client_secret={client_secret}
```

**Poll Error Codes:**
| Error | Action |
|-------|--------|
| `authorization_pending` | Sleep interval seconds, retry |
| `slow_down` | Add ≥5s to interval, sleep, retry |
| `access_denied` | Return `StepUpTimedOut` with "User denied" message |
| `expired_token` | Return `StepUpTimedOut` with "Approval window expired" |
| `invalid_grant` | Fatal: return error |

```rust
// Source: CIBA Core 1.0 §10.1, §11 (openid.net)
// Pattern for async poll loop in agent daemon
async fn poll_ciba(
    http: reqwest::Client,
    token_endpoint: String,
    auth_req_id: String,
    mut interval: Duration,
    timeout: Duration,
    client_id: String,
    client_secret: Option<String>,
) -> Result<CibaTokenResponse, CibaError> {
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        tokio::time::sleep(interval).await;

        if tokio::time::Instant::now() >= deadline {
            return Err(CibaError::Timeout);
        }

        match request_token(&http, &token_endpoint, &auth_req_id, &client_id, client_secret.as_deref()).await {
            Ok(token) => return Ok(token),
            Err(CibaError::AuthorizationPending) => continue,
            Err(CibaError::SlowDown) => {
                interval += Duration::from_secs(5);
                continue;
            }
            Err(e) => return Err(e),
        }
    }
}
```

### Pattern 2: IPC Step-Up Protocol Extension

**What:** Three new message variants in `AgentRequest` and corresponding `AgentResponseData` variants to coordinate step-up between PAM and agent.

```rust
// Source: Codebase analysis of protocol.rs patterns; consistent with Phase 9 SessionClosed pattern
// In daemon/protocol.rs:

// PAM → Agent: initiate CIBA step-up
#[serde(rename = "step_up")]
StepUp {
    username: String,
    command: String,      // shown in binding_message: "Approve: sudo {command} on {hostname}"
    hostname: String,
    method: String,       // "push" or "fido2" — determines acr_values
    timeout_secs: u64,    // from policy, default 120
},

// PAM → Agent: poll for result
#[serde(rename = "step_up_result")]
StepUpResult {
    correlation_id: String,  // from StepUpPending.correlation_id
},

// Agent → PAM (immediate response to StepUp):
StepUpPending {
    correlation_id: String,  // UUID; PAM uses to poll for result
    expires_in: u64,         // from IdP auth_req_id expires_in
    poll_interval_secs: u64, // recommended poll interval for PAM→agent polling
},

// Agent → PAM (response to StepUpResult query):
StepUpComplete {
    acr: Option<String>,     // actual acr claim from token (PAM validates)
    session_id: String,
},

// Agent → PAM (step-up failed or timed out):
StepUpTimedOut {
    reason: String,          // "timeout", "denied", "expired"
    user_message: String,    // displayed to user (non-sensitive)
},
```

**Discriminant safety:** Follow the Phase 9 `SessionAcknowledged`/`Ok{}` precedent — place `StepUpPending` before `StepUpComplete` in the untagged enum, using the required `correlation_id` field as discriminant.

### Pattern 3: OIDC Discovery Extension for CIBA Endpoints

**What:** The existing `OidcDiscovery` struct in `pam-unix-oidc/src/oidc/jwks.rs` only deserializes `jwks_uri` and `issuer`. Extend it to also capture CIBA metadata for STP-03 and STP-06.

```rust
// Source: CIBA Core 1.0 §4; OpenID Connect Discovery 1.0
// In pam-unix-oidc/src/oidc/jwks.rs (or a new discovery.rs):
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    issuer: String,
    token_endpoint: String,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,   // RFC 8628
    #[serde(default)]
    backchannel_authentication_endpoint: Option<String>,  // CIBA
    #[serde(default)]
    backchannel_token_delivery_modes_supported: Option<Vec<String>>, // ["poll", ...]
    #[serde(default)]
    revocation_endpoint: Option<String>,             // already used by Phase 9
}
```

Expose a `discover()` function that returns `OidcDiscovery`, shared across all callers (JWKS, device flow, CIBA, revocation). This replaces the Keycloak-hardcoded `/protocol/openid-connect/auth/device` path in `DeviceFlowClient::new()`.

### Pattern 4: ACR Claim Validation for FIDO2 Step-Up (STP-04)

**What:** After the CIBA poll succeeds, validate the `acr` claim in the resulting ID token to confirm the IdP actually performed phishing-resistant authentication.

**ACR URIs (from OpenID EAP ACR Values 1.0 Final):**
| Config value | ACR URI to send | Validates against |
|---|---|---|
| `step_up_method = "fido2"` | `http://schemas.openid.net/pape/policies/2007/06/phishing-resistant` (phr) | acr claim must equal phr or phrh |
| `step_up_method = "fido2_hardware"` | `http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware` (phrh) | acr claim must equal phrh |

Validation rule: the returned `acr` claim in the ID token must exactly equal (or be a value considered at least as strong as) the requested ACR value. The OpenID EAP ACR spec places responsibility on the RP. Implement as:

```rust
// Source: OpenID Connect EAP ACR Values 1.0 Final (openid.net)
fn validate_acr(required: &str, actual: Option<&str>) -> Result<(), CibaError> {
    match actual {
        None => Err(CibaError::AcrMissing {
            required: required.to_string(),
        }),
        Some(got) if satisfies_acr(required, got) => Ok(()),
        Some(got) => Err(CibaError::AcrInsufficient {
            required: required.to_string(),
            got: got.to_string(),
        }),
    }
}

// phrh satisfies a phr requirement (hardware-protected is stronger)
fn satisfies_acr(required: &str, got: &str) -> bool {
    const PHR: &str = "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant";
    const PHRH: &str = "http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware";
    match required {
        r if r == PHR  => got == PHR || got == PHRH,
        r if r == PHRH => got == PHRH,
        _ => got == required, // exact match for unknown/custom ACR values
    }
}
```

The HARD-FAIL category applies: if `step_up_method = "fido2"` is configured and the IdP returns a token without the required ACR, step-up MUST fail (not warn-and-allow). This is not configurable via `EnforcementMode` — it is a security invariant per CLAUDE.md.

### Anti-Patterns to Avoid

- **Polling in the PAM thread:** CIBA approval can take up to 120s. `sshd` `LoginGraceTime` defaults to 120s; a blocking PAM call during approval would race against it and is unreliable. All polling MUST be in the agent daemon's async Tokio runtime.
- **Hardcoding grant type string:** Use `"urn:openid:params:grant-type:ciba"` exactly — the colon-separated URN with `openid:params`, not `ietf:params`. This differs from device flow's `urn:ietf:params:oauth:grant-type:device_code`.
- **Using CIBA ping/push modes:** These require the PAM host to expose an HTTP callback endpoint. Out of scope per REQUIREMENTS.md.
- **Missing IdP mode check:** Before initiating CIBA, verify the IdP's `backchannel_token_delivery_modes_supported` contains `"poll"`. If absent, fall back to device flow or return a clear config error. Okta (as of 2025) supports only poll; Keycloak supports both poll and ping.
- **Sending binding_message > 30 characters:** Authenticator app UIs display this in a small field. Keep it human-readable and short. Recommended format: `"sudo {truncated_command} on {hostname}"` with a hard cap of 64 characters.
- **Concurrent poll requests with same auth_req_id:** CIBA spec prohibits overlapping poll requests for the same `auth_req_id`. The agent's async poller must use a single sequential loop with `tokio::time::sleep` between attempts, not concurrent task spawning.
- **Panic if no CIBA endpoint in discovery:** Some IdPs don't support CIBA at all. If `backchannel_authentication_endpoint` is absent from discovery and the policy requests `step_up_method = "push"` or `"fido2"`, return a clear config error rather than panicking. The PAM module invariant (no panics) applies.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CIBA grant type polling state machine | Custom retry loop with ad-hoc sleep | `tokio::time::sleep` + `tokio::time::timeout` wrapping the loop | The spec-defined error codes map cleanly to simple sequential loop; no exponential backoff needed (CIBA defines fixed interval extension for `slow_down`) |
| ACR string comparison | String equality with custom ordering | `satisfies_acr()` helper with the two well-known URIs hard-coded | Ordering is fixed by the spec (phrh > phr); no dynamic comparator needed |
| OIDC discovery parsing | Regex/manual JSON parse | Extend existing serde `OidcDiscovery` struct | Already working; just add optional fields |
| Async HTTP client | Build new reqwest::Client per poll | Reuse the `reqwest::Client` from the agent's existing state or construct once per step-up session | `reqwest::Client` is designed for reuse; creating per-request wastes connection pool resources |

**Key insight:** CIBA poll mode is simpler than device flow — there's no user_code/verification_uri to display. The complexity is purely organizational: keeping the poll loop in the right place (agent daemon, not PAM) and getting the protocol message sequence right.

---

## Common Pitfalls

### Pitfall 1: CIBA Grant Type String Uses `openid:params`, Not `ietf:params`

**What goes wrong:** The token endpoint rejects the request with `unsupported_grant_type`.
**Why it happens:** Device flow uses `urn:ietf:params:oauth:grant-type:device_code`; CIBA uses `urn:openid:params:grant-type:ciba` — a different namespace authority.
**How to avoid:** Hard-code the exact constant: `const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";` and use it as a compile-time constant, not a constructed string.
**Warning signs:** HTTP 400 with `error: unsupported_grant_type` from the token endpoint.

### Pitfall 2: Okta CIBA Supports Only Poll Mode — Must Check Discovery

**What goes wrong:** Code assumes `ping` or `push` mode is available from Okta and sends the wrong `backchannel_token_delivery_mode` parameter.
**Why it happens:** Pre-planning research flag in STATE.md: Okta CIBA supports PUSH mode only in some docs, but current (2026) Okta developer docs confirm only poll mode is supported.
**How to avoid:** Always read `backchannel_token_delivery_modes_supported` from OIDC discovery before constructing the CIBA request. If `"poll"` is not in the list, return `CibaError::DeliveryModeNotSupported`. Do NOT send `backchannel_token_delivery_mode` as a parameter — CIBA §7.1 says the client uses the mode it registered for; the parameter is in the registration, not the request.
**Warning signs:** IdP returns error about unsupported delivery mode.

**IMPORTANT NOTE:** The STATE.md flag states "Okta CIBA supports PUSH mode only, not POLL." However, the 2025 Okta developer blog post found during research explicitly states "Okta supports CIBA in poll mode." This is a contradiction with the pre-planning flag. The flag may have been written when push meant something different, or Okta documentation changed. **Verify against current Okta OIDC discovery document during implementation** by checking `backchannel_token_delivery_modes_supported` from the live Okta `.well-known/openid-configuration` endpoint.

### Pitfall 3: PAM Thread Timeout Race with sshd LoginGraceTime

**What goes wrong:** The SSH connection drops mid-approval because the PAM call in the sshd process exceeds `LoginGraceTime`.
**Why it happens:** If the PAM module polls the agent via IPC in a tight loop for 120 seconds, the sshd `LoginGraceTime` (default 120s) may expire and kill the connection.
**How to avoid:** The agent's async Tokio task handles ALL CIBA polling. The PAM thread does short, bounded IPC calls to check completion status — each IPC call returns quickly. The PAM thread's total blocking time is the sum of its check intervals, not the CIBA timeout. Use a PAM-side poll interval of 2-5s with a total cap matching the configured step-up timeout.
**Warning signs:** SSH connection dropped with "Connection reset by peer" during step-up.

### Pitfall 4: ACR Claim Absent Without Hard-Fail

**What goes wrong:** IdP returns a token without the `acr` claim after a FIDO2 step-up request; the PAM module accepts it as valid.
**Why it happens:** Some IdPs omit `acr` if the value matches their default. Other IdPs return it only when `acr_values` is present in the request.
**How to avoid:** When `step_up_method = "fido2"` is configured, ACR validation is hard-fail (like signature verification). A missing `acr` claim fails step-up with `CibaError::AcrMissing`. This is not configurable via `EnforcementMode`.
**Warning signs:** Step-up succeeds without any FIDO2 actually occurring.

### Pitfall 5: DeviceFlowClient Still Hardcodes Keycloak URL After STP-06 Fix

**What goes wrong:** `DeviceFlowClient::new()` still constructs `{issuer}/protocol/openid-connect/auth/device` even after the STP-06 fix is applied to CIBA, breaking non-Keycloak device flow users.
**Why it happens:** STP-06 covers both device flow and CIBA endpoint discovery. The device flow client must be updated to use the `device_authorization_endpoint` from OIDC discovery.
**How to avoid:** In the same plan that adds CIBA discovery, fix `DeviceFlowClient::new()` to accept an optional discovered endpoint. Keep `DeviceFlowClient::with_endpoints()` (already exists) as the single source of truth; make `new()` call discovery and then delegate to `with_endpoints()`.
**Warning signs:** Tests against non-Keycloak IdPs for device flow fail after STP-06 is supposedly fixed.

### Pitfall 6: binding_message Contains Sensitive Command Arguments

**What goes wrong:** A command like `sudo cat /etc/shadow` exposes filesystem path in the push notification visible to an adversary who can see the user's phone screen.
**Why it happens:** `SudoContext.command` is passed verbatim as `binding_message`.
**How to avoid:** Apply a command sanitization step: strip arguments to executable name only (e.g., `sudo cat ...` → `cat`), or provide only the basename of the executable. Include hostname and timestamp. The goal is phishing context ("I'm approving this command on this server") without leaking sensitive arguments.
**Warning signs:** Security audit finds sensitive paths/args in push notification logs.

---

## Code Examples

Verified patterns from official sources:

### CIBA Backchannel Auth Request
```rust
// Source: CIBA Core 1.0 §7.1 (openid.net)
// Constructs the form parameters for POST to backchannel_authentication_endpoint
fn build_backchannel_auth_params<'a>(
    client_id: &'a str,
    client_secret: Option<&'a str>,
    login_hint: &'a str,    // typically the username or email claim
    binding_message: &'a str,
    acr_values: Option<&'a str>,
) -> Vec<(&'static str, &'a str)> {
    let mut params = vec![
        ("client_id", client_id),
        ("scope", "openid"),
        ("login_hint", login_hint),
        ("binding_message", binding_message),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }
    if let Some(acr) = acr_values {
        params.push(("acr_values", acr));
    }
    params
}
```

### CIBA Token Poll Request
```rust
// Source: CIBA Core 1.0 §10.1 (openid.net)
const CIBA_GRANT_TYPE: &str = "urn:openid:params:grant-type:ciba";

fn build_ciba_token_params<'a>(
    client_id: &'a str,
    client_secret: Option<&'a str>,
    auth_req_id: &'a str,
) -> Vec<(&'static str, &'a str)> {
    let mut params = vec![
        ("grant_type", CIBA_GRANT_TYPE),
        ("client_id", client_id),
        ("auth_req_id", auth_req_id),
    ];
    if let Some(secret) = client_secret {
        params.push(("client_secret", secret));
    }
    params
}
```

### Poll Error Code Handling
```rust
// Source: CIBA Core 1.0 §11 (openid.net)
// Maps CIBA token endpoint error responses to typed errors
fn parse_ciba_error(error: &str) -> CibaError {
    match error {
        "authorization_pending" => CibaError::AuthorizationPending,
        "slow_down"             => CibaError::SlowDown,
        "access_denied"         => CibaError::AccessDenied,
        "expired_token"         => CibaError::ExpiredToken,
        other                   => CibaError::Protocol(other.to_string()),
    }
}
```

### Phishing-Resistant ACR URI Constants
```rust
// Source: OpenID Connect EAP ACR Values 1.0 Final (openid.net)
pub const ACR_PHR: &str =
    "http://schemas.openid.net/pape/policies/2007/06/phishing-resistant";
pub const ACR_PHRH: &str =
    "http://schemas.openid.net/acr/2016/07/phishing-resistant-hardware";

// Map from policy StepUpMethod to ACR URI
pub fn acr_for_method(method: StepUpMethod) -> Option<&'static str> {
    match method {
        StepUpMethod::Fido2         => Some(ACR_PHR),
        StepUpMethod::FidoHardware  => Some(ACR_PHRH), // if added in future
        StepUpMethod::DeviceFlow
        | StepUpMethod::Push        => None,            // no ACR constraint for push
    }
}
```

### binding_message Construction
```rust
// Produces a short, human-readable message for the authenticator app.
// Cap at 64 chars to fit authenticator UI constraints.
pub fn build_binding_message(command: &str, hostname: &str) -> String {
    // Extract executable basename only — avoid leaking sensitive arguments
    let exe = command
        .split_whitespace()
        .next()
        .and_then(|s| s.rsplit('/').next())
        .unwrap_or("unknown");

    let msg = format!("sudo {} on {}", exe, hostname);
    if msg.len() > 64 {
        msg[..64].to_string()
    } else {
        msg
    }
}
```

### OIDC Discovery Extension
```rust
// Source: CIBA Core 1.0 §4; OpenID Connect Discovery 1.0
// Extend existing OidcDiscovery struct in pam-unix-oidc/src/oidc/jwks.rs
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
    issuer: String,
    token_endpoint: String,
    #[serde(default)]
    device_authorization_endpoint: Option<String>,
    #[serde(default)]
    backchannel_authentication_endpoint: Option<String>,
    #[serde(default)]
    backchannel_token_delivery_modes_supported: Option<Vec<String>>,
    // revocation_endpoint already used by Phase 9 cleanup_session()
    #[serde(default)]
    revocation_endpoint: Option<String>,
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Device flow (RFC 8628) for step-up | CIBA poll mode (OpenID CIBA Core 1.0) for step-up | Phase 10 | No browser/QR needed; push to phone or FIDO2 without user switching windows |
| Hardcoded Keycloak endpoint paths | OIDC discovery for all endpoints | Phase 10 (STP-06) | IdP-agnostic; works with Auth0, Okta, Azure AD, Google |
| `preferred_username` as login_hint | Configurable claim as login_hint | Phase 10 | Must match what IdP accepts as a user identifier (often email, sometimes sub) |

**Deprecated/outdated:**
- `DeviceFlowClient::new()` with hardcoded `/protocol/openid-connect/auth/device`: after STP-06, this constructor should use discovery and delegate to `with_endpoints()`.
- `StepUpMethod::Push` in `rules.rs`: currently stub-defined but unimplemented. Phase 10 implements it as CIBA push-notification (without ACR) — same CIBA path as Fido2, just without `acr_values`.

---

## IdP-Specific Notes

### Keycloak (Primary CI Target)
- Supports poll mode and ping mode (ping requires callback endpoint — not used)
- `backchannel_authentication_endpoint`: `{issuer}/protocol/openid-connect/ext/ciba/auth`
- `backchannel_token_delivery_modes_supported`: `["poll", "ping"]` (Keycloak adds both)
- Must configure the CIBA grant on the specific client in Keycloak admin UI
- `binding_message` is displayed in Keycloak's authentication device UI
- ACR values work if Keycloak authentication flows map the ACR to a flow that triggers FIDO2

### Okta (Community Testing Target)
- Supports poll mode only (confirmed 2025)
- `backchannel_token_delivery_modes_supported`: `["poll"]`
- CIBA feature is called "Transactional Verification" in Okta admin UI
- Web app type only (server-to-server — matches unix-oidc-agent's confidential client model)
- STATE.md pre-planning flag incorrectly states Okta supports push-only. Current Okta docs confirm poll mode. **Verify at implementation time by fetching Okta's `.well-known/openid-configuration`.**

### Azure AD / Entra ID
- CIBA support status: not confirmed in 2026. Fallback to device flow if `backchannel_authentication_endpoint` absent from discovery.
- Phishing-resistant ACR: Entra uses its own ACR values (e.g., `urn:microsoft:policies:mfa`). ACR_PHR may not be honored — validate `acr` claim strictly when configured.

---

## Open Questions

1. **login_hint format per IdP**
   - What we know: CIBA §7.1 allows `login_hint` (string), `login_hint_token` (JWT), or `id_token_hint`. `login_hint` is most common.
   - What's unclear: Keycloak accepts username; Okta typically expects email. The PAM module knows the Unix username but may not know the email.
   - Recommendation: Make `login_hint_claim` configurable in `policy.yaml` — default to the same claim used for username mapping (from `IdentityConfig.username_claim`). If the IdP needs email but PAM has username, the user must configure the mapping correctly. This is an operator concern, not a code concern.

2. **Okta CIBA delivery mode clarification**
   - What we know: 2025 Okta blog says poll-only. STATE.md flag says push-only (written 2026-03-10, possibly based on earlier docs or confusion between CIBA modes and native push).
   - What's unclear: Whether the STATE.md flag was about Okta's native push authenticator (which is separate from CIBA push delivery mode) or CIBA poll support.
   - Recommendation: During implementation, fetch `https://{okta_domain}/.well-known/openid-configuration` and log `backchannel_token_delivery_modes_supported`. Treat this as a validation check at startup when CIBA is configured.

3. **ACR claim validation strictness for non-FIDO2 CIBA (Push method)**
   - What we know: When `step_up_method = "push"` (phone approval without FIDO2), no specific ACR is requested. The returned `acr` claim may or may not be present.
   - What's unclear: Should push step-up validate any ACR value at all?
   - Recommendation: For `push` method, do not require ACR. For `fido2` method, ACR is hard-fail. This matches the intent of the requirements.

---

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | cargo test + integration tests via Docker Compose |
| Config file | None (unit tests inline; integration: `docker-compose.test.yaml`) |
| Quick run command | `cargo test -p pam-unix-oidc --lib -- ciba` |
| Full suite command | `cargo test --workspace` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| STP-01 | CIBA poll loop lives in agent daemon; PAM returns quickly | unit (mock IdP) | `cargo test -p unix-oidc-agent -- ciba::poll` | ❌ Wave 0 |
| STP-02 | binding_message contains command and hostname | unit | `cargo test -p pam-unix-oidc -- ciba::binding_message` | ❌ Wave 0 |
| STP-03 | Backchannel endpoint read from discovery, not hardcoded | unit (mock discovery) | `cargo test -p pam-unix-oidc -- ciba::discovery` | ❌ Wave 0 |
| STP-04 | FIDO2 ACR requested; token ACR validated; missing ACR is hard-fail | unit | `cargo test -p pam-unix-oidc -- ciba::acr` | ❌ Wave 0 |
| STP-05 | StepUp/StepUpPending/StepUpComplete IPC round-trips correctly | unit | `cargo test -p unix-oidc-agent -- daemon::protocol::step_up` | ❌ Wave 0 |
| STP-06 | DeviceFlowClient uses discovery endpoint, not Keycloak hardcode | unit (regression) | `cargo test -p pam-unix-oidc -- device_flow::discovery` | ❌ Wave 0 |
| STP-07 | Poll loop respects timeout; returns StepUpTimedOut at deadline | unit | `cargo test -p unix-oidc-agent -- ciba::timeout` | ❌ Wave 0 |

**Adversarial tests required (mandatory per ROADMAP testing mandate):**
| Scenario | Test Type | Reason |
|----------|-----------|--------|
| CIBA response with wrong ACR — hard-fail, never warn | unit | Security invariant |
| auth_req_id expired before poll completes | unit | `expired_token` error code path |
| slow_down response increases interval | unit | Spec compliance |
| IdP returns access_denied | unit | User denial path |
| No `backchannel_authentication_endpoint` in discovery | unit | Config error, not panic |
| binding_message > 64 chars truncated | unit | UI safety |
| Concurrent StepUp requests for same user | unit | Guard against double-initiation |

### Sampling Rate
- **Per task commit:** `cargo test -p pam-unix-oidc --lib -- ciba && cargo test -p unix-oidc-agent --lib -- ciba`
- **Per wave merge:** `cargo test --workspace`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `pam-unix-oidc/src/ciba/mod.rs` + `client.rs` + `types.rs` — new module skeleton (STP-01, STP-02, STP-03, STP-04)
- [ ] `pam-unix-oidc/src/ciba/tests/` — unit test fixtures (mock CIBA responses for each error code)
- [ ] `unix-oidc-agent/src/daemon/protocol.rs` — StepUp/StepUpPending/StepUpComplete/StepUpTimedOut variants (STP-05)
- [ ] `unix-oidc-agent/src/daemon/socket.rs` — handle_step_up() handler function (STP-01, STP-05)
- [ ] No new framework install required — cargo test is already in CI

---

## Sources

### Primary (HIGH confidence)
- OpenID Client-Initiated Backchannel Authentication Core 1.0 (https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html) — §4 discovery, §7.1 request parameters, §10.1 poll grant type, §11 error codes
- OpenID Connect EAP ACR Values 1.0 Final (https://openid.net/specs/openid-connect-eap-acr-values-1_0-final.html) — phr and phrh URI definitions, RP validation responsibility
- Okta Developer Blog 2025/07 (https://developer.okta.com/blog/2025/07/31/ciba-okta) — Okta poll-only CIBA support confirmed
- Okta CIBA Guide (https://developer.okta.com/docs/guides/configure-ciba/main/) — client authentication, login_hint, scope requirements

### Secondary (MEDIUM confidence)
- Keycloak community design doc (https://github.com/keycloak/keycloak-community/blob/main/design/client-initiated-backchannel-authentication-flow.md) — Keycloak-specific backchannel endpoint path, poll/ping mode support
- NIST SP 800-63B-4 (July 2025) (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-63B-4.pdf) — phishing-resistant authenticator definition; FIDO2/WebAuthn as canonical example
- Curity CIBA flow guide (https://curity.io/resources/learn/ciba-flow/) — implementation notes on poll interval handling

### Tertiary (LOW confidence — for validation)
- STATE.md pre-planning blocker: "Okta CIBA supports PUSH mode only, not POLL" — CONTRADICTED by 2025 Okta docs. Verify at implementation time by inspecting live Okta discovery document.

---

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new dependencies; all existing crates are correct
- CIBA protocol: HIGH — verified against openid.net specification
- Architecture patterns: HIGH — consistent with established Phase 9 IPC patterns in codebase
- ACR URIs: HIGH — verified against OpenID EAP ACR Values 1.0 Final spec
- Okta poll support: MEDIUM — 2025 blog confirms poll; contradicts earlier STATE.md flag; must verify at impl time
- Keycloak CIBA endpoint path: MEDIUM — found in community design doc; verify against live instance
- Azure/Entra CIBA support: LOW — no confirmed data found

**Research date:** 2026-03-10
**Valid until:** 2026-04-10 (30 days) — CIBA spec is stable; IdP support pages change more frequently
