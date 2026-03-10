# Architecture Research

**Domain:** OIDC PAM + agent daemon — production hardening and enterprise auth extension
**Researched:** 2026-03-10
**Confidence:** HIGH (based on direct code reading + RFC authority)

---

## Standard Architecture

### System Overview: v2.0 Target State

```
┌────────────────────────────── User Machine ─────────────────────────────────┐
│                                                                               │
│  ┌──────────────────────────── unix-oidc-agent ─────────────────────────┐   │
│  │  main.rs CLI ──► daemon/socket.rs (UnixListener, RwLock<AgentState>) │   │
│  │                                                                        │   │
│  │  AgentState {                                                          │   │
│  │    signer: DPoPSigner (Software | YubiKey | TPM)                      │   │
│  │    access_token: SecretString                                          │   │
│  │    session_store: Arc<SessionStore>   <- NEW                          │   │
│  │    stepup_state: StepUpCoordinator    <- NEW                          │   │
│  │  }                                                                     │   │
│  │                                                                        │   │
│  │  IPC Protocol (JSON/Unix socket):                                     │   │
│  │    GetProof | Refresh | Status | Metrics | Shutdown  (existing)       │   │
│  │    StepUp { method, context }         <- NEW                          │   │
│  │    StepUpResult { poll_handle? }      <- NEW                          │   │
│  └────────────────────────────────────────────────────────────────────────┘  │
│                                                                               │
│  ┌──────── device_flow ──┐  ┌────── CIBA client ─────┐  ┌── WebAuthn ────┐  │
│  │ RFC 8628 (existing)   │  │ CIBA Core 1.0          │  │ webauthn-rs    │  │
│  │ poll loop in agent    │  │ poll loop in agent     │  │ challenge +    │  │
│  │                       │  │ NEW: ciba.rs module    │  │ verify via IdP │  │
│  └───────────────────────┘  └────────────────────────┘  └────────────────┘  │
└───────────────────────────────────────────────────────────────────────────────┘
                  │ SSH keyboard-interactive / PAM env token
                  ▼
┌────────────────────────────── Linux Server ─────────────────────────────────┐
│                                                                               │
│  sshd → pam_unix_oidc.so                                                    │
│                                                                               │
│  lib.rs  ──►  auth.rs  ──►  oidc/validation.rs                             │
│   │             │              │                                              │
│   │             │              ├── JTI cache (in-process RwLock<HashMap>)    │
│   │             │              ├── JWKS cache (reqwest + Mutex<JwksCache>)   │
│   │             │              └── token introspection (NEW: optional)        │
│   │             │                                                             │
│   │             ├── oidc/dpop.rs  (nonce issuance NEW: per-auth nonce)       │
│   │             │                                                             │
│   │             └── policy/rules.rs  ──►  sudo.rs / step-up flow             │
│   │                       │                                                   │
│   │                       └── security_modes.rs (NEW: enforce/warn/disabled) │
│   │                                                                           │
│   ├── sssd.rs  (username lookup via getpwnam_r)                              │
│   ├── username_map.rs  (NEW: claim → Unix user mapping table)                │
│   ├── group_policy.rs  (NEW: claim-based group membership rules)             │
│   └── session_store.rs  (NEW: PAM open_session / close_session hooks)       │
└───────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

| Component | Responsibility | New vs Existing |
|-----------|----------------|-----------------|
| `pam-unix-oidc/src/lib.rs` | PAM entry points (authenticate, open_session, close_session) | Existing — extend open/close_session |
| `pam-unix-oidc/src/auth.rs` | Main auth flow, DPoP validation, user resolution | Existing — add username mapping |
| `pam-unix-oidc/src/oidc/validation.rs` | JWT sig check, issuer/aud/exp/ACR/JTI | Existing — add introspection hook |
| `pam-unix-oidc/src/oidc/dpop.rs` | DPoP proof verification, JTI replay cache | Existing — add server nonce issuance |
| `pam-unix-oidc/src/policy/config.rs` | policy.yaml parsing | Existing — add security_modes section |
| `pam-unix-oidc/src/policy/rules.rs` | Auth action engine | Existing — group policy rules |
| `pam-unix-oidc/src/sudo.rs` | Step-up (currently Device Flow only) | Existing — add CIBA + FIDO2 branches |
| `pam-unix-oidc/src/security_modes.rs` | Strict/warn/disabled per-check enforcement | NEW |
| `pam-unix-oidc/src/username_map.rs` | Claim to local user mapping (regex, static table) | NEW |
| `pam-unix-oidc/src/group_policy.rs` | Groups claim to PAM group membership rules | NEW |
| `pam-unix-oidc/src/session_store.rs` | Server-side session record (open/close PAM hooks) | NEW |
| `unix-oidc-agent/src/daemon/ciba.rs` | CIBA backchannel request + poll loop | NEW |
| `unix-oidc-agent/src/daemon/webauthn.rs` | WebAuthn credential store + sign/verify | NEW |
| `unix-oidc-agent/src/daemon/socket.rs` | IPC handler | Existing — add StepUp/StepUpResult messages |
| `unix-oidc-agent/src/storage/*` | Credential persistence | Existing — persist WebAuthn credential |

---

## Recommended Project Structure (Delta from v1.0)

New files relative to existing layout:

```
pam-unix-oidc/src/
├── oidc/
│   ├── validation.rs     # add: introspection::check_active() call (optional, configurable)
│   ├── dpop.rs           # add: nonce_store::issue_nonce(), nonce_store::consume_nonce()
│   └── introspection.rs  # NEW: RFC 7662 client; cached active check
│
├── policy/
│   ├── config.rs         # add: SecurityModes struct, group_rules, username_map
│   └── rules.rs          # add: group membership evaluation
│
├── security_modes.rs     # NEW: per-check Enforcement enum (Strict/Warn/Disabled)
├── username_map.rs       # NEW: MappingRule enum (Exact | Regex | Claim); apply()
├── group_policy.rs       # NEW: GroupRule; evaluate(claims) -> bool
└── session_store.rs      # NEW: in-process Arc<Mutex<HashMap<session_id, SessionRecord>>>

unix-oidc-agent/src/
├── daemon/
│   ├── ciba.rs           # NEW: CibaClient; start_backchannel(), poll_token()
│   ├── webauthn.rs       # NEW: challenge generation, assertion verify (webauthn-rs)
│   └── socket.rs         # add: handle StepUp{method} -> dispatch CIBA or WebAuthn
│
└── storage/
    └── router.rs         # add: persist webauthn_credential key
```

### Structure Rationale

- `introspection.rs` as a separate module: Introspection is a network call with its own cache TTL and error path. Isolating it prevents coupling to the local JWT validation path.
- `security_modes.rs` as a standalone enum: Every security check calls `enforcement.apply(check_result, &mut warnings)` at one callsite. The Strict/Warn/Disabled logic lives in one place, not scattered across `dpop.rs`, `validation.rs`, and `rules.rs`.
- `session_store.rs` in the PAM crate, not the agent: PAM `open_session` and `close_session` hooks run on the server host. Sessions are per-host state. The agent is a client-side component with no visibility into server-side sessions.
- CIBA and WebAuthn in the agent daemon: Step-up challenges are initiated by the user's machine, not the server. The agent holds the DPoP key and token; it is the correct place to manage the interactive flow before handing a fresh token back to PAM.

---

## Architectural Patterns

### Pattern 1: CIBA — Agent-Side Poll, PAM Receives Final Token

**What:** CIBA (OpenID Connect Client-Initiated Backchannel Authentication Core 1.0) is an out-of-band authentication flow. The consumption device (agent) sends a backchannel authentication request to the IdP, which pushes a notification to the user's phone. The agent polls for the resulting token.

**Where it fits:**
- CIBA belongs entirely in the agent daemon (`unix-oidc-agent`).
- PAM never speaks CIBA directly. PAM remains stateless: it receives a token and validates it.
- The sudo step-up IPC sequence: PAM sends `StepUp { method: "ciba", user, context }` to the agent via the Unix socket. The agent executes the CIBA poll loop and responds with a new `AgentResponse::StepUpComplete` containing the step-up token + DPoP proof. PAM validates that token.

**Mode recommendation:** Use poll mode, not push/ping. Rationale:
- Push mode requires the agent to expose an HTTP notification endpoint. The agent is a Unix domain socket daemon, not an HTTP server. Adding an inbound listener substantially expands attack surface, requires a publicly-reachable address, and adds certificate management complexity.
- Ping mode requires the same inbound endpoint plus a second outbound fetch.
- Poll mode: agent calls the IdP token endpoint on a timer. No inbound listener. The agent already contains a tokio runtime and `reqwest` for JWKS fetching. Poll fits naturally.

**CIBA polling invariants (required by the specification):**
- `interval` from the backchannel authentication response sets the minimum poll interval (default 5 seconds per spec; `slow_down` responses require increasing the interval by at least 5 seconds).
- `auth_req_id` ties all poll requests to the original backchannel request.
- Poll loop terminates on `authorization_pending` (continue), `slow_down` (backoff), `access_denied` or `expired_token` (error), or successful token delivery.
- `expires_in` from the auth request bounds the total poll window; abort if exceeded.

**IPC protocol extension:**
```rust
// protocol.rs additions
pub enum AgentRequest {
    // ... existing variants unchanged ...
    StepUp {
        method: StepUpMethod,       // Ciba | Fido2ViaIdp
        user: String,
        context: String,            // audit label: "sudo:/usr/bin/systemctl restart nginx"
        acr_required: Option<String>,
    },
}

pub enum AgentResponse {
    // ... existing variants unchanged ...
    StepUpPending {
        handle: String,             // CIBA: auth_req_id
        message: String,            // display to user: "Approve on your authenticator app"
        expires_in: u64,
    },
    StepUpComplete {
        token: String,
        dpop_proof: String,
        expires_in: u64,
    },
}
```

**Trade-offs:**
- Poll mode adds latency of one poll interval (5-10 seconds typical) vs push mode (near-instant delivery). For sudo step-up, 5-10 second user-visible latency is acceptable.
- Poll mode is IdP-agnostic: any IdP that supports CIBA poll works without callback URL registration. Keycloak 21+, Auth0, and Azure AD CIBA all support poll mode.
- MEDIUM confidence on all three IdPs; Keycloak 21+ is confirmed; Azure AD requires specific CIBA preview configuration.

---

### Pattern 2: WebAuthn Step-Up — Delegate to IdP via CIBA ACR

**What:** For FIDO2/WebAuthn step-up, the recommended path in v2.0 is to request a CIBA backchannel authentication with a phishing-resistant ACR value. The IdP handles the FIDO2 challenge-response. PAM receives a token with the appropriate ACR claim and validates it via the existing ACR check in `validation.rs`.

**Why not direct WebAuthn in PAM for v2.0:**
- Direct WebAuthn requires PAM to act as a FIDO2 Relying Party: it must store registered credential public keys per user per server, manage authenticator counter state, issue challenges, and verify assertions using CTAP2.
- The user's FIDO2 authenticator is on their machine, not the server. Passing CTAP2 commands through the SSH keyboard-interactive channel is architecturally possible but requires a custom framing protocol.
- `webauthn-rs` (kanidm, SUSE-audited) is the correct Rust RP crate when this path is needed. However, the implementation complexity exceeds v2.0 scope.
- `pam-u2f` (Yubico) is a reference implementation showing how FIDO2 can be done in PAM; its architecture requires per-host credential files and is not directly compatible with the agent model.

**v2.0 approach:**
1. Add `Fido2ViaIdp` to `StepUpMethod` enum in `policy/rules.rs`.
2. In `sudo.rs`, when method is `Fido2ViaIdp`, dispatch a CIBA step-up request with `acr_values` set to the configured phishing-resistant ACR string (e.g., `"urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO"` or IdP-specific).
3. PAM validates the returned token's ACR claim via the existing `ValidationError::InsufficientAcr` path.
4. No `webauthn-rs` dependency in v2.0. No new credential storage.

**Phase 8+ (direct WebAuthn):** When direct WebAuthn in PAM is needed (air-gapped environments, no CIBA support), add `webauthn-rs` as a PAM crate dependency for RP-side challenge/verify. The agent adds a `webauthn.rs` module for CTAP2 transport. Credential public keys are stored in `/etc/unix-oidc/webauthn/` per-user with 0600 permissions.

---

### Pattern 3: Token Introspection — Optional Supplement to Local Validation

**What:** RFC 7662 `POST /introspect` asks the IdP whether a specific token is currently active. Used to detect revoked tokens between JWT expiration cycles.

**Where it fits in the validation pipeline:**
```
validate(token) {
    1. JWT sig + iss + aud + exp check        (always — existing, Strict always)
    2. JTI replay check                       (always — existing, modes.jti)
    3. DPoP binding check (if cnf.jkt)        (conditional — existing, modes.dpop)
    4. ACR check                              (if configured — existing, modes.acr)
    5. introspection active check             (if configured — NEW, modes.introspection)
}
```

Introspection is always a supplement, never a replacement for steps 1-4. Local validation runs regardless. Introspection adds a conditional network round-trip.

**Caching rule (RFC 7662):** Cache per JTI claim, never beyond the token's `exp`. For 15-minute tokens, a 5-minute cache is reasonable. Use a `HashMap<String, (bool, Instant)>` bounded by JTI, cleared on entries older than `exp`.

**Fail mode:** Introspection endpoint unreachable. Two options:
- `fail_open` (default): log warning, treat token as active if local validation passed. Degrades gracefully; maintains IdP-downtime resilience.
- `fail_closed`: reject auth. More secure; operationally risky if IdP availability is not guaranteed.

Configurable via `security_modes.introspection: strict | warn | disabled`.

**Integration point:** `introspection.rs` exposes `check_active(jti, token, config) -> Result<bool, IntrospectionError>`. Called from `validation.rs::TokenValidator::validate()` as the final optional step when `config.introspection_enabled == true`. `TokenValidator` holds an `Option<Arc<IntrospectionCache>>` initialized at construction time.

---

### Pattern 4: Configurable Security Modes — Single Enforcement Enum

**What:** Issue #10 pattern. Each security check has an independent enforcement level. The enforcement decision (fail, warn+allow, skip) lives in a single function, not duplicated across the validation chain.

**Threading through the chain:**
```
policy.yaml
  security_modes:
    jti_enforcement: strict        # default
    dpop_enforcement: strict       # default
    acr_enforcement: warn          # default (IdP compat)
    auth_time_enforcement: warn    # default (optional claim)
    introspection: warn            # default (availability risk)

PolicyConfig::load()
  -> SecurityModes { jti, dpop, acr, auth_time, introspection: Enforcement }
       -> ValidationConfig (passed to TokenValidator)
       -> DPoPAuthConfig (passed to dpop.rs validation)
```

**Core type:**
```rust
// security_modes.rs
#[derive(Debug, Clone, Copy, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Enforcement { Strict, #[default] Warn, Disabled }

impl Enforcement {
    pub fn apply<E: std::fmt::Display>(
        &self,
        result: Result<(), E>,
        warn_fn: impl FnOnce(&str),
    ) -> Result<(), E> {
        match (self, result) {
            (Enforcement::Strict, Err(e)) => Err(e),
            (Enforcement::Warn,   Err(e)) => { warn_fn(&e.to_string()); Ok(()) }
            (Enforcement::Disabled, _)    => Ok(()),
            (_,                  Ok(())) => Ok(()),
        }
    }
}
```

**Where each check needs modes applied:**

| Check | Current File | Location |
|-------|-------------|----------|
| JTI uniqueness | `validation.rs` | `ValidationError::TokenReplay` / `MissingJti` |
| DPoP required | `auth.rs` line ~220 | `AuthError::DPoPRequired` |
| ACR level | `validation.rs` | `ValidationError::InsufficientAcr` |
| auth_time age | `validation.rs` | `ValidationError::AuthTimeTooOld` / `MissingAuthTime` |
| Introspection active | `introspection.rs` (new) | new error variant |

---

### Pattern 5: Session Store — In-Process on the Server

**What:** Track active PAM sessions (open_session to close_session lifecycle) server-side. Provides audit trail, session duration logging, and a foundation for future revocation enforcement.

**Decision: in-process, not external.**

Rationale:
- The PAM module is a `.so` loaded into `sshd`. It has no persistent process of its own to communicate with an external store on every session event.
- `sshd` maintains the PAM context across the open_session/close_session lifecycle within a single process. An `Arc<RwLock<HashMap>>` initialized via `once_cell::sync::Lazy` (same pattern as `global_jti_cache()`) survives across PAM calls within that process lifetime.
- Redis would add a network call on every session open/close and create an availability dependency during session teardown. No benefit at single-host scale.
- O(thousands) of concurrent SSH sessions is the realistic upper bound per host. In-process HashMap handles this trivially.

**Session record:**
```rust
pub struct SessionRecord {
    pub session_id: String,
    pub username: String,
    pub uid: u32,
    pub token_jti: Option<String>,
    pub dpop_thumbprint: Option<String>,
    pub acr: Option<String>,
    pub opened_at: SystemTime,
    pub source_ip: Option<String>,
}
```

**PAM hook integration:**
- `lib.rs::open_session()`: currently returns `PamError::SUCCESS` no-op. Insert `SessionRecord` into `global_session_store()`.
- `lib.rs::close_session()`: currently returns `PamError::SUCCESS` no-op. Remove record, emit audit event with session duration.

**Forward compatibility:** Define a `SessionStore` trait now with an in-process `InMemorySessionStore` implementation. When the Redis milestone arrives, add `RedisSessionStore` implementing the same trait.

---

### Pattern 6: Username Mapping — Claim Transform Before SSSD Lookup

**What:** Map the IdP-provided claim value (typically `preferred_username`, but may be `email` or `sub`) to a local Unix username before the `getpwnam_r` call in `auth.rs`.

**Insertion point in `auth.rs::authenticate_with_token()`:**
```
let raw_name = match config.username_claim {
    Claim::PreferredUsername => &claims.preferred_username,
    Claim::Email => claims.email.as_deref().unwrap_or_default(),
    Claim::Sub => &claims.sub,
};
let local_name = username_map.apply(raw_name)?;
if !user_exists(&local_name) { ... }
```

**Mapping rule types (evaluated in priority order):**
1. Static exact match: `"alice@corp.example.com" -> "alice"`.
2. Regex with capture group: `"^(.+)@corp\\.example\\.com$" -> "$1"`.
3. Identity (default): raw claim value used directly.

**Security invariant for mapping:** `username_map.apply()` must reject any output username that resolves to UID < 1000 or that appears in a deny-list (`root`, `daemon`, `nobody`, etc.) unless an explicit `allow_privileged_mapping: true` flag is set. Misconfigured regex rules are a privilege escalation path.

---

### Pattern 7: systemd Socket Activation vs Standalone

**What:** The agent daemon supports two socket binding modes: socket-activated (systemd passes a pre-bound fd via `SD_LISTEN_FDS`) or standalone (daemon binds its own socket).

**Recommendation:** Support both; default to standalone for v2.0.

Implementation using `tokio-listener` crate, which abstracts both modes:
```rust
// main.rs — unified listener
let addr = if std::env::var("LISTEN_FDS").is_ok() {
    "sd-listen".to_string()              // socket activation
} else {
    socket_path.to_string_lossy().to_string()  // standalone
};
let listener = tokio_listener::Listener::bind(&addr, &Default::default()).await?;
```

**systemd unit files** belong in `deploy/systemd/unix-oidc-agent.socket` and `deploy/systemd/unix-oidc-agent.service`. The socket unit enables auto-start on first connection; the service unit specifies the daemon binary and security hardening options (`NoNewPrivileges=yes`, `ProtectSystem=strict`, etc.).

Socket activation is the preferred deployment mode for production Linux because:
- The agent auto-starts on first SSH connection without requiring user-level login sessions.
- systemd handles socket lifecycle and restart policy.
- Systemd socket units enable `SocketMode=0600` and `SocketUser` without the agent needing to chmod after bind.

---

## Data Flow

### v2.0 SSH Authentication Flow

```
SSH client sends keyboard-interactive token + DPoP proof
    │
sshd -> pam_unix_oidc.so::authenticate()
    │
    ├── get_auth_token() -> token string  (existing)
    ├── PolicyConfig::load() -> SecurityModes  (NEW: configurable modes)
    ├── ValidationConfig::from_env_with_modes()  (NEW: pass modes into validator)
    │
    ├── TokenValidator::validate(token)
    │     ├── JWT sig check against JWKS  [Strict: always hard-fail]
    │     ├── iss / aud check             [Strict: always hard-fail]
    │     ├── exp check                   [Strict: always hard-fail]
    │     ├── JTI replay check            [modes.jti.apply()]
    │     ├── ACR level check             [modes.acr.apply()]
    │     ├── auth_time age check         [modes.auth_time.apply()]
    │     └── introspection active check  [modes.introspection.apply(), optional]
    │
    ├── DPoP binding check (if cnf.jkt present)  [modes.dpop.apply()]
    ├── username_map.apply(claims.preferred_username)  (NEW)
    ├── group_policy.evaluate(claims) -> Ok | Deny    (NEW, optional)
    ├── user_exists(local_username) via getpwnam_r    (existing)
    │
    └── pam_unix_oidc.so::open_session()
          └── global_session_store().insert(SessionRecord)  (NEW)
```

### v2.0 Step-Up (Sudo + CIBA) Flow

```
sudo /usr/bin/systemctl restart nginx
    │
pam-unix-oidc sudo path
    │
    ├── policy: command_requires_step_up() -> StepUpRequirements
    │     allowed_methods: [Ciba, Fido2ViaIdp]  (NEW methods)
    │
    ├── connect to agent Unix socket
    │
    ├── send: AgentRequest::StepUp { method: Ciba, user, context, acr }  (NEW)
    │
    │   [agent daemon]
    │   ├── CibaClient::start_backchannel(user, acr) -> auth_req_id
    │   │     POST /backchannel_authentication to IdP
    │   ├── return AgentResponse::StepUpPending { message: "Approve on your phone" }
    │   ├── poll loop: POST /token with auth_req_id at interval seconds
    │   │     authorization_pending -> wait; slow_down -> backoff; success -> token
    │   └── sign DPoP proof for step-up token
    │
    ├── recv: AgentResponse::StepUpComplete { token, dpop_proof }  (NEW)
    │
    └── validate step-up token (same pipeline as SSH auth)
          verify ACR in token matches required level
```

---

## Integration Points

### External Services

| Service | Integration Pattern | Notes |
|---------|---------------------|-------|
| IdP CIBA endpoint | Agent: POST /backchannel_authentication, poll /token | Poll mode. Requires IdP CIBA support. Keycloak 21+, Auth0, Azure AD CIBA preview |
| IdP Introspection | PAM: POST /introspect with client credentials | RFC 7662. Configurable fail-open/close. Cached per JTI |
| IdP JWKS | PAM: GET /.well-known/jwks.json | Existing. In-memory cached |
| SSSD/NSS | PAM: getpwnam_r() | Existing. No change |
| systemd | Agent: receive fd from SD_LISTEN_FDS | Optional socket activation |

### Internal Boundaries (New Interfaces)

| Boundary | Communication | Notes |
|----------|---------------|-------|
| PAM auth.rs -> security_modes.rs | Pass `&SecurityModes` into `ValidationConfig` and `DPoPAuthConfig` | No global state; modes are loaded per-auth call from PolicyConfig |
| PAM validation.rs -> introspection.rs | `check_active(jti, token, config)` with timeout | `Arc<IntrospectionCache>` shared via `TokenValidator` |
| PAM lib.rs -> session_store.rs | `global_session_store()` via `once_cell::sync::Lazy` | Same pattern as `global_jti_cache()` and `global_rate_limiter()` |
| PAM auth.rs -> username_map.rs | `username_map.apply(raw_claim)` synchronous call | MappingRules loaded from PolicyConfig at each call |
| PAM sudo.rs -> Agent (CIBA) | JSON `StepUp` / `StepUpComplete` over existing Unix socket | Agent must be running; PAM returns `AUTH_ERR` if agent unreachable |
| policy/config.rs -> username_map.rs | `PolicyConfig.username_mapping` field owns `Vec<MappingRule>` | Loaded from YAML at policy load time |

---

## Suggested Build Order

Dependencies drive the order. Each phase produces shippable, tested code with no circular dependencies on subsequent phases.

### Phase 1: Security Mode Infrastructure

Implement `security_modes.rs` with `Enforcement { Strict, Warn, Disabled }` and `apply()`. Thread `SecurityModes` through `ValidationConfig` and `DPoPAuthConfig`. Replace the hard-coded enforcement in `validation.rs` (JTI, ACR, auth_time) and `auth.rs` (DPoP required) with `modes.X.apply()` calls. Update `policy/config.rs` to deserialize a `[security_modes]` section.

**Why first:** Every subsequent feature needs to express its enforcement level. Modes infrastructure built first means all new features are born configurable and the existing behavior is explicitly preserved (defaults match current behavior).

### Phase 2: PAM DPoP Nonce Issuance

Add `nonce_store::issue_nonce()` and `nonce_store::consume_nonce()` in `dpop.rs`. The PAM module issues a server-chosen nonce per authentication attempt (per RFC 9449 §8). The nonce is communicated to the client via a pre-auth step or via the initial DPoP rejection response. `GetProof` in the IPC protocol already has `nonce: Option<String>`; wire nonce validation in `validate_dpop_proof()`.

**Why second:** Closes a DPoP replay window present in the current implementation. Independent of all new auth flows. Small scope, high security value.

### Phase 3: Username Mapping + Group Policy

Implement `username_map.rs` and `group_policy.rs`. Hook `username_map.apply()` in `auth.rs` after claim extraction. Hook `group_policy.evaluate()` in `auth.rs` after user resolution. Update `policy/config.rs` for new YAML sections.

**Why third:** Username mapping is a prerequisite for enterprise IdP integrations where `preferred_username` is an email address. Many real deployments are blocked until this exists. Group policies need the resolved local username. Neither item blocks auth method work.

### Phase 4: Token Introspection

Implement `oidc/introspection.rs`. Add `IntrospectionConfig` to `ValidationConfig`. Add per-JTI cache bounded by token `exp`. Wire as optional final step in `validation.rs::validate()`. Use `SecurityModes.introspection` from Phase 1.

**Why fourth:** Independent of step-up flows. Uses Phase 1 modes. Can be built and enabled or disabled without affecting CIBA or WebAuthn.

### Phase 5: Session Store + PAM open_session / close_session

Implement `session_store.rs` with `SessionStore` trait and `InMemorySessionStore`. Implement `lib.rs::open_session()` and `close_session()` (currently no-op `SUCCESS` returns). Emit audit events on open and close with session duration.

**Why fifth:** Depends on the resolved username (Phase 3) and auth result metadata (Phases 1-2). Provides session context for Phase 6 audit integration.

### Phase 6: CIBA Step-Up

Implement `unix-oidc-agent/src/daemon/ciba.rs`: `CibaClient`, `start_backchannel()`, poll loop, backoff, timeout handling. Extend `protocol.rs` with `StepUp`, `StepUpPending`, `StepUpComplete` variants. Extend `socket.rs` handler to dispatch `StepUp` to `CibaClient`. Extend `sudo.rs` to send `StepUp { method: Ciba }` over the Unix socket and validate the returned step-up token.

**Why sixth:** Requires the IPC protocol extensions, security modes (Phase 1), and the existing token validation pipeline (Phases 3-4). CIBA is the primary new interactive auth method and unblocks WebAuthn-via-IdP.

### Phase 7: FIDO2 Step-Up via CIBA ACR

Add `Fido2ViaIdp` to `StepUpMethod`. In `sudo.rs`, when method is `Fido2ViaIdp`, dispatch a `StepUp { method: Ciba }` with `acr_required` set to the configured phishing-resistant ACR value. Validate the returned token's ACR claim via the existing `InsufficientAcr` path. No new crates; no new credential storage.

**Why seventh:** CIBA infrastructure from Phase 6 is the prerequisite. Phase 7 is a configuration-level addition on top of Phase 6 with the ACR escalation wired in.

### Phase 8: Operational Hardening

Add socket activation support via `tokio-listener`. Add `deploy/systemd/` unit files and `deploy/launchd/` plist. Ensure all network calls (JWKS, introspection, CIBA poll) have explicit timeouts. Add tracing span IDs to all auth events. Harden agent systemd unit (`NoNewPrivileges`, `ProtectSystem`, `MemoryDenyWriteExecute`).

**Why last:** Operational hardening does not block correctness or security features. Ships as a late milestone item without holding back Phases 1-7.

---

## Anti-Patterns

### Anti-Pattern 1: CIBA Push or Ping Mode in the Agent

**What people do:** Implement CIBA push mode for instant token delivery.
**Why it's wrong:** Push mode requires the agent daemon to expose an inbound HTTP listener with a stable URL that the IdP can reach. The agent is a user-space Unix socket daemon. An inbound TLS listener requires certificate management, a publicly-reachable address, and firewall rules — none of which are reasonable assumptions for a user's local machine or a CI runner.
**Do this instead:** Poll mode. The agent already has a tokio runtime and makes outbound HTTP calls (JWKS fetching). CIBA poll fits this model exactly with no new inbound listener.

### Anti-Pattern 2: Putting the Session Store in the Agent

**What people do:** Track server-side session records in the agent daemon.
**Why it's wrong:** The agent runs on the user's machine; the PAM module runs on the server. Session state — who is logged in to a specific server — is inherently server-local. The agent cannot track sessions on hosts it has no ongoing connection to, and the agent may not be running at all when a session terminates (e.g., the user's laptop is closed).
**Do this instead:** In-process server-side store via `once_cell::sync::Lazy<Arc<RwLock<SessionStore>>>` in the PAM crate, identical in structure to `global_jti_cache()` in `security/jti_cache.rs`.

### Anti-Pattern 3: Replacing Local Validation with Introspection

**What people do:** Skip local JWT validation, reason that introspection is the authoritative active check.
**Why it's wrong:** Introspection is a network call that can fail, be rate-limited, or return stale cached data. Removing local validation means IdP downtime equals total authentication failure. Signature verification, issuer, audience, and expiration checks are synchronous, zero-dependency, and cannot be safely replaced.
**Do this instead:** Local validation always runs. Introspection is a configurable supplement gated on `SecurityModes.introspection`. `fail_open` is the default to preserve IdP-downtime resilience.

### Anti-Pattern 4: SecurityModes in Global State

**What people do:** Store `SecurityModes` in a `std::sync::OnceLock` loaded once.
**Why it's wrong:** PAM modules are `.so` files; there is no persistent process startup. Global state in a PAM library is per-sshd-worker-process, not per-system. More critically, per-auth policy reload (with a short TTL) allows security mode changes to take effect without restarting sshd. A global lock also creates subtle problems in multi-threaded sshd configurations.
**Do this instead:** Load `SecurityModes` from `PolicyConfig::load()` on each `authenticate()` call, with a file-modification-time cache to skip re-parsing the YAML when it has not changed. The existing `ValidationConfig::from_env()` pattern shows the per-call loading approach.

### Anti-Pattern 5: Validating WebAuthn Assertions Directly in PAM (v2.0)

**What people do:** Import `webauthn-rs` into the PAM crate, issue challenges via PAM conversation, and verify CTAP2 assertions server-side.
**Why it's wrong for v2.0:** The user's FIDO2 authenticator is on their machine, not the server. CTAP2 communication requires the agent as a bridge. The PAM conversation interface has a ~512-byte buffer limit, which is insufficient for WebAuthn assertion payloads (~1-2 KB). Per-host credential registration storage adds a new attack surface.
**Do this instead for v2.0:** Use CIBA with `acr_values` requesting phishing-resistant authentication. The IdP handles the FIDO2 challenge-response. PAM validates the ACR claim in the resulting token. Direct WebAuthn in PAM is a Phase 8+ item with its own scoping.

---

## Scaling Considerations

| Scale | Architecture Adjustments |
|-------|--------------------------|
| 0-100 servers | In-process session store, in-process JTI cache, no introspection. All state is single-host. |
| 100-1k servers | Enable introspection for revocation detection. Keep local JTI cache per host. Keep token lifetimes short (15 minutes or less). |
| 1k+ servers | Distributed JTI cache (Redis) becomes necessary — separate scalability milestone. CIBA `auth_req_id` uniqueness across hosts relies on IdP-side guarantees. |

The v2.0 design targets 0-1k servers. `SessionStore` and JtiCache are trait-based to accept a future `RedisBackend` without changing callers.

---

## Sources

- OpenID Connect Client-Initiated Backchannel Authentication Core 1.0: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html
- RFC 9449 (DPoP): https://www.rfc-editor.org/rfc/rfc9449
- RFC 7662 (Token Introspection): https://www.rfc-editor.org/rfc/rfc7662
- RFC 8628 (Device Authorization Grant): https://www.rfc-editor.org/rfc/rfc8628
- W3C WebAuthn Level 3: https://www.w3.org/TR/webauthn-3/
- kanidm/webauthn-rs (SUSE product security audited Rust RP library): https://github.com/kanidm/webauthn-rs
- tokio-listener crate (socket activation abstraction for Rust/tokio): https://lib.rs/crates/tokio-listener
- Yubico pam-u2f (reference PAM + FIDO2 implementation): https://developers.yubico.com/pam-u2f/
- DPoP nonce mechanics: https://darutk.medium.com/dpop-nonce-9787b9d276d1
- CIBA poll mode interval and flow semantics: https://curity.io/resources/learn/ciba-flow/

---
*Architecture research for: unix-oidc v2.0 production hardening and enterprise auth*
*Researched: 2026-03-10*
