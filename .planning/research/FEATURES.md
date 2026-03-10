# Feature Landscape: v2.0 Production Hardening and Enterprise Readiness

**Domain:** OIDC PAM module + agent daemon — production hardening, enterprise auth methods, session lifecycle
**Researched:** 2026-03-10
**Confidence:** HIGH (RFC primary sources + codebase inspection) | MEDIUM (CIBA/WebAuthn integration patterns)

> **Scope note:** This file covers only features new to v2.0. Features already delivered in v1.0
> (software/YubiKey/TPM signers, storage backends, memory protection, secure deletion, audit events,
> step-up sudo via device authorization grant) are not re-catalogued here. The existing v1.0
> FEATURES.md entry still applies to the agent key-protection domain.

---

## Framing: What "Production Ready" Means for This Domain

A PAM module that only works at the happy path is a liability in production. Production readiness
for a Linux authentication component means: it fails safely, it handles session revocation, it
integrates with how enterprises actually manage users (claim-based groups, IdP-agnostic MFA), and
it gives operators enough configuration surface to tune security without modifying code.

The eight features under research fall into two categories:

- **Security completeness:** DPoP nonce issuance, configurable enforcement modes, session lifecycle
  and revocation. These are gaps in the current implementation that represent security risks at
  scale.
- **Enterprise integration:** CIBA push, FIDO2 step-up, username mapping, group policies. These
  are what enterprises need to adopt the system alongside existing IdP infrastructure.

---

## Table Stakes (Users Expect These)

Features that production operators assume exist. Missing these blocks adoption in any non-trivial
deployment.

| Feature | Why Expected | Complexity | RFC/Spec | Notes |
|---------|--------------|------------|----------|-------|
| **DPoP nonce issuance (RFC 9449 §8)** | Without server-issued nonces, DPoP proofs have unbounded replay window — any proof valid during token lifetime can be replayed later. The RFC designates nonces as the mechanism for limiting proof lifetime to server-controlled intervals. Major IdPs (Okta, Auth0) have begun requiring nonces. | MEDIUM | RFC 9449 §8 | PAM module acts as the resource server in the auth model. Nonce issued in the PAM challenge phase; validated in the DPoP proof. Client must implement the `use_dpop_nonce` 400 retry cycle. |
| **Configurable security enforcement modes** | Enterprises span a spectrum from "strict RFC compliance required" (FAPI-grade finance) to "legacy IdP that omits JTI claims — please don't lock us out." The current codebase has a single hardcoded warn-vs-reject decision. Issue #10 tracks this. | LOW | IETF OAuth / internal | Three-level enum: `strict` (reject), `warn` (log and allow), `disabled` (skip check). Applies to: JTI enforcement, DPoP requirement, ACR/AMR claims. Config-file driven. HARD-FAIL checks (signature, issuer, audience, expiry, algorithm) are never configurable. |
| **Username claim mapping and transforms** | Every enterprise has a gap between OIDC `preferred_username` (e.g. `alice@corp.example.com`) and the Linux username (`alice`). Without mapping, authentication fails for 100% of users at large organizations. All comparable PAM-OIDC modules (Salesforce `pam_oidc`, `oidc-pam`) implement this. | LOW | OIDC Core §5 | Template expression (Go-template or Tera) applied to token claims. Required functions: `trimSuffix`, `trimPrefix`, `replace`, `lower`. Example: `{{.preferred_username \| trimSuffix "@corp.example.com"}}`. Claim source configurable: `sub`, `email`, `preferred_username`, or custom claim. |
| **Group-based access policy from OIDC claims** | Enterprises enforce "only members of the `linux-admins` group can SSH to production." Without OIDC-group gating at the PAM layer, organizations must maintain a separate out-of-band group membership sync (SCIM/LDAP) alongside the OIDC auth. This is the #1 adoption blocker at the org level. | MEDIUM | OIDC Core (custom claims) | PAM module reads a configured claim name (default: `groups`), checks user membership against a configured allow-list. Two policy levels: `login_groups` (can any session open) and `sudo_groups` (can step-up occur). Fail-open vs fail-closed configurable at deploy time. |
| **Automatic token refresh during session** | OIDC access tokens have short TTLs (typically 1h). A developer SSH session lasting 4 hours will fail mid-session when the token expires and the PAM module re-validates. The agent already holds refresh tokens but does not use them for background renewal. | MEDIUM | RFC 6749 §6 | Agent daemon refreshes access token in background before expiry (at configurable threshold, e.g. 80% of TTL elapsed). PAM module re-validates against current token on each sudo/step-up, not just at session open. Requires agent IPC: `RefreshToken` command path. |
| **Break-glass account enforcement** | Every production security guide (NIST SP 800-53 AC-2, CIS Controls) requires an emergency local account that bypasses OIDC. Without explicit configuration, deployers forget this step and get locked out when the IdP goes down. The CLAUDE.md for this project already calls it mandatory. | LOW | NIST SP 800-53 AC-2 | Config field `break_glass_users: [list]`. PAM module skips OIDC validation for these usernames and passes to next PAM module in stack. Audit event emitted on every break-glass use. Not a bypass — it is an intentional fallback chain. |

---

## Differentiators (Competitive Advantage)

Features that set unix-oidc apart from comparable tools. None of the three major PAM-OIDC
alternatives (Salesforce `pam_oidc`, `pam-keycloak-oidc`, `oidc-pam`) implement these.

| Feature | Value Proposition | Complexity | RFC/Spec | Notes |
|---------|-------------------|------------|----------|-------|
| **CIBA push notification step-up** | Current step-up uses Device Authorization Grant (RFC 8628), which is Keycloak-specific and requires the user to navigate a browser URL. CIBA (OpenID CIBA Core 1.0) is IdP-agnostic and delivers a push notification to a mobile authenticator app — dramatically better UX for a `sudo` approval flow. Users get a phone notification; they tap approve; access granted. | HIGH | OpenID CIBA Core 1.0 | Implement **poll mode** only in v2.0. Push and ping modes require the client to register a notification endpoint — not viable for a PAM module. Poll mode: PAM initiates backchannel auth request → receives `auth_req_id` → polls token endpoint until complete or timeout. `binding_message` field used to correlate notification to terminal command. Keycloak, Auth0, Okta, PingFederate, IBM Security Verify all support CIBA. |
| **FIDO2/WebAuthn hardware key step-up** | For high-security environments (e.g. access to production secrets), pressing a physical hardware key (YubiKey, SoloKey) as a second factor provides hardware-bound proof of presence that TOTP and push notifications cannot. This uses the CTAP2 assertion flow, not browser WebAuthn. | HIGH | W3C WebAuthn Level 2 / CTAP 2.1 | PAM module generates challenge, invokes CTAP2 assertion via `ctap-hid-fido2` or `libfido2` (C, well-maintained by Yubico). Credential ID stored per-user in a server-side registry (or in the token's `cnf` extension claim). Assertion verifies against registered public key. Requires: credential registration flow (out-of-band, not at PAM time), per-user credential store. **This is high complexity — evaluate whether CIBA push is sufficient before committing.** |
| **Token introspection for session revocation** | JWT-based access tokens are stateless; once issued, the only revocation mechanism is expiry. Token introspection (RFC 7662) lets the PAM module ask the IdP "is this token still active?" on every re-authentication check. This means revoking a token at the IdP immediately blocks new sessions and step-up operations — critical for "terminate terminated employee's access NOW" enterprise requirements. | MEDIUM | RFC 7662, RFC 7009 | Introspection endpoint called with `token_type_hint=access_token`. Cache result with short TTL (30s) to avoid flooding IdP on rapid sudo invocations. Configurable: `introspection: always | on_step_up | never`. When set to `never`, revocation relies only on token expiry (current behavior). TLS mutual auth for introspection endpoint per RFC 7662 §4. |
| **Full session lifecycle (open/close hooks)** | Current PAM module only implements `pam_sm_authenticate`. Production systems need `pam_sm_open_session` (record session start, anchor token to session) and `pam_sm_close_session` (revoke DPoP keys for the session, call RFC 7009 revocation endpoint, emit session-close audit event). This closes the gap where a token is still valid after the SSH session ends. | MEDIUM | Linux-PAM API, RFC 7009 | `pam_sm_open_session`: write `{token_thumbprint, session_id, username, remote_ip, opened_at}` to session store. `pam_sm_close_session`: call RFC 7009 revocation endpoint (best-effort), delete session record, emit `session_close` audit event. Session store: per-user state file under `/run/unix-oidc/sessions/` (tmpfs, 0600, root-owned). No panic paths — all failures logged and return `PAM_SUCCESS` to avoid session orphaning. |

---

## Anti-Features (Commonly Requested, Often Problematic)

| Anti-Feature | Why Requested | Why Problematic | Alternative |
|--------------|---------------|-----------------|-------------|
| **CIBA ping/push mode** | Eliminates client-side polling; server pushes result | PAM module cannot register a notification endpoint. Ping mode requires the PAM module to run an HTTP listener — entirely wrong model for a PAM module. Push mode has the same problem plus delivers tokens to an endpoint that may not be the authenticating host. | Use CIBA poll mode — same UX for the user (mobile push notification), correct server-client model for PAM. |
| **Interactive PIN/OTP prompt in PAM auth path** | Users expect to type their YubiKey OTP or TOTP at the terminal | PAM keyboard-interactive is unreliable under non-interactive SSH (`BatchMode yes`, ProxyJump, scripts), and the current step-up design uses the agent for all user interaction. Mixing direct terminal prompts with agent-based flows is fragile. | CIBA push or FIDO2 CTAP2 assertion (touch required, no PIN typing needed for presence check). |
| **Distributed JTI cache (Redis/Valkey)** | Prevent replay attacks in multi-node deployments sharing a PAM module | High operational complexity, requires Redis availability as a PAM dependency — if Redis is unreachable, fallback behavior (allow or deny all) is dangerous either way. Adds a network call to every authentication. | Scoped to v2.1 scalability milestone as a separate, opt-in backend. For v2.0, per-node JTI cache with bounded LRU is correct. |
| **Token exchange for server-to-server delegation** | Services running under a user session want a derived token for downstream calls | Requires RFC 8693 token exchange endpoint support, significant scope creep, and a separate ADR (ADR-005 already deferred to v2.1). The PAM module's job is user auth, not service-to-service identity propagation. | Separate milestone (v2.1). See ADR-005. |
| **VDI/agent forwarding** | Users want DPoP keys available on remote hosts after SSH hop | Proof-of-possession requires the private key on the authenticating device. Forwarding the key to another host undermines the threat model — the remote host now possesses the key, defeating the binding. | ProxyJump for multi-hop SSH; token exchange for service delegation (v2.1). |
| **SCIM provisioning** | Automatically create Linux accounts when a user logs in for the first time | Significant scope: SCIM endpoint, group sync, user lifecycle management. Conflicts with the PAM module's read-only posture (it should validate identity, not provision it). | Separate provisioning milestone. For v2.0, `sssd` or nss-pam-ldapd handles account existence; PAM handles authentication. |
| **WebAuthn browser-based flows at PAM** | Users want to authenticate via passkey in their browser and have it flow to SSH | Browser WebAuthn requires a browser context and JavaScript API. PAM is non-browser. Passkeys via CTAP2 to a physical authenticator are the correct non-browser analog — but require the device to be physically present, which is incompatible with remote SSH. | CIBA push covers the "remote phone approval" case. FIDO2 CTAP2 covers the "physical key presence on the client machine" case. |

---

## Feature Dependencies

```
DPoP nonce issuance (RFC 9449 §8)
    └── requires: existing DPoP proof generation (v1.0 - done)
    └── requires: PAM challenge/response extension (new IPC message: NonceChallenge)
    └── must land before: CIBA push (CIBA proofs also need nonce if IdP requires it)

Configurable security enforcement modes
    └── no hard prerequisites; touches existing validation.rs
    └── enables: safe deployment of DPoP nonce (can set to warn during rollout)
    └── should land before: group policy (group enforcement also needs a mode level)

Username claim mapping
    └── requires: existing claims parsing in validation.rs (v1.0 - done)
    └── no prerequisite features
    └── must land before: group policy (group membership check needs mapped username)

Group-based access policy
    └── requires: username mapping (group check must use final mapped identity)
    └── requires: existing policy engine in pam-unix-oidc/src/policy/ (v1.0 - done)

Break-glass account enforcement
    └── no prerequisites; config-file addition and PAM pass-through
    └── should land in same phase as group policy (both are access control features)

Automatic token refresh
    └── requires: agent daemon IPC (v1.0 - done)
    └── requires: existing refresh_token storage in AgentState (v1.0 - done)
    └── requires: session lifecycle (refresh must know if session is still open)

Session lifecycle (open/close hooks)
    └── requires: DPoP nonce issuance (session open should anchor nonce to session)
    └── requires: automatic token refresh (refresh runs within open session context)
    └── enables: token introspection (introspection only meaningful within a session)
    └── enables: RFC 7009 revocation on session close

Token introspection (RFC 7662)
    └── requires: session lifecycle (introspection result cached per session)
    └── requires: configurable enforcement modes (introspection mode is another knob)
    └── independent of: CIBA, FIDO2 (orthogonal concern)

CIBA push step-up
    └── requires: existing step-up policy engine (v1.0 - done)
    └── requires: configurable enforcement modes (CIBA required vs fallback policy)
    └── requires: DPoP nonce (CIBA token endpoint may require DPoP-bound tokens)
    └── replaces: Keycloak-specific device_authorization step-up (kept as fallback)
    └── independent of: FIDO2 (two different step-up methods, both valid)

FIDO2/WebAuthn CTAP2 step-up
    └── requires: existing step-up policy engine (v1.0 - done)
    └── requires: credential registration store (new component; high complexity)
    └── independent of: CIBA (orthogonal step-up method)
    └── complexity risk: higher than all other v2.0 features; evaluate after CIBA ships
```

### Dependency Notes

- **Session lifecycle gates several features:** `pam_sm_open_session` / `pam_sm_close_session` must
  be implemented before token refresh and introspection make full sense. Without a session record,
  "refresh during session" has no session to track.

- **Configurable modes are a prerequisite for safe rollout:** Every organization deploying v2.0
  will want to start in `warn` mode and tighten to `strict` after confirming their IdP emits the
  required claims. Ship configurable modes early.

- **Username mapping before group policy:** The group membership check must execute against the
  mapped username (the Linux identity), not the raw IdP identity, or the allow-list configuration
  is inconsistent with what `nsswitch` resolves.

- **FIDO2 step-up is independent but high-risk:** It does not block any other feature, but it
  introduces a new credential registration store and libfido2 dependency. Treat as an optional
  sub-feature of the step-up system; ship CIBA first.

---

## MVP Definition for v2.0 Milestone

### Phase A — Security Completeness (must ship; blocks enterprise production use)

- [x] DPoP nonce issuance per RFC 9449 §8 — closes replay window gap
- [x] Configurable security enforcement modes (strict/warn/disabled) — enables safe rollout
- [x] Session lifecycle: `pam_sm_open_session` + `pam_sm_close_session` — closes token-after-logout gap
- [x] Token introspection (RFC 7662) — enables immediate revocation for terminated users
- [x] Automatic token refresh — closes mid-session expiry failure

### Phase B — Enterprise Integration (must ship; blocks org-level adoption)

- [x] Username claim mapping with template transforms — blocks 100% of multi-domain enterprise deployments
- [x] Group-based access policy from OIDC claims — blocks org-level adoption gating
- [x] Break-glass account enforcement with audit trail — mandatory operational safety

### Phase C — Advanced Auth Methods (high value; CIBA is prerequisite for FIDO2 phase)

- [x] CIBA poll-mode step-up (IdP-agnostic) — replaces Keycloak-specific device_authorization flow
- [ ] FIDO2/WebAuthn CTAP2 step-up — defer until CIBA is in production; evaluate complexity vs. value

### Explicitly Deferred to v2.1+

- Distributed JTI cache (Redis/Valkey)
- RFC 8693 token exchange
- VDI/agent forwarding
- SCIM provisioning
- Post-quantum algorithm migration

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Configurable security enforcement modes | HIGH | LOW | P1 |
| Username claim mapping | HIGH | LOW | P1 |
| Break-glass enforcement | HIGH | LOW | P1 |
| DPoP nonce issuance (RFC 9449 §8) | HIGH | MEDIUM | P1 |
| Group-based access policy | HIGH | MEDIUM | P1 |
| Session lifecycle (open/close hooks) | HIGH | MEDIUM | P1 |
| Automatic token refresh | HIGH | MEDIUM | P1 |
| Token introspection (RFC 7662) | HIGH | MEDIUM | P2 |
| CIBA poll-mode step-up | MEDIUM | HIGH | P2 |
| FIDO2/WebAuthn CTAP2 step-up | MEDIUM | VERY HIGH | P3 |

**Priority key:**
- P1: Must ship in v2.0 — blocks production deployments
- P2: Should ship in v2.0 — significant security/UX improvement
- P3: Conditional — evaluate after P1+P2 are complete and stable

---

## Detailed Feature Notes

### DPoP Nonce (RFC 9449 §8) — Implementation Detail

The PAM module acts as the "resource server" in the RFC model. The nonce lifecycle:

1. **Issue:** PAM generates a cryptographically random nonce (128-bit minimum, base64url encoded)
   and delivers it to the client via the PAM challenge/response mechanism before the token
   presentation step.
2. **Verify:** Client includes `nonce` claim in the DPoP proof JWT. PAM verifies the nonce matches
   what was issued for this session, within the configured nonce TTL (suggested: 60s).
3. **Nonce error:** If the client presents a DPoP proof without a required nonce, PAM returns a
   structured error analogous to the `use_dpop_nonce` HTTP 400 response in RFC 9449 §8. The client
   agent retries with the nonce.
4. **Freshness:** Nonces are single-use; once verified, add to the JTI cache to prevent replay.
   Cache expiry at nonce TTL.

**Confidence:** HIGH — RFC 9449 §8 is unambiguous. The PAM IPC adaptation is novel but
mechanically straightforward.

### CIBA Poll Mode — Implementation Detail

The step-up flow using CIBA poll mode:

1. PAM module (or agent on behalf of PAM) sends HTTP POST to IdP backchannel authentication
   endpoint with: `login_hint` (the username), `binding_message` (the command being authorized,
   e.g. `sudo systemctl restart nginx on prod-server-1`), `scope` (requested ACR), client
   credentials.
2. IdP responds with `auth_req_id`, `expires_in`, `interval` (minimum poll interval, typically
   5s).
3. Agent polls the IdP token endpoint with `grant_type=urn:openid:params:grant-type:ciba` and
   `auth_req_id`. Responses: `authorization_pending` (keep polling), `slow_down` (double interval),
   success (tokens returned), error (deny).
4. PAM blocks (within its timeout budget) waiting for poll to complete. On success, validates the
   returned token for the step-up ACR claim.
5. `binding_message` is the key UX feature — the mobile push notification displays the exact
   command the user is approving, giving meaningful context rather than a generic "approve request"
   notification.

**IdP support:** Keycloak (CIBA PR merged 2022+, poll mode supported), Auth0 (enterprise tier),
Okta (preview 2024+), PingFederate 13.0+, IBM Security Verify. Pure poll mode is the most widely
supported across IdPs.

**PAM timeout:** The PAM module must respect a configurable total timeout (suggested: 120s). The
user has this window to approve on their phone before the step-up fails with `PAM_AUTH_ERR`.

**Confidence:** MEDIUM — CIBA poll mode is well-specified; the PAM integration pattern is derived
from the existing device authorization grant step-up code, which is an analogous polling flow.

### FIDO2/WebAuthn CTAP2 — Why It Is P3

Browser WebAuthn (`navigator.credentials.get()`) is the wrong API for PAM. The correct mechanism
for non-browser FIDO2 is CTAP2 directly over USB HID (or NFC), without any relying party server
HTTP round-trip at authentication time (only at registration time).

The flow: PAM generates a random challenge → agent invokes `libfido2` (`fido_assert_new` +
`fido_dev_get_assert`) → FIDO2 device signs challenge → PAM verifies assertion against stored
public key. The credential ID and public key are registered once (out-of-band enrollment CLI)
and stored in a per-user credential store (suggested: `/etc/unix-oidc/credentials/<username>.json`
or the user's home directory `.config/unix-oidc/fido2_credentials`).

**Why P3:** Credential registration workflow is entirely separate from the PAM path and requires
its own UX design. The credential store adds a new data management concern. For most enterprises,
CIBA push (phone approval) is operationally simpler and covers the same security tier. Defer
unless there is explicit demand for "physical key touch required" enforcement.

**Confidence:** MEDIUM — CTAP2 over USB HID is well-understood (pam-u2f demonstrates this);
the integration with the existing step-up ACR policy engine is novel.

### Token Introspection (RFC 7662) — Caching Requirement

Introspection adds a network call to every re-authentication check. Without caching, a rapid
succession of `sudo` commands would flood the IdP introspection endpoint.

**Required caching strategy:** Cache `{token_jti → {active, exp, username}}` with TTL = min(30s,
`exp - now`). On cache hit: use cached result. On cache miss: call introspection endpoint, cache
result. On introspection endpoint failure: configurable fallback — `allow` (current behavior,
stateless) or `deny` (strict revocation enforcement). Mutually exclusive with `introspection: never`
mode.

**RFC 7662 §4 authentication:** The PAM module presents client credentials to the introspection
endpoint (client_credentials or private_key_jwt). This means the PAM module needs a client_id and
client_secret (or key pair) in its configuration. This is a new credential type not currently in
the config schema.

### Session Lifecycle — PAM Hook Model

Linux PAM has four hook categories: `auth`, `account`, `password`, `session`. Currently only `auth`
is implemented. The `session` category adds `pam_sm_open_session` and `pam_sm_close_session`.

**Session store design:** `/run/unix-oidc/sessions/<username>-<session-id>` (one file per session).
Contents: `{token_thumbprint, jti, username, remote_ip, opened_at, agent_socket_path}`. This is
tmpfs-backed, cleared on reboot, 0600 permissions, root-owned. Accessed only by the PAM module.

**Close session:** Called by sshd (and sudo) when the session ends. Must not panic. Must not block
indefinitely. Uses a short timeout (5s) for the RFC 7009 revocation call; logs failure and proceeds
regardless.

**Conflict with DPoP:** When `pam_sm_close_session` revokes the access token, the DPoP key in
the agent is now orphaned — it is bound to a revoked token. The agent should receive a
`SessionClosed` IPC event and schedule the DPoP key for deletion after a short grace period (to
allow in-flight operations to complete).

---

## Competitor Feature Comparison

| Feature | Salesforce `pam_oidc` | `pam-keycloak-oidc` | `oidc-pam` | unix-oidc v2.0 |
|---------|----------------------|---------------------|------------|----------------|
| DPoP binding | No | No | No | Yes (v1.0) |
| Username transform | Yes (Go template) | Yes (config field) | Yes (regex) | Yes (template, v2.0) |
| Group policy | Yes (allow-list) | No | Yes | Yes (v2.0) |
| Session lifecycle hooks | No | No | No | Yes (v2.0) |
| Token introspection | No | No | No | Yes (v2.0) |
| CIBA step-up | No | No | No | Yes, poll mode (v2.0) |
| FIDO2 step-up | No | No | No | Deferred (v2.1) |
| DPoP nonce issuance | No | No | No | Yes (v2.0) |
| Configurable enforcement | No | No | No | Yes (v2.0) |
| Hardware signers | No | No | No | Yes (v1.0) |
| Break-glass enforcement | No | Partial | No | Yes (v2.0) |

unix-oidc has no direct feature-equivalent competitor for the full combination. The gap vs.
commercial solutions (BeyondTrust, CyberArk) is largely in PAM-level token binding (DPoP) and the
absence of a management plane — both are intentional scope decisions.

---

## Sources

**RFCs (HIGH confidence):**
- RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP): https://www.rfc-editor.org/rfc/rfc9449 — Section 8 covers server-issued nonces; nonces are unpredictable, single-use, conveyed via `DPoP-Nonce` header; client retries on `use_dpop_nonce` 400 error
- RFC 7662 — OAuth 2.0 Token Introspection: https://www.rfc-editor.org/rfc/rfc7662
- RFC 7009 — OAuth 2.0 Token Revocation: https://www.rfc-editor.org/rfc/rfc7009
- RFC 6749 §6 — Refreshing an Access Token: https://www.rfc-editor.org/rfc/rfc6749#section-6
- RFC 8628 — OAuth 2.0 Device Authorization Grant: https://www.rfc-editor.org/rfc/rfc8628 (existing v1.0 step-up; keep as IdP-specific fallback)
- OIDC Core 1.0 §5 — Standard Claims (preferred_username, email, sub): https://openid.net/specs/openid-connect-core-1_0.html

**OpenID Foundation specs (HIGH confidence):**
- OpenID CIBA Core 1.0: https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html — Defines poll/ping/push modes, `auth_req_id`, `binding_message`, polling error codes (`authorization_pending`, `slow_down`)

**W3C/FIDO specs (HIGH confidence for protocol; MEDIUM for PAM integration pattern):**
- W3C WebAuthn Level 2: https://www.w3.org/TR/webauthn-2/
- CTAP 2.1 spec: https://fidoalliance.org/specs/fido-v2.1-rd-20210615/fido-client-to-authenticator-protocol-v2.1-rd-20210615.html
- Yubico pam-u2f (reference FIDO2 PAM implementation): https://developers.yubico.com/pam-u2f/ and https://github.com/Yubico/pam-u2f

**NIST (HIGH confidence):**
- NIST SP 800-53 Rev. 5, AC-2 (Account Management) — break-glass accounts as a required control

**IdP documentation (MEDIUM confidence — verified at search time):**
- Auth0 CIBA: https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
- Keycloak CIBA design: https://github.com/keycloak/keycloak-community/blob/main/design/client-initiated-backchannel-authentication-flow.md
- Okta DPoP nonce requirement: https://developer.okta.com/docs/guides/dpop/nonoktaresourceserver/main/
- Connect2id token introspection: https://connect2id.com/products/server/docs/api/token-introspection

**Comparable PAM-OIDC implementations (MEDIUM confidence):**
- Salesforce pam_oidc (Go template username mapping): https://github.com/salesforce/pam_oidc
- pam-keycloak-oidc: https://github.com/zhaow-de/pam-keycloak-oidc
- oidc-pam (scttfrdmn): https://github.com/scttfrdmn/oidc-pam

---

*Research completed: 2026-03-10*
*Milestone: unix-oidc v2.0 — Production Hardening and Enterprise Readiness*
*Ready for roadmap: yes*
