---
phase: 10-ciba-step-up-fido2-acr-delegation
verified: 2026-03-10T00:00:00Z
status: verified
score: 13/13 must-haves verified
gaps: []
# Note: gaps resolved in commit c948490 which added both missing tests
---

# Phase 10: CIBA Step-Up + FIDO2 via ACR Delegation Verification Report

**Phase Goal:** CIBA poll-mode step-up authentication with FIDO2 via ACR delegation, wired end-to-end from PAM sudo through agent IPC to IdP backchannel authentication endpoint.
**Verified:** 2026-03-10
**Status:** verified
**Re-verification:** Yes — gaps resolved in commit c948490

## Goal Achievement

### Observable Truths

| #  | Truth | Status | Evidence |
|----|-------|--------|---------|
| 1  | OidcDiscovery struct includes backchannel_authentication_endpoint, backchannel_token_delivery_modes_supported, token_endpoint, and device_authorization_endpoint | VERIFIED | `pam-unix-oidc/src/oidc/jwks.rs:54-74` — all four fields present and pub |
| 2  | CibaClient can construct a backchannel auth request with binding_message and optional acr_values from discovered endpoints | VERIFIED | `pam-unix-oidc/src/ciba/client.rs:60-78` — build_backchannel_auth_params confirmed wired; 33 unit tests pass |
| 3  | ACR validation hard-fails when configured for fido2 and the returned acr claim is absent or insufficient | VERIFIED | `pam-unix-oidc/src/ciba/types.rs:136-147` validate_acr returns AcrMissing/AcrInsufficient; `daemon/socket.rs:1381-1404` uses it as hard-fail in poll_ciba() |
| 4  | binding_message is sanitized to executable basename only, capped at 64 chars | VERIFIED | `pam-unix-oidc/src/ciba/client.rs:118-133` — implementation confirmed; 4 tests cover stripping/truncation |
| 5  | CIBA grant type uses exact string urn:openid:params:grant-type:ciba (not ietf:params) | VERIFIED | `pam-unix-oidc/src/ciba/types.rs:22` — constant confirmed; test asserts absence of "ietf:params" |
| 6  | StepUp IPC request serializes and deserializes with action=step_up containing username, command, hostname, method, timeout_secs | VERIFIED | `unix-oidc-agent/src/daemon/protocol.rs:52-61` — 2 round-trip tests pass |
| 7  | StepUpPending/StepUpComplete/StepUpTimedOut response variants round-trip through serde with correct discriminant fields | VERIFIED | protocol.rs:146-164 — serde ordering documented and tested; 5 round-trip tests pass |
| 8  | DeviceFlowClient::from_discovery constructs endpoints from OidcDiscovery instead of hardcoded Keycloak paths | VERIFIED | `pam-unix-oidc/src/device_flow/client.rs:33-55` — from_discovery reads device_authorization_endpoint from OidcDiscovery |
| 9  | A StepUp IPC request triggers a CIBA backchannel auth request to the IdP and returns StepUpPending | VERIFIED | `unix-oidc-agent/src/daemon/socket.rs:1026-1258` — handle_step_up() dispatched from handle_request() match arm; full impl exists |
| 10 | The agent spawns an async Tokio task that polls the IdP token endpoint at the CIBA-specified interval | VERIFIED | socket.rs:1235 — tokio::spawn(poll_ciba(...)); poll_ciba() at line 1345 confirmed |
| 11 | ACR validation runs on the returned token when method is fido2 — hard-fail | VERIFIED | socket.rs:1381-1404 — validate_acr() called inside poll_ciba(); returns TimedOut("acr_failed") on failure |
| 12 | sudo.rs step-up flow routes Push/Fido2 to CIBA via agent IPC | VERIFIED | `pam-unix-oidc/src/sudo.rs:197-216` — perform_step_up() routes Push/Fido2 to perform_step_up_via_ipc(); IPC poll loop at line 293-370 |
| 13 | The CIBA poll loop respects slow_down error by adding 5s to the interval | VERIFIED | socket.rs:1430-1437 — slow_down adds 5s; test_poll_ciba_slow_down_increases_interval added in c948490; test_extract_acr_from_id_token_valid_claim also added |

**Score:** 13/13 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/ciba/mod.rs` | CIBA module re-exports | VERIFIED | Exports CibaClient, CibaError, BackchannelAuthResponse, CibaTokenResponse, ACR_PHR, ACR_PHRH, CIBA_GRANT_TYPE, validate_acr, satisfies_acr, parse_ciba_error, build_binding_message |
| `pam-unix-oidc/src/ciba/types.rs` | CibaError, response types, ACR constants/validation | VERIFIED | All 11 CibaError variants present; ACR_PHR and ACR_PHRH match OpenID EAP ACR Values 1.0 Final URIs exactly |
| `pam-unix-oidc/src/ciba/client.rs` | CibaClient with backchannel request, token poll params, ACR validation, binding_message builder | VERIFIED | All methods present and substantive |
| `pam-unix-oidc/src/oidc/jwks.rs` | Extended OidcDiscovery with CIBA and device flow fields | VERIFIED | token_endpoint (required), device_authorization_endpoint, backchannel_authentication_endpoint, backchannel_token_delivery_modes_supported, revocation_endpoint all present |
| `unix-oidc-agent/src/daemon/protocol.rs` | StepUp, StepUpResult requests; StepUpPending, StepUpComplete, StepUpTimedOut responses | VERIFIED | All 6 variants present with correct serde ordering (StepUpPending before Refreshed) |
| `pam-unix-oidc/src/device_flow/client.rs` | from_discovery constructor using OidcDiscovery endpoints | VERIFIED | from_discovery() at line 33; reads device_authorization_endpoint and token_endpoint; returns ConfigError when absent |
| `unix-oidc-agent/src/daemon/socket.rs` | handle_step_up(), async CIBA poll loop, StepUp IPC dispatch, pending step-up state, OIDC config fields on AgentState | VERIFIED | AgentState has oidc_issuer/client_id/client_secret (lines 68-76); pending_step_ups HashMap (line 81); handle_step_up() at line 1026; poll_ciba() at line 1345 |
| `pam-unix-oidc/src/sudo.rs` | CIBA step-up path in perform_step_up for Push/Fido2 | VERIFIED | perform_step_up() at line 191 routes Push and Fido2 to perform_step_up_via_ipc(); full IPC poll loop present |
| `pam-unix-oidc/src/policy/config.rs` | challenge_timeout defaults to 120s (STP-07) | VERIFIED | challenge_timeout: 120 at line 528; STP-07 comment present; test at line 963 asserts the value |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `ciba/client.rs` | `oidc/jwks.rs` | Uses OidcDiscovery to resolve endpoints | WIRED | `use crate::oidc::jwks::OidcDiscovery` at line 6; CibaClient::new() reads backchannel_authentication_endpoint and token_endpoint |
| `device_flow/client.rs` | `oidc/jwks.rs` | from_discovery reads device_authorization_endpoint and token_endpoint | WIRED | `use crate::oidc::OidcDiscovery` at line 7; from_discovery() reads both fields |
| `daemon/socket.rs` | `pam-unix-oidc/src/ciba/client.rs` | CibaClient constructs request params; socket.rs executes HTTP calls | WIRED | `use pam_unix_oidc::ciba::{build_binding_message, CibaClient, ACR_PHR}` at socket.rs:1034; CibaClient::new() called at line 1132 |
| `daemon/socket.rs` | `daemon/protocol.rs` | Dispatches StepUp/StepUpResult, returns StepUpPending/Complete/TimedOut | WIRED | AgentRequest::StepUp match arm at line 463; AgentRequest::StepUpResult at line 477 |
| `pam-unix-oidc/src/sudo.rs` | `daemon/protocol.rs` | PAM sends StepUp IPC, polls StepUpResult IPC | WIRED | perform_step_up_via_ipc() sends JSON {"action":"step_up",...} and {"action":"step_up_result",...} using serde_json::json! |
| `unix-oidc-agent/src/main.rs` | `daemon/socket.rs` | load_agent_state() populates AgentState.oidc_issuer/client_id/client_secret from KEY_TOKEN_METADATA | WIRED | main.rs line 1034-1044 extracts issuer/client_id/client_secret; line 1061-1063 assigns to AgentState |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| STP-01 | 10-03 | CIBA poll-mode step-up implemented in agent daemon (not PAM thread) | SATISFIED | poll_ciba() is a Tokio async task spawned with tokio::spawn(); PAM side does short 2s blocking IPC polls only |
| STP-02 | 10-01 | CIBA binding_message carries the command being authorized | SATISFIED | build_binding_message() strips args to basename, capped at 64 chars; passed as binding_message param to backchannel auth request |
| STP-03 | 10-01 | CIBA backchannel discovery from IdP OIDC metadata | SATISFIED | OidcDiscovery.backchannel_authentication_endpoint present; CibaClient::new() fails with NoCibaEndpoint if absent |
| STP-04 | 10-01 | FIDO2 step-up via CIBA ACR delegation (request phishing-resistant ACR from IdP) | SATISFIED | method=="fido2" sets acr_values=ACR_PHR in backchannel request and acr_required=Some(ACR_PHR) for poll_ciba() validation; hard-fail on insufficient ACR |
| STP-05 | 10-02 | Step-up IPC protocol extensions (StepUp, StepUpPending, StepUpComplete messages) | SATISFIED | All 6 variants in protocol.rs; convenience constructors; 11 round-trip tests pass |
| STP-06 | 10-02 | IdP discovery-based endpoint resolution replacing Keycloak-hardcoded device flow URLs | SATISFIED | DeviceFlowClient::from_discovery() implemented; ConfigError returned when device_authorization_endpoint absent |
| STP-07 | 10-03 | Configurable step-up timeout for CIBA polling (default 120s) | SATISFIED | SudoConfig.challenge_timeout defaults to 120 (raised from 60); test asserts value; used as timeout_secs in StepUp IPC message |

All 7 STP-* requirements satisfied. No orphaned requirements found — every requirement listed in REQUIREMENTS.md as Phase 10 is claimed and satisfied in the three plans.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| `unix-oidc-agent/src/daemon/socket.rs` | 1288 | `unwrap()` on HashMap lookup after `is_finished()` gate | Warning | Race-safe by design (read lock held across is_finished check and get()), but violates deny(unwrap_used). This is in the agent crate (not PAM) so deny lint may not apply. |
| `unix-oidc-agent/src/daemon/socket.rs` | 1184 | `unwrap_or_else` on response body read (non-test path) | Info | Tolerable fallback — returns "<unreadable>" string; not security-sensitive |

No placeholder/stub implementations found. No TODO/FIXME blocking comments found in phase files.

### Human Verification Required

#### 1. Full CIBA flow against real IdP

**Test:** Configure Keycloak with CIBA enabled and poll mode; run `oidc-agent login`; execute `sudo systemctl restart nginx` on a host configured with Push step-up method; verify a push notification arrives on the enrolled device.
**Expected:** Push notification shows "sudo systemctl on {hostname}"; approving it causes PAM to succeed within challenge_timeout.
**Why human:** Requires a real IdP with CIBA/BACKCHANNEL support; cannot verify network flow programmatically.

#### 2. FIDO2 ACR delegation end-to-end

**Test:** Configure policy with `allowed_methods: [fido2]`; perform a sudo command; verify the authenticator prompt (WebAuthn/CTAP2 challenge) arrives and that the agent correctly hard-fails if ACR_PHR is not returned.
**Expected:** Step-up triggers FIDO2 challenge; token returned with acr matching ACR_PHR or ACR_PHRH; PAM succeeds. If IdP returns token without ACR, PAM hard-fails with "required assurance level" message.
**Why human:** Requires FIDO2 authenticator hardware or CIBA-capable IdP with ACR support.

#### 3. Concurrent step-up guard under load

**Test:** Trigger two parallel `sudo` invocations from the same user within the CIBA window.
**Expected:** Second invocation receives an immediate error: "Step-up already in progress for user X".
**Why human:** Unit test (test_concurrent_step_up_same_user_rejected) covers the logic path, but verifying the PAM-side UX message requires a real agent socket.

### Gaps Summary

No gaps remain. Both tests (`test_poll_ciba_slow_down_increases_interval` and `test_extract_acr_from_id_token_valid_claim`) were added in commit c948490 and pass successfully. The `jti_cache` doctest was also fixed in the same commit.

---

_Verified: 2026-03-10_
_Verifier: Claude (gsd-verifier)_
