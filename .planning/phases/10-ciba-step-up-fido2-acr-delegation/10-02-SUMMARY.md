---
phase: 10-ciba-step-up-fido2-acr-delegation
plan: "02"
subsystem: ipc-protocol, device-flow
tags: [ciba, step-up, ipc, device-flow, oidc-discovery]
dependency_graph:
  requires: []
  provides: [step-up-ipc-protocol, device-flow-from-discovery]
  affects: [unix-oidc-agent/daemon, pam-unix-oidc/device_flow, pam-unix-oidc/oidc]
tech_stack:
  added: []
  patterns: [serde-untagged-enum-ordering, oidc-discovery-driven-endpoints]
key_files:
  created: []
  modified:
    - unix-oidc-agent/src/daemon/protocol.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - pam-unix-oidc/src/device_flow/client.rs
    - pam-unix-oidc/src/device_flow/types.rs
    - pam-unix-oidc/src/oidc/mod.rs
decisions:
  - "StepUpPending placed before Refreshed in untagged AgentResponseData enum — both have expires_in; serde must try StepUpPending (with unique poll_interval_secs) first to prevent incorrect Refreshed match"
  - "DeviceFlowClient::new() retained for backward compat but documented as Keycloak-specific; from_discovery() is the IdP-agnostic constructor for all future use"
  - "OidcDiscovery re-exported from pam_unix_oidc::oidc module — single import path for device_flow, ciba, and future modules"
  - "DeviceFlowError::ConfigError added for missing endpoint errors — distinct from NetworkError and InvalidResponse"
metrics:
  duration_secs: 277
  completed_date: "2026-03-11"
  tasks_completed: 2
  files_modified: 5
requirements: [STP-05, STP-06]
---

# Phase 10 Plan 02: Step-Up IPC Protocol + Device Flow Discovery Summary

**One-liner:** Step-up IPC contract (StepUp/StepUpResult/StepUpPending/StepUpComplete/StepUpTimedOut) added to agent protocol; DeviceFlowClient gains IdP-agnostic from_discovery() constructor reading endpoints from OIDC discovery metadata.

## What Was Built

### Task 1: Step-Up IPC Protocol Messages (unix-oidc-agent)

Six new IPC message variants define the PAM-to-agent step-up authentication contract:

**AgentRequest additions:**
- `StepUp { username, command, hostname, method, timeout_secs }` — PAM initiates CIBA step-up
- `StepUpResult { correlation_id }` — PAM polls for result

**AgentResponseData additions (with serde ordering critical):**
- `StepUpPending { correlation_id, expires_in, poll_interval_secs }` — step-up initiated, PAM should poll
- `StepUpComplete { acr, session_id }` — step-up succeeded
- `StepUpTimedOut { reason, user_message }` — step-up failed or expired

**Serde untagged enum ordering:** `StepUpPending` placed BEFORE `Refreshed` because both variants contain `expires_in`. Serde's untagged deserializer tries variants in declaration order; `StepUpPending`'s unique `poll_interval_secs` field discriminates it correctly when tried first.

**Convenience constructors added:** `step_up_pending()`, `step_up_complete()`, `step_up_timed_out()`

**Socket stub arms:** `handle_request` in `socket.rs` gets exhaustive match arms for `StepUp` and `StepUpResult` returning `NOT_IMPLEMENTED` — the full CIBA poll loop is implemented in Plan 10-03.

### Task 2: DeviceFlowClient::from_discovery (pam-unix-oidc)

- `DeviceFlowClient::from_discovery(&OidcDiscovery, client_id, client_secret)` — reads `device_authorization_endpoint` and `token_endpoint` directly from discovery metadata; returns `ConfigError` when the IdP does not advertise `device_authorization_endpoint`
- `DeviceFlowError::ConfigError(String)` variant added for missing endpoint detection
- `DeviceFlowClient` derives `Debug`
- `OidcDiscovery` re-exported from `pam_unix_oidc::oidc` — accessible to device_flow, ciba, and future modules
- `DeviceFlowClient::new()` documented as Keycloak-specific (hardcoded `/protocol/openid-connect/` paths); `from_discovery()` preferred for all other IdPs

## Verification

```
cargo test -p unix-oidc-agent --lib -- daemon::protocol   → 22/22 pass
cargo test -p pam-unix-oidc --lib -- device_flow          → 9/9 pass
cargo clippy -p unix-oidc-agent -p pam-unix-oidc -D warn → clean
```

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added stub arms for StepUp/StepUpResult in socket.rs handle_request**
- **Found during:** Task 1 GREEN phase — exhaustive match compile error
- **Issue:** Adding new AgentRequest variants requires all match arms to be handled; socket.rs's `handle_request` would not compile
- **Fix:** Added `NOT_IMPLEMENTED` error arms for both variants with doc comment explaining full implementation is in Plan 10-03
- **Files modified:** unix-oidc-agent/src/daemon/socket.rs
- **Commit:** a85a742

**2. [Rule 1 - Bug] Reordered StepUpPending before Refreshed in AgentResponseData**
- **Found during:** Task 1 GREEN phase — test failure (StepUpPending deserialized as Refreshed)
- **Issue:** Both variants have `expires_in`; serde's untagged deserializer matched `Refreshed` first because it appeared earlier in the enum
- **Fix:** Moved `StepUpPending`, `StepUpComplete`, `StepUpTimedOut` before `Refreshed` in the enum; added ordering contract documentation
- **Files modified:** unix-oidc-agent/src/daemon/protocol.rs
- **Commit:** a85a742

**3. [Rule 3 - Blocking] OidcDiscovery already had CIBA fields from prior planning work**
- **Found during:** Task 2 RED phase — `OidcDiscovery` in jwks.rs already had `backchannel_*` fields added (likely during Phase 10 planning)
- **Action:** Test helper updated to include `backchannel_authentication_endpoint: None` and `backchannel_token_delivery_modes_supported: None`; no structural change needed

**4. [Rule 2 - Missing functionality] Added `#[derive(Debug)]` to DeviceFlowClient**
- **Found during:** Task 2 — test `unwrap_err()` requires Debug on Ok type
- **Fix:** Added `#[derive(Debug)]` to DeviceFlowClient struct
- **Files modified:** pam-unix-oidc/src/device_flow/client.rs
- **Commit:** 06b6bfe

## Self-Check: PASSED

- FOUND: unix-oidc-agent/src/daemon/protocol.rs
- FOUND: pam-unix-oidc/src/device_flow/client.rs
- FOUND: .planning/phases/10-ciba-step-up-fido2-acr-delegation/10-02-SUMMARY.md
- FOUND commit a85a742: feat(10-02): add step-up IPC protocol messages to agent daemon
- FOUND commit 06b6bfe: feat(10-02): add DeviceFlowClient::from_discovery and re-export OidcDiscovery
