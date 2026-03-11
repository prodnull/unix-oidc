---
phase: 10-ciba-step-up-fido2-acr-delegation
plan: "01"
subsystem: auth
tags: [ciba, oidc-discovery, acr, fido2, dpop, jwt, rust]

# Dependency graph
requires:
  - phase: 09-session-management-revocation
    provides: revocation_endpoint stored in token metadata at login (reused in OidcDiscovery extension)

provides:
  - Extended OidcDiscovery (pub) with CIBA + device-flow endpoint fields
  - pam-unix-oidc/src/ciba/ module with CibaError, BackchannelAuthResponse, CibaTokenResponse
  - ACR_PHR / ACR_PHRH constants (OpenID EAP ACR Values 1.0 Final URIs)
  - CIBA_GRANT_TYPE constant (urn:openid:params:grant-type:ciba)
  - satisfies_acr / validate_acr hard-fail ACR validation helpers
  - parse_ciba_error CIBA Core 1.0 §11 error mapping
  - CibaClient: new() validates poll mode support; builds backchannel auth + token poll params
  - build_binding_message: command-arg-stripped, 64-char-capped user message

affects: [10-02, 10-03, agent-daemon, step-up-handler]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Parameter-builder pattern: CibaClient builds form params only; HTTP execution stays in agent daemon"
    - "ACR hierarchy: phrh (hardware) satisfies phr (phishing-resistant), not the reverse"
    - "binding_message security: strip args before display, basename only, 64-char cap"
    - "CIBA poll mode assumption: absent backchannel_token_delivery_modes_supported → poll assumed"

key-files:
  created:
    - pam-unix-oidc/src/ciba/mod.rs
    - pam-unix-oidc/src/ciba/types.rs
    - pam-unix-oidc/src/ciba/client.rs
  modified:
    - pam-unix-oidc/src/oidc/jwks.rs
    - pam-unix-oidc/src/lib.rs

key-decisions:
  - "OidcDiscovery made pub with all fields pub; backward compat via serde(default) on all new optional fields"
  - "token_endpoint added as required field (not Option) — mandatory per OIDC Core 1.0 and needed for CIBA token polling"
  - "ACR validation is hard-fail, not EnforcementMode-configurable — security invariant per CLAUDE.md"
  - "CibaClient is parameter-builder only, no HTTP — keeps PAM crate free of async I/O for CIBA"
  - "build_binding_message strips command arguments — they may contain sensitive paths (research Pitfall 6)"
  - "CIBA_GRANT_TYPE uses urn:openid:params not urn:ietf:params — corrected per CIBA Core 1.0 §2"

patterns-established:
  - "Security invariant: ACR checks never bypassed via configuration"
  - "CibaError variants map 1:1 to CIBA Core 1.0 §11 error codes"
  - "binding_message never leaks command-line arguments"

requirements-completed: [STP-02, STP-03, STP-04]

# Metrics
duration: 10min
completed: 2026-03-11
---

# Phase 10 Plan 01: CIBA Protocol Foundation Summary

**CIBA backchannel auth parameter builder + ACR hard-fail validation + extended OidcDiscovery with CIBA/device-flow fields**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-11T03:25:00Z
- **Completed:** 2026-03-11T03:35:30Z
- **Tasks:** 2
- **Files modified:** 5 (3 created, 2 modified)

## Accomplishments

- Extended `OidcDiscovery` to pub with `token_endpoint`, `device_authorization_endpoint`, `backchannel_authentication_endpoint`, `backchannel_token_delivery_modes_supported`, `revocation_endpoint`; all new fields `serde(default)` for backward compat
- New `pam-unix-oidc/src/ciba/` module: `CibaError` with CIBA Core 1.0 §11 error codes, `BackchannelAuthResponse`/`CibaTokenResponse` deserializers, ACR constants, `validate_acr` hard-fail helper
- `CibaClient`: validates poll mode from discovery metadata, builds backchannel auth and token poll params per CIBA Core 1.0 §7.1 and §10.1
- `build_binding_message`: strips command arguments (security), extracts basename, 64-char cap
- 33 new tests; all 291 existing tests pass; clippy clean

## Task Commits

1. **Task 1 RED: OidcDiscovery extension + CIBA types tests** - `93f9deb` (test)
2. **Task 1+2 GREEN: Full implementation** - `1756564` (feat)

## Files Created/Modified

- `pam-unix-oidc/src/ciba/mod.rs` - Module re-exports for CibaClient and types
- `pam-unix-oidc/src/ciba/types.rs` - CibaError, response types, ACR constants/validation, parse_ciba_error
- `pam-unix-oidc/src/ciba/client.rs` - CibaClient parameter builder + build_binding_message
- `pam-unix-oidc/src/oidc/jwks.rs` - OidcDiscovery extended and made pub
- `pam-unix-oidc/src/lib.rs` - `pub mod ciba;` added

## Decisions Made

- `token_endpoint` is a required field on `OidcDiscovery` (not `Option`) — OIDC Core 1.0 mandates it and CIBA token polling requires it
- ACR validation is always hard-fail; there is no `EnforcementMode` wrapper — this is a security invariant per CLAUDE.md and the plan spec
- `CibaClient` is a parameter-builder only; actual HTTP calls stay in the agent daemon — keeps the PAM crate free of async dependencies for CIBA
- `build_binding_message` strips all command arguments — they may contain sensitive paths/data (research Pitfall 6 from 10-RESEARCH.md)
- `CIBA_GRANT_TYPE = "urn:openid:params:grant-type:ciba"` uses `openid:params` not `ietf:params` — corrected per CIBA Core 1.0 §2
- Poll mode assumption: if `backchannel_token_delivery_modes_supported` is absent, assume poll is available — some IdPs omit the field when poll is the only mode

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- `CibaClient` needed `#[derive(Debug)]` to allow `unwrap_err()` in tests — trivial fix inline with RED phase.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Plan 02 can use `CibaClient::new()` and `build_binding_message()` directly
- Plan 03 (agent daemon step-up handler) needs `CibaClient`, `BackchannelAuthResponse`, `CibaTokenResponse`, and `validate_acr`
- `OidcDiscovery` is now pub — device_flow module and agent daemon can access endpoints without re-discovery

---
*Phase: 10-ciba-step-up-fido2-acr-delegation*
*Completed: 2026-03-11*

## Self-Check: PASSED

- pam-unix-oidc/src/ciba/mod.rs: FOUND
- pam-unix-oidc/src/ciba/types.rs: FOUND
- pam-unix-oidc/src/ciba/client.rs: FOUND
- commit 93f9deb: FOUND
- commit 1756564: FOUND
