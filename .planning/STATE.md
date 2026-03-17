---
gsd_state_version: 1.0
milestone: v3.0
milestone_name: External IdP Integration & PoP Landscape
status: defining_requirements
stopped_at: null
last_updated: "2026-03-16T22:00:00.000Z"
last_activity: "2026-03-16 — Milestone v3.0 started"
progress:
  total_phases: 0
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-16)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** v3.0 — External IdP Integration & PoP Landscape

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-03-16 — Milestone v3.0 started

## Accumulated Context

### Key Decisions Affecting v3.0

- DPoP + Device Auth Grant is not supported by any commercial IdP (Entra, Auth0, Okta) — only Keycloak 26.0+ issues DPoP-bound tokens on device flow
- Entra has no RFC 9449 DPoP at all; proprietary PoP (SHR) is Windows WAM-only
- Auth0 DPoP is GA (Enterprise) but only on Auth Code + PKCE, not Device Auth Grant
- IETF draft-parecki-oauth-dpop-device-flow-00 (Sep 2025) addresses the gap but has no implementations
- Auth Code + PKCE flow deferred — Keycloak covers DPoP better than building a new flow
- Token Exchange (RFC 8693) bridge architecture documented but implementation deferred to v3.1
- mTLS (RFC 8705) incompatible with SSH/PAM transport
- Client Attestation PoP (draft-ietf-oauth-attestation-based-client-auth-08) is cleanest future path, not yet RFC
- Tests must run in CI (secrets-gated) AND locally with env vars

### Research Sources

- Entra: Microsoft Learn primary docs, MSAL.NET PoP docs
- Auth0: auth0.com/docs, DPoP GA announcement (Aug 2025)
- Keycloak: keycloak.org release notes, GitHub #30179
- IETF: RFC 9449, RFC 8628, RFC 8705, RFC 8693, draft-parecki-oauth-dpop-device-flow-00, draft-ietf-oauth-attestation-based-client-auth-08

### Blockers/Concerns

- Entra tenant access needed for live E2E (user confirms available)
- Auth0 free tier — no DPoP available, bearer-only testing
- No blockers known

### Pending Todos

- None (fresh milestone)

## Key Decisions

| Phase | Decision |
|-------|----------|
| — | (none yet) |

## Session Continuity

Last session: 2026-03-16
Stopped at: Milestone v3.0 initialized, defining requirements
Resume file: None
