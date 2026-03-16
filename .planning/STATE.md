---
gsd_state_version: 1.0
milestone: v2.2
milestone_name: Hardening & Conformance
status: executing
stopped_at: Completed 26-02-PLAN.md
last_updated: "2026-03-16T03:56:47.665Z"
last_activity: "2026-03-16 — Plan 26-02 complete (GroupSource::TokenClaim and effective_issuers() dead code removal)"
progress:
  total_phases: 22
  completed_phases: 16
  total_plans: 45
  completed_plans: 42
  percent: 3
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-14)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** v2.2 Phase 26 — Tech Debt Resolution

## Current Position

Phase: 26 of 28 (Tech Debt Resolution)
Plan: 3 of 3
Status: In progress
Last activity: 2026-03-16 — Plan 26-02 complete (GroupSource::TokenClaim and effective_issuers() dead code removal)

Progress: [█░░░░░░░░░] 3% (v2.2, Phases 24-28)

## Accumulated Context

### Key Decisions Affecting v2.2

- v2.2 is finishing work: bugs, tech debt, security hardening, conformance, observability, E2E gaps
- Phase 24 first: lint fixes unblock token-exchange CI; security bugs fixed before hardening work
- Phase 25 depends on Phase 24 (same validation.rs touch points)
- Phase 26 depends on Phase 24 (multi-IdP dead code requires clean lint baseline)
- Phase 27 depends on Phase 26 (multi-IdP advanced needs wired config paths)
- Phase 28 last: E2E tests validate everything built in Phases 24-27

### Blockers/Concerns

- RESOLVED: unwrap_used/expect_used violations cleared; CI check job unblocked (24-02)
- No additional blockers known

### Pending Todos

- None (fresh milestone)

## Key Decisions

| Phase | Decision |
|-------|----------|
| 24-01 | BreakGlassAuth.severity changed from &'static str to String for runtime CRITICAL/INFO selection based on alert_on_use |
| 24-01 | SBUG-01 uses pre-auth extract_iss_for_routing() to capture issuer for forensic audit before auth call |
| 24-01 | SBUG-03 sudo fallback to claims.sub when preferred_username absent — graceful mismatch vs separate error |
| 24-02 | field_reassign_with_default fixed via struct literal + ..Default::default() pattern throughout test helpers |
| 24-02 | DEBT-01 closed: crate-level deny(clippy::unwrap_used, clippy::expect_used) at lib.rs:19 enforces production code cleanliness |
| 25-02 | Terminal sanitization strips-and-displays rather than rejecting URIs (graceful degradation) |
| 25-02 | D-Bus encryption enforcement uses env var UNIX_OIDC_REJECT_PLAIN_DBUS (matches existing UNIX_OIDC_ pattern) |
| 25-02 | D-Bus probe returns Unknown on non-Linux; zbus/oo7 actual probe deferred as architectural decision |
| 25-01 | Standalone function key_algorithm_to_algorithm() instead of TryFrom due to orphan rule (external types) |
| 25-01 | Allowlist DEFAULT_ALLOWED_ALGORITHMS replaces blocklist — fails safe when new algorithms added to crate |
| 25-01 | HTTPS enforcement at config load time via validate_https_url() shared between config and device_flow |
| 25-01 | SHRD-03 verified by existing Phase 24 tests — regression guard documentation added, no duplicate tests |
| 26-03 | Bash source guard pattern (_ENTRA_TOKEN_SOURCED=1) enables function-level testing without executing main script body |
| 26-03 | curl -s (not -sf) to capture error response body for Conditional Access diagnostic parsing |
| 26-01 | required_acr added to AcrMappingConfig (not IssuerConfig) to keep ACR config co-located |
| 26-01 | JWKS defaults 300s/10s preserved via serde default functions for backward compatibility |
| 26-02 | GroupMappingConfig.claim field retained for forward compat; effective_issuers() removed entirely including OIDC_ISSUER legacy path |

## Session Continuity

Last session: 2026-03-16T03:50:34Z
Stopped at: Completed 26-02-PLAN.md
Resume file: .planning/phases/26-tech-debt-resolution/26-CONTEXT.md
