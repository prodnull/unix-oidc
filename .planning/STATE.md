---
gsd_state_version: 1.0
milestone: v2.1
milestone_name: Integration Testing Infrastructure
status: planning
stopped_at: Completed 21-03-PLAN.md
last_updated: "2026-03-13T19:27:11.987Z"
last_activity: 2026-03-13 — v2.1 roadmap created; all 30 requirements mapped to phases 18-22
progress:
  total_phases: 16
  completed_phases: 11
  total_plans: 34
  completed_plans: 31
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-13)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** v2.1 — Phase 18: Blocker Fixes + E2E Infrastructure

## Current Position

Phase: 18 of 22 (Blocker Fixes + E2E Infrastructure)
Plan: — (not yet planned)
Status: Ready to plan
Last activity: 2026-03-13 — v2.1 roadmap created; all 30 requirements mapped to phases 18-22

Progress: [░░░░░░░░░░] 0% (v2.1)

## Performance Metrics

**Velocity (v2.0 reference):**
- Total plans completed: 29 (v2.0)
- Average duration: ~120m
- Total execution time: ~58h (v2.0)

**Recent Trend:**
- Last 5 plans: Phase 21-03 (3m), Phase 21-02 (10m), Phase 21-01 (6m), Phase 17-03 (8m), 17-01 (5m)
- Trend: stable

*Updated after each plan completion*

## Accumulated Context

### Key Decisions Affecting v2.1

- [21-03]: GroupMappingConfig::default_claim() is serde-only; Rust Default yields empty string — test verifies serde path via figment round-trip; documented in test comments
- [21-02]: JWKS_REGISTRY is static Lazy<IssuerJwksRegistry> in lib.rs for cache persistence across PAM calls without a persistent daemon struct
- [21-02]: JTI scoping at call site (format!("{iss}:{jti}")) — JtiCache struct unchanged; per-issuer collision prevention is a calling-convention
- [21-02]: JWKS TTL/timeout hardcoded (300s/10s) in authenticate_multi_issuer(); future per-issuer config possible if needed
- [21-01]: IssuerConfig.dpop_enforcement defaults to Strict; Entra overrides to disabled (SHR not RFC 9449)
- [21-01]: IssuerJwksRegistry is non-global; Plan 02 owns it as a static in lib.rs (read-first RwLock for hot path)
- [v2.0]: reqwest stays on 0.11 — 0.11→0.13 upgrade is a separate hardening item (TLS layer audit required)
- [Research]: Keycloak must be upgraded from 24.0 to 26.4 — DPoP is GA in 26.4; 24.x DPoP behavior in device flow is undefined
- [Research]: Playwright runs on GHA host (not in Docker) — avoids Chromium `--no-sandbox` failures inside containers
- [Research]: Entra ID is bearer-only scope — Entra uses SHR not RFC 9449 DPoP; `dpop_required: off` in all Entra fixtures; zero `cnf.jkt` assertions
- [Research]: Phase 21 (Multi-IdP) must land before Phase 22 (Entra) — Entra requires per-issuer config and RS256 support that Multi-IdP delivers
- [Research]: Sentinel assertion is mandatory — `UNIX_OIDC_TEST_MODE` propagation produces false green; guard every real-sig test script

### Critical Research Flags for Implementation

- Phase 18 realm JSON: verify `deviceAuthorizationGrantEnabled: true` as boolean field in Keycloak 26.4 Admin REST API before assuming existing realm JSON imports cleanly
- Phase 19 selectors: verify `#username`, `#password`, `[type=submit]`, `[name=accept]` against actual Keycloak 26.4 login page HTML before CI relies on them
- Phase 22 Entra: client credentials tokens may not carry `preferred_username` — verify token claims against a real tenant before writing UPN mapping assertions

### Pending Todos

- [Global]: Every phase must include adversarial/negative tests (malformed tokens, replayed proofs, wrong issuers, forged claims, degraded IdP) — not just happy-path

### Blockers/Concerns

- [Phase 20 - pre-planning]: CI unwrap_used violations in pam-unix-oidc (audit.rs, ciba/client.rs, etc.) block the `check` CI job; may need a lint-fix plan before the `keycloak-e2e` job can depend on `check`
- [Phase 19 - pre-planning]: Playwright Keycloak 26.4 login form selectors unverified — must confirm against live container before writing CI-reliant spec

## Session Continuity

Last session: 2026-03-13T19:27:11.982Z
Stopped at: Completed 21-03-PLAN.md
Resume file: None
