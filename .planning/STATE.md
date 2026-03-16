---
gsd_state_version: 1.0
milestone: v2.2
milestone_name: Hardening & Conformance
status: executing
stopped_at: "Completed 27-01-PLAN.md (re-executed: MIDP-09 priority ordering, MIDP-10 health monitoring, MIDP-11 config hot-reload)"
last_updated: "2026-03-16T14:05:17.518Z"
last_activity: 2026-03-16 — Plan 27-02 complete (KEY_GENERATED/KEY_LOADED/KEY_DESTROYED audit events on ProtectedSigningKey and HybridPqcSigner)
progress:
  total_phases: 22
  completed_phases: 16
  total_plans: 50
  completed_plans: 45
  percent: 86
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-14)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** v2.2 Phase 27 — Multi-IdP Advanced + Observability

## Current Position

Phase: 27 of 28 (Multi-IdP Advanced + Observability)
Plan: 4 of 5 complete (01, 02, 03, done; 04 and 05 remaining)
Status: In progress
Last activity: 2026-03-16 — Plan 27-02 complete (KEY_GENERATED/KEY_LOADED/KEY_DESTROYED audit events on ProtectedSigningKey and HybridPqcSigner)

Progress: [█████████░] 86% (v2.2, Phases 24-28)

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
| 27-03 | weekly + rotate 52 as logrotate default satisfies SOC2/PCI-DSS/FedRAMP; HIPAA 6-year override documented as rotate 312 |
| 27-03 | 0640 root:adm on new log files — audit logs contain username/IP (GDPR Art 4(1) PII); world-readable violates Art 5(1)(e) |
| 27-03 | GDPR Art 17(3)(b) retention exemption documented — SOC2/PCI-DSS-required audit logs have legal basis to retain |
| 27-02 | tracing-test no-env-filter feature required to assert on unix_oidc_audit target events (default filter only captures crate-name target) |
| 27-02 | Drop impl emits KEY_DESTROYED before ZeroizeOnDrop — thumbprint still accessible in drop body (Rust drops fields after body) |
| 27-02 | key_id = 8-char thumbprint prefix — sufficient for correlation without fingerprint leakage per security constraint |
| 27-01 | Health state is file-based (/run/unix-oidc/issuer-health/) — each forked sshd process is ephemeral with no shared memory |
| 27-01 | Only ValidationError::JwksFetchError counts as health failure — token errors (expired, bad audience) do not degrade issuer |
| 27-01 | Config hot-reload uses UNIX_OIDC_POLICY env var; stat-based mtime check, no SIGHUP (already decided in Phase 27 planning) |

## Session Continuity

Last session: 2026-03-16T14:05:17.514Z
Stopped at: Completed 27-01-PLAN.md (re-executed: MIDP-09 priority ordering, MIDP-10 health monitoring, MIDP-11 config hot-reload)
Resume file: None
