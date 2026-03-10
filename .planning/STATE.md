---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Production Hardening & Enterprise Readiness
status: planning
stopped_at: Completed 07-dpop-nonce-issuance Plan 02 (DPoP nonce issuance pipeline complete)
last_updated: "2026-03-10T23:32:03.145Z"
last_activity: 2026-03-10 — v2.0 roadmap created; 42 requirements mapped across 6 phases
progress:
  total_phases: 6
  completed_phases: 2
  total_plans: 5
  completed_plans: 5
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-10)

**Core value:** DPoP private keys must be protected at rest, in memory, and on deletion
**Current focus:** v2.0 — Phase 6: PAM Panic Elimination + Security Mode Infrastructure

## Current Position

Phase: 6 of 11 (PAM Panic Elimination + Security Mode Infrastructure)
Plan: — (not yet planned)
Status: Ready to plan
Last activity: 2026-03-10 — v2.0 roadmap created; 42 requirements mapped across 6 phases

Progress: [░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**
- Total plans completed: 12
- Average duration: ~15m
- Total execution time: ~3h (v1.0)

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| v1.0 Phases 1-5 | 12 | ~3h | ~15m |

**Recent Trend:**
- Last 5 plans: 35m, 45m, 10m, 2m, 1m
- Trend: variable (hardware backend work was heavier)

*Updated after each plan completion*
| Phase 06 P01 | 20 | 2 tasks | 10 files |
| Phase 06 P02 | 270 | 1 tasks | 2 files |
| Phase 06 P03 | 803 | 2 tasks | 4 files |
| Phase 07-dpop-nonce-issuance P01 | 45 | 2 tasks | 7 files |
| Phase 07-dpop-nonce-issuance P02 | 3 | 1 tasks | 1 files |
| Phase 07-dpop-nonce-issuance P02 | 3 | 2 tasks | 1 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- [v2.0 roadmap]: figment 0.10.19 replaces serde_yaml for config loading — enables Issue #10 security mode config shape
- [v2.0 roadmap]: moka 0.12.14 chosen for all TTL caches (JTI replay, DPoP nonce, introspection results)
- [v2.0 roadmap]: CIBA polling must live in agent daemon, not PAM thread — avoids sshd LoginGraceTime timeout
- [v2.0 roadmap]: PAM session store uses tmpfs files under /run/unix-oidc/sessions/ — pam_sm_open_session and pam_sm_close_session run in different sshd worker processes
- [v2.0 roadmap]: FIDO2 step-up via CIBA ACR delegation only — no libfido2/webauthn-rs in PAM crate; direct CTAP2 deferred to v2.1+
- [v2.0 roadmap]: reqwest stays on 0.11 — 0.11→0.12 TLS layer change requires full ClientBuilder audit; separate hardening item
- [Phase 06]: parking_lot is unconditional production dep (not feature flag); getrandom errors map to AuthError::Config; DeviceFlowClient constructors return Result
- [Phase 06-02]: EnforcementMode uses hand-rolled Deserialize to reject invalid strings with clear error; Option<SecurityModes> in PolicyConfig preserves v1.0 backward compat; Env::prefixed().only() prevents UNIX_OIDC_TEST_MODE from polluting config parse
- [Phase 06]: ValidationConfig.enforce_jti: bool replaced by jti_enforcement: EnforcementMode — removes UNIX_OIDC_DISABLE_JTI_CHECK env var in favour of policy.yaml enforcement
- [Phase 06]: Replay detection hard-fail in all modes; missing JTI configurable but replayed JTI never configurable (CLAUDE.md invariant)
- [Phase 06]: deny(clippy::unwrap_used, clippy::expect_used) activated crate-wide in lib.rs; test modules have allow attribute; ENV_MUTEX migrated to parking_lot::Mutex
- [Phase 07-dpop-nonce-issuance]: moka Cache.remove() is atomic single-use primitive for nonce consume; no TOCTOU
- [Phase 07-dpop-nonce-issuance]: validate_dpop_proof() returns DPoPProofResult{thumbprint,nonce} to decouple binding check from cache consumption
- [Phase 07-dpop-nonce-issuance]: Nonce replay is always hard-fail; missing nonce enforcement respects dpop_required mode (strict/warn/disabled)
- [Phase 07-dpop-nonce-issuance]: Safe-default Strict enforcement when policy file absent; orphaned nonces expire via TTL; single auth dispatch routes both strict+no-proof and has-proof through authenticate_with_dpop()
- [Phase 07-dpop-nonce-issuance]: issue_and_deliver_nonce() extracted as named helper in lib.rs; orphaned nonces handled by TTL eviction; dpop_proof.is_some() || mode==Strict routes both cases through authenticate_with_dpop()

### Pending Todos

- [Global]: Every phase must include adversarial/negative tests (malformed tokens, replayed nonces, forged claims, timing attacks, resource exhaustion) — not just happy-path tests

### Blockers/Concerns

- [Phase 10 - pre-planning flag]: Okta CIBA supports PUSH mode only, not POLL — detect via backchannel_token_delivery_modes_supported from OIDC discovery; verify current Okta docs during Phase 10 planning (may have changed since research 2026-03-10)
- [Phase 11 - pre-planning flag]: PAM stack order fix for RHEL 9 (pam_systemd.so before pam_unix_oidc.so) needs platform verification; socket activation has known ordering race on RHEL 9

## Session Continuity

Last session: 2026-03-10T23:27:26.828Z
Stopped at: Completed 07-dpop-nonce-issuance Plan 02 (DPoP nonce issuance pipeline complete)
Resume file: None
