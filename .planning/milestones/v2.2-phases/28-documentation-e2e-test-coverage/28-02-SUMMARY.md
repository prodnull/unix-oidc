---
phase: 28-documentation-e2e-test-coverage
plan: 02
subsystem: documentation
tags: [oidc, freeipa, entra, sssd, identity, upn-mapping, dpop, group-policy, offboarding]

# Dependency graph
requires:
  - phase: 26-multi-idp-dead-code-cleanup
    provides: GroupSource::TokenClaim removed; SSSD-only model confirmed as sole supported path
  - phase: 27-multi-idp-advanced-observability
    provides: Issuer health, OCSF audit events, HMAC chain — referenced in offboarding audit section
provides:
  - Enterprise identity rationalization guide covering FreeIPA+Entra coexistence patterns
  - UPN-to-uid mapping documentation with worked YAML examples
  - SSSD group resolution design anchor explanation with code reference
  - Offboarding audit procedure with jq/SIEM query examples
  - Multi-IdP troubleshooting table
affects: [documentation, external-users, enterprise-deployment]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Identity doc pattern: per-pattern YAML config blocks + implementation file references"
    - "Offboarding audit pattern: structured jq queries + SIEM integration examples"

key-files:
  created:
    - docs/identity-rationalization-guide.md
  modified: []

key-decisions:
  - "Guide leads with the archaeology problem as the primary enterprise pain point — motivates the solution before explaining configuration"
  - "SSSD-only group resolution documented with code reference to config.rs GroupSource enum and Phase 26 DEBT-03 decision"
  - "allow_unsafe_identity_pipeline explained with security rationale — single-tenant IdP constraint compensates for strip_domain non-injectivity"

patterns-established:
  - "Enterprise guide pattern: problem statement first, design anchor second, worked examples third, reference snippets last"

requirements-completed: [DOC-02]

# Metrics
duration: 3min
completed: 2026-03-16
---

# Phase 28 Plan 02: Identity Rationalization Guide Summary

**Comprehensive FreeIPA+Entra coexistence guide (953 lines) covering UPN-to-uid mapping pipeline, SSSD-only group resolution design anchor, three deployment patterns with full YAML configs, and jq-based offboarding audit procedure**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-16T17:32:21Z
- **Completed:** 2026-03-16T17:35:28Z
- **Tasks:** 1
- **Files modified:** 1

## Accomplishments

- Created `docs/identity-rationalization-guide.md` (953 lines) — the definitive guide for enterprise identity admins deploying unix-oidc alongside FreeIPA and Entra ID
- Documents all three coexistence patterns (FreeIPA-only, dual-issuer, Entra-only) with complete working `policy.yaml` snippets
- Explains the SSSD-only group resolution design anchor with code reference to `pam-unix-oidc/src/policy/config.rs` GroupSource enum and DEBT-03 Phase 26 decision
- UPN-to-uid mapping section covers five scenarios: FreeIPA native (no transforms), Entra strip_domain, email claim with lowercase, regex transform, and identity collision detection
- Offboarding section includes jq queries, SIEM integration examples, and step-by-step revocation procedure with cache flush instructions
- Troubleshooting table covers 11 common multi-IdP failures with root cause and resolution

## Task Commits

1. **Task 1: Create docs/identity-rationalization-guide.md** - `346bbec` (feat)

## Files Created/Modified

- `docs/identity-rationalization-guide.md` — 953-line identity rationalization guide; 8 sections, 14 YAML code blocks, 60 SSSD references, 18 strip_domain references, 5 archaeology references

## Decisions Made

- Guide leads with the archaeology problem as the enterprise pain point — motivates the solution before explaining configuration details
- `allow_unsafe_identity_pipeline` explained with security rationale: single-tenant Entra app registration enforces the domain constraint that compensates for `strip_domain` non-injectivity
- Offboarding section explicitly documents the v2.2 limitation: no token introspection support; recommends short TTL as the correct mitigation

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — documentation only, no external service configuration required.

## Next Phase Readiness

- DOC-02 complete. Plan 28-03 (JTI cache architecture doc) can proceed independently.
- Enterprise identity admins can use this guide to configure FreeIPA+Entra coexistence deployments.
- The guide references token introspection as a planned feature — Phase 28 E2E tests and future milestones may reference this gap.

---
*Phase: 28-documentation-e2e-test-coverage*
*Completed: 2026-03-16*
