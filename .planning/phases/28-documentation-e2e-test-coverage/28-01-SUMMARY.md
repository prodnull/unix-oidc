---
phase: 28-documentation-e2e-test-coverage
plan: 01
subsystem: docs
tags: [compliance, audit, jti-cache, dpop, nist, soc2, pci-dss, fedramp, ocsf]

requires:
  - phase: 27-multi-idp-advanced-observability
    provides: "HMAC chain (OBS-06), key lifecycle audit events (OBS-04), logrotate/retention (OBS-05), OCSF enrichment (OBS-07)"
  - phase: 25-hardening-conformance
    provides: "per-issuer algorithm allowlist (SHRD-01/02), HTTPS enforcement at config load (SHRD-04)"
  - phase: 24-tech-debt-security-bugs
    provides: "break-glass CRITICAL severity (SBUG-02)"
  - phase: 26-multi-idp-dead-code
    provides: "SP 800-88 citation correction (DEBT-08)"
provides:
  - "v2.2-updated RFC/NIST/SOC2/PCI compliance matrix with all phase 24-27 gap closures reflected"
  - "JTI cache architecture document explaining per-process design sufficiency and Redis out-of-scope rationale"
affects: [29-e2e-tests, conference-submissions, ietf-wg-outreach, security-reviews, auditors]

tech-stack:
  added: []
  patterns:
    - "Gap closure documentation pattern: strikethrough row + CLOSED(Phase N ref) in Known Gaps table"
    - "Architecture decision document pattern: forked-sshd model + primary defense + secondary defense + out-of-scope rationale"

key-files:
  created:
    - docs/jti-cache-architecture.md
  modified:
    - docs/standards-compliance-matrix.md

key-decisions:
  - "SP 800-115 promoted from Referenced-Only to Partial with section references (§4/§5/§6.3) — the doc was already cited in security-testing-roadmap.md and deserved proper matrix coverage"
  - "Section 6 totals updated to reflect closed gaps: SOC2 now 8 mapped (1 gap), PCI 6 mapped (0 gaps); OCSF Schema row added as a new standards category"
  - "Cross-reference index for audit.rs expanded to include all new standards: RFC 5424, SOC2 CC7.1/CC7.2, PCI 10.2.1, OCSF, GDPR Art 17(3)(b); audit_verify.rs added as new entry"

patterns-established:
  - "Gap closure format: ~~strikethrough original row~~ with CLOSED(Phase N description) — preserves audit trail of what was fixed and when"
  - "Architecture doc structure for security-sensitive design decisions: background + model diagram + implementation refs + sufficiency argument + primary defense + out-of-scope rationale + sizing + properties table"

requirements-completed: [DOC-01, DOC-03]

duration: 4min
completed: 2026-03-16
---

# Phase 28 Plan 01: Standards Compliance Matrix v2.2 Update + JTI Cache Architecture Summary

**Standards compliance matrix updated with 16 v2.2 gap closures (RFC 9700 now Full, 6 Known Gaps closed, PCI DSS all 0 gaps); new JTI cache architecture document explains per-process design sufficiency and 5 reasons Redis is out of scope.**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T17:31:59Z
- **Completed:** 2026-03-16T17:36:11Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Standards compliance matrix updated to v2.2: 16 CLOSED entries reflecting Phases 24-27 gap closures; RFC 9700 promoted to Full; SP 800-115 promoted to Partial with section references; OCSF Schema row added to Section 6; cross-reference index expanded for audit.rs and audit_verify.rs
- All v2.2 gap closures reflected: F-04 (SP 800-88 citation), F-06 (algorithm allowlist), F-08 (HMAC chain), F-09 (URI scheme), F-12 (issuer HTTPS), OBS-4 (key lifecycle events), SOC2 CC7.1/CC7.3/A1.2, PCI DSS 10.2.1/10.2.1.3/10.3.3/10.5.1/3.7.6
- Created jti-cache-architecture.md (173 lines) with forked-sshd model diagram, per-process cache design with dpop.rs code references, DPoP nonce as primary replay defense, 5 architectural reasons Redis is out of scope, and DoS protection sizing

## Task Commits

Each task was committed atomically:

1. **Task 1: Update standards-compliance-matrix.md for v2.2** - `7f8a58c` (docs)
2. **Task 2: Create docs/jti-cache-architecture.md** - `9d15d14` (docs)

## Files Created/Modified

- `docs/standards-compliance-matrix.md` - Updated Last-updated, RFC 9700, NIST rows, SOC2/PCI tables, Section 6 counts, Section 7 cross-refs, Section 8 gap closures
- `docs/jti-cache-architecture.md` - New: forked-sshd model, per-process JTI cache design with dpop.rs constants, DPoP nonce as primary defense, Redis out-of-scope rationale, DoS sizing, security properties table

## Decisions Made

- SP 800-115 promoted from Referenced-Only to Partial: the spec was already cited in `docs/security-testing-roadmap.md` and deserved a proper matrix row with section references (§4 test design, §5 network discovery, §6.3 password cracking)
- Section 6 totals updated comprehensively: SOC2 now shows 8 mapped (was 5), PCI shows 6 mapped (was 3), OCSF Schema added as new row since Phase 27 delivered 7 structured event types with full OCSF fields
- JTI cache architecture doc does not claim Redis is permanently out of scope for all deployments — it documents 5 architectural reasons specific to the current sshd fork model, which is accurate and complete

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 28 Plan 01 (DOC-01, DOC-03) complete; matrix is audit-ready for conference submissions and IETF WG outreach
- Next: Phase 28 Plan 02 (DOC-02 identity rationalization strategy) or Phase 28 E2E test coverage plans

---
*Phase: 28-documentation-e2e-test-coverage*
*Completed: 2026-03-16*
