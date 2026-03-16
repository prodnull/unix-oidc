# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v2.2 — Hardening & Conformance

**Shipped:** 2026-03-16
**Phases:** 5 | **Plans:** 19 (+2 gap closure) | **Requirements:** 35

### What Was Built
- Security hardened: algorithm allowlist, HTTPS enforcement, terminal sanitization, D-Bus encryption, forensic attribution fixes
- Multi-IdP resilient: priority ordering, health monitoring with quarantine/recovery, stat-based config hot-reload
- OCSF 1.3.0 audit pipeline: 16 structured event variants with HMAC-SHA256 tamper-evidence chain + verification CLI
- Key lifecycle visibility: KEY_GENERATED/KEY_LOADED/KEY_DESTROYED for DPoP and ML-DSA-65+ES256
- Enterprise documentation: standards compliance matrix (14+ RFCs), identity rationalization guide (953 lines), JTI cache architecture
- E2E test coverage: 5 automated suites (DPoP nonce, break-glass, session lifecycle, systemd/launchd, CIBA FIDO2)
- Compliance docs: logrotate config, log retention matrix (SOC2/PCI-DSS/HIPAA/FedRAMP), GDPR Art. 17 erasure guide

### What Worked
- Per-phase verification with gap closure cycle caught real issues (ISSUER_DEGRADED/RECOVERED bypassing AuditEvent, testuser2 missing from Docker image)
- Maximum parallelism in Wave 1 (5 agents) — all documentation and E2E test plans independent
- Existing Docker Compose infrastructure provided solid foundation for E2E tests
- Context gathering was light-touch for this milestone — most decisions were already locked from prior phases

### What Was Inefficient
- Wave 2 plans (27-04, 27-05) ran in parallel despite dependency — 27-05 picked up 27-04's working tree changes by coincidence rather than design
- Some SUMMARY.md files lacked extractable one-liners (summary-extract returned None)

### Patterns Established
- Gap closure cycle: verify → plan --gaps → execute → re-verify is reliable for closing infrastructure gaps
- OCSF enrichment via `#[serde(flatten)]` pattern — additive enrichment without breaking existing field names
- File-based health state for forked-sshd processes (no shared memory needed)
- Stat-based config hot-reload (no SIGHUP in PAM process space)

### Key Lessons
1. E2E test infrastructure gaps (missing users, policy fixtures) are best caught by verification, not assumed correct at plan time
2. Documentation phases are highly parallelizable — all plans can run simultaneously
3. HMAC chain composition (bare → OCSF → HMAC) is cleaner than trying to apply all three layers simultaneously

### Cost Observations
- Model mix: ~5% opus (orchestration), ~95% sonnet (executors, verifiers, planners)
- Sessions: 1 session for full milestone (phases 27-28 executed, 27 gap closure, 28 planned+executed+gap closure, milestone complete)
- Notable: 70 commits in 3 days across 5 phases

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Phases | Plans | Gap Closures | Days |
|-----------|--------|-------|-------------|------|
| v1.0 | 5 | 12 | 0 | 1 |
| v2.0 | 12 | 35 | 2 | 3 |
| v2.1 | 6 | 11 | 1 | 1 |
| v2.2 | 5 | 19 | 2 | 3 |

### Recurring Themes
- Per-phase verification consistently catches 1-2 gaps per milestone
- Parallel wave execution is the default; sequential only when files overlap
- Documentation phases complete fastest (no compilation, no test infrastructure)
- Security-critical phases require the most gap closure iterations
