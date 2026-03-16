---
phase: 27-multi-idp-advanced-observability
plan: 03
subsystem: infra
tags: [logrotate, gdpr, compliance, soc2, pci-dss, hipaa, fedramp, log-retention]

requires:
  - phase: 27-multi-idp-advanced-observability
    provides: phase context (HMAC chain composition, audit event schema)

provides:
  - deploy/logrotate.d/unix-oidc: production logrotate snippet for weekly/52-week rotation
  - docs/log-retention.md: compliance retention matrix (SOC2, PCI-DSS, HIPAA, GDPR, FedRAMP) with SIEM integration guides
  - docs/gdpr-erasure-guide.md: Article 17 data inventory, erasure procedures, limitations, and data controller checklist

affects: [28-e2e-verification, docs, compliance-teams, deployment]

tech-stack:
  added: []
  patterns:
    - "deploy/logrotate.d/ directory for operator-installable distribution configs"
    - "Three-pass secure overwrite cited to NIST SP 800-88 Rev 1 §2.4, not DoD 5220.22-M"

key-files:
  created:
    - deploy/logrotate.d/unix-oidc
    - docs/log-retention.md
    - docs/gdpr-erasure-guide.md
  modified: []

key-decisions:
  - "weekly + rotate 52 chosen as logrotate default — satisfies SOC2/PCI-DSS/FedRAMP 1-year minimum; documented HIPAA 6-year override (rotate 312)"
  - "0640 root:adm permissions on new log files — audit logs contain usernames/IPs (GDPR Art 4(1) PII); world-readable is a data minimization violation"
  - "GDPR Art 17(3)(b) exemption documented — audit logs required for SOC2/PCI-DSS legal compliance may be retained beyond erasure request"
  - "SIEM entries explicitly out-of-scope for unix-oidc erasure — data controller must contact SIEM vendor; limitation documented prominently"

patterns-established:
  - "Erasure guides distinguish unix-oidc-controlled data vs. externally forwarded data — never overstate the tool's erasure scope"
  - "All retention figures traced to authoritative primary sources (regulation text or NIST SP), not secondary summaries"

requirements-completed: [OBS-05, OBS-09]

duration: 4min
completed: 2026-03-16
---

# Phase 27 Plan 03: Log Retention and GDPR Erasure Guide Summary

**Logrotate config (weekly/52-week, 0640 root:adm) plus compliance retention matrix and GDPR Article 17 erasure procedures covering all unix-oidc data types**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-16T13:49:38Z
- **Completed:** 2026-03-16T13:53:38Z
- **Tasks:** 2
- **Files created:** 3

## Accomplishments

- Shipped `deploy/logrotate.d/unix-oidc` with annotated decisions (why 52 weeks, why 0640, why delaycompress), ready to `cp` into `/etc/logrotate.d/`
- `docs/log-retention.md` covers SOC 2 CC7.2/CC7.3, PCI-DSS v4.0 Req 10.7, HIPAA 45 CFR §164.530(j), GDPR Art. 5(1)(e), FedRAMP AU-11, and ISO 27001:2022 Annex A 8.15 with primary-source citations; includes Splunk HEC, Filebeat, Datadog, and CloudWatch configuration examples
- `docs/gdpr-erasure-guide.md` enumerates all 8 data categories unix-oidc handles, provides erasure CLI commands for each, explicitly lists 5 categories outside unix-oidc's control (SIEM, auditd, IdP, CoW snapshots, backups), and includes an Art. 17(3)(b) legal retention exemption analysis and an automation script template

## Task Commits

Each task was committed atomically:

1. **Task 1: Logrotate config + log retention documentation (OBS-05)** - `0ede150` (chore)
2. **Task 2: GDPR Article 17 erasure guide (OBS-09)** - `18d1aba` (docs)

**Plan metadata:** (docs commit — see below)

## Files Created

- `deploy/logrotate.d/unix-oidc` — Production logrotate configuration with inline decision commentary
- `docs/log-retention.md` — Compliance retention matrix, logrotate install/adjust guidance, SIEM integration for Splunk/ELK/Datadog/CloudWatch
- `docs/gdpr-erasure-guide.md` — Data inventory, per-type erasure procedures, limitations, automation script, Art. 17(3)(b) guidance

## Decisions Made

- **weekly + rotate 52 as default** — satisfies the most common compliance requirements (SOC2/PCI-DSS/FedRAMP); HIPAA override documented as `rotate 312` rather than shipping a separate HIPAA config to keep deployment simple
- **0640 root:adm** — audit logs contain username and source IP which are personal data under GDPR Art. 4(1); world-readable (0644) would be a data minimization violation
- **SIEM limitation stated prominently** — unlike local file deletion, unix-oidc has no API to delete entries from external SIEM platforms; the guide makes this explicit so data controllers are not misled about erasure completeness
- **Art. 17(3)(b) exemption documented** — SOC2/PCI-DSS-required audit logs have a legal basis to retain despite erasure requests; DPOs need to know this before instructing operators to delete audit logs

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- OBS-05 and OBS-09 complete; no blockers for remaining Phase 27 plans
- Plans 27-04 and 27-05 (OCSF enrichment and HMAC audit chain) can proceed independently

---
*Phase: 27-multi-idp-advanced-observability*
*Completed: 2026-03-16*
