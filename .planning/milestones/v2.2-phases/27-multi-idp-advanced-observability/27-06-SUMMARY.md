---
phase: 27-multi-idp-advanced-observability
plan: "06"
subsystem: pam-unix-oidc/audit
tags: [gap-closure, audit, ocsf, hmac-chain, issuer-health, midp-10, obs-06, obs-07]
dependency_graph:
  requires: [27-04, 27-05]
  provides: [MIDP-10-audit-pipeline, OBS-06-issuer-events, OBS-07-issuer-events]
  affects: [pam-unix-oidc/src/audit.rs, pam-unix-oidc/src/policy/config.rs]
tech_stack:
  added: []
  patterns: [AuditEvent-pipeline, OCSF-enrichment, HMAC-chain]
key_files:
  modified:
    - pam-unix-oidc/src/audit.rs
    - pam-unix-oidc/src/policy/config.rs
decisions:
  - "IssuerDegraded syslog severity is Warning (same as other failure events); IssuerRecovered is Info"
  - "ocsf_fields() returns (99, 4) for IssuerDegraded (High) and (99, 1) for IssuerRecovered (Info)"
  - "cast_possible_truncation suppressed with allow attribute: DEGRADATION_THRESHOLD is 3, always fits u8"
metrics:
  duration_minutes: 4
  completed_date: "2026-03-16"
  tasks_completed: 2
  tasks_total: 2
  files_modified: 2
---

# Phase 27 Plan 06: Issuer Health Event Gap Closure Summary

**One-liner:** ISSUER_DEGRADED and ISSUER_RECOVERED events now route through AuditEvent::log() for OCSF enrichment and HMAC tamper-evidence chain coverage, closing the single OBS-06/OBS-07 verification gap.

## What Was Built

Two new `AuditEvent` variants were added to `pam-unix-oidc/src/audit.rs` and the raw `tracing::warn!/info!` calls in `IssuerHealthManager` were replaced with `AuditEvent::log()` calls.

**Before this plan:** `IssuerHealthManager::record_failure()` and `record_success()` emitted events via raw `tracing::warn!/info!` targeting `"unix_oidc_audit"`. These events:
- Received no OCSF enrichment (category_uid, class_uid, severity_id, activity_id, type_uid, metadata.version)
- Were excluded from the HMAC tamper-evidence chain

**After this plan:** Both events pass through `AuditEvent::log()` like all 14 other audit event variants:
- OCSF enrichment added automatically by `enriched_log_json()`
- HMAC chain covers all fields including OCSF metadata
- Events appear in syslog, audit file, and stderr

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add IssuerDegraded and IssuerRecovered AuditEvent variants | 3364872 | pam-unix-oidc/src/audit.rs |
| 2 | Replace raw tracing calls with AuditEvent::log() in IssuerHealthManager | 05a5a77 | pam-unix-oidc/src/policy/config.rs |

## Changes Made

### pam-unix-oidc/src/audit.rs

**New enum variants** (after `SessionCloseFailed`):
- `IssuerDegraded { timestamp, issuer_url, failure_count: u8, host }` — serde rename `ISSUER_DEGRADED`
- `IssuerRecovered { timestamp, issuer_url, host }` — serde rename `ISSUER_RECOVERED`

**New constructor methods** (after `session_close_failed()`):
- `issuer_degraded(issuer_url: &str, failure_count: u8) -> Self`
- `issuer_recovered(issuer_url: &str) -> Self`

**Updated match arms:**
- `event_type()`: two new arms returning `"ISSUER_DEGRADED"` / `"ISSUER_RECOVERED"`
- `syslog_severity()`: `IssuerDegraded` added to Warning arm; `IssuerRecovered` added to Info arm
- `ocsf_fields()`: `IssuerDegraded => (99, 4)` (High); `IssuerRecovered => (99, 1)` (Info)

**Test update:**
- `test_ocsf_all_14_variants_have_fields` renamed to `test_ocsf_all_16_variants_have_fields`
- Two new events added to the vec: `issuer_degraded` and `issuer_recovered`

### pam-unix-oidc/src/policy/config.rs

- Added `use crate::audit::AuditEvent;` import
- `record_failure()`: replaced `tracing::warn!(target: "unix_oidc_audit", ...)` with `AuditEvent::issuer_degraded(issuer_url, state.failure_count as u8).log()`
- `record_success()`: replaced `tracing::info!(target: "unix_oidc_audit", ...)` with `AuditEvent::issuer_recovered(issuer_url).log()`
- Operational log `tracing::warn!("Recorded JWKS fetch failure...")` on line ~614 retained unchanged — it is an operational log, not an audit event

## Verification Results

```
cargo build -p pam-unix-oidc         → no errors
cargo clippy -p pam-unix-oidc -D W   → no errors
cargo test -p pam-unix-oidc          → 409 tests, 0 failed
IssuerDegraded|IssuerRecovered       → 10 occurrences in audit.rs (>= 10 required)
AuditEvent::issuer_ in config.rs     → 2 occurrences (>= 2 required)
event = "ISSUER_" in config.rs       → 0 occurrences (old raw tracing removed)
test_ocsf_all_16_variants_have_fields → PASSED
```

## Deviations from Plan

None — plan executed exactly as written.

## Requirements Closed

- MIDP-10: Issuer health monitoring events are now SIEM-ingestible (OCSF fields) and tamper-evident (HMAC chain)
- OBS-06: HMAC tamper-evidence chain now covers all 16 audit event types including ISSUER_DEGRADED and ISSUER_RECOVERED
- OBS-07: OCSF enrichment now applied to all 16 audit event types

## Self-Check: PASSED

Files verified:
- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/src/audit.rs` — FOUND
- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/src/policy/config.rs` — FOUND

Commits verified:
- `3364872` — FOUND: feat(27-06): add IssuerDegraded and IssuerRecovered AuditEvent variants
- `05a5a77` — FOUND: feat(27-06): route issuer health events through AuditEvent::log()
