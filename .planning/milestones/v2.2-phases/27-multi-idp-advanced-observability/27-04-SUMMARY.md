---
phase: 27-multi-idp-advanced-observability
plan: 04
subsystem: audit
tags: [ocsf, siem, audit, observability, pam]

# Dependency graph
requires:
  - phase: 27-01
    provides: Issuer health monitoring and HMAC chain infrastructure that log() extends
  - phase: 27-03
    provides: HMAC chain audit tamper-evidence that covers the new OCSF fields
provides:
  - AUTH_NO_TOKEN audit event variant (OBS-02) — no-token attempts distinct from SSH_LOGIN_FAILED
  - SESSION_CLOSE_FAILED audit event variant (OBS-08) — IPC failures no longer silently dropped
  - OCSF 1.3.0 fields on all 14 AuditEvent variants (OBS-07) — category_uid, class_uid, activity_id, severity_id, type_uid, metadata.version
  - enriched_log_json() and ocsf_fields() public methods for external consumers
  - Backward-compatible: existing JSON field names unchanged (serde flatten)
affects: [28-e2e-integration, phase-29-siem-integration]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "EnrichedAuditEvent with serde(flatten): adds OCSF fields alongside existing event fields without renaming/removing anything"
    - "ocsf_fields() method: decouples OCSF field computation from serialization for testability"
    - "enriched_log_json() returns the canonical serialization payload used by log() and HMAC chain"

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/audit.rs
    - pam-unix-oidc/src/lib.rs
    - pam-unix-oidc/src/bin/audit_verify.rs

key-decisions:
  - "OCSF enrichment via EnrichedAuditEvent + serde(flatten) in log() — not per-variant fields — keeps AuditEvent variants slim and guarantees backward compatibility"
  - "ocsf_fields() is a public method — external consumers can inspect OCSF values without JSON parsing"
  - "HMAC chain covers OCSF-enriched JSON (enriched_log_json() is the verifiable payload) — OCSF fields are tamper-evident alongside event data"
  - "SESSION_CLOSE_FAILED username is empty string in notify_agent_session_closed() — function only receives session_id; correlate via session_id with preceding SESSION_CLOSED"
  - "OCSF version pinned to 1.3.0 (December 2024 release) in OCSF_VERSION constant — single change point for future upgrades"

patterns-established:
  - "OCSF activity_id mapping: 1=Logon, 2=Logoff, 3=AuthChallenge, 99=Other — follow for any future event types"
  - "OCSF severity_id mapping: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical — BreakGlass+alert maps to 5"
  - "type_uid = class_uid * 100 + activity_id — OCSF composite key formula"

requirements-completed: [OBS-02, OBS-07, OBS-08]

# Metrics
duration: 10min
completed: 2026-03-16
---

# Phase 27 Plan 04: OCSF-Enriched Audit Events — AUTH_NO_TOKEN, SESSION_CLOSE_FAILED, and OCSF 1.3.0 Schema Fields on All 14 Event Variants

**AUTH_NO_TOKEN and SESSION_CLOSE_FAILED audit events added (OBS-02/08), all 14 AuditEvent variants enriched with OCSF 1.3.0 fields (category_uid=3, class_uid=3002) via serde(flatten) — purely additive, backward compatible**

## Performance

- **Duration:** 10 min
- **Started:** 2026-03-16T14:07:50Z
- **Completed:** 2026-03-16T14:17:50Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- AUTH_NO_TOKEN event (OBS-02): emitted in `pam_sm_authenticate` when `get_auth_token()` returns None — SIEM can now distinguish "no token provided" from "token present but invalid" via `event=AUTH_NO_TOKEN` vs `SSH_LOGIN_FAILED`/`TOKEN_VALIDATION_FAILED` filter
- SESSION_CLOSE_FAILED event (OBS-08): emitted at each IPC error return in `notify_agent_session_closed()` (connect failure, write failure, newline write failure) — missed agent-side revocations are no longer silently dropped
- OCSF 1.3.0 schema fields (OBS-07): all 14 variants enriched with `category_uid`, `class_uid`, `activity_id`, `severity_id`, `type_uid`, `metadata.version` — SIEM connectors can ingest events without custom field mapping
- HMAC chain now covers OCSF-enriched JSON: `enriched_log_json()` is the verifiable payload, so any OCSF field modification breaks the chain

## Task Commits

1. **Task 1: AUTH_NO_TOKEN and SESSION_CLOSE_FAILED events (OBS-02, OBS-08)** — `fd4eb98` (feat)
2. **Task 2: OCSF schema fields on all audit events (OBS-07)** — `7c42d0b` (feat)

**Plan metadata:** (docs commit follows)

_Note: Both tasks used TDD (RED → GREEN) with 8 tests each._

## Files Created/Modified

- `pam-unix-oidc/src/audit.rs` — AuthNoToken/SessionCloseFailed variants + constructors; OcsfMetadata/OcsfFields/EnrichedAuditEvent structs; ocsf_fields() and enriched_log_json() methods; log() updated to use enriched_log_json(); HmacChain expect() replaced with let-else
- `pam-unix-oidc/src/lib.rs` — AuditEvent::auth_no_token() emission in pam_sm_authenticate None arm; AuditEvent::session_close_failed() emission at all 3 IPC error return paths
- `pam-unix-oidc/src/bin/audit_verify.rs` — Pre-existing dead_code warnings suppressed with #[allow(dead_code)] on BreakRecord fields and ParseError tuple field

## Decisions Made

- OCSF enrichment via `EnrichedAuditEvent` + `#[serde(flatten)]` rather than adding fields to every variant — variant structs stay slim; existing field names unchanged; one place to update if OCSF version changes
- `ocsf_fields()` is public — enables external tooling to inspect OCSF values without JSON round-trip
- `enriched_log_json()` is the canonical serialization for `log()` and HMAC chain — ensures OCSF fields are tamper-evident
- SESSION_CLOSE_FAILED username is empty string — `notify_agent_session_closed` only receives session_id; correlate with preceding SESSION_CLOSED via session_id in SIEM
- OCSF version "1.3.0" in `OCSF_VERSION` constant — single change point for future schema upgrades

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed pre-existing `expect()` in HmacChain::compute_chain**
- **Found during:** Task 2 (clippy run)
- **Issue:** `HmacSha256::new_from_slice(key).expect(...)` violated `deny(clippy::expect_used)` at crate level — this was introduced in plan 27-03 but not caught until clippy ran as part of Task 1 commit
- **Fix:** Replaced with `let Ok(mut mac) = HmacSha256::new_from_slice(key) else { return None; }` — maps zero-length key failure (unreachable in practice) to disabling chain rather than panicking
- **Files modified:** `pam-unix-oidc/src/audit.rs`
- **Committed in:** `fd4eb98` (Task 1 commit)

**2. [Rule 1 - Bug] Fixed pre-existing dead_code warnings in audit_verify.rs**
- **Found during:** Task 2 (clippy run on bin target)
- **Issue:** `BreakRecord.recorded_chain_hash`, `BreakRecord.computed_chain_hash`, and `LineResult::ParseError(String)` triggered dead_code lint — fields are read via `println!` but clippy doesn't trace field access on borrowed struct refs
- **Fix:** Added `#[allow(dead_code)]` with explanatory comments on the affected fields
- **Files modified:** `pam-unix-oidc/src/bin/audit_verify.rs`
- **Committed in:** `7c42d0b` (Task 2 commit)

---

**Total deviations:** 2 auto-fixed (2 × Rule 1 — pre-existing bugs from plan 27-03)
**Impact on plan:** Both fixes necessary to achieve clean clippy -D warnings. No scope creep.

## Issues Encountered

None beyond the auto-fixed deviations above.

## Next Phase Readiness

- All OBS-02/07/08 requirements fulfilled — observability layer complete for Phase 27
- Plan 27-05 (sudo session linking + session expiry sweep) can proceed — audit infrastructure is stable
- SIEM consumers can ingest all events without custom field mapping via OCSF category_uid=3/class_uid=3002

---
*Phase: 27-multi-idp-advanced-observability*
*Completed: 2026-03-16*
