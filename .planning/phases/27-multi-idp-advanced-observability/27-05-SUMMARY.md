---
phase: 27-multi-idp-advanced-observability
plan: "05"
subsystem: audit
tags: [hmac-chain, tamper-evidence, audit-verification, ocsf, obs-06]
dependency_graph:
  requires: [27-04]
  provides: [OBS-06, audit-chain-verification]
  affects: [pam-unix-oidc/src/audit.rs, pam-unix-oidc/src/bin/audit_verify.rs]
tech_stack:
  added: [hmac = "0.12", hex = "0.4", clap = { version = "4", features = ["derive"] }]
  patterns:
    - HMAC-SHA256 chaining over serialized OCSF-enriched event JSON
    - Static Lazy<Mutex<ChainState>> for per-process chain state
    - let-else for fallible HMAC construction without .expect()
    - serde(flatten) for additive JSON enrichment
key_files:
  created: [pam-unix-oidc/src/bin/audit_verify.rs]
  modified: [pam-unix-oidc/src/audit.rs, pam-unix-oidc/Cargo.toml]
decisions:
  - HMAC input is "{prev_hash}:{ocsf_enriched_json}" — binds to previous event and covers all fields including OCSF
  - "genesis" as first event's prev_hash — unambiguous sentinel, no special-casing required
  - Key absent or empty → WARNING log, chain disabled; never a hard failure (backward compatible)
  - Mutex poisoned → falls back to base JSON without chain fields rather than refusing to log
  - Payload for verification = all fields EXCEPT prev_hash/chain_hash (OCSF fields are part of payload)
  - audit_verify uses --key or --key-file; key is NEVER logged or in error messages
metrics:
  duration_minutes: 11
  completed: "2026-03-16T14:18:16Z"
  tasks_completed: 2
  files_changed: 3
---

# Phase 27 Plan 05: HMAC Audit Chain + Verification Utility Summary

HMAC-SHA256 tamper-evidence chain on all audit events (over OCSF-enriched JSON) and `unix-oidc-audit-verify` CLI for chain validation, satisfying OBS-06.

## What Was Built

### Task 1: HMAC chain in audit.rs (OBS-06)

`ChainState` struct (protected by `Lazy<Mutex<>>`) holds the HMAC key and `prev_hash` state. On every `AuditEvent::log()` call:

1. The event is serialized to OCSF-enriched JSON (from Plan 27-04's `EnrichedAuditEvent`)
2. `ChainState::compute_chain(enriched_json)` computes `HMAC-SHA256(key, "{prev_hash}:{enriched_json}")`
3. The final logged JSON gains two extra fields: `prev_hash` (link to previous) and `chain_hash` (verifiable integrity)
4. `CHAIN_STATE.prev_hash` advances to the new `chain_hash`

The HMAC covers ALL event fields including OCSF enrichment fields (`category_uid`, `class_uid`, `severity_id`, `activity_id`, `type_uid`, `metadata`). Modifying any field — including OCSF fields — breaks the chain.

Key management:
- Sourced from `UNIX_OIDC_AUDIT_HMAC_KEY` env var at first use (Lazy init)
- Absent or empty → WARNING log, tamper-evidence gracefully disabled
- Key MUST be high-entropy (≥32 bytes); same key across all processes writing to the same log file
- In forked-sshd model, each child inherits the env var from the parent; each fork maintains its own chain segment (correct — each fork handles one session)

### Task 2: unix-oidc-audit-verify binary

`pam-unix-oidc/src/bin/audit_verify.rs` — a CLI that:

1. Reads a log file line by line
2. For each line, strips `prev_hash` and `chain_hash` to reconstruct the verifiable payload
3. Recomputes `HMAC-SHA256(key, "{prev_hash}:{payload_json}")` and compares to recorded `chain_hash`
4. Reports the first (and all subsequent) chain breaks with line number, event type, expected/actual hashes

CLI:
```
unix-oidc-audit-verify --key <KEY>           --file <LOG>
unix-oidc-audit-verify --key-file <KEY_FILE> --file <LOG>
```

Output examples:
```
Chain status: VALID (no breaks detected)
Chain status: INVALID (1 break(s) detected)
Chain status: NOT ENABLED (no chain fields found — tamper-evidence was not enabled)
```

Exit codes: 0=valid, 1=broken, 2=usage error.

## Execution Notes

This plan ran in parallel with Plan 27-04. The Plan 27-04 agent picked up the HMAC chain implementation from the working tree (where it appeared as we built it) and included it in their commits. Both commits (`fd4eb98` and `7c42d0b`) contain the 27-05 work alongside the 27-04 OCSF enrichment work. The final state is correct: HMAC chain wraps OCSF-enriched JSON as required.

## Deviations from Plan

### [Rule 3 - Blocking] Added AuthNoToken/SessionCloseFailed variants

- **Found during:** Task 1 implementation
- **Issue:** The parallel Plan 27-04 linter injected tests for `auth_no_token()` and `session_close_failed()` constructors that did not exist yet, causing compilation failure
- **Fix:** Added `AuthNoToken` and `SessionCloseFailed` enum variants and constructor methods to `audit.rs`, satisfying the Plan 27-04 tests that the linter had already added
- **Files modified:** `pam-unix-oidc/src/audit.rs`
- **Note:** This is Plan 27-04 work that was pulled in early; ultimately committed by the Plan 27-04 agent in `fd4eb98`

### [Rule 1 - Bug] Replaced .expect() in compute_chain

- **Found during:** Clippy run after Task 1 implementation
- **Issue:** `HmacSha256::new_from_slice(key).expect(...)` violates `deny(clippy::expect_used)` at crate level
- **Fix:** Replaced with `let Ok(...) else { ... }` that logs a WARN and disables the chain rather than panicking
- **Files modified:** `pam-unix-oidc/src/audit.rs`

## Commits

| Hash | Description |
|------|-------------|
| `fd4eb98` | feat(27-04): add AUTH_NO_TOKEN/SESSION_CLOSE_FAILED events — includes HMAC chain implementation |
| `7c42d0b` | feat(27-04): OCSF schema fields on all audit events — includes audit_verify binary |

## Self-Check: PASSED

- audit.rs: FOUND
- audit_verify.rs: FOUND
- fd4eb98 commit: FOUND
- 7c42d0b commit: FOUND
- ChainState in audit.rs: FOUND
- unix-oidc-audit-verify binary entry in Cargo.toml: FOUND
- UNIX_OIDC_AUDIT_HMAC_KEY env var reference: FOUND
