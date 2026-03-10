---
phase: 01-memory-protection-hardening
plan: 04
subsystem: auth
tags: [secrecy, SecretString, oauth, memory-protection, MEM-03]

requires:
  - phase: 01-memory-protection-hardening
    provides: "access_token wrapped in SecretString (plans 01-02 established the pattern)"

provides:
  - "refresh_token wrapped in SecretString in run_login, run_refresh (main.rs), and perform_token_refresh (socket.rs)"
  - "client_secret wrapped in SecretString at extraction in all three functions"
  - "expose_secret() usage confined to HTTP param boundaries and storage write points only"
  - "MEM-03 requirement fully satisfied: all three OAuth credential types protected"
  - "REQUIREMENTS.md traceability table corrected to show MEM-03 as Complete"

affects:
  - 01-memory-protection-hardening
  - future phases that modify unix-oidc-agent token handling

tech-stack:
  added: []
  patterns:
    - "SecretString wrapping at earliest extraction point — immediately on metadata read or CLI input"
    - "Clone SecretString for spawn_blocking closure capture (String: CloneableSecret in secrecy 0.10)"
    - "Bind expose_secret() to typed local &str before use in params — avoids unstable str::as_str on older toolchains"
    - "Storage JSON roundtrip reads from serde_json::Value, not from SecretString — avoids expose_secret at serialization"

key-files:
  created: []
  modified:
    - unix-oidc-agent/src/main.rs
    - unix-oidc-agent/src/daemon/socket.rs
    - .planning/REQUIREMENTS.md

key-decisions:
  - "Keep CLI struct client_secret: Option<String> parameter — wrap to SecretString inside run_login() at line 308, not at CLI boundary (avoids invasive function signature change)"
  - "Bind expose_secret() to typed &str local variable instead of chaining .as_str() — str::as_str() is an unstable feature on this toolchain, type binding is the stable equivalent"
  - "Storage JSON roundtrip: client_secret in updated_metadata reads from serde_json::Value (original metadata), not from the SecretString — avoids a second expose_secret() at serialization boundary"

patterns-established:
  - "SecretString-at-extraction: wrap immediately on .as_str()?.to_string() — no intermediate plain String binding"
  - "expose_secret() audit boundary: HTTP form params only, storage writes only, username extraction (non-sensitive output) only"

requirements-completed: [MEM-03]

duration: 10min
completed: 2026-03-10
---

# Phase 01 Plan 04: Memory Protection Hardening — MEM-03 Gap Closure Summary

**refresh_token and client_secret wrapped in SecretString at extraction across run_login, run_refresh, and perform_token_refresh — all three OAuth credential types now log-safe via secrecy 0.10**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-10T13:44:00Z
- **Completed:** 2026-03-10T13:54:43Z
- **Tasks:** 2
- **Files modified:** 3

## Accomplishments

- `run_login()` in main.rs: `client_secret` converted from `Option<String>` to `Option<SecretString>` at extraction; `expose_secret()` used only at HTTP params and storage JSON write
- `run_refresh()` in main.rs: `refresh_token` and `client_secret` wrapped in `SecretString` at metadata extraction; `expose_secret()` used inside `spawn_blocking` at HTTP param boundary only
- `perform_token_refresh()` in socket.rs: same wrapping pattern applied; `expose_secret()` confined to HTTP params and storage write
- `REQUIREMENTS.md` traceability table updated: MEM-03 row changed from `Pending` to `Complete`, consistent with the `[x]` checklist entry

## Task Commits

Each task was committed atomically:

1. **Task 1: Wrap refresh_token and client_secret in SecretString** - `4de0359` (feat)
2. **Task 2: Update REQUIREMENTS.md traceability table for MEM-03** - `ff52d54` (chore)

## Files Created/Modified

- `unix-oidc-agent/src/main.rs` — SecretString wrapping in run_login and run_refresh; expose_secret at HTTP params and storage boundaries
- `unix-oidc-agent/src/daemon/socket.rs` — SecretString wrapping in perform_token_refresh; same expose_secret pattern
- `.planning/REQUIREMENTS.md` — MEM-03 traceability corrected to Complete

## Decisions Made

- **CLI parameter kept as `Option<String>`**: The `client_secret` field in the `Commands::Login` enum and the `run_login` signature remain `Option<String>` — this is the CLI parsing boundary, wrapping happens immediately inside the function body. Changing the signature would require plumbing through clap's CLI parsing which is out of scope.

- **Stable `&str` binding pattern**: `expose_secret()` returns `&String`; calling `.as_str()` chains through `str::as_str()` which is an unstable feature on this toolchain (issue #130366). Fixed by binding to a typed local: `let v: &str = secret.expose_secret();`. This is semantically identical and compiles on stable.

- **JSON storage roundtrip reads from `serde_json::Value`**: In `run_refresh()` and `perform_token_refresh()`, the `updated_metadata` JSON re-uses `metadata["client_secret"]` (the original parsed JSON value) for storage — not the `SecretString`. This avoids a second `expose_secret()` at serialization. The pattern is transient: JSON value → JSON value, no intermediate plain String variable.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Replaced `.expose_secret().as_str()` chain with stable `&str` binding**
- **Found during:** Task 1 (first build attempt)
- **Issue:** `str::as_str()` is an unstable library feature (issue #130366) on this toolchain; the pattern `expose_secret().as_str()` in the plan's action description triggered E0658 in 5 places
- **Fix:** Bound `expose_secret()` result to a typed local `let v: &str = secret.expose_secret();` — achieves identical semantics via `Deref<Target=str>` coercion on `&String`, no unstable feature required
- **Files modified:** unix-oidc-agent/src/main.rs, unix-oidc-agent/src/daemon/socket.rs
- **Verification:** `cargo build -p unix-oidc-agent` clean; `cargo clippy -p unix-oidc-agent -- -D warnings` clean
- **Committed in:** `4de0359` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 — compiler compatibility fix)
**Impact on plan:** Auto-fix was necessary for compilation on stable Rust. No semantic change; expose_secret boundaries unchanged.

## Issues Encountered

None beyond the toolchain quirk documented above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- MEM-03 is fully closed: all three OAuth credential types (access_token, refresh_token, client_secret) are wrapped in `SecretString` with grep-auditable `expose_secret()` boundaries
- Phase 1 memory protection requirements are now all Complete in REQUIREMENTS.md
- Phase 2 (keyring storage) may proceed; no memory protection concerns remain in the agent token handling paths

---
*Phase: 01-memory-protection-hardening*
*Completed: 2026-03-10*

## Self-Check: PASSED

- unix-oidc-agent/src/main.rs: FOUND
- unix-oidc-agent/src/daemon/socket.rs: FOUND
- .planning/REQUIREMENTS.md: FOUND
- .planning/phases/01-memory-protection-hardening/01-04-SUMMARY.md: FOUND
- Commit 4de0359: FOUND
- Commit ff52d54: FOUND
