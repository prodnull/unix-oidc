---
phase: 07-dpop-nonce-issuance
plan: 02
subsystem: auth
tags: [dpop, nonce, rfc9449, pam, conversation, lib-rs, enforcement-mode, rust]

# Dependency graph
requires:
  - phase: 07-dpop-nonce-issuance
    plan: 01
    provides: DPoPNonceCache, generate_dpop_nonce(), global_nonce_cache(), DPoPProofResult, authenticate_with_dpop()

provides:
  - Two-round PAM keyboard-interactive DPoP nonce challenge/response in pam_sm_authenticate
  - issue_and_deliver_nonce(): CSPRNG + cache issue + PROMPT_ECHO_ON delivery helper
  - DPoP mode gating from PolicyConfig::from_env() — strict/warn/disabled enforcement
  - Graceful fallback to authenticate_with_token() when mode is warn/disabled and no proof

affects:
  - All future phases touching pam_sm_authenticate
  - SSH agent (must respond to DPOP_NONCE: prompt and send DPOP_PROOF: response)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Two-round PAM keyboard-interactive: PROMPT_ECHO_ON (nonce delivery) then PROMPT_ECHO_OFF (proof collection)
    - Nonce issuance in lib.rs, consumption in auth.rs — no cross-function nonce passing
    - EnforcementMode::Strict as safe default when PolicyConfig::from_env() returns Err

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/lib.rs

key-decisions:
  - "issue_and_deliver_nonce() extracted as a named helper (not inline closure) for testability and error clarity"
  - "Orphaned nonces (conversation failure after issue) are handled by cache TTL eviction — no explicit cleanup needed"
  - "dpop_mode != Disabled check gates entire nonce path — Disabled skips nonce issuance entirely"
  - "When dpop_proof is Some or mode is Strict: use authenticate_with_dpop(); otherwise: authenticate_with_token() fallback"
  - "require_nonce=true, expected_nonce=None in DPoPAuthConfig activates cache-backed enforcement path in auth.rs"

# Metrics
duration: 3min
completed: 2026-03-10
---

# Phase 7 Plan 02: PAM DPoP Nonce Issuance Wire-Up Summary

**Two-round PAM keyboard-interactive DPoP nonce challenge/response wired into pam_sm_authenticate: round 1 delivers DPOP_NONCE:<value> via PROMPT_ECHO_ON, round 2 collects the nonce-bound proof via PROMPT_ECHO_OFF, then authenticate_with_dpop() consumes the nonce from cache**

## Performance

- **Duration:** ~3 min
- **Started:** 2026-03-10T23:19:07Z
- **Completed:** 2026-03-10T23:22:24Z
- **Tasks:** 2 of 2 (Task 2 human-verify checkpoint approved)
- **Files modified:** 1

## Accomplishments

- Extended `authenticate()` in `lib.rs` to load `dpop_required` enforcement mode from `PolicyConfig::from_env()` with `EnforcementMode::Strict` as safe default when policy file is absent.
- Added `issue_and_deliver_nonce()` helper: generates 256-bit CSPRNG nonce (43-char base64url), issues it to the global nonce cache, delivers via `PROMPT_ECHO_ON` PAM conversation with `"DPOP_NONCE:<value>"` prefix.
- Added proof collection: PAM `PROMPT_ECHO_OFF` conversation for `"DPOP_PROOF: "` prompt (round 2).
- Routes to `authenticate_with_dpop()` with `require_nonce=true, expected_nonce=None` (cache-backed mode) when DPoP mode is active or proof provided; falls back to `authenticate_with_token()` when mode is Warn/Disabled and no proof.
- Added 5 unit tests: nonce roundtrip via global cache, `DPOP_NONCE:` prompt format parsing, DPoP mode determination (strict without policy file, warn and disabled from inline YAML).

## Task Commits

1. **Task 1: Wire two-round PAM conversation for DPoP nonce challenge/response** - `1a5cfb8` (feat)

## Files Created/Modified

- `pam-unix-oidc/src/lib.rs` — DPoP mode determination, issue_and_deliver_nonce() helper, two-round conversation, authenticate_with_dpop() call, 5 new unit tests

## Decisions Made

- **Safe-default for missing policy**: `PolicyConfig::from_env()` returns `Err` when `/etc/unix-oidc/policy.yaml` is absent and `UNIX_OIDC_TEST_MODE` is not set. The authenticate() code maps this to `EnforcementMode::Strict` (fail closed), not Disabled. This ensures production servers without explicit policy configuration reject DPoP-less connections by default.

- **Orphaned nonce cleanup**: When `issue_and_deliver_nonce()` succeeds but the PAM conversation for the proof fails (round 2), the issued nonce is orphaned in the cache. No explicit cleanup is performed — the nonce's TTL (60s default) will evict it automatically. This is correct behavior: the alternative (removing the nonce on proof-collection failure) would introduce a different race condition.

- **Single auth dispatch**: Rather than two separate code paths for "proof provided" and "no proof with strict mode", the condition `dpop_proof.is_some() || dpop_mode == EnforcementMode::Strict` routes both through `authenticate_with_dpop()`. This ensures DPoP-bound tokens (`cnf.jkt`) are always checked even in strict+no-proof scenario, returning `DPoPRequired` as appropriate.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- The complete DPoP nonce issuance pipeline (Plan 01 + Plan 02) is ready for integration testing with the SSH agent.
- SSH agent must be updated to respond to `DPOP_NONCE:<value>` prompt and send `DPOP_PROOF: <proof>` in the two-round keyboard-interactive flow.
- All 134 pam-unix-oidc unit tests pass; workspace clean at plan completion.

## Self-Check

- `pam-unix-oidc/src/lib.rs`: FOUND
- Commit 1a5cfb8 (Task 1): FOUND
- `DPOP_NONCE:` in lib.rs at line 314: FOUND
- `global_nonce_cache()` used in lib.rs (issue) and auth.rs (consume): FOUND
- `authenticate_with_dpop` in lib.rs: FOUND
- Full workspace test suite: 134 pam-unix-oidc tests + 97 unix-oidc-agent tests + 1 main test = all PASSED
- Clippy: CLEAN

## Self-Check: PASSED

---
*Phase: 07-dpop-nonce-issuance*
*Plan: 02*
*Completed: 2026-03-10*
