---
phase: 07-dpop-nonce-issuance
verified: 2026-03-10T23:45:00Z
status: passed
score: 11/11 must-haves verified
re_verification: false
---

# Phase 7: DPoP Nonce Issuance Verification Report

**Phase Goal:** Implement server-side DPoP nonce issuance (RFC 9449 §8) — server generates nonces, delivers via PAM conversation, validates nonce-bound proofs. Makes captured DPoP proofs unreplayable even within their iat/exp window.
**Verified:** 2026-03-10T23:45:00Z
**Status:** PASSED
**Re-verification:** No — initial verification

---

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | A DPoP nonce issued by the server can be consumed exactly once; second consumption returns an error | VERIFIED | `nonce_cache.rs`: `consume()` uses `Cache::remove()` — atomic test-and-delete. `test_consume_twice_second_fails` passes. |
| 2 | A nonce older than 60 seconds is rejected even if not yet consumed | VERIFIED | `global_nonce_cache()` constructed with `ttl_secs=60`; moka TTL eviction removes entries automatically without explicit cleanup threads. |
| 3 | Nonce replay is always hard-fail regardless of dpop_required enforcement mode | VERIFIED | `auth.rs:270-277`: `ConsumedOrExpired` arm returns `NonceMismatch` unconditionally. `test_nonce_replay_is_always_hard_fail` iterates all three `EnforcementMode` variants and asserts all fail. |
| 4 | Missing nonce with dpop_required=strict rejects; with warn allows with log; with disabled skips | VERIFIED | `auth.rs:289-308`: match on `dpop_nonce_enforcement` — Strict returns `MissingNonce`, Warn logs and returns `Ok`, Disabled returns `Ok`. Three dedicated tests pass. |
| 5 | Nonce cache at max capacity (100k) does not panic and evicts oldest entries | VERIFIED | `test_cache_at_max_capacity_does_not_panic`: inserts 100,001 entries into a capacity-100 cache; moka evicts without panicking. `global_nonce_cache()` cap is 100,000. |
| 6 | The dpop_required enforcement mode from policy.yaml is threaded into authenticate_with_dpop() | VERIFIED | `auth.rs:212-217`: `dpop_nonce_enforcement` initialized to `Strict`, overridden with `modes.dpop_required` from `PolicyConfig::from_env()`. Tests in `lib.rs` verify strict/warn/disabled from inline YAML. |
| 7 | validate_dpop_proof() returns DPoPProofResult { thumbprint, nonce } so auth.rs can do cache-based nonce validation without re-parsing | VERIFIED | `dpop.rs:211-218, 351-355`: `DPoPProofResult` struct defined and returned. `test_dpop_proof_result_has_thumbprint_and_nonce` validates both fields are populated. |
| 8 | Each PAM DPoP authentication challenge carries a server-generated nonce delivered via conversation prompt | VERIFIED | `lib.rs:107-146`: `issue_and_deliver_nonce()` called when `dpop_mode != Disabled`. Nonce delivered as `DPOP_NONCE:<value>` via `PROMPT_ECHO_ON`. |
| 9 | The nonce is generated via CSPRNG, issued into the nonce cache, and delivered as DPOP_NONCE:<value> in PAM conversation | VERIFIED | `lib.rs:298-330`: `generate_dpop_nonce()` (32-byte getrandom), `global_nonce_cache().issue()`, then `format!("DPOP_NONCE:{nonce}")` via `PamMsgStyle::PROMPT_ECHO_ON`. |
| 10 | The DPoP proof collected in the second conversation round is validated against the cache-backed nonce | VERIFIED | `lib.rs:112-134`: PROMPT_ECHO_OFF collects proof. `auth.rs:257-310`: `global_nonce_cache().consume()` called when `require_nonce=true && expected_nonce=None`. |
| 11 | A DPoP proof replayed after its nonce has been consumed is rejected even if iat/exp and JTI are valid | VERIFIED | Same as truth #3. Nonce cache `consume()` is atomic; once consumed, any retry fails with `ConsumedOrExpired` → `NonceMismatch`, regardless of proof age or JTI validity. |

**Score:** 11/11 truths verified

---

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `pam-unix-oidc/src/security/nonce_cache.rs` | DPoPNonceCache with issue()/consume() backed by moka sync::Cache | VERIFIED | File exists, 349 lines, substantive. Exports: `DPoPNonceCache`, `NonceConsumeError`, `NonceIssueError`, `generate_dpop_nonce`, `global_nonce_cache`. 11 unit tests including adversarial TOCTOU test. |
| `pam-unix-oidc/src/policy/config.rs` | CacheConfig extended with nonce_max_entries and nonce_ttl_secs | VERIFIED | Fields present at lines 226, 230. Defaults 100,000 and 60. YAML override tested at lines 604-613. |
| `pam-unix-oidc/src/auth.rs` | authenticate_with_dpop() threads dpop_required enforcement and uses cache-backed nonce validation | VERIFIED | `dpop_nonce_enforcement` variable wired at lines 212-217. Cache enforcement closure at lines 240-313. TODO at former lines 211-212 is resolved with implementation. |
| `pam-unix-oidc/src/oidc/dpop.rs` | validate_dpop_proof() returns DPoPProofResult with thumbprint and nonce | VERIFIED | `DPoPProofResult` defined at lines 211-218. `validate_dpop_proof()` returns `Ok(DPoPProofResult { thumbprint, nonce })` at line 355. |
| `pam-unix-oidc/src/lib.rs` | Two-round PAM conversation: nonce delivery then proof collection | VERIFIED | `issue_and_deliver_nonce()` helper at lines 298-330. PROMPT_ECHO_ON at line 315. PROMPT_ECHO_OFF at line 112. `authenticate_with_dpop()` called at line 178. `"DPOP_NONCE:"` present at line 314. |
| `pam-unix-oidc/src/security/mod.rs` | pub mod nonce_cache with re-exports | VERIFIED | Line 10: `pub mod nonce_cache;`. Lines 15-17: re-exports `generate_dpop_nonce`, `global_nonce_cache`, `DPoPNonceCache`, `NonceConsumeError`. |

---

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `lib.rs` | `security/nonce_cache.rs` | `generate_dpop_nonce()` + `global_nonce_cache().issue()` | WIRED | `lib.rs:36`: `use security::nonce_cache::{generate_dpop_nonce, global_nonce_cache}`. Used at lines 300, 303 in `issue_and_deliver_nonce()`. |
| `lib.rs` | `auth.rs` | `authenticate_with_dpop()` call with `require_nonce=true` | WIRED | `lib.rs:178`: `authenticate_with_dpop(&token, dpop_proof.as_deref(), &dpop_config)` with `require_nonce: true, expected_nonce: None`. |
| `auth.rs` | `security/nonce_cache.rs` | `global_nonce_cache().consume()` in `authenticate_with_dpop()` | WIRED | `auth.rs:8`: `use crate::security::nonce_cache::{global_nonce_cache, NonceConsumeError}`. Used at line 263 in the enforcement closure. |
| `auth.rs` | `policy/config.rs` | `effective_security_modes().dpop_required` threading | WIRED | `auth.rs:7`: `use crate::policy::config::{EnforcementMode, PolicyConfig}`. Used at lines 213-216: `PolicyConfig::from_env()` → `modes.dpop_required`. |
| `auth.rs` | `oidc/dpop.rs` | `validate_dpop_proof()` returns `DPoPProofResult`; auth.rs reads `.nonce` for cache consumption | WIRED | `auth.rs:4`: `use crate::oidc::{validate_dpop_proof, ..., DPoPProofResult, ...}`. Used at line 252, `.nonce` accessed at line 258. |
| `oidc/dpop.rs` | `security/nonce_cache.rs` | via `EnforcementMode` (enforcement mode decides missing-nonce behavior) | WIRED | The enforcement mode lives in `policy/config.rs` and is threaded through `auth.rs`. `dpop.rs` handles the single-value path (`expected_nonce=Some`); `auth.rs` handles the cache path. This separation is intentional per the plan decision. |

---

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| SEC-05 | 07-01, 07-02 | Server-side DPoP nonce issuance per RFC 9449 §8 with PAM challenge delivery | SATISFIED | `lib.rs` generates nonce via CSPRNG, issues to cache, delivers via `DPOP_NONCE:<value>` over `PROMPT_ECHO_ON` PAM conversation. Two-round protocol fully wired. |
| SEC-06 | 07-01 | DPoP nonce single-use enforcement and TTL-bounded moka cache | SATISFIED | `DPoPNonceCache` backed by `moka::sync::Cache` with `max_capacity(100_000)` and `time_to_live(60s)`. `consume()` uses atomic `Cache::remove()` — no TOCTOU window. 11 unit tests cover single-use, TTL, capacity, and concurrent adversarial case. |

No orphaned requirements: SEC-05 and SEC-06 are the only requirements mapped to Phase 7 in REQUIREMENTS.md traceability table.

---

### Anti-Patterns Found

No blockers or warnings found.

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| — | — | — | — | No anti-patterns detected in phase 7 files. |

Checked: no `TODO`, `FIXME`, `placeholder`, `return null`, empty implementations, or `console.log`-only handlers in any of the six modified files.

The former TODO at `auth.rs:211-212` ("TODO(Phase 7): Also thread dpop_required enforcement mode once DPoP nonce issuance lands") is confirmed resolved — the implementation begins at line 211 with no TODO comment.

---

### Human Verification Required

Two items cannot be verified programmatically:

**1. Two-Round Keyboard-Interactive Flow Over SSH**

Test: Connect to a server running the PAM module with an SSH client that understands the DPoP conversation. Observe that the `DPOP_NONCE:<value>` prompt appears before the `DPOP_PROOF:` prompt.
Expected: Client receives the nonce, binds it to the next DPoP proof, submits the proof in round 2, and authentication succeeds.
Why human: Requires a live sshd + PAM conversation. Cannot be automated without a full integration environment.

**2. Replay Rejection in End-to-End Flow**

Test: Capture a valid nonce-bound DPoP proof from a successful authentication and replay it in a second SSH connection before the nonce TTL expires.
Expected: Second connection is rejected with an auth failure even though the proof's `iat`/`exp` window is still valid.
Why human: Requires capturing a real proof over a network and replaying it — not possible with unit tests alone.

---

### Gaps Summary

No gaps. All automated checks passed.

---

## Test Suite Confirmation

```
test result: ok. 134 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.37s
```

Clippy: clean (`cargo clippy -p pam-unix-oidc -- -D warnings` — no output, exit 0).

Commits verified in git history:
- `469483d` feat(07-01): add DPoP nonce cache module with moka backend
- `87ba0aa` feat(07-01): thread dpop_required enforcement and return DPoPProofResult
- `1a5cfb8` feat(07-02): wire two-round PAM conversation for DPoP nonce challenge/response

---

_Verified: 2026-03-10T23:45:00Z_
_Verifier: Claude (gsd-verifier)_
