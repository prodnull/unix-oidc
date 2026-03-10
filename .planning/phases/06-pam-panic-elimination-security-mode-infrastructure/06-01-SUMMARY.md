---
phase: 06-pam-panic-elimination-security-mode-infrastructure
plan: 01
subsystem: auth
tags: [parking_lot, getrandom, reqwest, pam, rust, panic-elimination]

# Dependency graph
requires: []
provides:
  - parking_lot RwLock in all PAM lock sites (no PoisonError, no .unwrap() on lock acquisition)
  - generate_ssh_session_id/generate_sudo_session_id/generate_secure_session_id return Result<String, getrandom::Error>
  - DeviceFlowClient::new() and with_endpoints() return Result<Self, DeviceFlowError>
  - SystemTime::now().unwrap_or_default() in dpop.rs (no panic on pre-epoch clock)
  - MAX_ENTRIES_BEFORE_CLEANUP = MAX_JTI_CACHE_ENTRIES = 100_000 (consistent constants)
affects: [06-02, 06-03]

# Tech tracking
tech-stack:
  added:
    - parking_lot = "0.12" (production dependency — was already in Cargo.toml from prior work)
  patterns:
    - "PAM panic elimination: all production panic sites converted to Result propagation"
    - "parking_lot::RwLock replaces std::sync::RwLock — no PoisonError, no .unwrap() on lock guards"
    - "getrandom errors propagate via ? through session ID generation up to auth.rs AuthError::Config"
    - "reqwest Client::builder errors propagate via DeviceFlowError::NetworkError"

key-files:
  created: []
  modified:
    - pam-unix-oidc/src/security/session.rs
    - pam-unix-oidc/src/device_flow/client.rs
    - pam-unix-oidc/src/auth.rs
    - pam-unix-oidc/src/sudo.rs
    - pam-unix-oidc/src/oidc/dpop.rs
    - pam-unix-oidc/src/oidc/jwks.rs
    - pam-unix-oidc/src/security/jti_cache.rs
    - pam-unix-oidc/src/security/rate_limit.rs
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/Cargo.toml

key-decisions:
  - "parking_lot is an unconditional production dependency (not a feature flag) — consistent with plan decision"
  - "getrandom failure in session ID generation maps to AuthError::Config, not a new error variant"
  - "DeviceFlowClient constructors now return Result — sudo.rs propagates via ? using existing DeviceFlowError From impl"
  - "audit.rs std::sync::Mutex retained — uses if let Ok() pattern already, no .unwrap() on lock acquisition"
  - "lib.rs ENV_MUTEX (test code) deferred to plan 03 deny lint pass"

patterns-established:
  - "PAM production code: zero .expect()/.unwrap() on lock acquisition or fallible OS calls"
  - "Error propagation chain: OS CSPRNG -> getrandom::Error -> AuthError::Config -> PAM error code (no panic)"

requirements-completed: [SEC-01, SEC-07]

# Metrics
duration: 20min
completed: 2026-03-10
---

# Phase 6 Plan 01: PAM Panic Elimination Summary

**parking_lot RwLock migration complete; getrandom and reqwest builder failures propagate as Result instead of panicking in PAM paths**

## Performance

- **Duration:** ~20 min
- **Started:** 2026-03-10T20:10:00Z
- **Completed:** 2026-03-10T20:30:00Z
- **Tasks:** 2
- **Files modified:** 10

## Accomplishments

- Migrated dpop.rs and jwks.rs from std::sync::RwLock to parking_lot::RwLock; removed all .unwrap() on lock acquisition (parking_lot has no PoisonError)
- Converted generate_random_bytes/generate_secure_session_id/generate_ssh_session_id/generate_sudo_session_id to return Result<_, getrandom::Error>; propagated through auth.rs and sudo.rs
- Changed DeviceFlowClient::new() and with_endpoints() to return Result<Self, DeviceFlowError> instead of .expect() on HTTP client construction
- Fixed SystemTime::now().expect() in dpop.rs to .unwrap_or_default() — pre-epoch clock causes proof to appear old (security-conservative), no PAM panic
- Verified MAX_ENTRIES_BEFORE_CLEANUP (jti_cache.rs) = MAX_JTI_CACHE_ENTRIES (dpop.rs) = 100_000
- Fixed pre-existing policy/config.rs compile errors (EnforcementMode manual serde impls, Format trait import for Yaml::string())
- All 110 tests pass

## Task Commits

1. **Task 1: parking_lot migration and JTI cache constant fix** - `0b03de9` (feat)
2. **Task 2: panic elimination in session.rs, device_flow/client.rs, auth.rs** - `ff61362` (feat)
3. **Task 2 fix: complete session.rs Result migration** - `f5666b7` (fix)

## Files Created/Modified

- `pam-unix-oidc/src/security/session.rs` - All public session ID functions now return Result<String, getrandom::Error>
- `pam-unix-oidc/src/device_flow/client.rs` - new()/with_endpoints() return Result<Self, DeviceFlowError>; tests updated
- `pam-unix-oidc/src/auth.rs` - Three authenticate_* functions propagate session ID errors; tests updated
- `pam-unix-oidc/src/sudo.rs` - DeviceFlowClient::new() call uses ? operator
- `pam-unix-oidc/src/oidc/dpop.rs` - parking_lot::RwLock; .unwrap_or_default() for SystemTime
- `pam-unix-oidc/src/oidc/jwks.rs` - parking_lot::RwLock; .unwrap() removed from lock guards
- `pam-unix-oidc/src/security/jti_cache.rs` - Already correct (verified: parking_lot, 100_000 constant)
- `pam-unix-oidc/src/security/rate_limit.rs` - Already correct (verified: parking_lot, no .unwrap() on locks)
- `pam-unix-oidc/src/policy/config.rs` - Fixed EnforcementMode serde, Format import; these were pre-existing blocking bugs
- `pam-unix-oidc/Cargo.toml` - parking_lot confirmed as production dep; figment moved to prod, serde_yaml to dev-deps

## Decisions Made

- **parking_lot unconditional**: Plan specified it must not be a feature flag. Already present in Cargo.toml from prior roadmap work.
- **getrandom error chain**: Maps to `AuthError::Config` rather than introducing a new `AuthError::RandomnessUnavailable` variant — minimal API surface change, sufficient for PAM error reporting.
- **audit.rs retained as std::sync::Mutex**: Already uses `if let Ok(mut guard) = lock()` pattern — no `.unwrap()` on lock acquisition. Meets plan success criteria without change.
- **session.rs was not staged in second commit**: The Write tool successfully wrote the file but it was not captured by `git add`. Fixed by re-writing and committing separately.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed pre-existing policy/config.rs compile errors**
- **Found during:** Task 1 verification (cargo test -p pam-unix-oidc)
- **Issue:** EnforcementMode had `#[derive(Deserialize, Serialize)]` with `#[serde(other)]` alongside a manual Deserialize impl — compiler error. Also `Yaml::string()` needed `Format` trait import.
- **Fix:** Removed conflicting derive, kept manual impls; added `Format` to figment imports; added manual `Serialize` impl for EnforcementMode.
- **Files modified:** pam-unix-oidc/src/policy/config.rs
- **Verification:** 110 tests pass including all policy::config::tests
- **Committed in:** 0b03de9 (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Pre-existing compile error in policy module blocked test verification; fix was necessary to complete Task 1 verification. No scope creep.

## Issues Encountered

- session.rs changes were written via Write tool but not staged in the second commit (git add appeared to succeed but the file was not in the commit). Diagnosed by observing compilation errors after the commit, confirmed with `git show`. Fixed by re-writing the file and creating a separate fix commit (f5666b7).

## Next Phase Readiness

- Plan 02 (security mode enforcement) can proceed — no production .expect()/.unwrap() on lock acquisition or fallible OS calls
- Plan 03 (deny clippy::unwrap_used lint) can proceed — remaining .unwrap() in production code is limited to audit.rs (safe `if let Ok` pattern) and test code
- lib.rs ENV_MUTEX (test-only std::sync::Mutex) should be converted in plan 03 with the deny lint pass

---
*Phase: 06-pam-panic-elimination-security-mode-infrastructure*
*Completed: 2026-03-10*
