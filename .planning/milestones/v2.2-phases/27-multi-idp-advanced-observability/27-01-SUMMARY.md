---
phase: 27-multi-idp-advanced-observability
plan: 01
subsystem: auth
tags: [oidc, multi-idp, health-monitoring, config-hot-reload, pam, dpop, tracing, serde]

# Dependency graph
requires:
  - phase: 26-tech-debt-resolution
    provides: "clean multi-IdP config paths, effective_issuers() removed, wired JWKS defaults"

provides:
  - "Priority-ordered issuer selection with structured audit log (position, total_issuers)"
  - "File-backed issuer health monitoring: degradation after 3 JWKS failures, recovery after interval"
  - "Stat-based config hot-reload: mtime check on each pam_sm_authenticate, no daemon restart"
  - "IssuerHealthManager and IssuerHealthState types exported from policy module"
  - "recovery_interval_secs field in IssuerConfig (default 300s)"

affects: [27-02, 27-03, 27-04, 27-05, 28-doc]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "File-backed health state: SHA-256 of issuer URL → short hex filename, atomic tmp+rename writes"
    - "Stat-based hot-reload: ConfigCache{config, mtime, path} in Lazy<Mutex<Option<>>> static"
    - "Health tracking: JwksFetchError triggers record_failure(); success triggers record_success()"
    - "ENV_MUTEX guards for tests that mutate UNIX_OIDC_HEALTH_DIR or UNIX_OIDC_POLICY"

key-files:
  created: []
  modified:
    - "pam-unix-oidc/src/auth.rs"
    - "pam-unix-oidc/src/policy/config.rs"
    - "pam-unix-oidc/src/policy/mod.rs"
    - "pam-unix-oidc/src/lib.rs"
    - "pam-unix-oidc/tests/multi_idp_integration.rs"

key-decisions:
  - "Health state is file-based (/run/unix-oidc/issuer-health/) because each forked sshd process is ephemeral with no shared memory"
  - "Only ValidationError::JwksFetchError counts as health failure — token errors (expired, bad audience) do not trigger degradation"
  - "Config hot-reload uses UNIX_OIDC_POLICY env var (not UNIX_OIDC_POLICY_FILE) to avoid conflicting with from_env() test paths"
  - "ENV_MUTEX used to serialize all health and config-reload tests — UNIX_OIDC_HEALTH_DIR and UNIX_OIDC_POLICY are process-wide"
  - "recovery_interval_secs=0 always allows retry (elapsed immediately) — safe default for testing"

patterns-established:
  - "IssuerHealthManager: new() reads UNIX_OIDC_HEALTH_DIR; all methods best-effort with WARN on I/O failure"
  - "load_fresh() path check: if cached.path != config_path → re-parse regardless of mtime"

requirements-completed: [MIDP-09, MIDP-10, MIDP-11]

# Metrics
duration: 13min
completed: 2026-03-16
---

# Phase 27 Plan 01: Multi-IdP Advanced Observability — Priority, Health, Hot-Reload Summary

**Priority-ordered issuer selection with structured audit logs, file-backed health quarantine after 3 JWKS failures, and stat-based config hot-reload without daemon restart**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-16T13:50:37Z
- **Completed:** 2026-03-16T14:03:24Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- MIDP-09: `authenticate_multi_issuer()` now emits a structured `tracing::info!` on target `unix_oidc_audit` showing `issuer`, `position`, and `total_issuers` so SIEM operators can observe selection order
- MIDP-10: `IssuerHealthManager` tracks consecutive JWKS fetch failures per issuer in `/run/unix-oidc/issuer-health/`. After 3 failures, issuer is quarantined; recovers after `recovery_interval_secs` elapses. `ISSUER_DEGRADED` and `ISSUER_RECOVERED` audit events emitted on state transitions
- MIDP-11: `PolicyConfig::load_fresh()` stats the config file on each PAM authenticate call, re-parses only when mtime changes, and preserves the previous valid config on YAML parse failures or missing file

## Task Commits

Each task was committed atomically:

1. **Task 1: IdP priority ordering with structured logging** - `b3b7e2d` (feat)
2. **Task 2: IdP health monitoring + config hot-reload** - `939f7cc` (feat)

## Files Created/Modified

- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/src/auth.rs` — priority position log (step 2b), health gate (step 4), health success/failure recording (step 6b), IssuerHealthManager import
- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/src/policy/config.rs` — IssuerHealthState, IssuerHealthManager, ConfigCache, CONFIG_CACHE static, PolicyConfig::load_fresh(), recovery_interval_secs field
- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/src/policy/mod.rs` — re-exports for IssuerHealthManager and IssuerHealthState
- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/src/lib.rs` — pam_sm_authenticate uses load_fresh() for multi-issuer path
- `/Users/cbc/code/apps/unix-oidc/pam-unix-oidc/tests/multi_idp_integration.rs` — 15 new tests: 4 MIDP-09 priority, 7 MIDP-10 health, 4 MIDP-11 config reload

## Decisions Made

- Health state is file-based because each forked sshd process is ephemeral — no shared memory; files at `/run/unix-oidc/issuer-health/` are the only inter-process shared medium
- Only `ValidationError::JwksFetchError` counts as a health failure — token validation errors (expired, wrong audience, invalid sig) are expected and should not degrade the issuer's health
- Config hot-reload uses `UNIX_OIDC_POLICY` env var to allow test isolation; from_env() uses `UNIX_OIDC_POLICY_FILE` for its own path override — both can coexist without interference
- `ENV_MUTEX` gates all health and config-reload tests because `UNIX_OIDC_HEALTH_DIR` and `UNIX_OIDC_POLICY` are process-wide env vars — parallel mutation causes flaky tests

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

- Parallel test races: health state tests initially failed intermittently because `UNIX_OIDC_HEALTH_DIR` was being mutated by multiple test threads simultaneously. Fixed by adding `ENV_MUTEX` guard to all health and config-reload tests (Rule 1 — bug in test isolation).

## Next Phase Readiness

- MIDP-09, MIDP-10, MIDP-11 complete; multi-issuer pipeline now has production-quality observability and resilience
- Plan 27-02 (structured audit events) can now use the `unix_oidc_audit` target established here
- No blockers

---
*Phase: 27-multi-idp-advanced-observability*
*Completed: 2026-03-16*
