---
phase: 13-operational-hardening
plan: "01"
subsystem: config
tags: [figment, config, timeouts, clock-skew, jwks, dpop, audit, gethostname]

requires:
  - phase: 11-implementation-completion
    provides: unix-oidc-agent daemon, DPoP proof generation, JwksProvider, token validation

provides:
  - TimeoutsConfig struct with 6 operator-tunable fields (jwks_http, device_flow, clock_skew_future, clock_skew_staleness, jwks_cache_ttl, ipc_idle)
  - AgentConfig::load_from_path() with figment layered loading (defaults + YAML + UNIX_OIDC__ env vars)
  - UNIX_OIDC_JWKS_CACHE_TTL legacy env var backward compat
  - JwksProvider::with_timeouts() constructor with configurable HTTP timeout
  - DPoPConfig::clock_skew_future_secs field replacing hardcoded 5
  - ValidationConfig::clock_skew_tolerance_secs field replacing CLOCK_SKEW_TOLERANCE const
  - get_hostname() using gethostname(2) syscall instead of env vars

affects:
  - 13-02 (JWKS TTL wiring to JwksProvider, timeouts in daemon serve loop)
  - all subsequent plans reading AgentConfig

tech-stack:
  added:
    - figment 0.10 (yaml + env features) added to unix-oidc-agent/Cargo.toml
    - parking_lot 0.12 added to unix-oidc-agent/Cargo.toml (already in pam-unix-oidc)
  patterns:
    - Figment layered config: defaults → YAML → UNIX_OIDC_TIMEOUTS__FIELD env vars → legacy UNIX_OIDC_JWKS_CACHE_TTL
    - TimeoutsConfig::validate() pattern for rejecting nonsensical timeout combinations at load time
    - ENV_MUTEX pattern (parking_lot::Mutex) used in pam-unix-oidc audit tests for env-var isolation

key-files:
  modified:
    - unix-oidc-agent/src/config.rs — TimeoutsConfig, AgentConfig::load_from_path(), figment loading
    - unix-oidc-agent/Cargo.toml — figment + parking_lot deps
    - pam-unix-oidc/src/audit.rs — get_hostname() syscall, ENV_MUTEX for test isolation
    - pam-unix-oidc/src/oidc/jwks.rs — http_timeout field, with_timeouts() constructor
    - pam-unix-oidc/src/oidc/dpop.rs — clock_skew_future_secs field in DPoPConfig
    - pam-unix-oidc/src/oidc/validation.rs — clock_skew_tolerance_secs field in ValidationConfig
    - pam-unix-oidc/src/auth.rs — clock_skew_future_secs in DPoPAuthConfig
    - pam-unix-oidc/src/lib.rs — clock_skew_future_secs in inline DPoPAuthConfig
    - pam-unix-oidc/src/sudo.rs — clock_skew_tolerance_secs in ValidationConfig
    - unix-oidc-agent/src/main.rs — device_flow_timeout_secs from config at run_login/run_refresh

key-decisions:
  - "figment UNIX_OIDC_TIMEOUTS__FIELD pattern (double-underscore separator) chosen for nested env var overrides — consistent with figment docs and avoids ambiguity with field names containing underscores"
  - "UNIX_OIDC_JWKS_CACHE_TTL preserved as legacy direct override applied AFTER figment extraction — allows operators who already export this env var to continue without change"
  - "load_from_path() added as primary API; from_env()/from_file() kept as backward compat delegation paths — no breaking change to existing callers"
  - "DPoPAuthConfig gains clock_skew_future_secs to thread value from AgentConfig through to DPoPConfig — avoids adding AgentConfig param to authenticate_with_dpop() signature"
  - "CLOCK_SKEW_TOLERANCE const retained as dead_code with #[allow(dead_code)] for documentation; all active code uses ValidationConfig::clock_skew_tolerance_secs"
  - "device_flow_timeout_secs loaded at run_login() and run_refresh() call sites; failure falls back to 30s default — keeps existing behavior on systems without config file"
  - "hostname tests serialized with ENV_MUTEX (parking_lot::Mutex) to prevent parallel test race on UNIX_OIDC_HOSTNAME env var"

patterns-established:
  - "TimeoutsConfig validate() pattern: validate cross-field constraints (cache_ttl >= http_timeout, future_skew <= staleness_skew) at config load time, not at use time"
  - "figment Env::prefixed().split('__') for nested struct env overrides"
  - "Non-fatal config load in async functions: AgentConfig::load().map(|c| c.timeouts.field).unwrap_or(default)"

requirements-completed: [OPS-07, OPS-08, OPS-09, OPS-10, OPS-12]

duration: 14min
completed: "2026-03-11"
---

# Phase 13 Plan 01: Config Foundation — TimeoutsConfig, figment Loading, Hostname Fix Summary

**Figment-based AgentConfig with 6 operator-tunable TimeoutsConfig fields, all wired to consumer call sites, replacing every hardcoded timeout constant; gethostname(2) syscall replaces unreliable env-var hostname resolution in audit logging**

## Performance

- **Duration:** 14 min
- **Started:** 2026-03-11T11:55:57Z
- **Completed:** 2026-03-11T12:09:28Z
- **Tasks:** 3 (all TDD where specified)
- **Files modified:** 10

## Accomplishments

- Added `TimeoutsConfig` with 6 fields and `validate()` rejecting nonsensical timeout combinations; wired to `AgentConfig` via `#[serde(default)]`
- Replaced `AgentConfig::load()` with figment-based layered loading: compiled-in defaults → YAML file → `UNIX_OIDC_TIMEOUTS__*` env vars → legacy `UNIX_OIDC_JWKS_CACHE_TTL`
- Replaced `get_hostname()` env-var fallback chain (HOSTNAME → HOST → "unknown") with `gethostname::gethostname()` syscall; `UNIX_OIDC_HOSTNAME` preserved as operator override
- Wired all 5 timeout fields to consumer code: `jwks_http_timeout_secs` → `JwksProvider::http_timeout`; `device_flow_http_timeout_secs` → two spawn_blocking HTTP clients in main.rs; `clock_skew_future_secs` → `DPoPConfig`; `clock_skew_staleness_secs` → `ValidationConfig::clock_skew_tolerance_secs`; all hardcoded constants removed from active paths
- 450 workspace tests pass; clean build with zero warnings

## Task Commits

1. **Task 1: TimeoutsConfig + figment loading** — `eff35c2` (feat)
2. **Task 2: gethostname(2) syscall** — `9b5fd1a` (feat)
3. **Task 3: Wire timeouts to consumer call sites** — `90af289` (feat)

## Files Created/Modified

- `unix-oidc-agent/src/config.rs` — TimeoutsConfig struct, validate(), AgentConfig::load_from_path() with figment, ConfigError::Figment/Validation variants
- `unix-oidc-agent/Cargo.toml` — figment 0.10 (yaml+env), parking_lot 0.12 added
- `pam-unix-oidc/src/audit.rs` — get_hostname() using gethostname(2), ENV_MUTEX for test isolation, 3 new tests
- `pam-unix-oidc/src/oidc/jwks.rs` — http_timeout field on JwksProvider, with_timeouts() constructor, fetch_discovery/fetch_jwks use self.http_timeout
- `pam-unix-oidc/src/oidc/dpop.rs` — clock_skew_future_secs field on DPoPConfig (default 5), replaces hardcoded `now + 5`
- `pam-unix-oidc/src/oidc/validation.rs` — clock_skew_tolerance_secs field on ValidationConfig, replaces CLOCK_SKEW_TOLERANCE in expiration and auth_time checks
- `pam-unix-oidc/src/auth.rs` — clock_skew_future_secs in DPoPAuthConfig and test DPoPConfig initializer
- `pam-unix-oidc/src/lib.rs` — clock_skew_future_secs in inline DPoPAuthConfig literal
- `pam-unix-oidc/src/sudo.rs` — clock_skew_tolerance_secs in ValidationConfig literal
- `unix-oidc-agent/src/main.rs` — device_flow_timeout_secs loaded from AgentConfig at run_login() and run_refresh(); hardcoded 30s replaced

## Decisions Made

- figment `UNIX_OIDC_TIMEOUTS__FIELD` double-underscore pattern for nested env overrides — avoids ambiguity with field names containing underscores
- `UNIX_OIDC_JWKS_CACHE_TTL` preserved as legacy direct override applied AFTER figment extraction — no breaking change for existing deployments
- `DPoPAuthConfig::clock_skew_future_secs` added to thread the value through to `DPoPConfig` without changing `authenticate_with_dpop()` signature
- `CLOCK_SKEW_TOLERANCE` const kept with `#[allow(dead_code)]` for documentation; all active code uses the struct field
- hostname tests serialized with `ENV_MUTEX` (parking_lot::Mutex) to prevent parallel test race on UNIX_OIDC_HOSTNAME

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Parallel test race on UNIX_OIDC_HOSTNAME env var in audit.rs tests**
- **Found during:** Task 2 verification (running audit tests as a batch)
- **Issue:** `test_get_hostname_env_override` and `test_get_hostname_syscall_without_override` ran in parallel; one test's `set_var` / `remove_var` raced with the other, causing flaky failures
- **Fix:** Added `ENV_MUTEX: parking_lot::Mutex<()>` static to the audit test module; each hostname test acquires the mutex guard before touching `UNIX_OIDC_HOSTNAME`
- **Files modified:** `pam-unix-oidc/src/audit.rs`
- **Committed in:** `90af289` (Task 3 commit — included with audit.rs changes)

---

**Total deviations:** 1 auto-fixed (Rule 1 - bug)
**Impact on plan:** Fix necessary for test correctness; zero scope creep.

## Issues Encountered

None — all planned changes compiled and tested on first attempt after structural fixes.

## User Setup Required

None — no external service configuration required. Operators may now optionally add a `[timeouts]` section to `~/.config/unix-oidc/config.yaml` or set `UNIX_OIDC_TIMEOUTS__*` env vars to override defaults.

## Next Phase Readiness

- TimeoutsConfig foundation ready for Phase 13 Plan 02 (moka JTI cache with configurable TTL, IPC idle timeout wiring to ipc_idle_timeout_secs)
- JwksProvider::with_timeouts() available for any caller that wants both configurable cache TTL and HTTP timeout
- All 6 timeout fields have sensible defaults — existing deployments need no config changes

---
*Phase: 13-operational-hardening*
*Completed: 2026-03-11*
