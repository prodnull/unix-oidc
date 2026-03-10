# Phase 6: PAM Panic Elimination + Security Mode Infrastructure - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Remove all `.expect()`/`.unwrap()` from PAM-reachable code paths, activate `#![deny(clippy::unwrap_used, clippy::expect_used)]` lint, and wire configurable strict/warn/disabled enforcement modes for security checks (Issue #10). A v1.0 policy.yaml must load with identical behavior.

Requirements: SEC-01, SEC-02, SEC-03, SEC-04, SEC-07

</domain>

<decisions>
## Implementation Decisions

### Enforcement Mode Config Shape
- Hybrid layout in policy.yaml: flat strings for simple checks, nested objects for checks needing extra config (ACR)
- Four configurable checks: `jti_enforcement`, `dpop_required`, `amr_enforcement` (flat strings), `acr` (nested with `enforcement` + `minimum_level`)
- Three enforcement levels: `strict` (reject), `warn` (log + allow), `disabled` (skip check)
- Figment-based config loading with env var overrides using double-underscore nesting: `UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT`, `UNIX_OIDC_SECURITY_MODES__DPOP_REQUIRED`, etc. (revised from flat names per RESEARCH.md — figment requires `__` split for nested struct fields)
- Invalid enforcement mode values (e.g., `jti_enforcement: "yolo"`) cause the PAM module to refuse to load, with errors logged to both console and syslog
- Config loaded from existing `/etc/unix-oidc/policy.yaml` path — no new file
- Existing YAML field names preserved exactly — figment replaces parser, not schema

### RwLock Poisoning Strategy
- `parking_lot::RwLock` and `parking_lot::Mutex` replace `std::sync::RwLock` and `std::sync::Mutex` across the entire `pam-unix-oidc` crate
- No poisoning semantics — a panic in one thread cannot cascade via poisoned locks
- All `.unwrap()` calls on lock acquisition are eliminated (parking_lot returns the guard directly, no Result)
- `reqwest::Client::builder().expect()` in device_flow/client.rs replaced with error propagation — TLS init failures return errors, not panics
- `getrandom().expect()` in session.rs replaced with error propagation

### JTI Cache Size Resolution
- Default: 100,000 entries (code updated to match existing documentation)
- Configurable via separate `[cache]` section in policy.yaml: `jti_max_entries` and `jti_cleanup_interval_secs`
- Cache config is operational tuning, separate from `[security_modes]` (policy)
- CLAUDE.md "100k" is the canonical value; code constant updated from 10k to 100k

### Backward Compatibility
- v1.0 defaults when `security_modes` section is absent: `jti_enforcement: warn`, `dpop_required: strict`, `acr.enforcement: warn`, `acr.minimum_level: null`, `amr_enforcement: disabled`
- These defaults match current v1.0 code behavior exactly — zero behavior change on upgrade
- INFO-level log on first load when security_modes section absent: "Loaded policy.yaml without security_modes section — using v1.0 defaults. See docs for v2.0 configuration."
- Figment `#[serde(default)]` on the SecurityModes struct ensures missing sections get defaults

### Claude's Discretion
- Exact figment Provider chain ordering and env var prefix normalization
- Which `.unwrap()`/`.expect()` calls in test code (`#[cfg(test)]`) to convert vs. leave (test panics are acceptable but consistency with parking_lot is preferred)
- Error type design for config validation failures
- Whether to add a `parking_lot` feature flag or make it an unconditional dependency
- Clippy allow attributes for test modules if needed after `deny(clippy::unwrap_used)` is active
- Exact cleanup interval default for JTI cache

</decisions>

<specifics>
## Specific Ideas

- parking_lot chosen over std+PoisonError handling because it eliminates the problem class entirely rather than adding verbose recovery code at every lock site
- Hybrid config shape chosen to avoid forcing nested objects on simple boolean-like toggles while still supporting ACR's extra `minimum_level` field
- Refuse-to-load on bad config is deliberate: silent fallback to defaults risks operators thinking they've hardened when they haven't (typo in "strct" silently becomes default "warn")
- The `[cache]` section is positioned as operational tuning to keep it conceptually separate from security policy — an operator increasing cache size is not changing security posture

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `PolicyConfig` (`pam-unix-oidc/src/policy/config.rs`): Current config struct — extend with `SecurityModes` and `CacheConfig` fields
- `ValidationConfig` (`pam-unix-oidc/src/oidc/validation.rs`): Token validation config — will consume enforcement mode settings
- `DPoPConfig` (`pam-unix-oidc/src/oidc/dpop.rs`): DPoP validation config — will consume `dpop_required` setting
- `JtiReplayCache` (`pam-unix-oidc/src/security/jti_cache.rs`): Has `MAX_JTI_CACHE_ENTRIES` constant to update and make configurable
- `RateLimiter` (`pam-unix-oidc/src/security/rate_limit.rs`): 12 RwLock sites to convert to parking_lot

### Established Patterns
- `thiserror` for error types — use for `ConfigValidationError`
- `tracing` structured logging — enforcement mode decisions logged with check name, mode, and outcome
- `serde(default)` on config structs — already used on `SshConfig`, apply same pattern to `SecurityModes`
- `#![deny(unsafe_code)]` already in lib.rs — `deny(clippy::unwrap_used, clippy::expect_used)` follows same pattern

### Integration Points
- `pam-unix-oidc/src/lib.rs`: PAM entry point — config loading happens here, enforcement modes flow to auth functions
- `pam-unix-oidc/src/auth.rs`: `authenticate_with_token()` — reads enforcement modes to decide warn vs reject
- `pam-unix-oidc/src/oidc/dpop.rs`: JTI cache (27 lock sites) + DPoP validation — both consume enforcement config
- `pam-unix-oidc/src/oidc/jwks.rs`: JWKS cache (6 lock sites) — parking_lot conversion
- `pam-unix-oidc/src/security/rate_limit.rs`: Rate limiter (12 lock sites) — parking_lot conversion
- `pam-unix-oidc/src/device_flow/client.rs`: 2 `.expect()` calls on reqwest Client builder — error propagation
- `pam-unix-oidc/Cargo.toml`: Add `parking_lot` and `figment` dependencies, remove `serde_yaml`

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 06-pam-panic-elimination-security-mode-infrastructure*
*Context gathered: 2026-03-10*
