---
phase: 06-pam-panic-elimination-security-mode-infrastructure
plan: "02"
subsystem: policy-config
tags: [figment, security-modes, config-loading, enforcement-mode, backward-compat]
dependency_graph:
  requires: []
  provides: [SecurityModes, CacheConfig, EnforcementMode, AcrConfig, figment-loading]
  affects: [pam-unix-oidc/src/policy/config.rs, pam-unix-oidc/src/policy/mod.rs]
tech_stack:
  added: [figment 0.10 (yaml + env features)]
  patterns: [figment layered config, serde hand-rolled Deserialize, Env::prefixed with .only() filter]
key_files:
  created: []
  modified:
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/policy/mod.rs
decisions:
  - "EnforcementMode uses hand-rolled Deserialize to reject unknown strings (e.g. 'strct') with a clear error rather than silently defaulting via #[serde(other)]"
  - "security_modes field in PolicyConfig is Option<SecurityModes> so figment can distinguish absent section (v1.0 file) from present section (v2.0) — effective_security_modes() provides unified access"
  - "Env::prefixed('UNIX_OIDC_').split('__').only(&['security_modes', 'cache']) prevents UNIX_OIDC_TEST_MODE and other non-config env vars from causing spurious parse errors"
  - "serde_yaml moved from [dependencies] to [dev-dependencies] — production code uses figment::providers::Yaml exclusively"
metrics:
  duration_secs: 270
  completed_date: "2026-03-10"
  tasks_completed: 1
  files_changed: 2
---

# Phase 6 Plan 02: SecurityModes/CacheConfig/EnforcementMode with Figment Config Loading Summary

SecurityModes, CacheConfig, EnforcementMode types added to pam-unix-oidc with figment-based YAML+env loading replacing serde_yaml in production paths. Backward-compatible with v1.0 policy.yaml files.

## Objective

Add configurable enforcement modes (strict/warn/disabled) for JTI, DPoP, ACR/AMR checks (Issue #10). Use figment for layered config with env var overrides. Preserve full v1.0 backward compatibility.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | SecurityModes, CacheConfig, EnforcementMode types and figment config loading | 4495df0 | config.rs, mod.rs |

## Implementation Details

### EnforcementMode

Three-variant enum (`Strict`, `Warn`, `Disabled`) with:
- Hand-rolled `Deserialize` that rejects unknown strings with a structured error (no silent fallback via `#[serde(other)]`)
- Hand-rolled `Serialize` that round-trips to lowercase strings
- Derived `Default` using `#[default]` on the `Warn` variant

### SecurityModes

v1.0-matching defaults:
- `jti_enforcement = Warn` — some IdPs omit JTI; warn and allow
- `dpop_required = Strict` — token binding is critical; always enforce
- `amr_enforcement = Disabled` — AMR not widely deployed yet
- `acr.enforcement = Warn`, `acr.minimum_level = None`

### PolicyConfig Extension

```rust
pub struct PolicyConfig {
    // ... existing fields ...
    pub security_modes: Option<SecurityModes>,  // None = v1.0 file detected
    pub cache: CacheConfig,
}
```

`effective_security_modes()` returns `SecurityModes::default()` when `None` — ensures identical behavior for operators who do not add the new section.

### Figment Loading

```rust
Figment::from(Serialized::defaults(PolicyConfig::default()))
    .merge(Yaml::file(path))
    .merge(
        Env::prefixed("UNIX_OIDC_")
            .split("__")
            .only(&["security_modes", "cache"]),
    )
    .extract()
```

The `.only()` filter is critical: it prevents `UNIX_OIDC_TEST_MODE`, `UNIX_OIDC_ACCEPT_PAM_ENV`, and similar vars from being mapped into PolicyConfig fields (which don't exist for them) and causing spurious parse errors.

### v1.0 Migration Notice

When `security_modes` is absent from the loaded YAML, an INFO log is emitted:
```
Loaded policy.yaml without security_modes section — using v1.0 defaults. See docs for v2.0 configuration.
```

## Test Coverage

18 policy tests pass, covering:
- `test_v1_yaml_loads_with_defaults` — v1.0 YAML produces `security_modes=None`
- `test_v2_yaml_overrides_security_modes` — v2.0 YAML sets explicit modes
- `test_invalid_enforcement_mode_rejected` — "strct" typo causes load failure
- `test_cache_section_overrides_defaults` — cache section configures JTI cache size
- `test_env_var_override_jti_enforcement` — `UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT=strict` overrides YAML
- `test_unknown_env_vars_do_not_break_load` — `UNIX_OIDC_TEST_MODE=true` not mapped to config
- `test_enforcement_mode_defaults` — default is Warn
- `test_security_modes_defaults` — all defaults verified
- `test_cache_config_defaults` — 100k entries, 300s cleanup
- Existing backward-compat tests: `test_parse_yaml_policy`, `test_default_policy`, `test_command_requires_step_up`, `test_pattern_matching`, `test_host_classification_parsing`

## Deviations from Plan

### Execution Context Deviation

**Found during:** Plan initialization

**Issue:** The concurrent plan 06-01 executor committed the GREEN implementation of plan 06-02 as a side effect. Specifically, commit `0b03de9 (feat(06-01): parking_lot migration and JTI cache constant fix)` included in its message: "Fix policy/config.rs compile errors (EnforcementMode serde, Format import, Yaml::string)". The full SecurityModes/figment implementation was placed in config.rs as part of that commit.

**Additional commits from 06-01 executor:** Two additional commits (`ff61362`, `f5666b7`) were made concurrently during plan 06-02 execution, covering session.rs/auth.rs/device_flow panic elimination.

**Fix:** Verified all plan 06-02 success criteria were met by the combined committed state. Applied rustfmt-standard formatting improvements to `config.rs` and `mod.rs` as the atomic task commit for plan 06-02 (`4495df0`). All 110 tests pass; clippy -D warnings clean.

**Files modified:** pam-unix-oidc/src/policy/config.rs, pam-unix-oidc/src/policy/mod.rs

**Commit:** 4495df0

## Verification Results

```
figment = { version = "0.10", features = ["yaml", "env"] }  # in [dependencies]
serde_yaml = "0.9"  # in [dev-dependencies] only

cargo test -p pam-unix-oidc policy: 18 passed
cargo test -p pam-unix-oidc: 110 passed
cargo clippy -p pam-unix-oidc -- -D warnings: clean
```

## Self-Check: PASSED

- pam-unix-oidc/src/policy/config.rs: FOUND
- pam-unix-oidc/src/policy/mod.rs: FOUND
- Commit 4495df0: FOUND
- 110 tests passing: VERIFIED
