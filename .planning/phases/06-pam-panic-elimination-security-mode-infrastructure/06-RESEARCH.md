# Phase 6: PAM Panic Elimination + Security Mode Infrastructure - Research

**Researched:** 2026-03-10
**Domain:** Rust PAM module hardening — panic elimination, lock poisoning mitigation, figment config, enforcement mode design
**Confidence:** HIGH

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **Config shape:** Hybrid layout in policy.yaml — flat strings for `jti_enforcement`, `dpop_required`, `amr_enforcement`; nested object for `acr` with `enforcement` + `minimum_level`
- **Enforcement levels:** `strict` (reject), `warn` (log + allow), `disabled` (skip check)
- **Config loader:** figment 0.10.19 replaces serde_yaml for policy.yaml parsing; env var overrides via prefix `UNIX_OIDC_*`
- **Invalid mode values:** Cause PAM module to refuse-to-load (logged to console + syslog); no silent fallback
- **Config file path:** `/etc/unix-oidc/policy.yaml` — unchanged
- **Lock primitive:** `parking_lot::RwLock` and `parking_lot::Mutex` replace `std::sync::RwLock` and `std::sync::Mutex` across the entire `pam-unix-oidc` crate
- **No poisoning:** parking_lot chosen specifically to eliminate PoisonError — every `lock().unwrap()` on `std::sync` is replaced, not just recovered
- **HTTP client panics:** `reqwest::Client::builder().expect()` in `device_flow/client.rs` (two sites) replaced with error propagation
- **getrandom panic:** `getrandom::fill().expect()` in `security/session.rs` replaced with error propagation
- **JTI cache default:** 100,000 entries (matches CLAUDE.md documentation; code constant was 10,000 — must update)
- **Cache config section:** Separate `[cache]` section in policy.yaml for `jti_max_entries` and `jti_cleanup_interval_secs`
- **v1.0 backward compat defaults:** When `[security_modes]` absent: `jti_enforcement: warn`, `dpop_required: strict`, `acr.enforcement: warn`, `acr.minimum_level: null`, `amr_enforcement: disabled`
- **Migration notice:** INFO-level log on first load when security_modes section absent

### Claude's Discretion

- Exact figment Provider chain ordering and env var prefix normalization
- Which `.unwrap()`/`.expect()` calls in test code (`#[cfg(test)]`) to convert vs. leave (test panics are acceptable but consistency with parking_lot is preferred)
- Error type design for config validation failures
- Whether to add a `parking_lot` feature flag or make it an unconditional dependency
- Clippy allow attributes for test modules if needed after `deny(clippy::unwrap_used)` is active
- Exact cleanup interval default for JTI cache

### Deferred Ideas (OUT OF SCOPE)

None — discussion stayed within phase scope
</user_constraints>

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| SEC-01 | All `.expect()` and `.unwrap()` calls removed from PAM-reachable code paths | Full inventory below; 6 production sites identified |
| SEC-02 | `#![deny(clippy::expect_used, clippy::unwrap_used)]` lint active in `pam-unix-oidc` | Lint placement pattern documented; test-module allow strategy clarified |
| SEC-03 | Configurable enforcement modes (strict/warn/disabled) for JTI, DPoP requirement, ACR/AMR | Figment API verified; struct design and validation patterns documented |
| SEC-04 | figment-based config loading with backward-compatible defaults matching v1.0 behavior | figment 0.10.19 verified current; Provider chain, serde(default), and env override patterns documented |
| SEC-07 | JTI cache size aligned between code and documentation (resolve 10k vs 100k) | Code site identified: `jti_cache.rs:26` `MAX_ENTRIES_BEFORE_CLEANUP = 10_000`; dpop.rs `MAX_JTI_CACHE_ENTRIES = 100_000` already correct |
</phase_requirements>

---

## Summary

Phase 6 is a precision refactoring phase with three interlocking concerns: (1) eliminating every production panic site in `pam-unix-oidc`, (2) migrating all `std::sync` lock primitives to `parking_lot` to remove PoisonError, and (3) adding a `[security_modes]` config section with figment-based loading and strict backward-compatibility guarantees.

The inventory of production panic sites is small and well-bounded. There are exactly six non-test `.unwrap()`/`.expect()` call sites that are reachable from PAM entry points: two `Client::builder().expect()` in `device_flow/client.rs`, one `getrandom::fill().expect()` in `security/session.rs`, and three lock acquisitions in `security/session.rs::is_valid_session_id` (the `.parts.last().unwrap()` call — but this function is not reachable from PAM production paths; it is only used in tests). The lock `.unwrap()` calls in `jti_cache.rs`, `rate_limit.rs`, `jwks.rs`, and `dpop.rs` are all on `std::sync::RwLock` and will be eliminated by the parking_lot migration, not by hand-converting each one.

The figment migration is straightforward: the existing `serde_yaml::from_str` call in `policy/config.rs::load_from` is replaced with a figment `Figment::from(Yaml::file(path)).merge(Env::prefixed("UNIX_OIDC_"))` chain. The existing `PolicyConfig` serde struct is preserved; two new structs (`SecurityModes`, `CacheConfig`) are added with `#[serde(default)]`. The validation step (reject unknown enforcement mode strings) runs after deserialization before the config is returned.

**Primary recommendation:** Work in four sequential waves — (1) parking_lot migration, (2) getrandom + reqwest panic elimination, (3) SecurityModes + CacheConfig structs + figment wiring, (4) deny lint activation + cleanup. Each wave compiles clean before moving to the next.

---

## Standard Stack

### Core Additions

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `parking_lot` | 0.12.5 | RwLock/Mutex without PoisonError | Eliminates entire panic-on-poisoned-lock problem class; widely used in security-critical Rust |
| `figment` | 0.10.19 | Layered config loading with env overrides | Only mature Rust config library with type-safe layered providers and env override support |

### Removed

| Library | Replacement | Why |
|---------|-------------|-----|
| `serde_yaml` | `figment` (with `figment::providers::Yaml`) | figment includes its own YAML provider; `serde_yaml` becomes unused |

### Retained (no change)

- `thiserror` — used for `ConfigValidationError`
- `tracing` — structured logging for enforcement mode decisions
- `serde` / `serde_json` — unchanged
- `once_cell::sync::Lazy` — global singleton initializers remain; parking_lot guards returned directly

**Installation:**
```bash
cargo add parking_lot --package pam-unix-oidc
cargo add figment --features yaml --package pam-unix-oidc
cargo remove serde_yaml --package pam-unix-oidc
```

---

## Architecture Patterns

### Recommended File Changes

```
pam-unix-oidc/
├── Cargo.toml                      # Add parking_lot, figment; remove serde_yaml
├── src/lib.rs                      # Add #![deny(clippy::unwrap_used, clippy::expect_used)]
├── src/policy/
│   ├── config.rs                   # Add SecurityModes, CacheConfig; swap serde_yaml → figment
│   └── mod.rs                      # Re-export new types
├── src/security/
│   ├── jti_cache.rs                # std::sync → parking_lot; MAX_ENTRIES_BEFORE_CLEANUP 10k → 100k
│   ├── rate_limit.rs               # std::sync → parking_lot
│   └── session.rs                  # getrandom panic → error propagation
├── src/oidc/
│   ├── dpop.rs                     # std::sync → parking_lot
│   └── jwks.rs                     # std::sync → parking_lot
└── src/device_flow/
    └── client.rs                   # Client::builder().expect() → Result
```

### Pattern 1: parking_lot Lock Migration

**What:** Replace `std::sync::RwLock<T>` with `parking_lot::RwLock<T>`. No API change except lock acquisition never returns `Result` — the guard is returned directly.

**When to use:** All production lock sites in the crate.

```rust
// BEFORE (std::sync — panics if poisoned)
use std::sync::RwLock;
let entries = self.entries.read().unwrap();

// AFTER (parking_lot — never poisons, returns guard directly)
use parking_lot::RwLock;
let entries = self.entries.read(); // returns RwLockReadGuard directly
```

The import swap is mechanical: `use std::sync::RwLock` → `use parking_lot::RwLock`, `use std::sync::Mutex` → `use parking_lot::Mutex`. No other call-site changes needed because parking_lot's guard type has the same `Deref` behavior. The `write().unwrap()` chain simply becomes `write()`.

**Note on dpop.rs line 105:** The double-lock in `maybe_cleanup` acquires `entries.write()` then immediately calls `*self.last_cleanup.write() = now`. With parking_lot this is fine (no deadlock on re-entrant write on different fields), but it can be simplified to a single write scope.

### Pattern 2: getrandom Error Propagation

**What:** Replace the `expect()` panic in `generate_random_bytes()` with a `Result` return; propagate up through `generate_secure_session_id()` and callers.

**When to use:** `security/session.rs::generate_random_bytes` and its call chain.

```rust
// BEFORE
fn generate_random_bytes() -> [u8; 8] {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).expect("secure random number generation failed ...");
    bytes
}

// AFTER
fn generate_random_bytes() -> Result<[u8; 8], getrandom::Error> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes)?;
    Ok(bytes)
}

pub fn generate_secure_session_id(prefix: &str) -> Result<String, getrandom::Error> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()  // clock-before-epoch: treat as 0, not a panic
        .as_nanos();
    let random_bytes = generate_random_bytes()?;
    Ok(format!("{}-{:x}-{}", prefix, timestamp, hex_encode(&random_bytes)))
}
```

The `generate_ssh_session_id()` caller in `auth.rs` must propagate this into `AuthError::Config(...)`. The PAM authenticate path already handles `AuthError::Config` by returning `PamError::SERVICE_ERR`.

**is_valid_session_id:** The `parts.last().unwrap()` on line 99 is safe because the `parts.len() < 3` guard on line 95 ensures the vec is non-empty. However, with `deny(clippy::unwrap_used)` active, the clippy lint will fire. Replace with `parts.last().ok_or(...)` pattern or rewrite with a slice index `parts[parts.len() - 1]` with the guard already proving it is valid. Since `is_valid_session_id` is only called from tests, an `#[allow(clippy::unwrap_used)]` on that function or the test module is also a valid choice (see test strategy below).

### Pattern 3: DeviceFlowClient Error Propagation

**What:** Convert the two `Client::builder().expect()` calls in `device_flow/client.rs` to return `Result`.

```rust
// BEFORE
pub fn new(issuer_url: &str, client_id: &str, client_secret: Option<&str>) -> Self {
    Self {
        http_client: Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client"),
        ...
    }
}

// AFTER
pub fn new(
    issuer_url: &str,
    client_id: &str,
    client_secret: Option<&str>,
) -> Result<Self, DeviceFlowError> {
    Ok(Self {
        http_client: Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| DeviceFlowError::NetworkError(format!("Failed to create HTTP client: {e}")))?,
        ...
    })
}
```

The same change applies to `with_endpoints`. Callers of `DeviceFlowClient::new` must handle the `Result`. In practice, `DeviceFlowClient` is constructed when a device flow is actually needed (during sudo step-up), which is already in a `Result`-returning context.

### Pattern 4: figment-Based Config Loading

**What:** Replace `serde_yaml::from_str` with a figment `Yaml` + `Env` provider chain. The existing `PolicyConfig` struct is unchanged; new structs added with defaults.

```rust
// BEFORE (policy/config.rs)
use serde_yaml;
let config: PolicyConfig = serde_yaml::from_str(&content)?;

// AFTER
use figment::{Figment, providers::{Yaml, Env, Serialized, Format}};

impl PolicyConfig {
    pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(PolicyError::NotFound(path.display().to_string()));
        }

        // Layer: defaults < YAML file < env overrides
        let config: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
            .merge(Yaml::file(path))
            .merge(Env::prefixed("UNIX_OIDC_").split("__"))
            .extract()
            .map_err(|e| PolicyError::ParseError(e.to_string()))?;

        config.validate()?;
        Ok(config)
    }
}
```

The `Env::prefixed("UNIX_OIDC_").split("__")` convention maps `UNIX_OIDC_SECURITY_MODES__JTI_ENFORCEMENT=strict` to `security_modes.jti_enforcement`. Single-level keys like `UNIX_OIDC_JTI_ENFORCEMENT` would need a flat-to-nested remapping; the `__` split is the standard figment idiom for nested keys.

**Validation step after extraction:**
```rust
impl PolicyConfig {
    fn validate(&self) -> Result<(), PolicyError> {
        self.security_modes.validate()
            .map_err(|e| PolicyError::ConfigError(e.to_string()))?;

        // Emit INFO if security_modes section was absent (v1.0 file)
        if self.security_modes_was_absent {
            tracing::info!(
                "Loaded policy.yaml without security_modes section — \
                 using v1.0 defaults. See docs for v2.0 configuration."
            );
        }
        Ok(())
    }
}
```

Detecting section absence requires a two-phase approach: first extract raw YAML, check for key presence, then extract typed config. Alternatively, wrap `SecurityModes` in `Option<SecurityModes>` and default to `None`, then convert to defaults in `validate()`.

### Pattern 5: SecurityModes and CacheConfig Structs

```rust
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct PolicyConfig {
    pub host: HostConfig,
    pub ssh_login: SshConfig,
    pub sudo: SudoConfig,
    pub break_glass: BreakGlassConfig,
    pub security_modes: Option<SecurityModes>,  // None = v1.0 file, Some = v2.0
    pub cache: CacheConfig,
}

/// Enforcement level for security checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum EnforcementMode {
    Strict,
    #[default]
    Warn,
    Disabled,
}

impl EnforcementMode {
    pub fn validate_str(s: &str) -> Result<(), ConfigValidationError> {
        match s {
            "strict" | "warn" | "disabled" => Ok(()),
            other => Err(ConfigValidationError::InvalidEnforcementMode(
                other.to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SecurityModes {
    pub jti_enforcement: EnforcementMode,       // default: warn
    pub dpop_required: EnforcementMode,         // default: strict
    pub amr_enforcement: EnforcementMode,       // default: disabled
    pub acr: AcrConfig,
}

impl Default for SecurityModes {
    fn default() -> Self {
        Self {
            jti_enforcement: EnforcementMode::Warn,
            dpop_required: EnforcementMode::Strict,
            amr_enforcement: EnforcementMode::Disabled,
            acr: AcrConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct AcrConfig {
    pub enforcement: EnforcementMode,    // default: warn
    pub minimum_level: Option<String>,   // default: null
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct CacheConfig {
    pub jti_max_entries: usize,              // default: 100_000
    pub jti_cleanup_interval_secs: u64,     // default: 300
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            jti_max_entries: 100_000,
            jti_cleanup_interval_secs: 300,
        }
    }
}
```

### Pattern 6: Enforcement Mode Decision at Validation Site

The enforcement mode decision is made in `oidc/validation.rs::TokenValidator::validate`. Instead of the current hardcoded `warn` behavior, the validator reads enforcement modes from config:

```rust
// Existing JTI check in validation.rs — extend to use enforcement mode
match jti_result {
    JtiCheckResult::Valid => {}
    JtiCheckResult::Replay => {
        return Err(ValidationError::TokenReplay { jti: ... });
    }
    JtiCheckResult::Missing => {
        match self.config.jti_enforcement {
            EnforcementMode::Strict => {
                return Err(ValidationError::MissingJti);
            }
            EnforcementMode::Warn => {
                tracing::warn!(
                    username = %claims.preferred_username,
                    "Token missing JTI claim — replay protection unavailable"
                );
            }
            EnforcementMode::Disabled => {}
        }
    }
}
```

The `dpop_required` mode gates whether a token without a `cnf.jkt` claim can authenticate without a DPoP proof. The `acr` mode gates whether a token without the required ACR level produces a hard reject or a warn-and-allow. The `amr_enforcement` mode is a placeholder that currently has no active check (the TODO in validation.rs acknowledges this).

### Anti-Patterns to Avoid

- **Hand-converting each `RwLock.read().unwrap()`:** Do NOT replace with `if let Ok(guard) = self.entries.read()` — this treats poisoning as recoverable per-site. The correct approach is wholesale import swap to parking_lot, which makes the problem structurally impossible.
- **Silent fallback on invalid enforcement mode:** NEVER default to `warn` when the operator typed `jti_enforcement: "strct"`. Refuse to load; log to syslog.
- **Adding `parking_lot` as an optional feature:** Make it an unconditional dependency. There is no use case for using std::sync in a single-process PAM module; optional features add complexity without benefit.
- **figment `extract_lossy()`:** Do NOT use — it silently ignores unknown fields, which would let typos in `security_modes` pass undetected.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Lock without poison | Manual `unwrap_or_else` recovery | `parking_lot::RwLock` | Removes the problem class; no per-site boilerplate |
| Layered config + env override | Custom env-var parsing | `figment` | Handles type coercion, merging, and error context |
| Enum from string validation | `match s { "strict" => ... }` in config load | serde `rename_all = "lowercase"` | Serde handles this at deserialization; validate afterward with a `validate()` method |

---

## Common Pitfalls

### Pitfall 1: dpop.rs Double-Lock in maybe_cleanup

**What goes wrong:** `maybe_cleanup` acquires `entries.write()` and then immediately calls `*self.last_cleanup.write()` as a separate statement. With `std::sync`, this is correct. With parking_lot, there is no deadlock risk on different fields, but the code still takes two separate write locks where one write scope would suffice.

**Why it happens:** Copied from std::sync pattern where you want to release entries lock before updating last_cleanup.

**How to avoid:** Restructure `maybe_cleanup` to hold the entries write lock through the full cleanup, then update `last_cleanup` within the same scope or after the entries write is dropped.

**Warning signs:** Clippy does not flag this; it is a logic smell, not a lint error.

### Pitfall 2: deny(unwrap_used) Breaks Test Code

**What goes wrong:** `#![deny(clippy::unwrap_used)]` in `lib.rs` applies to all modules including `#[cfg(test)]` blocks. Tests legitimately use `.unwrap()` extensively.

**How to avoid:** Two options, both valid:
1. Apply the deny at the module level instead of crate level for production modules:
   ```rust
   // lib.rs — crate-wide, applies to all
   #![deny(clippy::unwrap_used, clippy::expect_used)]
   // In each test module:
   #[cfg(test)]
   #[allow(clippy::unwrap_used, clippy::expect_used)]
   mod tests { ... }
   ```
2. Alternative: use `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]` to limit the deny to non-test compilation.

The crate-level deny with per-test-module allow is more explicit and is the pattern recommended by the Rust API Guidelines. It documents intentionality.

**Key decision for planner:** There are also `.unwrap()` calls in test helpers inside `#[cfg(test)]` blocks for `session.rs` (`is_valid_session_id` test), `dpop.rs` tests, and `lib.rs` test mutex. These are acceptable to leave as `.unwrap()` inside test modules with an allow attribute. The lib.rs `ENV_MUTEX.lock().unwrap()` (10 call sites, all `#[cfg(test)]`) should be left as-is with a test-module allow.

### Pitfall 3: figment Env Var Naming Collision

**What goes wrong:** The existing codebase already reads `UNIX_OIDC_POLICY_FILE`, `UNIX_OIDC_TEST_MODE`, `UNIX_OIDC_RATE_LIMIT_WINDOW`, etc. via `std::env::var` directly. Adding figment with `Env::prefixed("UNIX_OIDC_")` would attempt to map ALL `UNIX_OIDC_*` vars into the PolicyConfig struct, causing deserialization errors for vars like `UNIX_OIDC_TEST_MODE=true` (which has no field in PolicyConfig).

**How to avoid:** Use figment's `Env::prefixed("UNIX_OIDC_").only(&["security_modes", "cache", ...])` filter to limit which env vars figment processes, OR use a distinct prefix for security mode overrides (e.g., `UNIX_OIDC_POLICY_*`). Alternatively, figment silently ignores unknown fields by default during extraction (unlike `extract_lossy`, the default `extract()` raises error on type mismatch but not on unknown keys). Verify this behavior for the specific figment version.

**Warning signs:** Test failures where `UNIX_OIDC_TEST_MODE` can't be deserialized as a PolicyConfig field.

### Pitfall 4: serde_yaml Removal Breaks Policy Tests

**What goes wrong:** `policy/config.rs` tests use `serde_yaml::from_str(yaml).unwrap()` directly in test code. After removing the `serde_yaml` dependency, these tests fail to compile.

**How to avoid:** Replace test YAML parsing in test code with figment's in-memory YAML parsing:
```rust
use figment::{Figment, providers::Yaml};
let config: PolicyConfig = Figment::from(Yaml::string(yaml)).extract().unwrap();
```

Or, if test code should remain minimal, add `serde_yaml` back as a `[dev-dependencies]` entry only. Given the goal of removing serde_yaml entirely, the figment approach is cleaner.

### Pitfall 5: JtiCache vs DPoPJtiCache Constant Discrepancy

**What goes wrong:** There are TWO separate JTI caches:
- `security/jti_cache.rs` has `MAX_ENTRIES_BEFORE_CLEANUP = 10_000` (wrong — should be 100k)
- `oidc/dpop.rs` has `MAX_JTI_CACHE_ENTRIES = 100_000` (already correct)

Both need to be consistent. The `jti_cache.rs` constant is the one serving token-level replay protection. The `dpop.rs` constant serves DPoP proof-level replay protection. Both should be 100k and both should be made configurable via `CacheConfig`.

**How to avoid:** Phase SEC-07 explicitly targets `jti_cache.rs:26` for update. Do not miss the dpop.rs constant — it is already correct but should also be wired to `CacheConfig.jti_max_entries` for consistency.

---

## Code Examples

### parking_lot Import Swap

```rust
// BEFORE: pam-unix-oidc/src/security/jti_cache.rs
use std::sync::RwLock;

// AFTER
use parking_lot::RwLock;

// Acquisition sites: .read().unwrap() → .read()
//                   .write().unwrap() → .write()
```

### figment Provider Chain

```rust
// pam-unix-oidc/src/policy/config.rs
use figment::{Figment, providers::{Env, Format, Yaml, Serialized}};

pub fn load_from<P: AsRef<Path>>(path: P) -> Result<Self, PolicyError> {
    let path = path.as_ref();
    if !path.exists() {
        return Err(PolicyError::NotFound(path.display().to_string()));
    }

    let config: PolicyConfig = Figment::from(Serialized::defaults(PolicyConfig::default()))
        .merge(Yaml::file(path))
        .merge(Env::prefixed("UNIX_OIDC_").split("__"))
        .extract()
        .map_err(|e| PolicyError::ParseError(e.to_string()))?;

    config.validate()?;
    Ok(config)
}
```

### ConfigValidationError Type

```rust
// pam-unix-oidc/src/policy/config.rs (new)
#[derive(Debug, thiserror::Error)]
pub enum ConfigValidationError {
    #[error("Invalid enforcement mode '{0}': must be strict, warn, or disabled")]
    InvalidEnforcementMode(String),
}

impl SecurityModes {
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        // EnforcementMode is an enum — invalid values are caught by serde at extraction.
        // This validate() step is for cross-field rules (future use).
        // The serde deserialization of EnforcementMode will fail with ParseError
        // on unknown strings before validate() is called.
        Ok(())
    }
}
```

Note: Because `EnforcementMode` is an enum with `#[serde(rename_all = "lowercase")]`, serde will reject unknown strings (e.g., `"strct"`) at extraction time with a `figment::Error`. The `PolicyError::ParseError` wrapping of figment errors will surface this to the PAM module startup, causing a `SERVICE_ERR` return — which is the desired refuse-to-load behavior.

### Enforcement Mode Decision Pattern

```rust
// oidc/validation.rs — JTI enforcement check
JtiCheckResult::Missing => {
    match enforcement_mode {
        EnforcementMode::Strict => {
            tracing::warn!(
                check = "jti",
                mode = "strict",
                username = %claims.preferred_username,
                "JTI missing — rejecting (strict mode)"
            );
            return Err(ValidationError::MissingJti);
        }
        EnforcementMode::Warn => {
            tracing::warn!(
                check = "jti",
                mode = "warn",
                username = %claims.preferred_username,
                "JTI missing — allowing with warning"
            );
        }
        EnforcementMode::Disabled => {
            tracing::debug!(check = "jti", mode = "disabled", "JTI check skipped");
        }
    }
}
```

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `std::sync::RwLock` with `unwrap()` recovery | `parking_lot::RwLock` without Result | parking_lot 0.12 (stable since 2023) | Eliminates PoisonError as a panic vector |
| `serde_yaml::from_str` | `figment::Figment` with `Yaml` + `Env` providers | figment 0.10 (stable 2022) | Enables env var override, layered config, type coercion |
| Hardcoded enforcement behavior | Enum-gated enforcement modes | This phase | Operators can tune security posture without rebuilding |

---

## Open Questions

1. **figment Env::prefixed collision with existing UNIX_OIDC_* vars**
   - What we know: figment's `extract()` ignores unknown keys at the top level by default (it raises on type mismatch, not on unrecognized keys)
   - What's unclear: Does figment 0.10.19 silently skip `UNIX_OIDC_TEST_MODE` (a string that maps to no PolicyConfig field) or does it error?
   - Recommendation: Write a unit test that sets `UNIX_OIDC_TEST_MODE=true` and confirms `PolicyConfig::load_from` succeeds. If it errors, use `Env::prefixed("UNIX_OIDC_").only(&["security_modes__jti_enforcement", ...])`.

2. **DPoP enforcement mode wire-up scope**
   - What we know: `dpop_required: strict` is the v1.0 default; the enforcement mode must be threaded from `PolicyConfig` → `auth.rs::authenticate_with_dpop`
   - What's unclear: `authenticate_with_dpop` currently reads `ValidationConfig::from_env()` which has no access to `PolicyConfig`. The enforcement modes live in `PolicyConfig`, not `ValidationConfig`. The planner must decide whether to merge configs or pass both.
   - Recommendation: Add a `SecurityModes` field to `ValidationConfig`, populated from `PolicyConfig` during config loading in `lib.rs`. This keeps the enforcement mode co-located with the validation decision.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in `cargo test` (no external framework) |
| Config file | none — workspace `Cargo.toml` governs |
| Quick run command | `cargo test -p pam-unix-oidc 2>&1` |
| Full suite command | `cargo test --workspace 2>&1` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEC-01 | No production panics on malformed input | unit | `cargo test -p pam-unix-oidc 2>&1` | Existing tests pass; new adversarial tests needed |
| SEC-02 | Lint active, crate compiles clean | build | `cargo clippy -p pam-unix-oidc -- -D clippy::unwrap_used -D clippy::expect_used 2>&1` | ❌ Wave 0 |
| SEC-03a | `jti_enforcement = "strict"` rejects missing JTI | unit | `cargo test -p pam-unix-oidc test_jti_strict_rejects_missing 2>&1` | ❌ Wave 0 |
| SEC-03b | `jti_enforcement = "warn"` logs warning and passes | unit | `cargo test -p pam-unix-oidc test_jti_warn_allows_missing 2>&1` | ❌ Wave 0 |
| SEC-03c | `dpop_required = "strict"` rejects unbound token | unit | `cargo test -p pam-unix-oidc test_dpop_strict_requires_proof 2>&1` | ❌ Wave 0 |
| SEC-04 | v1.0 policy.yaml loads with v1.0 behavior | unit | `cargo test -p pam-unix-oidc test_v1_policy_backward_compat 2>&1` | ❌ Wave 0 |
| SEC-04 | Invalid enforcement mode string fails load | unit | `cargo test -p pam-unix-oidc test_invalid_enforcement_mode_rejected 2>&1` | ❌ Wave 0 |
| SEC-07 | JTI cache size = 100k in both code files | build | `grep -r "MAX_ENTRIES\|MAX_JTI_CACHE" pam-unix-oidc/src/ \| grep -v 100_000 \| wc -l` should be 0 | ❌ Wave 0 |

**Adversarial tests required (per global pending todo):**
- Malformed token (truncated, invalid base64, missing claims) → never panics, returns AuthError
- Corrupt config (unknown enforcement mode, missing required fields) → SERVICE_ERR, not panic
- Lock acquisition during concurrent auth (parking_lot stress test)
- JTI cache at capacity with no expired entries → DPoP ReplayDetected, not panic

### Sampling Rate

- **Per task commit:** `cargo test -p pam-unix-oidc 2>&1`
- **Per wave merge:** `cargo test --workspace && cargo clippy -p pam-unix-oidc -- -D clippy::unwrap_used -D clippy::expect_used`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `pam-unix-oidc/src/oidc/validation.rs` — new unit tests for enforcement mode paths (strict/warn/disabled for JTI and ACR)
- [ ] `pam-unix-oidc/src/policy/config.rs` — tests for v1.0 backward compat load, invalid mode string rejection, figment env override
- [ ] `pam-unix-oidc/src/security/session.rs` — tests for getrandom error propagation path (may require mock)

---

## Sources

### Primary (HIGH confidence)

- Direct codebase inspection — all `.unwrap()` and `.expect()` sites enumerated via `grep -rn` against `pam-unix-oidc/src/`
- `cargo search parking_lot` — confirmed 0.12.5 is current
- `cargo search figment` — confirmed 0.10.19 is current
- parking_lot crate documentation: no `PoisonError`, guards returned directly, API-compatible with `std::sync` except for error handling
- figment documentation: `Yaml::file`, `Env::prefixed`, `Serialized::defaults`, `.extract()` behavior

### Secondary (MEDIUM confidence)

- figment `extract()` unknown-key behavior: documented as "ignores unknown fields unless strict mode" — verify with unit test
- figment `Env::split("__")` for nested key mapping: standard figment pattern, widely cited in figment docs

### Tertiary (LOW confidence)

- Behavior of figment when `UNIX_OIDC_TEST_MODE=true` is present in env during `extract::<PolicyConfig>()` — untested, flagged as Open Question 1

---

## Metadata

**Confidence breakdown:**
- Standard stack (parking_lot, figment versions): HIGH — verified via `cargo search`
- Panic site inventory: HIGH — direct grep of source files, all 6 production sites identified
- Architecture patterns (parking_lot migration, figment chain): HIGH — based on direct code inspection + library docs
- figment env collision behavior: MEDIUM — documented behavior, unverified against this specific config struct
- Test strategy: HIGH — based on existing test patterns in codebase

**Research date:** 2026-03-10
**Valid until:** 2026-06-10 (parking_lot and figment are mature/stable; 90-day window appropriate)
