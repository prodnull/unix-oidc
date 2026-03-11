# Phase 8: Username Mapping + Group Policy + Break-Glass - Research

**Researched:** 2026-03-10
**Domain:** PAM/OIDC identity mapping, NSS group resolution, Rust trait design, PAM flow control
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Username Claim Source (IDN-01)**
- Configurable claim source with `preferred_username` as default (backward-compatible with v1.0)
- Config field: `identity.username_claim` in policy.yaml — accepts `sub`, `email`, `preferred_username`, or any custom claim name
- TokenClaims struct needs a generic claim extraction method (currently only has typed `preferred_username` field)
- Treat as a strategy that can be extended later — the claim source is a string key, not a hardcoded enum

**Username Transform Pipeline (IDN-02)**
- Ordered list of transforms applied sequentially: `identity.transforms: [strip_domain, lowercase]`
- Available transforms: `strip_domain` (remove @domain), `lowercase`, `regex` (with named capture group `(?P<username>...)`)
- Regex transform rejects patterns without `(?P<username>...)` at config load time
- Pipeline is composable — transforms chain in declared order
- Fuzz target `fuzz/fuzz_targets/username_mapper.rs` already sketches transform types — production module should align

**Username Collision Detection (IDN-03)**
- Config-load-time static validation only — no runtime collision checks
- Verify that the chosen claim + transform pipeline is injective (one-to-one)
- E.g., `strip_domain` on `email` is safe if constrained to a single domain; warn if multiple domains could collide
- Hard-fail always: refuse to start with a clear config error (never configurable, same class as signature verification)
- Error message reveals which identities collide — this is operator-facing (config load), not attacker-facing
- Treat as extensible strategy — initial implementation covers static transform analysis, can add explicit collision maps later

**Group-Based Login Policy (IDN-04)**
- Groups resolved from SSSD/NSS, NOT from OIDC token claims
- After username mapping resolves the local Unix username, query NSS for that user's group memberships
- `login_groups` allow-list in `[ssh_login]` section of policy.yaml — array of group name strings
- Exact string match only, case-sensitive (no wildcards, no regex)
- If the mapped user's NSS groups do not intersect `login_groups`, deny login
- When `login_groups` is empty/absent, no group restriction applied (backward compat with v1.0)
- Denial logged with the user's resolved groups for audit trail
- Token `groups` claim (if present) logged for audit enrichment but NOT used for access decisions
- `groups_enforcement` in `[security_modes]` controls behavior when NSS group lookup fails: strict/warn/disabled

**Group-Based Sudo Policy (IDN-05)**
- `sudo_groups` list in `[sudo]` section of policy.yaml — array of group name strings
- Separate from `login_groups` — being in sudo_groups does NOT imply login access (least privilege)
- Exact string match, case-sensitive
- Groups resolved from SSSD/NSS (same source as login_groups)
- If user's NSS groups do not intersect sudo_groups, deny at PAM step-up gate
- Same `groups_enforcement` mode applies for NSS group lookup failures

**Break-Glass Account Bypass (IDN-06)**
- Break-glass accounts identified by username list: `break_glass.accounts: ['breakglass', 'emergency-admin']`
- Extends existing `BreakGlassConfig` struct — change `local_account: Option<String>` to `accounts: Vec<String>`
- PAM returns `PAM_IGNORE` when pam_user matches a break-glass account
- Break-glass bypass applies to SSH login (pam_sm_authenticate) only, NOT sudo step-up
- Check happens BEFORE any OIDC processing (rate limiting, nonce issuance, token validation)
- `break_glass.enabled` must be `true` AND user must be in `accounts` list — disabled by default

**Break-Glass Audit (IDN-07)**
- New `AuditEvent::BreakGlassAuth` variant with CRITICAL severity
- Fields: timestamp, username, source_ip, hostname, reason ("break-glass bypass")
- Written to syslog AUTH facility + dedicated audit log (matches existing AuditEvent pattern)
- Every break-glass authentication emits this event — no way to suppress it (always-on audit)
- Audit event emitted BEFORE returning PAM_IGNORE

### Claude's Discretion

- Internal design of the transform pipeline (trait vs enum, execution model)
- How to extract arbitrary claims from JWT (serde_json::Value traversal vs typed struct extension)
- Exact config validation error messages beyond collision detection
- Whether to add a `groups` field to TokenClaims for audit enrichment logging
- Test strategy for collision detection edge cases
- Whether `groups_enforcement` gets its own field in SecurityModes or reuses an existing pattern
- How to extend `sssd/user.rs` to resolve group memberships (uzers crate group queries or getgrouplist(3))

### Deferred Ideas (OUT OF SCOPE)

- Glob/wildcard group matching
- Runtime collision detection across active sessions
- SCIM-based group sync from IdP to local system
- UID-range-based break-glass detection
- Break-glass bypass for sudo step-up
- Token-claim-based group policy (alternative to SSSD)
- Identity rationalization strategy (FreeIPA + Entra coexistence patterns)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|-----------------|
| IDN-01 | Username claim mapping with configurable claim source (sub, email, preferred_username, custom) | `TokenClaims` needs `get_claim(&str) -> Option<String>` via `serde_json::Value`; `IdentityConfig` struct with `username_claim: String` |
| IDN-02 | Username transform functions (strip domain suffix, regex with capture group, lowercase) | Enum-based transform pipeline; `regex` crate must be added as new dep; named capture group `(?P<username>...)` validation at config load |
| IDN-03 | Username uniqueness validation at config load time to prevent many-to-one collisions | Static injectivity analysis: strip_domain is non-injective across multiple domains; regex group is inherently non-injective if pattern matches multiple inputs identically; load-time hard-fail via `PolicyError::ConfigError` |
| IDN-04 | Group-based login access policy from OIDC groups claim with configurable allow-list | `uzers::get_user_groups(username, gid)` returns `Option<Vec<Group>>`; `Group::name()` returns `&OsStr`; check intersection with `login_groups` vec |
| IDN-05 | Group-based sudo access policy (sudo_groups) gating step-up authorization | Same `get_user_groups` path; hook into `sudo.rs` pam_sm_setcred or before step-up; `SudoConfig` gains `sudo_groups: Vec<String>` |
| IDN-06 | Break-glass account enforcement — skip OIDC for configured accounts, pass to next PAM module | `BreakGlassConfig.accounts: Vec<String>`; check pam_user membership before rate-limit; return `PamError::IGNORE`; no OIDC code path executes |
| IDN-07 | Break-glass audit event emitted on every break-glass authentication | `AuditEvent::BreakGlassAuth` variant; emit before `return PamError::IGNORE`; uses existing `AuditEvent::log()` pattern with AUTH facility |
</phase_requirements>

## Summary

Phase 8 adds the enterprise identity layer to the PAM module: configurable username claim extraction, a composable transform pipeline, load-time collision detection, SSSD-backed group policy for both login and sudo, and a break-glass bypass with mandatory audit logging. All seven requirements are tightly scoped to the `pam-unix-oidc` crate — no agent, no IPC, no network changes.

The code is well-structured for these additions. The existing `EnforcementMode` pattern (hand-rolled Deserialize, strict/warn/disabled) covers the new `groups_enforcement` field without modification to that type. The `uzers` crate (already a dependency at 0.12.2) provides `get_user_groups(username, gid) -> Option<Vec<Group>>` which is the right primitive for SSSD/NSS group resolution — no new crate needed for group lookup. The `regex` crate must be added as a new production dependency for the regex transform; it is already in the fuzz Cargo.toml and is a well-audited standard crate.

**Primary recommendation:** Implement in four self-contained modules — `identity/mapper.rs` (IDN-01+02), `identity/collision.rs` (IDN-03), `sssd/groups.rs` (IDN-04+05), break-glass in existing files (IDN-06+07) — wired together in `auth.rs` and `lib.rs` at the integration points the CONTEXT.md identifies exactly.

## Standard Stack

### Core (already in pam-unix-oidc)

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `uzers` | 0.12.2 | NSS/SSSD user+group lookup | Already dep; `get_user_groups` is exactly the right API |
| `serde_json` | 1.0 | `Value`-based claim traversal | Already dep; `Value::pointer()` handles nested claim paths |
| `figment` | 0.10 | Config loading for new `IdentityConfig` section | Already dep; zero-behavior-change pattern established |
| `thiserror` | 1.0 | Error types for new modules | Crate-wide convention |
| `tracing` | 0.1 | Structured audit-enrichment logging | Crate-wide convention |

### New Dependency Required

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `regex` | 1.10+ | Regex transform with named capture group | Required for IDN-02 regex transform; already in fuzz crate |

**Installation:**
```bash
# Add to pam-unix-oidc/Cargo.toml [dependencies]
regex = "1.10"
```

The `regex` crate is the only new production dependency. It is widely adopted, has no known CVEs, and is already present in the fuzz workspace confirming it was already evaluated for this codebase.

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `regex` crate | hand-rolled capture group parser | regex crate is audited and battle-tested; hand-rolling is higher risk for a security component |
| `uzers::get_user_groups` | `libc::getgrouplist` via FFI | `uzers` already in dep tree; safer Rust wrapper; same SSSD resolution path |
| `serde_json::Value` pointer | extending `TokenClaims` with `#[serde(flatten)] extra: HashMap<String, Value>` | Both work; `HashMap` approach is more ergonomic for arbitrary claim access; either is fine |

## Architecture Patterns

### Recommended Module Structure

```
pam-unix-oidc/src/
├── identity/               # NEW: claim-to-username mapping
│   ├── mod.rs              # re-exports: UsernameMapper, IdentityConfig, IdentityError
│   ├── mapper.rs           # Transform trait + pipeline execution (IDN-01, IDN-02)
│   └── collision.rs        # Static injectivity analysis (IDN-03)
├── sssd/
│   ├── mod.rs              # add get_user_groups_nss to re-exports
│   ├── user.rs             # existing — no changes
│   └── groups.rs           # NEW: get_nss_groups(), is_member() (IDN-04, IDN-05)
├── policy/
│   └── config.rs           # extend: IdentityConfig, SshConfig.login_groups,
│                           #         SudoConfig.sudo_groups, BreakGlassConfig.accounts,
│                           #         SecurityModes.groups_enforcement
├── audit.rs                # add: AuditEvent::BreakGlassAuth (IDN-07)
├── auth.rs                 # wire: mapper call replaces hardcoded preferred_username,
│                           #       group check after user_exists
└── lib.rs                  # wire: break-glass check FIRST in authenticate()
```

### Pattern 1: Transform Pipeline (Enum + Trait)

**What:** An enum `UsernameTransform` whose variants encapsulate each transform. A `Vec<UsernameTransform>` is applied left-to-right against the extracted claim value. Each transform returns `Option<String>` — `None` aborts the pipeline and triggers a config-load error (regex with no match for the tested input is NOT a runtime error; it produces `None` which means "no username could be derived").

**When to use:** Any time a claim value must be converted to a local Unix username.

```rust
// Source: design from CONTEXT.md + fuzz/fuzz_targets/username_mapper.rs alignment
pub enum UsernameTransform {
    StripDomain,
    Lowercase,
    Regex(regex::Regex),  // pre-compiled at config load time
}

impl UsernameTransform {
    pub fn apply(&self, input: &str) -> Option<String> {
        match self {
            Self::StripDomain => {
                input.split('@').next().filter(|s| !s.is_empty()).map(String::from)
            }
            Self::Lowercase => Some(input.to_lowercase()),
            Self::Regex(re) => {
                re.captures(input)
                    .and_then(|caps| caps.name("username"))
                    .map(|m| m.as_str().to_string())
            }
        }
    }
}

pub struct UsernameMapper {
    claim: String,                      // e.g. "email", "sub", "preferred_username"
    transforms: Vec<UsernameTransform>, // ordered pipeline
}

impl UsernameMapper {
    /// Apply the pipeline to a claims JSON object.
    /// Returns None if the claim is absent or any transform returns None.
    pub fn map(&self, raw_claims: &serde_json::Value) -> Option<String> {
        let claim_value = raw_claims.get(&self.claim)?.as_str()?.to_string();
        let mut current = claim_value;
        for transform in &self.transforms {
            current = transform.apply(&current)?;
        }
        Some(current)
    }
}
```

**Regex validation at config load time:**
```rust
// Source: design from CONTEXT.md
fn build_regex_transform(pattern: &str) -> Result<UsernameTransform, IdentityError> {
    // Reject patterns without (?P<username>...) named group before compilation.
    if !pattern.contains("(?P<username>") {
        return Err(IdentityError::MissingCaptureGroup(pattern.to_string()));
    }
    let re = regex::Regex::new(pattern)
        .map_err(|e| IdentityError::InvalidRegex(e.to_string()))?;
    Ok(UsernameTransform::Regex(re))
}
```

### Pattern 2: NSS Group Resolution

**What:** Call `uzers::get_user_groups(username, gid)` to retrieve the full group list for a mapped Unix user, then test set intersection against the policy allow-list.

**When to use:** After `get_user_info` succeeds (user exists) and before returning `AuthResult`.

```rust
// Source: uzers 0.12.2 docs — get_user_groups(username, gid) -> Option<Vec<Group>>
use uzers::{get_user_groups, Group};

pub fn resolve_nss_groups(username: &str, gid: u32) -> Option<Vec<String>> {
    get_user_groups(username, gid).map(|groups| {
        groups
            .iter()
            .filter_map(|g| g.name().to_str().map(String::from))
            .collect()
    })
}

pub fn is_group_member(user_groups: &[String], allowed: &[String]) -> bool {
    user_groups.iter().any(|g| allowed.contains(g))
}
```

**Enforcement mode pattern (mirrors existing EnforcementMode usage):**
```rust
// Source: established codebase pattern from Phase 06/07
match (resolve_nss_groups(username, gid), groups_enforcement) {
    (Some(groups), _) => {
        if !login_groups.is_empty() && !is_group_member(&groups, login_groups) {
            tracing::warn!(
                username = username,
                user_groups = ?groups,
                login_groups = ?login_groups,
                "Login denied: user not in login_groups"
            );
            return Err(AuthError::GroupDenied(username.to_string()));
        }
    }
    (None, EnforcementMode::Strict) => {
        tracing::warn!(username, "NSS group lookup failed (strict) — denying login");
        return Err(AuthError::GroupLookupFailed(username.to_string()));
    }
    (None, EnforcementMode::Warn) => {
        tracing::warn!(username, "NSS group lookup failed — allowing login (warn mode)");
    }
    (None, EnforcementMode::Disabled) => {}
}
```

### Pattern 3: Break-Glass Guard (PAM_IGNORE)

**What:** A guard at the very top of `pam_sm_authenticate` that checks pam_user against the break-glass accounts list. If matched, emit `AuditEvent::BreakGlassAuth` and return `PamError::IGNORE` before any OIDC code runs.

**When to use:** First thing in `PamServiceModule::authenticate()`, before rate-limit, nonce, or token collection.

```rust
// Source: CONTEXT.md IDN-06/IDN-07 decisions + lib.rs integration point
fn check_break_glass(pam_user: &str, config: &BreakGlassConfig, source_ip: Option<&str>) -> bool {
    if !config.enabled {
        return false;
    }
    config.accounts.iter().any(|a| a == pam_user)
}

// In PamServiceModule::authenticate():
let policy = PolicyConfig::from_env().unwrap_or_default();
if check_break_glass(&pam_user, &policy.break_glass, source_ip) {
    // Emit audit BEFORE returning — ensures log even if PAM stack crashes after
    AuditEvent::break_glass_auth(&pam_user, source_ip).log();
    return PamError::IGNORE;  // delegates to next PAM module (e.g., pam_unix)
}
// ... rest of OIDC auth flow follows
```

### Pattern 4: Dynamic Claim Extraction

**What:** Extend `TokenClaims` with an optional `extra: serde_json::Value` field captured via `#[serde(flatten)]` to allow arbitrary claim extraction, OR add a `get_claim` helper that does pointer-based lookup on the full claims `Value`.

**Recommendation (Claude's discretion):** Use `HashMap<String, serde_json::Value>` with `#[serde(flatten)]` on `TokenClaims`. This is clean, does not require re-parsing the token, and the claim source string becomes a direct key lookup.

```rust
// Extend TokenClaims (token.rs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub preferred_username: String,
    // ... existing fields ...
    /// Catch-all for arbitrary claims (e.g. custom IdP claims, groups for audit)
    #[serde(flatten)]
    pub extra: std::collections::HashMap<String, serde_json::Value>,
}

impl TokenClaims {
    /// Extract a claim value as String. Checks typed fields first, then extra.
    pub fn get_claim_str(&self, claim: &str) -> Option<String> {
        match claim {
            "sub" => Some(self.sub.clone()),
            "preferred_username" => Some(self.preferred_username.clone()),
            other => self.extra.get(other)?.as_str().map(String::from),
        }
    }

    /// Extract groups claim for audit enrichment only.
    pub fn groups_for_audit(&self) -> Option<Vec<String>> {
        self.extra.get("groups")?.as_array().map(|arr| {
            arr.iter().filter_map(|v| v.as_str().map(String::from)).collect()
        })
    }
}
```

### Anti-Patterns to Avoid

- **Validating regex named group only at runtime:** The `(?P<username>...)` check MUST happen at config load time; failing at auth time is a denial-of-service for legitimate users.
- **Calling `get_user_groups` before `user_exists`:** `get_user_groups` takes a `gid` which is only available after `get_user_info` succeeds. Always resolve user first.
- **Using `group.name().to_string_lossy()` for membership comparison:** Non-UTF-8 group names should be skipped (filter_map with `.to_str()`) rather than compared as lossy strings — lossy conversion can produce identical strings for distinct names.
- **Break-glass bypass after rate-limit check:** Rate-limit check calls `record_failure` on error paths and uses the pam_user as a key. A break-glass user should not be rate-limited. The break-glass check MUST precede rate-limit.
- **Emitting audit AFTER `return PamError::IGNORE`:** The return happens before the next statement. Audit emission must come first.
- **Using `#[serde(other)]` on config enums:** This silently swallows typos. The codebase uses hand-rolled Deserialize for all enums to produce clear errors — follow the same pattern for any new enums.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Group membership lookup | FFI to `getgrouplist(3)` | `uzers::get_user_groups` | Already dep; handles SSSD via NSS; safe Rust wrapper |
| Regex named group capture | Custom parser | `regex` crate + `caps.name("username")` | Battle-tested; ReDoS mitigations built in |
| Claim key traversal | Custom JWT re-parse | `serde_json::Value` + `HashMap<String,Value> #[serde(flatten)]` | Claims already deserialized; no re-parse needed |
| Config layering for new sections | Custom env-var merge | `figment` with existing `Serialized::defaults + Yaml::file + Env::prefixed` | Established pattern; only requires adding new struct |
| Syslog audit writing | New syslog client | Existing `AuditEvent::log()` | Pattern is established; adding a variant costs 5 lines |

**Key insight:** The username mapping + group policy domain looks complex but most of the hard work (NSS resolution, syslog, config layering, enforcement modes) is already in the codebase. Phase 8 primarily assembles existing primitives, adds the `regex` dep, and adds a new `identity/` module.

## Common Pitfalls

### Pitfall 1: Collision Detection for `strip_domain` Across Multiple Domains

**What goes wrong:** If `identity.transforms: [strip_domain]` and multiple users from different domains could map to the same username (e.g., `alice@corp.com` and `alice@subsidiary.com` both become `alice`), this is a silent security hole — the first token to arrive could authenticate as either user.

**Why it happens:** The transform is applied independently to each token at runtime. Without static analysis, there is no load-time check.

**How to avoid:** At config load time, analyze the transform pipeline for injectivity. `strip_domain` alone is non-injective unless the claim source is constrained to a single domain. The validation should emit `PolicyError::ConfigError` with a message like: "transforms [strip_domain] on claim 'email' are not guaranteed injective — if multiple email domains are in use, consider adding a domain suffix constraint or using a regex transform with an explicit domain anchor". For v2.0, emit this as a WARN (not hard-fail) unless a future `identity.allowed_domains: [corp.com]` constraint is added. `lowercase` alone is injective. `regex` with a named group is non-injective if the pattern is loose (e.g., `.*` — must document this limitation).

**Warning signs:** An operator configures `strip_domain` without also configuring a domain restriction. Alert at config load.

### Pitfall 2: `uzers::get_user_groups` Returns `None` in CI Without SSSD

**What goes wrong:** In CI, `/etc/nsswitch.conf` routes group lookups to files or LDAP, not SSSD. `get_user_groups` returns `None` for users that exist in NSS but whose group list cannot be fetched. Tests that call the real NSS will fail non-deterministically.

**Why it happens:** `get_user_groups` calls `getgrouplist(3)` which is system-dependent. In Docker containers for CI, the system user database may not include group membership.

**How to avoid:** The `get_nss_groups` wrapper in `sssd/groups.rs` should be designed with a testable seam — accept a function parameter or use a trait object for injection in tests. Unit tests mock the group resolver; integration tests use a real system user (e.g., `root`) which always has known groups.

### Pitfall 3: PAM_IGNORE vs PAM_SUCCESS Semantics

**What goes wrong:** Returning `PamError::SUCCESS` from a break-glass path would authenticate the user as OIDC-validated, which is false. Returning `PamError::AUTH_ERR` would deny them entirely. Only `PamError::IGNORE` correctly delegates to the next PAM module.

**Why it happens:** PAM stack semantics are non-obvious. `pam_sm_authenticate` returning IGNORE means "this module has no opinion — continue to next module in the stack."

**How to avoid:** Use `PamError::IGNORE` exclusively. Document with a comment referencing PAM Linux documentation. The `pamsm` crate exposes `PamError::IGNORE` correctly.

### Pitfall 4: `claims.preferred_username` Hardcoded in auth.rs

**What goes wrong:** After IDN-01 is implemented, `auth.rs` still references `claims.preferred_username` directly at line 106 (current code). If that line is not updated, the username mapping is applied but then overridden by the hardcoded field.

**Why it happens:** There are three authentication entry points in auth.rs (`authenticate_with_token`, `authenticate_with_dpop`, `authenticate_with_config`). All three have independent `let username = &claims.preferred_username` lines. Missing even one is a silent regression.

**How to avoid:** Replace all three with `let username = mapper.map(&claims_as_value)`. Add a test that verifies a token with `email: alice@corp.com` + `strip_domain` transform resolves to username `alice`, not `alice@corp.com`.

### Pitfall 5: Break-Glass Accounts List Defaulting to Non-Empty

**What goes wrong:** If `BreakGlassConfig::default()` produces a non-empty `accounts` vec, operators who do not configure break-glass could accidentally have bypass accounts active.

**Why it happens:** Copy-paste from `local_account: Some("breakglass")` pattern in some examples.

**How to avoid:** `accounts: Vec<String>` defaults to `Vec::new()`. The `enabled: false` guard is the first check, but belt-and-suspenders: an empty accounts list also means no bypass regardless of `enabled`.

### Pitfall 6: Group Name Comparison with OsStr Lossy Conversion

**What goes wrong:** `group.name().to_string_lossy()` replaces invalid UTF-8 bytes with `\uFFFD` (replacement character). Two distinct group names that differ only in non-UTF-8 bytes would both compare equal after lossy conversion, potentially granting access to a user in a similarly-named group.

**Why it happens:** Unix group names are byte strings, not UTF-8. Most names are ASCII, but the API is `OsStr`.

**How to avoid:** Use `group.name().to_str()` (not `to_string_lossy()`). Skip groups with non-UTF-8 names via `filter_map`. Log a warning if any group names are skipped.

## Code Examples

Verified patterns from existing codebase:

### Adding a New Figment Config Section (established pattern)

```rust
// Source: pam-unix-oidc/src/policy/config.rs — SecurityModes pattern
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct IdentityConfig {
    /// Claim name to use as the username source. Default: "preferred_username".
    pub username_claim: String,
    /// Ordered transform pipeline applied to the extracted claim value.
    pub transforms: Vec<TransformConfig>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            username_claim: "preferred_username".to_string(),
            transforms: Vec::new(),
        }
    }
}

// Add to PolicyConfig:
pub struct PolicyConfig {
    // ... existing fields ...
    pub identity: IdentityConfig,
}
```

### EnforcementMode Field Addition (established pattern)

```rust
// Source: pam-unix-oidc/src/policy/config.rs — SecurityModes
// Add to SecurityModes struct and its hand-rolled Deserialize:
pub groups_enforcement: EnforcementMode,
// Default: Warn (NSS lookup failure should not hard-lock users by default)
```

### AuditEvent New Variant (established pattern)

```rust
// Source: pam-unix-oidc/src/audit.rs
#[serde(rename = "BREAK_GLASS_AUTH")]
BreakGlassAuth {
    timestamp: String,
    username: String,
    source_ip: Option<String>,
    host: String,
    reason: String,
    // Severity field for SIEM filtering:
    severity: &'static str, // always "CRITICAL"
},

// Constructor:
pub fn break_glass_auth(username: &str, source_ip: Option<&str>) -> Self {
    Self::BreakGlassAuth {
        timestamp: iso_timestamp(),
        username: username.to_string(),
        source_ip: source_ip.map(String::from),
        host: get_hostname(),
        reason: "break-glass bypass".to_string(),
        severity: "CRITICAL",
    }
}
```

### uzers Group Resolution (verified from docs)

```rust
// Source: uzers 0.12.2 docs — https://docs.rs/uzers/0.12.2/uzers/fn.get_user_groups.html
use uzers::get_user_groups;

// Signature: pub fn get_user_groups<S: AsRef<OsStr>>(username: &S, gid: gid_t) -> Option<Vec<Group>>
// Group::name() returns &OsStr
// Group::gid() returns gid_t

pub fn resolve_nss_group_names(username: &str, primary_gid: u32) -> Option<Vec<String>> {
    get_user_groups(username, primary_gid).map(|groups| {
        groups
            .iter()
            .filter_map(|g| g.name().to_str().map(String::from))
            .collect()
    })
}
```

### Transform Config YAML Deserialization

```yaml
# policy.yaml example
identity:
  username_claim: email
  transforms:
    - strip_domain
    - lowercase

# Or with regex:
identity:
  username_claim: sub
  transforms:
    - type: regex
      pattern: "^corp-(?P<username>[a-z0-9]+)$"
```

The config deserializer needs to handle both the shorthand string form (`strip_domain`, `lowercase`) and the tagged object form (`type: regex, pattern: ...`). Use a `#[serde(untagged)]` enum:

```rust
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TransformConfig {
    /// Shorthand: "strip_domain" | "lowercase"
    Simple(String),
    /// Tagged object: { type: "regex", pattern: "..." }
    Object { r#type: String, pattern: String },
}
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `preferred_username` hardcoded in auth.rs | Configurable `identity.username_claim` | Phase 8 | Enables email-based IdPs, sub-based IdPs, custom claim schemas |
| `local_account: Option<String>` for break-glass | `accounts: Vec<String>` | Phase 8 | Multiple break-glass accounts for large ops teams |
| No group enforcement | SSSD/NSS group-based allow-list | Phase 8 | PAM-level group enforcement without SSSD PAM module |

**Still current:**
- SSSD as Unix group authority (not OIDC token claims) — this is the right pattern for enterprise FreeIPA/LDAP deployments
- `EnforcementMode` (strict/warn/disabled) for all configurable checks
- `figment` for config loading with env overrides

## Open Questions

1. **Multi-domain `strip_domain` injectivity: warn or hard-fail?**
   - What we know: CONTEXT.md says collision detection is hard-fail. But `strip_domain` injectivity is only a risk if multiple domains are in use.
   - What's unclear: Should the check detect potential non-injectivity and warn, or require an explicit `allowed_domains` constraint to proceed?
   - Recommendation: For v2.0, emit a `WARN` log at config load when `strip_domain` is configured without a domain constraint, stating the risk. This avoids breaking deployments that only have one domain. Reserve hard-fail for detected actual collisions (when explicit user-to-username mapping data is available).

2. **`authenticate_with_config` used in tests — does it need the mapper too?**
   - What we know: `authenticate_with_config(token, config)` is used in existing tests (auth.rs:364). It does not load PolicyConfig.
   - What's unclear: Should it accept a `UsernameMapper` parameter or always use the default (preferred_username, no transforms)?
   - Recommendation: Add `mapper: Option<&UsernameMapper>` parameter or provide an overloaded helper. Tests that don't need mapping can pass `None` to use the default (backwards-compatible with existing 134 tests).

3. **`groups_enforcement` field placement: inside `SecurityModes` or separate in `PolicyConfig`?**
   - What we know: CONTEXT.md says Claude's discretion. `SecurityModes` already holds `jti_enforcement`, `dpop_required`, `amr_enforcement`, `acr`.
   - Recommendation: Add `groups_enforcement: EnforcementMode` to `SecurityModes`. This is consistent with the existing pattern, shares the hand-rolled Deserialize, and keeps all security-mode fields in one place.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Rust built-in test (`cargo test`) |
| Config file | none — `#[cfg(test)]` modules inline in each source file |
| Quick run command | `cargo test -p pam-unix-oidc 2>&1 \| tail -5` |
| Full suite command | `cargo test -p pam-unix-oidc` |
| Current baseline | 134 tests, 0 failures |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| IDN-01 | `email` claim extracted and used as username source | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_claim_extraction` | ❌ Wave 0 |
| IDN-01 | `sub` claim extracted | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_sub_claim` | ❌ Wave 0 |
| IDN-01 | unknown claim returns error | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_unknown_claim_returns_none` | ❌ Wave 0 |
| IDN-02 | `strip_domain` removes @domain | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_strip_domain` | ❌ Wave 0 |
| IDN-02 | `lowercase` lowercases | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_lowercase` | ❌ Wave 0 |
| IDN-02 | `regex` with named group extracts correctly | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_regex_named_group` | ❌ Wave 0 |
| IDN-02 | `regex` without `(?P<username>...)` rejected at config load | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_regex_missing_capture_group_rejected` | ❌ Wave 0 |
| IDN-02 | Pipeline chains: `[strip_domain, lowercase]` on `Alice@CORP.COM` → `alice` | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_pipeline_chain` | ❌ Wave 0 |
| IDN-02 | Empty result after pipeline aborts with error | unit | `cargo test -p pam-unix-oidc identity::mapper::tests::test_pipeline_empty_result` | ❌ Wave 0 |
| IDN-03 | `strip_domain` on single domain is accepted | unit | `cargo test -p pam-unix-oidc identity::collision::tests::test_single_domain_ok` | ❌ Wave 0 |
| IDN-03 | `strip_domain` on two different domain strings warns | unit | `cargo test -p pam-unix-oidc identity::collision::tests::test_multi_domain_warns` | ❌ Wave 0 |
| IDN-04 | User in `login_groups` is allowed | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_group_member_allowed` | ❌ Wave 0 |
| IDN-04 | User not in `login_groups` is denied | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_group_member_denied` | ❌ Wave 0 |
| IDN-04 | Empty `login_groups` allows all | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_empty_login_groups_allows_all` | ❌ Wave 0 |
| IDN-04 | NSS lookup failure in strict mode denies | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_nss_fail_strict_denies` | ❌ Wave 0 |
| IDN-04 | NSS lookup failure in warn mode allows | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_nss_fail_warn_allows` | ❌ Wave 0 |
| IDN-05 | User in `sudo_groups` is allowed | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_sudo_group_allowed` | ❌ Wave 0 |
| IDN-05 | User not in `sudo_groups` is denied at sudo gate | unit | `cargo test -p pam-unix-oidc sssd::groups::tests::test_sudo_group_denied` | ❌ Wave 0 |
| IDN-06 | Break-glass user with `enabled: true` returns PAM_IGNORE | unit | `cargo test -p pam-unix-oidc tests::test_break_glass_returns_ignore` | ❌ Wave 0 |
| IDN-06 | Break-glass user with `enabled: false` proceeds to OIDC | unit | `cargo test -p pam-unix-oidc tests::test_break_glass_disabled_proceeds` | ❌ Wave 0 |
| IDN-06 | Non-break-glass user is not caught by break-glass check | unit | `cargo test -p pam-unix-oidc tests::test_non_break_glass_user_not_caught` | ❌ Wave 0 |
| IDN-07 | Break-glass event serializes with CRITICAL severity and correct fields | unit | `cargo test -p pam-unix-oidc audit::tests::test_break_glass_event_serialization` | ❌ Wave 0 |
| IDN-07 | Break-glass event `event_type()` returns `BREAK_GLASS_AUTH` | unit | `cargo test -p pam-unix-oidc audit::tests::test_break_glass_event_type` | ❌ Wave 0 |

**Adversarial tests (per project standing directive):**

| Behavior | Test Type | File |
|----------|-----------|------|
| Null byte in claim value does not crash mapper | unit | `identity::mapper::tests::test_claim_null_byte_rejected` |
| Regex with catastrophic backtracking pattern (e.g., `(a+)+`) — regex crate mitigates but should test | unit | `identity::mapper::tests::test_regex_catastrophic_backtracking_bounded` |
| `accounts` list with duplicate entries does not produce double audit events | unit | `tests::test_break_glass_duplicate_accounts_single_event` |
| Group name with non-UTF-8 bytes is skipped safely | unit | `sssd::groups::tests::test_non_utf8_group_name_skipped` |
| Username after transform exceeds 256 bytes is rejected | unit | `identity::mapper::tests::test_username_too_long_rejected` |
| Claim value with `/` (path separator) is rejected from username | unit | `identity::mapper::tests::test_slash_in_username_rejected` |

### Sampling Rate
- **Per task commit:** `cargo test -p pam-unix-oidc 2>&1 | tail -5`
- **Per wave merge:** `cargo test -p pam-unix-oidc`
- **Phase gate:** Full suite green + `cargo clippy -p pam-unix-oidc -- -D warnings` + `cargo fmt --check -p pam-unix-oidc` before `/gsd:verify-work`

### Wave 0 Gaps

- [ ] `pam-unix-oidc/src/identity/mod.rs` — new module
- [ ] `pam-unix-oidc/src/identity/mapper.rs` — UsernameMapper, transforms, tests
- [ ] `pam-unix-oidc/src/identity/collision.rs` — static injectivity analysis, tests
- [ ] `pam-unix-oidc/src/sssd/groups.rs` — resolve_nss_group_names, is_group_member, tests
- [ ] `regex = "1.10"` added to `pam-unix-oidc/Cargo.toml`
- [ ] `groups_enforcement: EnforcementMode` added to `SecurityModes` (with hand-rolled Deserialize update)
- [ ] `login_groups: Vec<String>` added to `SshConfig`
- [ ] `sudo_groups: Vec<String>` added to `SudoConfig`
- [ ] `accounts: Vec<String>` replacing `local_account: Option<String>` in `BreakGlassConfig`
- [ ] `identity: IdentityConfig` added to `PolicyConfig`
- [ ] `AuditEvent::BreakGlassAuth` variant + `break_glass_auth()` constructor
- [ ] `AuditEvent::event_type()` match arm for `BreakGlassAuth`

*(All are new additions — no existing test infrastructure needs replacement)*

## Sources

### Primary (HIGH confidence)

- `uzers` 0.12.2 — https://docs.rs/uzers/0.12.2/uzers/fn.get_user_groups.html — verified `get_user_groups(username, gid) -> Option<Vec<Group>>` signature and `Group::name() -> &OsStr`
- Existing codebase — `pam-unix-oidc/src/policy/config.rs` — verified `EnforcementMode`, `SecurityModes`, figment pattern, hand-rolled Deserialize
- Existing codebase — `pam-unix-oidc/src/audit.rs` — verified `AuditEvent` variant structure and `log()` pattern
- Existing codebase — `pam-unix-oidc/src/sssd/user.rs` — verified `uzers::get_user_by_name` usage and `UserInfo` struct
- Existing codebase — `pam-unix-oidc/src/auth.rs` — verified three call sites of `claims.preferred_username` that must be replaced
- Fuzz target — `fuzz/fuzz_targets/username_mapper.rs` — verified transform enum shape to align production code with
- `pam-unix-oidc/Cargo.toml` — verified `uzers = "0.12"` is already a dep; `regex` is not yet a prod dep

### Secondary (MEDIUM confidence)

- `pamsm` crate behavior — `PamError::IGNORE` semantics inferred from PAM Linux specification (Linux-PAM System Administrators' Guide, §6.1) and `pamsm` crate docs; consistent with standard PAM return code semantics
- `regex` crate named capture groups — `(?P<username>...)` syntax is stable in `regex` 1.x; confirmed from regex crate documentation pattern (https://docs.rs/regex/latest/regex/#syntax)

### Tertiary (LOW confidence)

- Injectivity analysis for `strip_domain` across multiple domains — no single authoritative source; derived from first principles of function injectivity; recommendation to warn rather than hard-fail is a design judgment

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — all core deps verified in Cargo.toml; uzers API verified from docs.rs
- Architecture: HIGH — integration points identified from source code; established patterns verified
- Pitfalls: HIGH — derived from actual code reading (three hardcoded preferred_username sites in auth.rs); PAM_IGNORE semantics from spec
- Group resolution: HIGH — uzers docs verified; API signature confirmed

**Research date:** 2026-03-10
**Valid until:** 2026-06-10 (uzers 0.12.x API is stable; regex 1.x API is stable)
