# Phase 8: Username Mapping + Group Policy + Break-Glass - Context

**Gathered:** 2026-03-10
**Status:** Ready for planning

<domain>
## Phase Boundary

Enterprise deployments can map IdP claim values to local Unix usernames, restrict login to specific OIDC groups, and rely on break-glass accounts being enforced with an audit trail. Implements IDN-01 through IDN-07.

Requirements: IDN-01, IDN-02, IDN-03, IDN-04, IDN-05, IDN-06, IDN-07

</domain>

<decisions>
## Implementation Decisions

### Username Claim Source (IDN-01)
- Configurable claim source with `preferred_username` as default (backward-compatible with v1.0)
- Config field: `identity.username_claim` in policy.yaml — accepts `sub`, `email`, `preferred_username`, or any custom claim name
- TokenClaims struct needs a generic claim extraction method (currently only has typed `preferred_username` field)
- Treat this as a strategy that can be extended later — the claim source is a string key, not a hardcoded enum

### Username Transform Pipeline (IDN-02)
- Ordered list of transforms applied sequentially: `identity.transforms: [strip_domain, lowercase]`
- Available transforms: `strip_domain` (remove @domain), `lowercase`, `regex` (with named capture group `(?P<username>...)`)
- Regex transform rejects patterns without a `(?P<username>...)` capture group at config load time
- Pipeline is composable — transforms chain in declared order
- Fuzz target `fuzz/fuzz_targets/username_mapper.rs` already sketches transform types — production module should align

### Username Collision Detection (IDN-03)
- Config-load-time static validation only — no runtime collision checks
- Verify that the chosen claim + transform pipeline is injective (one-to-one)
- E.g., `strip_domain` on `email` is safe if constrained to a single domain; warn if multiple domains could collide
- Hard-fail always: refuse to start with a clear config error (never configurable, same class as signature verification)
- Error message reveals which identities collide — this is operator-facing (config load), not attacker-facing
- Treat as an extensible strategy — initial implementation covers static transform analysis, can add explicit collision maps later

### Group-Based Login Policy (IDN-04)
- Groups sourced from configurable OIDC claim (default: `groups`), config field: `identity.groups_claim`
- `login_groups` allow-list in `[ssh_login]` section of policy.yaml — array of group name strings
- Exact string match only, case-sensitive (no wildcards, no regex — avoids ReDoS and keeps policy auditable)
- Missing groups claim behavior driven by enforcement mode: `groups_enforcement` in `[security_modes]` section
  - strict: deny login
  - warn: log warning, skip groups check, allow login
  - disabled: skip groups check entirely
- When `login_groups` is empty/absent, no group restriction applied (backward compat with v1.0)
- Denial logged with the user's groups claim values for audit trail (success criteria #2)

### Group-Based Sudo Policy (IDN-05)
- `sudo_groups` list in `[sudo]` section of policy.yaml — array of group name strings
- Separate from `login_groups` — being in sudo_groups does NOT imply login access (least privilege)
- Exact string match, case-sensitive (matches login_groups behavior)
- If user's groups claim does not intersect sudo_groups, deny at PAM step-up gate
- Same `groups_enforcement` mode applies for missing groups claim

### Break-Glass Account Bypass (IDN-06)
- Break-glass accounts identified by username list: `break_glass.accounts: ['breakglass', 'emergency-admin']`
- Extends existing `BreakGlassConfig` struct — change `local_account: Option<String>` to `accounts: Vec<String>`
- PAM returns `PAM_IGNORE` when pam_user matches a break-glass account — delegates auth to next PAM module (e.g., pam_unix)
- Break-glass bypass applies to SSH login (pam_sm_authenticate) only, NOT sudo step-up — keeps bypass scope minimal
- Check happens BEFORE any OIDC processing (rate limiting, nonce issuance, token validation) — break-glass must work when IdP is completely unreachable
- `break_glass.enabled` must be `true` AND user must be in `accounts` list — disabled by default

### Break-Glass Audit (IDN-07)
- New `AuditEvent::BreakGlassAuth` variant with CRITICAL severity
- Fields: timestamp, username, source_ip, hostname, reason ("break-glass bypass")
- Written to syslog AUTH facility + dedicated audit log (matches existing AuditEvent pattern)
- Every break-glass authentication emits this event — no way to suppress it (always-on audit)
- Audit event emitted BEFORE returning PAM_IGNORE (ensures log even if subsequent PAM module crashes)

### Claude's Discretion
- Internal design of the transform pipeline (trait vs enum, execution model)
- How to extract arbitrary claims from JWT (serde_json::Value traversal vs typed struct extension)
- Exact config validation error messages beyond collision detection
- Whether to add a `groups` field to TokenClaims or use dynamic claim extraction
- Test strategy for collision detection edge cases
- Whether `groups_enforcement` gets its own field in SecurityModes or reuses an existing pattern

</decisions>

<specifics>
## Specific Ideas

- Standing directive: ultra secure, standards/best practice compliant, enterprise ready, fully audited and tested
- Every security feature must include adversarial/negative tests (invalid transforms, collision edge cases, group bypass attempts, break-glass abuse scenarios)
- Balance security, least privilege, and enterprise-grade flexibility — except where flexibility would severely dilute security
- All security decisions and their rationale should be documented in public-facing docs or a security guide
- Post-context audit: run security and least-privilege analysis of all decisions to verify no principle violations

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `BreakGlassConfig` (`pam-unix-oidc/src/policy/config.rs:348-369`): Existing struct — extend `local_account: Option<String>` to `accounts: Vec<String>`
- `SudoConfig` (`pam-unix-oidc/src/policy/config.rs:313-336`): Existing struct — add `sudo_groups: Vec<String>` field
- `SshConfig` (`pam-unix-oidc/src/policy/config.rs:291-310`): Existing struct — add `login_groups: Vec<String>` field
- `EnforcementMode` (`pam-unix-oidc/src/policy/config.rs:58-64`): Reuse for `groups_enforcement`
- `SecurityModes` (`pam-unix-oidc/src/policy/config.rs`): Add `groups_enforcement` field
- `TokenClaims` (`pam-unix-oidc/src/oidc/token.rs:16-56`): Needs `groups` field and/or dynamic claim extraction
- `AuditEvent` (`pam-unix-oidc/src/audit.rs:38-115`): Add `BreakGlassAuth` variant
- `UserInfo` (`pam-unix-oidc/src/sssd/user.rs:23-30`): Used after username mapping resolves to local user
- Fuzz target (`fuzz/fuzz_targets/username_mapper.rs`): Transform types already sketched — production module should align

### Established Patterns
- `parking_lot::RwLock` — crate-wide locking primitive (Phase 6)
- `deny(clippy::unwrap_used, clippy::expect_used)` — all new code must comply
- figment-based config loading from policy.yaml with env var overrides
- `thiserror` for error types, `tracing` for structured logging
- `EnforcementMode` for configurable security checks with strict/warn/disabled semantics
- Hand-rolled `Deserialize` for enums that must reject invalid strings (EnforcementMode pattern)

### Integration Points
- `pam-unix-oidc/src/lib.rs:51`: `authenticate()` entry point — add break-glass check BEFORE OIDC flow
- `pam-unix-oidc/src/auth.rs:105-106`: `claims.preferred_username` hardcoded — replace with configurable claim extraction + transform pipeline
- `pam-unix-oidc/src/auth.rs:108`: `user_exists(username)` — insert group policy check between username extraction and user lookup
- `pam-unix-oidc/src/policy/config.rs:398-413`: `PolicyConfig` struct — add `identity: IdentityConfig` field
- `pam-unix-oidc/src/audit.rs`: Add `BreakGlassAuth` variant and `break_glass_auth()` constructor

</code_context>

<deferred>
## Deferred Ideas

- Glob/wildcard group matching — potential future enhancement if enterprises request it
- Runtime collision detection across active sessions — adds state tracking complexity, defer unless proven necessary
- SCIM-based group sync from IdP to local system — separate provisioning milestone (PROV-02)
- UID-range-based break-glass detection — alternative strategy, not needed with username list approach
- Break-glass bypass for sudo step-up — intentionally excluded for least-privilege; revisit if operational need emerges

</deferred>

---

*Phase: 08-username-mapping-group-policy-break-glass*
*Context gathered: 2026-03-10*
