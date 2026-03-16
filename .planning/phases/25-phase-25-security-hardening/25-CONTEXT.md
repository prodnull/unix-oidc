# Phase 25: Security Hardening - Context

**Gathered:** 2026-03-15
**Status:** Ready for planning

<domain>
## Phase Boundary

Block algorithm confusion attacks via explicit allowlist, enforce HTTPS for all OIDC endpoints at config load time, sanitize terminal escape sequences from IdP-supplied URIs, and harden D-Bus Secret Service sessions to require encryption. Six requirements: SHRD-01 through SHRD-06.

</domain>

<decisions>
## Implementation Decisions

### HTTPS Enforcement (SHRD-04)
- Enforce HTTPS for all issuer URLs at config load time — `http://` rejected with clear error message
- Enforce HTTPS for device flow `verification_uri` at runtime (already partially implemented in `device_flow/types.rs`)
- Extract a shared `validate_https_url()` function used by both config loading and device flow response parsing — DRY, single enforcement point
- **Test exception**: `allow_insecure_http_for_testing` config field gated by `#[cfg(any(test, feature = "test-mode"))]` — production binary physically cannot parse the field
- **Runtime audit**: If test-mode binary uses the field, emit a CRITICAL-severity audit event at startup ("INSECURE: HTTP issuer URLs permitted") — impossible to miss in logs
- CI e2e tests (which run production binary against `http://keycloak:8080`) use the test-mode feature build

### Algorithm Enforcement (SHRD-01, SHRD-02)
- **Allowlist, not blocklist**: Default allowlist of permitted algorithms: RS256, RS384, RS512, ES256, ES384, PS256, PS384, PS512, EdDSA. Anything not on the list is rejected when JWKS key omits `alg` field
- **Configurable per-issuer**: Each issuer in `policy.yaml` can set `allowed_algorithms: [RS256, ES256, ...]` to override the default. Matches multi-IdP architecture — one issuer can use ES256 while another uses RS256
- **Explicit enum match via TryFrom**: Replace serde string comparison with `impl TryFrom<KeyAlgorithm> for Algorithm` using exhaustive match arms. Compiler catches new variants. Standard Rust trait convention, composable with `?` operator
- Algorithm comparison in `validation.rs` uses the TryFrom impl, not Debug format or serde serialization

### Break-Glass Syslog Severity (SHRD-03)
- Already implemented in Phase 24 (SBUG-02): `syslog_severity()` maps `BreakGlassAuth` with `alert_on_use=true` to `AuditSeverity::Critical`
- Verify existing implementation satisfies the success criterion — may only need a test confirming the syslog path

### Terminal Sanitization (SHRD-05)
- Strip all ANSI escape sequences (CSI, OSC, DCS, APC, PM, SOS) from `verification_uri` before display — not just `\x1b[`
- Replace non-printable bytes with safe representations, preserving valid Unicode (internationalized domain names are legitimate)
- Return sanitized string rather than rejecting the URI — graceful degradation
- Log a WARNING when sanitization strips anything, including the raw bytes removed — maximum visibility for operators whose IdP returns suspicious URIs
- Apply sanitization at the display point in `unix-oidc-agent/src/main.rs` where `verification_uri` is printed to terminal

### D-Bus Secret Service Encryption (SHRD-06)
- New config toggle: `reject_plain_dbus_sessions: strict/warn/disabled`
- **Default: warn** — log warning when unencrypted D-Bus Secret Service session detected, but allow it. Matches project philosophy of conservative security with pragmatic usability
- **Detection point**: Probe at backend selection in `StorageRouter::detect()`, after Secret Service probe succeeds. Inspect whether session used DH negotiation or fell back to plain. Check once at startup, not on every operation
- **Visibility**: Both structured audit event AND tracing log when plain session detected — gives fleet-level SIEM visibility for which hosts run with unencrypted sessions
- **strict mode**: Reject Secret Service backend entirely if session is unencrypted, fall through to keyutils or file fallback

### Claude's Discretion
- Exact sanitization regex/function implementation for ANSI escape stripping
- Test structure and organization for the new validation code
- Whether SHRD-03 needs new code or just a verification test
- Internal error types and error message wording

</decisions>

<specifics>
## Specific Ideas

- User's guiding principle: **security and risk first, but choose the most flexible option within those parameters, with maximum visibility through logs and events**
- The `allow_insecure_http_for_testing` compile-time gate follows the existing `test-mode` feature pattern — consistent with `UNIX_OIDC_TEST_MODE` gating but narrower in scope (only HTTP bypass, not signature bypass)
- Per-issuer `allowed_algorithms` follows the per-issuer config pattern established in Phase 21 (multi-IdP configuration)
- D-Bus audit event extends the fleet visibility story — operators can query SIEM for hosts running with weak transport security

</specifics>

<code_context>
## Existing Code Insights

### Reusable Assets
- `pam-unix-oidc/src/oidc/validation.rs:306-353`: Current algorithm comparison code (serde-based) — replacement target for SHRD-01/02
- `pam-unix-oidc/src/device_flow/types.rs:71-94`: Existing HTTPS validation for verification_uri — model for shared validator
- `pam-unix-oidc/src/audit.rs:322-340`: Break-glass audit event with CRITICAL severity — already satisfies SHRD-03 intent
- `pam-unix-oidc/src/policy/config.rs:275-317`: IssuerConfig struct — where `allowed_algorithms` per-issuer config would be added
- `unix-oidc-agent/src/storage/router.rs:348-359`: Secret Service backend selection — where D-Bus encryption probe would go
- `unix-oidc-agent/src/main.rs:787-814`: verification_uri display code — where terminal sanitization applies

### Established Patterns
- `SecurityModes` struct with `strict/warn/disabled` enforcement (Phase 6) — reuse for D-Bus config
- `#[cfg(feature = "test-mode")]` gating for insecure paths — reuse for HTTP allowance
- Per-issuer config fields in `IssuerConfig` (Phase 21) — reuse for `allowed_algorithms`
- `StorageRouter::detect()` probe pattern — extend for D-Bus encryption check
- `AuditEvent` structured events with `syslog_severity()` mapping — extend for D-Bus plain session warning

### Integration Points
- Config validation in `PolicyConfig::load_from()` — add HTTPS scheme check for `issuer_url`
- `verify_and_decode()` in `validation.rs` — replace serde comparison with TryFrom-based enum match
- `StorageRouter::detect()` — add D-Bus encryption probe after Secret Service success
- `main.rs` device flow display — wrap `verification_uri` in sanitizer before `eprintln!`

</code_context>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope

</deferred>

---

*Phase: 25-phase-25-security-hardening*
*Context gathered: 2026-03-15*
