---
phase: 09-token-introspection-session-lifecycle-token-refresh
plan: "02"
subsystem: pam-unix-oidc
tags: [introspection, rfc-7662, moka-cache, pam, revocation-detection]
dependency_graph:
  requires: [09-01]
  provides: [introspection-client, introspection-cache, introspection-wired-to-authenticate]
  affects:
    - pam-unix-oidc/src/oidc/introspection.rs
    - pam-unix-oidc/src/oidc/mod.rs
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/lib.rs
tech_stack:
  added: []
  patterns:
    - moka sync::Cache for introspection result TTL caching (same pattern as DPoPNonceCache)
    - once_cell::sync::Lazy for global HTTP client and cache singletons
    - SHA-256 of first 32 token bytes as cache key fallback (no raw bearer in map keys)
    - RFC 7662 §2.1 Basic Auth (client_id + optional client_secret) via reqwest blocking
    - Fail-open/fail-closed via EnforcementMode (Warn/Strict) — same pattern as dpop_required
key_files:
  created:
    - pam-unix-oidc/src/oidc/introspection.rs
  modified:
    - pam-unix-oidc/src/oidc/mod.rs
    - pam-unix-oidc/src/policy/config.rs
    - pam-unix-oidc/src/lib.rs
decisions:
  - "Inactive (active=false) results are NOT cached — revoked tokens are re-checked every auth attempt rather than being blocked for the full cache TTL"
  - "Error results are NOT cached — a transient endpoint failure does not poison the cache with a deny that persists until TTL"
  - "IntrospectionConfig gains client_secret: Option<String> — RFC 7662 §2.1 requires endpoint to authenticate caller; many IdPs support public (client_id-only) or confidential (client_id+secret) clients"
  - "Introspection runs AFTER all cryptographic validation — it is an additional liveness check, not a replacement for signature/issuer/audience/expiry verification"
  - "Default config (enabled=false) has zero overhead — no behavior change for existing deployments"
metrics:
  duration_secs: 259
  completed_date: "2026-03-11"
  tasks_completed: 2
  files_modified: 4
---

# Phase 9 Plan 02: RFC 7662 Token Introspection Client + Moka Cache Summary

RFC 7662 introspection client with moka-backed result caching (JTI-keyed, SHA-256 fallback) and configurable fail-open/fail-closed enforcement wired into the PAM `authenticate()` flow as a post-validation active-status check.

## What Was Built

### Task 1: RFC 7662 introspection client + moka cache

**pam-unix-oidc/src/oidc/introspection.rs** (new, 340+ lines)

- `IntrospectionError` enum: `Http`, `Parse`, `NotConfigured`, `TokenInactive` (thiserror)
- `IntrospectionCache`: wraps `moka::sync::Cache<String, bool>`:
  - `get_or_insert(cache_key, token_exp, introspect_fn)` — cache hit returns immediately; on miss calls the closure, logs WARN if `token_exp < now + ttl_secs`, caches only `Ok(true)` results (negative and error results re-checked every auth attempt)
  - `entry_count()` for diagnostics
- `global_introspection_cache()` — `Lazy<IntrospectionCache>` singleton (10k entries, 60s TTL)
- `global_http_client()` — `Lazy<reqwest::blocking::Client>` singleton (5s timeout, reuses TLS sessions across PAM auth calls)
- `derive_cache_key(token_jti, token)` — JTI preferred; SHA-256 of `token[..32]` hex-encoded as fallback (no raw bearer credentials as map keys)
- `introspect_token(config, token, token_jti, token_exp, client_id, session_id, username)` — public API; fast-path `Ok(true)` when disabled; returns `Err(NotConfigured)` when no endpoint; uses cache with HTTP closure
- `do_introspect(endpoint, ...)` — HTTP POST `application/x-www-form-urlencoded` with `token` + `token_type_hint=access_token`, Basic Auth (client_id + optional client_secret) per RFC 7662 §2.1; emits `IntrospectionFailed` audit event on HTTP error, non-2xx, or JSON parse failure
- `IntrospectionResponse { active: bool }` — minimal RFC 7662 §2.2 deserializable struct
- **12 unit tests**: disabled short-circuit, NotConfigured, cache key derivation (JTI/SHA-256/determinism/collisions/short-token), cache hit prevents second closure call, cache miss invokes closure, inactive/error results not cached, singleton identity, unreachable endpoint returns Http error

**pam-unix-oidc/src/oidc/mod.rs** — added `pub mod introspection;`

**pam-unix-oidc/src/policy/config.rs** — added `client_secret: Option<String>` field to `IntrospectionConfig` with Serialize + hand-rolled Deserialize; default `None`. Required per RFC 7662 §2.1.

### Task 2: Wire introspection into authenticate() flow

**pam-unix-oidc/src/lib.rs** — inserted introspection block in `authenticate()` between username-match check and `record_success()`:

1. Loads `PolicyConfig::from_env()` (non-fatal; if policy absent, introspection is skipped)
2. If `policy.introspection.enabled`: reads `OIDC_CLIENT_ID` env var (default `"unix-oidc"`), calls `introspect_token()`
3. Result dispatch by `enforcement` mode:
   - `Ok(true)` — active; no-op, proceed to SUCCESS
   - `Ok(false)` — inactive: `Strict` → `AUTH_ERR` + `IntrospectionFailed` audit; `Warn` → log + proceed
   - `Err(NotConfigured)` — misconfiguration: `Strict` → `SERVICE_ERR` + log; `Warn` → log + proceed
   - `Err(other)` — endpoint error (audit already emitted in `do_introspect`): `Strict` → `AUTH_ERR`; `Warn` → fail-open
4. When `enabled = false` (default): the entire block is a non-entering `if` — zero overhead

## Verification Results

```
cargo test -p pam-unix-oidc --features test-mode   → 270 passed, 0 failed (+12 new introspection tests)
cargo clippy -p pam-unix-oidc -- -D warnings        → Finished (no warnings)
cargo build -p pam-unix-oidc                         → Finished (no test-mode features)
```

## Commits

| Task | Commit  | Description |
|------|---------|-------------|
| 1    | afa7702 | feat(09-02): RFC 7662 introspection client + moka cache |
| 2    | fdaed47 | feat(09-02): wire RFC 7662 introspection into authenticate() flow |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing functionality] Added client_secret field to IntrospectionConfig**
- **Found during:** Task 1 (implementation)
- **Issue:** The plan noted "add client_secret to IntrospectionConfig if needed" — RFC 7662 §2.1 explicitly requires the endpoint to authenticate the caller. Without `client_secret`, operators with confidential clients (Keycloak, Okta) cannot configure introspection correctly.
- **Fix:** Added `client_secret: Option<String>` to `IntrospectionConfig` with hand-rolled Deserialize and default `None`. Backward-compatible (absent in existing policy.yaml files = `None`).
- **Files modified:** pam-unix-oidc/src/policy/config.rs
- **Commit:** afa7702

**2. [Rule 3 - Blocking] Used `{b:02x}` formatting instead of `hex` crate**
- **Found during:** Task 1 (implementation)
- **Issue:** Implementation initially referenced the `hex` crate for SHA-256 hex encoding, but `hex` is not in the workspace dependencies and adding it is unnecessary overhead.
- **Fix:** Replaced with `digest.iter().map(|b| format!("{b:02x}")).collect()` — stdlib only.
- **Files modified:** pam-unix-oidc/src/oidc/introspection.rs
- **Commit:** afa7702

## Self-Check: PASSED
